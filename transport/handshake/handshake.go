package handshake

import (
	"crypto/ecdh"
	"encoding/binary"
	"hash"
	"log"
	"math"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
)

type HandshakeConnection struct {
	LocalRandom  [32]byte
	X25519Secret *ecdh.PrivateKey // Tons of allocations here. TODO - compute in calculator goroutine

	HandshakeTrafficSecretSend    [32]byte // we need to keep this for finished message.
	HandshakeTrafficSecretReceive [32]byte // we need to keep this for finished message.

	MasterSecret [32]byte

	currentFlight byte // both send and receive

	receivedPartialMessageSet    bool // if set, Header.MessageSeq == Keys.NextMessageSeqReceive
	receivedPartialMessage       format.MessageHandshake
	receivedPartialMessageOffset uint32 // we do not support holes for now. TODO - support holes

	// end of previous flight, all messages before are implicitly acked by any message from messages
	sendAcksfromMessageSeq uint16
	sendAcks               AcksSet

	SendQueue SendQueue

	TranscriptHasher hash.Hash // when messages are added to messages, they are also added to TranscriptHasher

	certificateChain format.MessageCertificate
}

func NewHandshakeConnection(hasher hash.Hash) *HandshakeConnection {
	hctx := &HandshakeConnection{
		TranscriptHasher: hasher,
	}
	hctx.SendQueue.Reserve()
	return hctx
}

func (hctx *HandshakeConnection) ComputeKeyShare(rnd dtlsrand.Rand) {
	var X25519Secret [32]byte
	rnd.ReadMust(X25519Secret[:])
	priv, err := ecdh.X25519().NewPrivateKey(X25519Secret[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.X25519Secret = priv
}

func (hctx *HandshakeConnection) AddAck(messageSeq uint16, rn format.RecordNumber) {
	if messageSeq < hctx.sendAcksfromMessageSeq {
		return
	}
	hctx.sendAcks.Add(rn)
}

func (hctx *HandshakeConnection) ReceivedFlight(conn *ConnectionImpl, flight byte) (newFlight bool) {
	if flight <= hctx.currentFlight {
		return false
	}
	hctx.currentFlight = flight
	// implicit ack of all previous flights
	hctx.SendQueue.Clear()

	hctx.sendAcksfromMessageSeq = conn.Keys.NextMessageSeqReceive
	hctx.sendAcks.Clear()
	return true
}

func (hctx *HandshakeConnection) ReceivedMessage(conn *ConnectionImpl, handshakeHdr format.MessageHandshakeHeader, body []byte, rn format.RecordNumber) (registerInSender bool) {
	if handshakeHdr.MessageSeq < conn.Keys.NextMessageSeqReceive {
		hctx.AddAck(handshakeHdr.MessageSeq, rn) // otherwise, peer will send those messages forever
		return false                             // totally ok to ignore
	}
	if handshakeHdr.MessageSeq > conn.Keys.NextMessageSeqReceive {
		return false // totally ok to ignore
	}
	// we do not check that message is full here, because if partial message set, we want to clear that by common code
	if !hctx.receivedPartialMessageSet {
		hctx.AddAck(handshakeHdr.MessageSeq, rn)
		if !handshakeHdr.IsFragmented() {
			conn.Keys.NextMessageSeqReceive++
			return hctx.receivedFullMessage(conn, handshakeHdr, body)
		}
		hctx.receivedPartialMessageSet = true
		hctx.receivedPartialMessageOffset = 0
		// TODO - take body from pool
		hctx.receivedPartialMessage.Body = append(hctx.receivedPartialMessage.Body[:0], make([]byte, handshakeHdr.Length)...)
		hctx.receivedPartialMessage.Header = handshakeHdr
		// now process partial message below
	}
	if handshakeHdr.Length != hctx.receivedPartialMessage.Header.Length {
		// TODO - alert and close connection, invariant violated
		return false
	}
	if handshakeHdr.FragmentOffset > hctx.receivedPartialMessageOffset {
		return false // we do not support holes, ignore, wait for earlier message first
	}
	hctx.AddAck(handshakeHdr.MessageSeq, rn) // should ack it independent of conditions below
	newOffset := handshakeHdr.FragmentOffset + handshakeHdr.FragmentLength
	if newOffset <= hctx.receivedPartialMessageOffset {
		return false // nothing new, ignore
	}
	copy(hctx.receivedPartialMessage.Body[handshakeHdr.FragmentOffset:], body)
	hctx.receivedPartialMessageOffset = newOffset
	if hctx.receivedPartialMessageOffset != handshakeHdr.Length {
		return false // ok, waiting for more fragments
	}
	hctx.receivedPartialMessageSet = false
	conn.Keys.NextMessageSeqReceive++
	registerInSender = hctx.receivedFullMessage(conn, hctx.receivedPartialMessage.Header, hctx.receivedPartialMessage.Body)
	// TODO - return message body to pool here
	return registerInSender
}

// also acks (removes) all previous flights
func (hctx *HandshakeConnection) PushMessage(conn *ConnectionImpl, msg format.MessageHandshake) {
	if conn.Keys.NextMessageSeqSend >= math.MaxUint16 {
		// TODO - prevent wrapping next message seq
		// close connection here
		return // for now
	}
	msg.Header.MessageSeq = conn.Keys.NextMessageSeqSend
	conn.Keys.NextMessageSeqSend++

	hctx.SendQueue.PushMessage(msg)

	msg.Header.AddToHash(hctx.TranscriptHasher)
	_, _ = hctx.TranscriptHasher.Write(msg.Body)
}

// must not write over len(datagram), returns part of datagram filled
func (hctx *HandshakeConnection) ConstructDatagram(conn *ConnectionImpl, datagram []byte) (datagramSize int, addToSendQueue bool) {
	// we decided to first send our messages, then acks.
	// because message has a chance to ack the whole flight
	datagramSize, addToSendQueue = hctx.SendQueue.ConstructDatagram(conn, datagram)
	if hctx.sendAcks.Size() != 0 && conn.Keys.Send.Symmetric.Epoch != 0 {
		// We send only encrypted acks
		acksSpace := len(datagram) - datagramSize - format.MessageAckHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
		if acksSpace < format.MessageAckRecordNumberSize { // not a single one fits
			return datagramSize, true
		}
		acksCount := min(hctx.sendAcks.Size(), acksSpace/format.MessageAckRecordNumberSize)
		if acksSpace < constants.MinFragmentBodySize && acksCount != hctx.sendAcks.Size() {
			return datagramSize, true // do not send tiny records at the end of datagram
		}
		sendAcks := hctx.sendAcks.PopSorted(acksCount)

		da := conn.constructCiphertextAck(datagram[datagramSize:datagramSize], sendAcks)

		if len(da) > len(datagram[datagramSize:]) {
			panic("ciphertext ack record construction length invariant failed")
		}
		datagramSize += len(da)
		addToSendQueue = addToSendQueue || hctx.sendAcks.Size() != 0
	}
	return
}

func (conn *ConnectionImpl) constructRecord(datagram []byte, msg format.MessageHandshake, fragmentOffset uint32, maxFragmentLength uint32) (recordSize int, fragmentInfo format.FragmentInfo, rn format.RecordNumber) {
	// during fragmenting we always write header at the start of the message, and then part of the body
	if msg.Header.Length != uint32(len(msg.Body)) {
		panic("invariant of send queue fragment offset violated")
	}
	if fragmentOffset >= msg.Header.Length { // >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
		panic("invariant of send queue fragment offset violated")
	}
	msg.Header.FragmentOffset = fragmentOffset

	if msg.Header.HandshakeType == format.HandshakeTypeClientHello || msg.Header.HandshakeType == format.HandshakeTypeServerHello {
		remainingSpace := len(datagram) - format.MessageHandshakeHeaderSize + format.PlaintextRecordHeaderSize
		if remainingSpace <= 0 {
			return
		}
		msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
		if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
			return // do not send tiny records at the end of datagram
		}
		da, rn := conn.constructPlaintextRecord(datagram[:0], msg)
		if uint32(len(da)) != msg.Header.FragmentLength+format.MessageHandshakeHeaderSize+format.PlaintextRecordHeaderSize {
			panic("plaintext handshake record construction length invariant failed")
		}
		return len(da), msg.Header.FragmentInfo, rn
	}
	remainingSpace := len(datagram) - format.MessageHandshakeHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if remainingSpace <= 0 {
		return
	}
	msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
	if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
		return // do not send tiny records at the end of datagram
	}
	da, rn := conn.constructCiphertextRecord(datagram[:0], msg)
	if len(da) > len(datagram) {
		panic("ciphertext handshake record construction length invariant failed")
	}
	return len(da), msg.Header.FragmentInfo, rn
}

func (conn *ConnectionImpl) constructPlaintextRecord(data []byte, msg format.MessageHandshake) ([]byte, format.RecordNumber) {
	rn := format.RecordNumberWith(0, conn.Keys.Send.NextEpoch0Sequence)
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		SequenceNumber: conn.Keys.Send.NextEpoch0Sequence,
	}
	conn.Keys.Send.NextEpoch0Sequence++
	data = recordHdr.Write(data, format.MessageHandshakeHeaderSize+int(msg.Header.FragmentLength))
	data = msg.Header.Write(data)
	data = append(data, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return data, rn
}

func (conn *ConnectionImpl) constructCiphertextRecord(datagram []byte, msg format.MessageHandshake) ([]byte, format.RecordNumber) {
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.Send.NextSegmentSequence)
	seq := send.NextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	send.NextSegmentSequence++
	log.Printf("constructing ciphertext handshake with seq: %v", rn)

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	hdr := format.NewCiphertextRecordHeader(false, true, true, epoch)
	startRecordOffset := len(datagram)
	datagram = append(datagram, hdr.FirstByte)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(seq))
	datagram = append(datagram, 0, 0) // fill length later
	startBodyOFfset := len(datagram)
	datagram = msg.Header.Write(datagram)
	datagram = append(datagram, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	datagram = append(datagram, format.PlaintextContentTypeHandshake)

	padding := len(datagram) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		datagram = append(datagram, 0)
	}

	binary.BigEndian.PutUint16(datagram[startRecordOffset+3:], uint16(len(datagram)-startBodyOFfset))

	encrypted := gcm.Seal(datagram[startBodyOFfset:startBodyOFfset], iv[:], datagram[startBodyOFfset:len(datagram)-constants.AEADSealSize], datagram[startRecordOffset:startBodyOFfset])
	if &encrypted[0] != &datagram[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(datagram[startBodyOFfset:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.Keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(datagram[startRecordOffset+1:startRecordOffset+3], datagram[startBodyOFfset:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return datagram, rn
}

func (conn *ConnectionImpl) constructCiphertextAck(datagram []byte, acks []format.RecordNumber) []byte {
	// TODO - harmonize with code above
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.Send.NextSegmentSequence)
	seq := send.NextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	send.NextSegmentSequence++
	log.Printf("constructing ciphertext ack with seq: %v", rn)

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	hdr := format.NewCiphertextRecordHeader(false, true, true, epoch)
	datagram = append(datagram, hdr.FirstByte)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(seq))
	datagram = append(datagram, 0, 0) // fill length later
	startBodyOFfset := len(datagram)
	// serialization of ack message, TODO - move out?
	datagram, mark := format.MarkUint16Offset(datagram)
	for _, ack := range acks {
		datagram = binary.BigEndian.AppendUint64(datagram, uint64(ack.Epoch()))
		datagram = binary.BigEndian.AppendUint64(datagram, ack.SeqNum())
	}
	format.FillUint16Offset(datagram, mark)
	datagram = append(datagram, format.PlaintextContentTypeAck)

	padding := len(datagram) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		datagram = append(datagram, 0)
	}

	binary.BigEndian.PutUint16(datagram[3:], uint16(len(datagram)-startBodyOFfset))

	encrypted := gcm.Seal(datagram[startBodyOFfset:startBodyOFfset], iv[:], datagram[startBodyOFfset:len(datagram)-constants.AEADSealSize], datagram[:startBodyOFfset])
	if &encrypted[0] != &datagram[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(datagram[startBodyOFfset:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.Keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(datagram[1:3], datagram[startBodyOFfset:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return datagram
}

func (conn *ConnectionImpl) constructCiphertextApplication(record []byte) []byte {
	// TODO - harmonize with code above
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.Send.NextSegmentSequence)
	seq := send.NextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	send.NextSegmentSequence++
	log.Printf("constructing ciphertext application with seq: %v", rn)

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	hdr := format.NewCiphertextRecordHeader(false, true, true, epoch)
	const hdrSize = format.OutgoingCiphertextRecordHeader
	record = append(record, format.PlaintextContentTypeApplicationData)

	padding := len(record) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		record = append(record, 0)
	}

	record[0] = hdr.FirstByte
	binary.BigEndian.PutUint16(record[1:], uint16(seq))
	binary.BigEndian.PutUint16(record[3:], uint16(len(record)-hdrSize))

	encrypted := gcm.Seal(record[hdrSize:hdrSize], iv[:], record[hdrSize:len(record)-constants.AEADSealSize], record[:hdrSize])
	if &encrypted[0] != &record[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(record[hdrSize:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.Keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(record[1:3], record[hdrSize:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return record
}
