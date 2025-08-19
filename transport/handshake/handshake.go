package handshake

import (
	"crypto/ecdh"
	"encoding/binary"
	"hash"
	"log"
	"math"

	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
)

type HandshakeConnection struct {
	LocalRandom  [32]byte
	X25519Secret *ecdh.PrivateKey // Tons of allocations here. TODO - compute in calculator goroutine

	MasterSecret                  [32]byte
	HandshakeTrafficSecretSend    [32]byte // we need this to generate finished message.
	HandshakeTrafficSecretReceive [32]byte // we need this to check peer's finished message.

	// for ServerHello retransmit and replay protection
	// we decided 2^16 ServerHello/ClientHello is enough for all practical purposes,
	// see dtlserrors.ErrSendEpoch0RecordSeqOverflow
	SendNextSegmentSequenceEpoch0 uint16

	currentFlight byte // both send and receive

	receivedPartialMessageSet bool // if set, Header.MessageSeq == conn.NextMessageSeqReceive
	receivedPartialMessage    PartialHandshakeMessage

	// We need more than 1 message, otherwise we will lose them, while
	// handshake is in a state of waiting finish of offloaded calculations.
	// if full message is received, and it is the first in the queue (or queue is empty),
	// then
	receivedMessages        circular.BufferExt[recordFragmentRelation]
	receivedMessagesStorage [constants.MaxReceiveMessagesQueue]PartialHandshakeMessage

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

func (hctx *HandshakeConnection) ReceivedFlight(conn *ConnectionImpl, flight byte) (newFlight bool) {
	if flight <= hctx.currentFlight {
		return false
	}
	hctx.currentFlight = flight
	// implicit ack of all previous flights
	hctx.SendQueue.Clear()

	conn.Keys.SendAcks.Reset()
	return true
}

func (hctx *HandshakeConnection) ReceivedMessage(conn *ConnectionImpl, handshakeHdr format.MessageHandshakeHeader, body []byte, rn format.RecordNumber) error {
	if handshakeHdr.MessageSeq != conn.NextMessageSeqReceive {
		return nil // < was processed by ack state machine already
	}
	if conn.NextMessageSeqReceive == math.MaxUint16 { // would overflow below
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	// we do not check that message is full here, because if partial message set, we want to clear that by common code
	if !hctx.receivedPartialMessageSet {
		conn.Keys.AddAck(rn)
		if !handshakeHdr.IsFragmented() {
			conn.NextMessageSeqReceive++ // never due to check above
			return hctx.receivedFullMessage(conn, handshakeHdr, body)
		}
		// TODO - take body from pool
		hctx.receivedPartialMessage = PartialHandshakeMessage{
			Header: MessageHeaderMinimal{
				HandshakeType: handshakeHdr.HandshakeType,
				MessageSeq:    handshakeHdr.MessageSeq,
			},
			Body:       append(hctx.receivedPartialMessage.Body[:0], make([]byte, handshakeHdr.Length)...),
			SendOffset: 0,
			SendEnd:    handshakeHdr.Length,
		}
		hctx.receivedPartialMessageSet = true
		// now process partial message below
	}
	if handshakeHdr.Length != uint32(len(hctx.receivedPartialMessage.Body)) {
		// TODO - alert and close connection, invariant violated
		return dtlserrors.ErrHandshakeMessageFragmentLengthMismatch
	}
	if handshakeHdr.HandshakeType != hctx.receivedPartialMessage.Header.HandshakeType {
		// TODO - alert and close connection, invariant violated
		return dtlserrors.ErrHandshakeMessageFragmentTypeMismatch
	}
	shouldAck, changed := hctx.receivedPartialMessage.Ack(handshakeHdr.FragmentOffset, handshakeHdr.FragmentLength)
	if !shouldAck {
		return nil // we do not support holes, ignore, wait for earlier or later fragment first
	}
	conn.Keys.AddAck(rn) // should ack it independent of conditions below
	if !changed {        // nothing new, ignore
		return nil
	}
	copy(hctx.receivedPartialMessage.Body[handshakeHdr.FragmentOffset:], body) // copy all bytes for simplicity
	if !hctx.receivedPartialMessage.FullyAcked() {
		return nil // ok, waiting for more fragments
	}
	body = hctx.receivedPartialMessage.Body
	hctx.receivedPartialMessage = PartialHandshakeMessage{}
	hctx.receivedPartialMessageSet = false
	conn.NextMessageSeqReceive++ // never due to check above
	handshakeHdr.FragmentOffset = 0
	handshakeHdr.FragmentLength = handshakeHdr.Length
	err := hctx.receivedFullMessage(conn, handshakeHdr, body)
	// TODO - return message body to pool here
	return err
}

// also acks (removes) all previous flights
func (hctx *HandshakeConnection) PushMessage(conn *ConnectionImpl, msg format.MessageHandshake) {
	if conn.NextMessageSeqSend >= math.MaxUint16 {
		// TODO - prevent wrapping next message seq
		// close connection here
		return // for now
	}
	msg.Header.MessageSeq = conn.NextMessageSeqSend
	conn.NextMessageSeqSend++

	hctx.SendQueue.PushMessage(msg)

	msg.Header.AddToHash(hctx.TranscriptHasher)
	_, _ = hctx.TranscriptHasher.Write(msg.Body)
}

func (conn *ConnectionImpl) constructRecord(datagram []byte, header MessageHeaderMinimal, body []byte, fragmentOffset uint32, maxFragmentLength uint32, sendNextSegmentSequenceEpoch0 *uint16) (recordSize int, fragmentInfo format.FragmentInfo, rn format.RecordNumber, err error) {
	// during fragmenting we always write header at the start of the message, and then part of the body
	if fragmentOffset >= uint32(len(body)) { // >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
		panic("invariant of send queue fragment offset violated")
	}
	msg := format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: header.HandshakeType,
			Length:        uint32(len(body)),
			FragmentInfo: format.FragmentInfo{
				MessageSeq:     header.MessageSeq,
				FragmentOffset: fragmentOffset,
				FragmentLength: 0,
			},
		},
		Body: body,
	}
	if header.HandshakeType == format.HandshakeTypeClientHello || header.HandshakeType == format.HandshakeTypeServerHello {
		if sendNextSegmentSequenceEpoch0 == nil {
			panic("the same check for plaintext record should be above")
		}
		remainingSpace := len(datagram) - format.MessageHandshakeHeaderSize + format.PlaintextRecordHeaderSize
		if remainingSpace <= 0 {
			return
		}
		msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
		if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
			return // do not send tiny records at the end of datagram
		}
		da, rn, err := conn.constructPlaintextRecord(datagram[:0], msg, sendNextSegmentSequenceEpoch0)
		if uint32(len(da)) != msg.Header.FragmentLength+format.MessageHandshakeHeaderSize+format.PlaintextRecordHeaderSize {
			panic("plaintext handshake record construction length invariant failed")
		}
		if err != nil {
			return 0, format.FragmentInfo{}, format.RecordNumber{}, err
		}
		return len(da), msg.Header.FragmentInfo, rn, nil
	}
	remainingSpace := len(datagram) - format.MessageHandshakeHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if remainingSpace <= 0 {
		return
	}
	msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
	if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
		return // do not send tiny records at the end of datagram
	}
	da, rn, err := conn.constructCiphertextRecord(datagram[:0], msg)
	if err != nil {
		return 0, format.FragmentInfo{}, format.RecordNumber{}, err
	}
	if len(da) > len(datagram) {
		panic("ciphertext handshake record construction length invariant failed")
	}
	return len(da), msg.Header.FragmentInfo, rn, nil
}

func (conn *ConnectionImpl) constructPlaintextRecord(data []byte, msg format.MessageHandshake, sendNextSegmentSequenceEpoch0 *uint16) ([]byte, format.RecordNumber, error) {
	if *sendNextSegmentSequenceEpoch0 >= math.MaxUint16 {
		// We arbitrarily decided that we do not need more outgoing sequence numbers for epoch 0
		// We needed code to prevent overflow below anyway
		return nil, format.RecordNumber{}, dtlserrors.ErrSendEpoch0RecordSeqOverflow
	}
	rn := format.RecordNumberWith(0, uint64(*sendNextSegmentSequenceEpoch0))
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		SequenceNumber: uint64(*sendNextSegmentSequenceEpoch0),
	}
	*sendNextSegmentSequenceEpoch0++ // never overflows due to check above
	data = recordHdr.Write(data, format.MessageHandshakeHeaderSize+int(msg.Header.FragmentLength))
	data = msg.Header.Write(data)
	data = append(data, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return data, rn, nil
}

func (conn *ConnectionImpl) checkSendLimit() error {
	sendLimit := conn.Keys.SequenceNumberLimit()
	if conn.Keys.SendNextSegmentSequence >= sendLimit {
		return dtlserrors.ErrSendRecordSeqOverflow
	}
	if conn.Keys.Send.Symmetric.Epoch < 3 || conn.Keys.SendNextSegmentSequence < sendLimit*3/4 { // simple heuristic
		return nil
	}
	return conn.startKeyUpdate(false)
}

func (conn *ConnectionImpl) constructCiphertextRecord(datagram []byte, msg format.MessageHandshake) ([]byte, format.RecordNumber, error) {
	if err := conn.checkSendLimit(); err != nil {
		return nil, format.RecordNumber{}, err
	}
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.SendNextSegmentSequence)
	seq := conn.Keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.Keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext handshake with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

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
	return datagram, rn, nil
}

func (conn *ConnectionImpl) constructCiphertextAck(datagram []byte, acks []format.RecordNumber) ([]byte, error) {
	// TODO - harmonize with code above
	if err := conn.checkSendLimit(); err != nil {
		return nil, err
	}
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.SendNextSegmentSequence)
	seq := conn.Keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.Keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext ack with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

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
	return datagram, nil
}

func (conn *ConnectionImpl) constructCiphertextApplication(record []byte) ([]byte, error) {
	// TODO - harmonize with code above
	if err := conn.checkSendLimit(); err != nil {
		return nil, err
	}
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.SendNextSegmentSequence)
	seq := conn.Keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.Keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext application with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

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
	return record, nil
}
