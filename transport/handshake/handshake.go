package handshake

import (
	"encoding/binary"
	"hash"
	"log"
	"math"
	"slices"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
	"golang.org/x/crypto/curve25519"
)

const (
	// zero is reserved as a flag for "flight not set"
	MessagesFlightClientHello1               = 1
	MessagesFlightServerHRR                  = 2
	MessagesFlightClientHello2               = 3
	MessagesFlightServerHello_Finished       = 4 // ServerHello, EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished
	MessagesFlightClientCertificate_Finished = 5 // Certificate, CertificateVerify, Finished
)

type HandshakeConnection struct {
	LocalRandom  [32]byte
	X25519Secret [32]byte
	X25519Public [32]byte // TODO - compute in calculator goroutine

	MasterSecret [32]byte

	receivedPartialMessageSet    bool // if set, Header.MessageSeq == Keys.NextMessageSeqReceive
	receivedPartialMessage       format.MessageHandshake
	receivedPartialMessageOffset uint32 // we do not support holes for now. TODO - support holes

	sendAcks map[format.RecordNumber]struct{} // len() <= MaxSendAcks, sorted before sending
	// all message before that are implicitly acked by any message from messagesSendQueue
	sendAcksfromMessageSeq uint16

	sendQueueFlight         byte                      // message from the next flight will ack (clear) all messages in send queue
	messagesSendQueue       []format.MessageHandshake // all messages here belong to the same flight. TODO - fixed array storage with some limit
	SendQueueMessageOffset  int                       // offset in messagesSendQueue of the message we are sending, len(messagesSendQueue) if all sent
	SendQueueFragmentOffset int                       // offset inside messagesSendQueue[SendQueueMessageOffset] or 0 if SendQueueMessageOffset == len(messagesSendQueue)

	TranscriptHasher hash.Hash // when messages are added to messagesSendQueue, they are also added to TranscriptHasher

	certificateChain    format.MessageCertificate
	ServerHelloReceived bool
}

func NewHandshakeConnection(hasher hash.Hash) *HandshakeConnection {
	return &HandshakeConnection{
		TranscriptHasher: hasher,
		sendAcks:         make(map[format.RecordNumber]struct{}),
	}
}

func (hctx *HandshakeConnection) ComputeKeyShare() {
	x25519Public, err := curve25519.X25519(hctx.X25519Secret[:], curve25519.Basepoint)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	copy(hctx.X25519Public[:], x25519Public)
}

func (hctx *HandshakeConnection) AddAck(messageSeq uint16, rn format.RecordNumber) {
	if messageSeq < hctx.sendAcksfromMessageSeq {
		return
	}
	hctx.sendAcks[rn] = struct{}{}
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

func (hctx *HandshakeConnection) SendQueueFlight() byte { return hctx.sendQueueFlight }

// also acks (removes) all previous flights
func (hctx *HandshakeConnection) PushMessage(conn *ConnectionImpl, flight byte, msg format.MessageHandshake) {
	if flight < hctx.sendQueueFlight {
		panic("you cannot add message from previous flight")
	}
	if flight > hctx.sendQueueFlight {
		// implicit ack of all previous flights
		hctx.sendQueueFlight = flight
		hctx.messagesSendQueue = hctx.messagesSendQueue[:0]
		hctx.SendQueueMessageOffset = 0
		hctx.SendQueueFragmentOffset = 0

		// all received messages (and acks) were from the previous flight
		hctx.sendAcksfromMessageSeq = conn.Keys.NextMessageSeqReceive
		clear(hctx.sendAcks)
	}
	if conn.Keys.NextMessageSeqSend >= math.MaxUint16 {
		// TODO - prevent wrapping next message seq
		// close connection here
		return // for now
	}
	msg.Header.MessageSeq = conn.Keys.NextMessageSeqSend
	conn.Keys.NextMessageSeqSend++
	hctx.messagesSendQueue = append(hctx.messagesSendQueue, msg)

	msg.Header.AddToHash(hctx.TranscriptHasher)
	_, _ = hctx.TranscriptHasher.Write(msg.Body)
}

// must not write over len(datagram), returns part of datagram filled
// should fill it and return datagramSize, if state changed since was added to sender queue, should return 0
// also, should return addToSendQueue=true, if it needs to send more datagrams.
// returning (0, true) makes no sense and will panic
func (hctx *HandshakeConnection) ConstructDatagram(conn *ConnectionImpl, datagram []byte) (datagramSize int, addToSendQueue bool) {
	// we decided to first send our messages, then acks.
	// because message has a chance to ack the whole flight
	for {
		if hctx.SendQueueMessageOffset > len(hctx.messagesSendQueue) {
			panic("invariant of send queue message offset violated")
		}
		if hctx.SendQueueMessageOffset == len(hctx.messagesSendQueue) {
			break
		}
		msg := hctx.messagesSendQueue[hctx.SendQueueMessageOffset]
		recordSize, fragmentLength := hctx.constructRecord(conn, datagram[datagramSize:], msg, hctx.SendQueueFragmentOffset)
		if recordSize == 0 {
			return datagramSize, true
		}
		datagramSize += recordSize
		hctx.SendQueueFragmentOffset += fragmentLength
		// append record to datagram
		if hctx.SendQueueFragmentOffset == len(msg.Body) {
			hctx.SendQueueMessageOffset++
			hctx.SendQueueFragmentOffset = 0
		}
	}
	if len(hctx.sendAcks) != 0 && conn.Keys.Send.Epoch != 0 {
		// TODO - we shuold send only encrypted acks, but is the second condition correct?
		acksSpace := len(datagram) - datagramSize - format.MessageAckHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
		if acksSpace < format.MessageAckRecordNumberSize { // not a single one fits
			return datagramSize, true
		}
		acksCount := acksSpace / format.MessageAckRecordNumberSize
		if acksSpace < constants.MinFragmentBodySize && acksCount != len(hctx.sendAcks) {
			return datagramSize, true // do not send tiny records at the end of datagram
		}
		// TODO - this algorithm looks expensive, test and replace with linear search during adding ack?
		sortedAcks := make([]format.RecordNumber, 0, constants.MaxSendAcks)
		for ack := range hctx.sendAcks { // we must sort all acks, not random acksCount only
			sortedAcks = append(sortedAcks, ack)
		}
		slices.SortFunc(sortedAcks, format.RecordNumberCmp)
		for _, ack := range sortedAcks {
			delete(hctx.sendAcks, ack)
		}
		da := hctx.constructCiphertextAck(conn, datagram[datagramSize:datagramSize], sortedAcks)
		if len(da) > len(datagram[datagramSize:]) {
			panic("ciphertext ack record construction length invariant failed")
		}
		datagramSize += len(da)
		return datagramSize, len(hctx.sendAcks) != 0
	}
	return datagramSize, false // everything sent, wait for ack (TODO) or local timer to start from the scratch
}

func (hctx *HandshakeConnection) constructRecord(conn *ConnectionImpl, datagram []byte, msg format.MessageHandshake, fragmentOffset int) (recordSize int, fragmentLength int) {
	// during fragmenting we always write header at the start of the message, and then part of the body
	if fragmentOffset >= len(msg.Body) { // >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
		panic("invariant of send queue fragment offset violated")
	}
	msg.Header.FragmentOffset = uint32(fragmentOffset)

	if msg.Header.HandshakeType == format.HandshakeTypeClientHello || msg.Header.HandshakeType == format.HandshakeTypeServerHello {
		fragmentLength = min(len(msg.Body)-fragmentOffset, len(datagram)-format.MessageHandshakeHeaderSize+format.PlaintextRecordHeaderSize)
		if fragmentLength <= constants.MinFragmentBodySize && fragmentLength != len(msg.Body)-fragmentOffset {
			return 0, 0 // do not send tiny records at the end of datagram
		}
		msg.Header.FragmentLength = uint32(fragmentLength)
		da := hctx.constructPlaintextRecord(conn, datagram[:0], msg)
		if len(da) != fragmentLength+format.MessageHandshakeHeaderSize+format.PlaintextRecordHeaderSize {
			panic("plaintext handshake record construction length invariant failed")
		}
		return len(da), fragmentLength
	}
	fragmentLength = min(len(msg.Body)-fragmentOffset, len(datagram)-format.MessageHandshakeHeaderSize-format.MaxOutgoingCiphertextRecordOverhead-constants.AEADSealSize)
	if fragmentLength <= constants.MinFragmentBodySize && fragmentLength != len(msg.Body)-fragmentOffset {
		return 0, 0 // do not send tiny records at the end of datagram
	}
	msg.Header.FragmentLength = uint32(fragmentLength) // those are scratch space inside header
	msg.Header.FragmentLength = uint32(fragmentLength)
	da := hctx.constructCiphertextRecord(conn, datagram[:0], msg)
	if len(da) > len(datagram) {
		panic("ciphertext handshake record construction length invariant failed")
	}
	return len(da), fragmentLength
}

func (hctx *HandshakeConnection) constructPlaintextRecord(conn *ConnectionImpl, data []byte, msg format.MessageHandshake) []byte {
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		SequenceNumber: conn.Keys.Send.NextEpoch0Sequence,
	}
	conn.Keys.Send.NextEpoch0Sequence++
	data = recordHdr.Write(data, format.MessageHandshakeHeaderSize+int(msg.Header.FragmentLength))
	data = msg.Header.Write(data)
	data = append(data, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return data
}

func (hctx *HandshakeConnection) constructCiphertextRecord(conn *ConnectionImpl, datagram []byte, msg format.MessageHandshake) []byte {
	send := &conn.Keys.Send
	epoch := send.Epoch
	seq := send.NextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	send.NextSegmentSequence++
	log.Printf("constructing ciphertext with seq: %d", seq)

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
	return datagram
}

func (hctx *HandshakeConnection) constructCiphertextAck(conn *ConnectionImpl, datagram []byte, acks []format.RecordNumber) []byte {
	// TODO - harmonize with code above
	send := &conn.Keys.Send
	epoch := send.Epoch
	seq := send.NextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	send.NextSegmentSequence++
	log.Printf("constructing ciphertext with seq: %d", seq)

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
		datagram = binary.BigEndian.AppendUint64(datagram, uint64(ack.SeqNum()))
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
