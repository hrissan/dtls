package handshake

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"log"
	"math"
	"net/netip"
	"sync"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
	"github.com/hrissan/tinydtls/signature"
)

const MessagesFlightClientHello1 = 0
const MessagesFlightServerHRR = 1
const MessagesFlightClientHello2 = 2
const MessagesFlightServerHello = 3       // ServerHello, EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished
const MessagesFlightClientCertificate = 4 // Certificate, CertificateVerify, Finished

type HandshakeConnection struct {
	Addr       netip.AddrPort // never changes, accessible without lock
	RoleServer bool

	InSenderQueue bool // intrusive, must not be changed except by sender, protected by sender mutex

	receivedPartialMessageSet    bool // if set, Header.MessageSeq == Keys.NextMessageSeqReceive - 1
	receivedPartialMessage       format.MessageHandshake
	receivedPartialMessageOffset uint32 // we do not support holes for now. TODO - support holes

	mu                      sync.Mutex // TODO - check that mutex is alwasy taken
	Keys                    keys.Keys
	sendQueueFlight         byte                      // message from the next flight will ack (clear) all messages in send queue
	messagesSendQueue       []format.MessageHandshake // all messages here belong to the same flight. TODO - fixed array storage with some limit
	SendQueueMessageOffset  int                       // offset in messagesSendQueue of the message we are sending, len(messagesSendQueue) if all sent
	SendQueueFragmentOffset int                       // offset inside messagesSendQueue[SendQueueMessageOffset] or 0 if SendQueueMessageOffset == len(messagesSendQueue)

	TranscriptHasher hash.Hash // when messages are added to messagesSendQueue, they are also added to TranscriptHasher

	certificateChain format.MessageCertificate
}

func (hctx *HandshakeConnection) receivedFullMessage(handshakeHdr format.MessageHandshakeHeader, body []byte) {
	// we ignore handshakeHdr.MessageSeq here TODO - check, update
	switch handshakeHdr.HandshakeType {
	case format.HandshakeTypeEncryptedExtensions:
		var msg format.ExtensionsSet
		if err := msg.ParseOutside(body, false, true, false); err != nil {
			// rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
			//TODO: alert here
			return
		}
		log.Printf("encrypted extensions parsed: %+v", msg)
		//rc.opts.Stats.ServerHelloMessage(handshakeHdr, msg, addr)
		//rc.OnServerHello(body, handshakeHdr, msg, addr)
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(body)
	case format.HandshakeTypeCertificate:
		var msg format.MessageCertificate
		if err := msg.Parse(body); err != nil {
			// rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
			//TODO: alert here
			return
		}
		// We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, probably send ack,
		// then offload ECC to separate core and trigger state machine depending on result
		hctx.certificateChain = msg
		log.Printf("certificate parsed: %+v", msg)
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(body)
	case format.HandshakeTypeCertificateVerify:
		var msg format.MessageCertificateVerify
		if err := msg.Parse(body); err != nil {
			// rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
			//TODO: alert here
			return
		}
		// TODO - We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, probably send ack,
		// then offload ECC to separate core and trigger state machine depending on result
		// But, for now we check here
		if hctx.certificateChain.CertificatesLength == 0 {
			// TODO - alert here
			return
		}
		if msg.SignatureScheme != format.SignatureAlgorithm_RSA_PSS_RSAE_SHA256 {
			// Single algorithm for now
			// TODO - alert here
			return
		}
		// [rfc8446:4.4.3] - certificate verification
		var certVerifyTranscriptHash [constants.MaxHashLength]byte
		hctx.TranscriptHasher.Sum(certVerifyTranscriptHash[:0])
		sigMessage := []byte("                                                                " +
			"TLS 1.3, server CertificateVerify")
		sigMessage = append(sigMessage, 0)
		sigMessage = append(sigMessage, certVerifyTranscriptHash[:sha256.Size]...)

		sigMessageHash := sha256.Sum256(sigMessage)

		cert := hctx.certificateChain.Certificates[0].Cert
		if err := signature.VerifySignature_RSA_PSS_RSAE_SHA256(cert, sigMessageHash[:], msg.Signature); err != nil {
			log.Printf("certificate verify error: %v", err)
		}
		log.Printf("certificate verify parsed: %+v", msg)
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(body)
	case format.HandshakeTypeFinished:
		var msg format.MessageFinished
		if err := msg.Parse(body); err != nil {
			// rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
			//TODO: alert here
			return
		}
		// [rfc8446:4.4.3] - certificate verification
		var finishedTranscriptHash [constants.MaxHashLength]byte
		hctx.TranscriptHasher.Sum(finishedTranscriptHash[:0])

		mustBeFinished := hctx.Keys.ComputeServerFinished(sha256.New(), finishedTranscriptHash[:])
		if string(msg.VerifyData[:msg.VerifyDataLength]) != string(mustBeFinished) {
			log.Printf("finished message verify error")
		}
		log.Printf("finished message parsed: %+v", msg)
	default:
		log.Printf("TODO - message type %d not supported", handshakeHdr.HandshakeType)
		//rc.opts.Stats.MustBeEncrypted("handshake", format.HandshakeTypeToName(handshakeHdr.HandshakeType), addr, handshakeHdr)
	}
}

func (hctx *HandshakeConnection) ReceivedMessage(handshakeHdr format.MessageHandshakeHeader, body []byte) {
	if !hctx.receivedPartialMessageSet {
		if handshakeHdr.MessageSeq != hctx.Keys.NextMessageSeqReceive {
			return // totally ok to ignore
		}
		hctx.Keys.NextMessageSeqReceive++
		if !handshakeHdr.IsFragmented() {
			hctx.receivedFullMessage(handshakeHdr, body)
			return
		}
		hctx.receivedPartialMessageSet = true
		hctx.receivedPartialMessageOffset = 0
		// TODO - take body from pool
		hctx.receivedPartialMessage.Body = append(hctx.receivedPartialMessage.Body[:0], make([]byte, handshakeHdr.Length)...)
		hctx.receivedPartialMessage.Header = handshakeHdr
		// now process partial message below
	}
	if handshakeHdr.MessageSeq != hctx.receivedPartialMessage.Header.MessageSeq {
		return // totally ok to ignore
	}
	if handshakeHdr.Length != hctx.receivedPartialMessage.Header.Length {
		// TODO - alert and close connection, invariant violated
		return
	}
	if handshakeHdr.FragmentOffset > hctx.receivedPartialMessageOffset {
		return // we do not support holes, ignore
	}
	newOffset := handshakeHdr.FragmentOffset + handshakeHdr.FragmentLength
	if newOffset <= hctx.receivedPartialMessageOffset {
		return // nothing new, ignore
	}
	copy(hctx.receivedPartialMessage.Body[handshakeHdr.FragmentOffset:], body)
	hctx.receivedPartialMessageOffset = newOffset
	if hctx.receivedPartialMessageOffset != handshakeHdr.Length {
		return // ok, waiting for more fragments
	}
	hctx.receivedFullMessage(hctx.receivedPartialMessage.Header, hctx.receivedPartialMessage.Body)
	// TODO - return message body to pool
	hctx.receivedPartialMessageSet = false
}

func (hctx *HandshakeConnection) SendQueueFlight() byte { return hctx.sendQueueFlight }

// acks (removes) all previous flights
func (hctx *HandshakeConnection) AckFlight(flight byte) {
	if flight > hctx.sendQueueFlight { // implicit ack of all previous flights
		hctx.messagesSendQueue = hctx.messagesSendQueue[:0]
		hctx.SendQueueMessageOffset = 0
		hctx.SendQueueFragmentOffset = 0
		hctx.sendQueueFlight = flight
	}
}

// also acks (removes) all previous flights
func (hctx *HandshakeConnection) PushMessage(flight byte, msg format.MessageHandshake) {
	if flight < hctx.sendQueueFlight {
		panic("you cannot add message from previous flight")
	}
	hctx.AckFlight(flight)
	if hctx.Keys.NextMessageSeqSend >= math.MaxUint16 {
		// TODO - prevent wrapping next message seq
		// close connection here
		return // for now
	}
	msg.Header.MessageSeq = hctx.Keys.NextMessageSeqSend
	hctx.Keys.NextMessageSeqSend++
	hctx.messagesSendQueue = append(hctx.messagesSendQueue, msg)

	msg.Header.AddToHash(hctx.TranscriptHasher)
	_, _ = hctx.TranscriptHasher.Write(msg.Body)
}

// datagram is empty slice with enough capacity (TODO - capacity corresponds to PMTU)
// should fill it and return datagramSize, if state changed since was added to sender queue, should return 0
// also, should return addToSendQueue=true, if it needs to send more datagrams.
// returning (0, true) makes no sense and will panic
func (hctx *HandshakeConnection) ConstructDatagram(datagram []byte) (datagramSize int, addToSendQueue bool) {
	hctx.mu.Lock()
	defer hctx.mu.Unlock()
	for {
		if hctx.SendQueueMessageOffset > len(hctx.messagesSendQueue) {
			panic("invariant of send queue message offset violated")
		}
		if hctx.SendQueueMessageOffset == len(hctx.messagesSendQueue) {
			return len(datagram), false // everything sent, wait for ack (TODO) or local timer to start from the scratch
		}
		spaceLeft := 512 - len(datagram) - 12 - 13 // TODO - take into account CID size
		if spaceLeft <= 0 {                        // some heuristic
			return len(datagram), true
		}
		msg := hctx.messagesSendQueue[hctx.SendQueueMessageOffset]
		datagram, hctx.SendQueueFragmentOffset = hctx.constructDatagram(datagram, msg, 512, hctx.SendQueueFragmentOffset)
		// append record to datagram
		if hctx.SendQueueFragmentOffset == len(msg.Body) {
			hctx.SendQueueMessageOffset++
			hctx.SendQueueFragmentOffset = 0
		}
	}
}

func (hctx *HandshakeConnection) constructDatagram(datagram []byte, msg format.MessageHandshake, maxBodySize int, fragmentOffset int) ([]byte, int) {
	// during fragmenting we always write header at the start of the message, and then part of the body
	if fragmentOffset >= len(msg.Body) { // >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
		panic("invariant of send queue fragment offset violated")
	}
	fragmentLength := min(len(msg.Body)-fragmentOffset, maxBodySize)
	if fragmentLength == 0 { // only if maxBodySize == 0
		panic("invariant of send queue fragment body, empty body")
	}

	msg.Header.FragmentOffset = uint32(fragmentOffset) // those are scratch space inside header
	msg.Header.FragmentLength = uint32(fragmentLength) // those are scratch space inside header

	if msg.Header.HandshakeType == format.HandshakeTypeClientHello || msg.Header.HandshakeType == format.HandshakeTypeServerHello {
		datagram = hctx.constructPlaintextRecord(datagram, msg)
	} else {
		datagram = hctx.constructCiphertextRecord(datagram, msg)
	}
	return datagram, fragmentOffset + fragmentLength
}

func (hctx *HandshakeConnection) constructPlaintextRecord(datagram []byte, msg format.MessageHandshake) []byte {
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		Epoch:          0,
		SequenceNumber: hctx.Keys.NextEpoch0SequenceReceive,
	}
	hctx.Keys.NextEpoch0SequenceReceive++
	datagram = recordHdr.Write(datagram, format.MessageHandshakeHeaderSize+int(msg.Header.FragmentLength))
	datagram = msg.Header.Write(datagram)
	datagram = append(datagram, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return datagram
}

func (hctx *HandshakeConnection) constructCiphertextRecord(datagram []byte, msg format.MessageHandshake) []byte {
	// TODO - fragment message
	epoch := hctx.Keys.Epoch
	seq := hctx.Keys.NextSegmentSequenceSend // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check we correctly parse/decrypt them from peer
	hctx.Keys.NextSegmentSequenceSend++

	gcm := hctx.Keys.ClientWrite
	iv := hctx.Keys.ClientWriteIV
	if hctx.RoleServer {
		gcm = hctx.Keys.ServerWrite
		iv = hctx.Keys.ServerWriteIV
	}
	hctx.Keys.FillIVSequence(iv[:], seq)

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
	const SealSize = 16          // TODO - include constant into our gcm wrapper
	for i := 0; i != padding+SealSize; i++ {
		datagram = append(datagram, 0)
	}

	// TODO - subtract max overhead we add here on the 1 leel above, so we do not end up with larger fragment than allowed
	binary.BigEndian.PutUint16(datagram[startRecordOffset+3:], uint16(len(datagram)-startBodyOFfset))

	encrypted := gcm.Seal(datagram[startBodyOFfset:], iv[:], datagram[startBodyOFfset:], datagram[startRecordOffset:startBodyOFfset])
	if &encrypted[0] != &datagram[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if string(encrypted[len(encrypted)-SealSize:]) != string(datagram[len(datagram)-SealSize:]) {
		panic("gcm.Seal put seal to unexpected place")
	}

	if err := hctx.Keys.EncryptSequenceNumbers(datagram[startRecordOffset+1:startRecordOffset+3], datagram[startBodyOFfset:], hctx.RoleServer); err != nil {
		panic("cipher text too short when sending")
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return datagram
}
