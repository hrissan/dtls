package handshake

import (
	"hash"
	"log"
	"math"
	"net/netip"
	"sync"

	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
)

const MessagesFlightClientHello1 = 0
const MessagesFlightServerHRR = 1
const MessagesFlightClientHello2 = 2
const MessagesFlightServerHello = 3       // ServerHello, EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished
const MessagesFlightClientCertificate = 4 // Certificate, CertificateVerify, Finished

type HandshakeConnection struct {
	Addr netip.AddrPort // never changes, accessible without lock

	InSenderQueue bool // intrusive, must not be changed except by sender, protected by sender mutex

	receivedPartialMessageSet    bool // if set, Header.MessageSeq == Keys.NextMessageSeqReceive - 1
	receivedPartialMessage       format.MessageHandshake
	receivedPartialMessageOffset uint32 // we do not support holes for now. TODO - support holes

	mu                      sync.Mutex // TODO - check that mutex is alwasy taken
	Keys                    keys.Keys
	sendQueueFlight         byte                      // message from the next flight will ack (clear) all messages in send queue
	messagesSendQueue       []format.MessageHandshake // all messages here belong to the same flight.
	SendQueueMessageOffset  int                       // offset in messagesSendQueue of the message we are sending, len(messagesSendQueue) if all sent
	SendQueueFragmentOffset int                       // offset inside messagesSendQueue[SendQueueMessageOffset] or 0 if SendQueueMessageOffset == len(messagesSendQueue)

	TranscriptHasher hash.Hash // when messages are added to messagesSendQueue, they are also added to TranscriptHasher
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
	case format.HandshakeTypeCertificate:
		var msg format.MessageCertificate
		if err := msg.Parse(body); err != nil {
			// rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
			//TODO: alert here
			return
		}
		log.Printf("certificate parsed: %+v", msg)
	case format.HandshakeTypeCertificateVerify:
		var msg format.MessageCertificateVerify
		if err := msg.Parse(body); err != nil {
			// rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
			//TODO: alert here
			return
		}
		log.Printf("certificate verify parsed: %+v", msg)
	case format.HandshakeTypeFinished:
		var msg format.MessageFinished
		if err := msg.Parse(body); err != nil {
			// rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
			//TODO: alert here
			return
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
		panic("TODO - construct ciphertext")
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
