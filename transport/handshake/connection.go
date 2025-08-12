package handshake

import (
	"hash"
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

	mu                      sync.Mutex
	Keys                    keys.Keys
	messagesFlight          byte                      // message from the next flight will ack (clear) all messages in send queue
	messagesSendQueue       []format.MessageHandshake // all messages here belong to the same flight.
	SendQueueMessageOffset  int                       // offset in messagesSendQueue of the message we are sending, len(messagesSendQueue) if all sent
	SendQueueFragmentOffset int                       // offset inside messagesSendQueue[SendQueueMessageOffset] or 0 if SendQueueMessageOffset == len(messagesSendQueue)

	TranscriptHasher hash.Hash // when messages are added to messagesSendQueue, they are also added to TranscriptHasher
}

// ack (remove) all previous flights
func (hctx *HandshakeConnection) PushMessage(flight byte, msg format.MessageHandshake) {
	if flight < hctx.messagesFlight {
		panic("you cannot add message from previous flight")
	}
	if flight > hctx.messagesFlight { // implicit ack of all previous flights
		hctx.messagesSendQueue = hctx.messagesSendQueue[:0]
		hctx.SendQueueMessageOffset = 0
		hctx.SendQueueFragmentOffset = 0
		hctx.messagesFlight = flight
	}
	if hctx.Keys.NextMessageSeqSend >= math.MaxUint16 {
		// TODO - prevent wrapping next message seq
		// close connection here
		return // for now
	}
	msg.Header.MessageSeq = uint16(hctx.Keys.NextMessageSeqSend)
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
		SequenceNumber: hctx.Keys.NextEpoch0Sequence,
	}
	hctx.Keys.NextEpoch0Sequence++
	datagram = recordHdr.Write(datagram, format.MessageHandshakeHeaderSize+int(msg.Header.FragmentLength))
	datagram = msg.Header.Write(datagram)
	datagram = append(datagram, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return datagram
}
