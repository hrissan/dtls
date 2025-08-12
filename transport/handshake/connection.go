package handshake

import (
	"hash"
	"net/netip"
	"sync"

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
	MessagesFlight          byte     // message from the next flight will ack (clear) all messages in send queue
	MessagesSendQueue       [][]byte // all messages here belong to the same flight
	SendQueueMessageOffset  int      // offset in MessagesSendQueue of the message we are sending, len(MessagesSendQueue) if all sent
	SendQueueFragmentOffset int      // offset inside MessagesSendQueue[SendQueueMessageOffset] or 0 if SendQueueMessageOffset == len(MessagesSendQueue)

	TranscriptHasher hash.Hash // when messages are added to MessagesSendQueue, they are also added to TranscriptHasher
}

// datagram is empty slice with enough capacity (TODO - capacity corresponds to PMTU)
// should fill it and return datagramSize, if state changed since was added to sender queue, should return 0
// also, should return addToSendQueue=true, if it needs to send more datagrams.
// returning (0, true) makes no sense and will panic
func (hctx *HandshakeConnection) ConstructDatagram(datagram []byte) (datagramSize int, addToSendQueue bool) {
	hctx.mu.Lock()
	defer hctx.mu.Unlock()
	for {
		if hctx.SendQueueMessageOffset > len(hctx.MessagesSendQueue) {
			panic("invariant of send queue message offset violated")
		}
		if hctx.SendQueueMessageOffset == len(hctx.MessagesSendQueue) {
			return len(datagram), false // everything sent, wait for ack (TODO) or local timer to start from the scratch
		}
		msg := hctx.MessagesSendQueue[hctx.SendQueueMessageOffset]
		if hctx.SendQueueFragmentOffset >= len(msg) { // >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
			panic("invariant of send queue fragment offset violated")
		}
		fragmentSize := min(len(msg)-hctx.SendQueueFragmentOffset, 512) // TODO - record size
		// append record to datagram
		// if message kind is (handshake,*hello), then send unencrypted in zero epoch
		// otherwise send encrypted
		hctx.SendQueueFragmentOffset += fragmentSize
		if hctx.SendQueueFragmentOffset == len(msg) {
			hctx.SendQueueMessageOffset++
			hctx.SendQueueFragmentOffset = 0
		}
	}
}
