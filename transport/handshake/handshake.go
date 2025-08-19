package handshake

import (
	"crypto/ecdh"
	"hash"
	"math"

	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/format"
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

	// state machine sets this to true or false depending on state.
	// TODO - return bool from DeliveryReceivedMessages instead
	CanDeliveryMessages bool

	currentFlight byte // both send and receive

	// We need more than 1 message, otherwise we will lose them, while
	// handshake is in a state of waiting finish of offloaded calculations.
	// if full message is received, and it is the first in the queue (or queue is empty),
	// then
	receivedMessages        circular.BufferExt[PartialHandshakeMessage]
	receivedMessagesStorage [constants.MaxReceiveMessagesQueue]PartialHandshakeMessage

	SendQueue SendQueue

	TranscriptHasher hash.Hash // when messages are added to messages, they are also added to TranscriptHasher

	certificateChain format.MessageCertificate
}

func NewHandshakeConnection(hasher hash.Hash) *HandshakeConnection {
	hctx := &HandshakeConnection{
		TranscriptHasher:    hasher,
		CanDeliveryMessages: true,
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

func (hctx *HandshakeConnection) ReceivedMessage(conn *ConnectionImpl, handshakeHdr format.MessageFragmentHeader, body []byte, rn format.RecordNumber) error {
	if handshakeHdr.HandshakeType == 0 { // we use it as a flag of not yet received message below, so check here
		return dtlserrors.ErrHandshakeMessageTypeUnknown
	}
	// Receiving any fragment of any message from the next flight will remove all acks for previous flights.
	// We must do it before we generate ack for this fragment.
	flight := HandshakeTypeToFlight(handshakeHdr.HandshakeType, conn.RoleServer) // zero if unknown
	conn.Handshake.ReceivedFlight(conn, flight)

	messageOffset := int(handshakeHdr.MessageSeq) + hctx.receivedMessages.Len() - int(conn.NextMessageSeqReceive)
	if messageOffset < 0 {
		panic("checked before calling HandshakeConnection.ReceivedMessage")
	}
	if messageOffset >= hctx.receivedMessages.Cap(hctx.receivedMessagesStorage[:]) {
		return nil // would be beyond queue even if we fill it
	}
	for messageOffset >= hctx.receivedMessages.Len() {
		hctx.receivedMessages.PushBack(hctx.receivedMessagesStorage[:], PartialHandshakeMessage{})
		if conn.NextMessageSeqReceive == math.MaxUint16 {
			// can happen only when handshakeHdr.MessageSeq == math.MaxUint16
			return dtlserrors.ErrReceivedMessageSeqOverflow
		}
		conn.NextMessageSeqReceive++
	}
	message := hctx.receivedMessages.IndexRef(hctx.receivedMessagesStorage[:], messageOffset)
	if message.Header.HandshakeType == 0 { // this fragment, set header, allocate body
		*message = PartialHandshakeMessage{
			Header: MessageHandshake{
				HandshakeType: handshakeHdr.HandshakeType,
				MessageSeq:    handshakeHdr.MessageSeq,
			},
			SendOffset: 0,
			SendEnd:    handshakeHdr.Length,
		}
		message.Body = make([]byte, handshakeHdr.Length) // TODO - rope from pull
	} else {
		if handshakeHdr.MessageSeq != handshakeHdr.MessageSeq {
			panic("message sequence is queue offset and must always match")
		}
		if handshakeHdr.Length != uint32(len(message.Body)) {
			return dtlserrors.ErrHandshakeMessageFragmentLengthMismatch
		}
		if handshakeHdr.HandshakeType != message.Header.HandshakeType {
			return dtlserrors.ErrHandshakeMessageFragmentTypeMismatch
		}
	}
	shouldAck, changed := message.Ack(handshakeHdr.FragmentOffset, handshakeHdr.FragmentLength)
	if !shouldAck {
		return nil // got in the middle of the hole, wait for fragment which we can actully add
	}
	conn.Keys.AddAck(rn) // should ack it independent of conditions below
	if !changed {        // nothing new, save copy
		return nil
	}
	copy(message.Body[handshakeHdr.FragmentOffset:], body) // copy all bytes for simplicity
	// now we could ack the first message, so delivery all full messages
	return hctx.DeliveryReceivedMessages(conn)
}

// called when fully received message or when hctx.CanDeliveryMessages change
func (hctx *HandshakeConnection) DeliveryReceivedMessages(conn *ConnectionImpl) error {
	for hctx.receivedMessages.Len() != 0 && hctx.CanDeliveryMessages { // check here because changes in receivedFullMessage
		first := hctx.receivedMessages.FrontRef(hctx.receivedMessagesStorage[:])
		if !first.FullyAcked() {
			return nil
		}
		body := first.Body
		handshakeHdr := format.MessageFragmentHeader{
			HandshakeType: first.Header.HandshakeType,
			Length:        uint32(len(body)),
			FragmentInfo: format.FragmentInfo{
				MessageSeq:     first.Header.MessageSeq,
				FragmentOffset: 0,
				FragmentLength: uint32(len(body)),
			},
		}
		hctx.receivedMessages.PopFront(hctx.receivedMessagesStorage[:])
		err := hctx.receivedFullMessage(conn, handshakeHdr, body)
		// TODO - return message body to pool here
		if err != nil {
			return err
		}
	}
	return nil
}

// also acks (removes) all previous flights
func (hctx *HandshakeConnection) PushMessage(conn *ConnectionImpl, msg format.MessageHandshakeFragment) {
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
