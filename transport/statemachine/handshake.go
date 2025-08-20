package statemachine

import (
	"crypto/ecdh"
	"hash"
	"math"

	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/record"
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
	receivedMessages        circular.BufferExt[PartialHandshakeMsg]
	receivedMessagesStorage [constants.MaxReceiveMessagesQueue]PartialHandshakeMsg

	SendQueue SendQueue

	TranscriptHasher hash.Hash // when messages are added to messages, they are also added to TranscriptHasher

	certificateChain handshake.MsgCertificate
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

func (hctx *HandshakeConnection) ReceivedFragment(conn *ConnectionImpl, fragment handshake.Fragment, rn record.Number) error {
	if fragment.Header.MsgType == handshake.MsgTypeZero { // we use it as a flag of not yet received message below, so check here
		return dtlserrors.ErrHandshakeMessageTypeUnknown
	}
	// Receiving any fragment of any message from the next flight will remove all acks for previous flights.
	// We must do it before we generate ack for this fragment.
	flight := MsgTypeToFlight(fragment.Header.MsgType, conn.RoleServer) // zero if unknown
	conn.Handshake.ReceivedFlight(conn, flight)

	messageOffset := int(fragment.Header.MsgSeq) + hctx.receivedMessages.Len() - int(conn.NextMessageSeqReceive)
	if messageOffset < 0 {
		panic("checked before calling HandshakeConnection.ReceivedFragment")
	}
	if messageOffset >= hctx.receivedMessages.Cap(hctx.receivedMessagesStorage[:]) {
		return nil // would be beyond queue even if we fill it
	}
	for messageOffset >= hctx.receivedMessages.Len() {
		hctx.receivedMessages.PushBack(hctx.receivedMessagesStorage[:], PartialHandshakeMsg{})
		if conn.NextMessageSeqReceive == math.MaxUint16 {
			// can happen only when fragment.MsgSeq == math.MaxUint16
			return dtlserrors.ErrReceivedMessageSeqOverflow
		}
		conn.NextMessageSeqReceive++
	}
	partialMessage := hctx.receivedMessages.IndexRef(hctx.receivedMessagesStorage[:], messageOffset)
	if partialMessage.Msg.MsgType == handshake.MsgTypeZero { // the first fragment, we need to set header, allocate body
		*partialMessage = PartialHandshakeMsg{
			Msg: handshake.Message{
				MsgType: fragment.Header.MsgType,
				MsgSeq:  fragment.Header.MsgSeq,
			},
			SendOffset: 0,
			SendEnd:    fragment.Header.Length,
		}
		partialMessage.Msg.Body = make([]byte, fragment.Header.Length) // TODO - rope from pull
	} else {
		if fragment.Header.MsgSeq != partialMessage.Msg.MsgSeq {
			panic("message sequence is queue offset and must always match")
		}
		if fragment.Header.Length != uint32(len(partialMessage.Msg.Body)) {
			return dtlserrors.ErrHandshakeMessageFragmentLengthMismatch
		}
		if fragment.Header.MsgType != partialMessage.Msg.MsgType {
			return dtlserrors.ErrHandshakeMessageFragmentTypeMismatch
		}
	}
	shouldAck, changed := partialMessage.Ack(fragment.Header.FragmentOffset, fragment.Header.FragmentLength)
	if !shouldAck {
		return nil // got in the middle of the hole, wait for fragment which we can actully add
	}
	conn.Keys.AddAck(rn) // should ack it independent of conditions below
	if !changed {        // nothing new, save copy
		return nil
	}
	copy(partialMessage.Msg.Body[fragment.Header.FragmentOffset:], fragment.Body) // copy all bytes for simplicity
	// now we could ack the first message, so delivery all full messages
	return hctx.DeliveryReceivedMessages(conn)
}

// called when fully received message or when hctx.CanDeliveryMessages change
func (hctx *HandshakeConnection) DeliveryReceivedMessages(conn *ConnectionImpl) error {
	for hctx.receivedMessages.Len() != 0 && hctx.CanDeliveryMessages { // check here because changes in receivedFullMessage
		first := hctx.receivedMessages.FrontRef(hctx.receivedMessagesStorage[:])
		if first.Msg.MsgType == handshake.MsgTypeZero || !first.FullyAcked() {
			// not a single fragment received, or not fully acknowledged
			return nil
		}
		msg := first.Msg
		hctx.receivedMessages.PopFront(hctx.receivedMessagesStorage[:])
		err := hctx.receivedFullMessage(conn, msg)
		// TODO - return message body to pool here
		if err != nil {
			return err
		}
	}
	return nil
}

// also acks (removes) all previous flights
func (hctx *HandshakeConnection) PushMessage(conn *ConnectionImpl, msg handshake.Message) error {
	if conn.NextMessageSeqSend == math.MaxUint16 {
		return dtlserrors.ErrSendMessageSeqOverflow
	}
	msg.MsgSeq = conn.NextMessageSeqSend
	conn.NextMessageSeqSend++

	hctx.SendQueue.PushMessage(msg)

	msg.AddToHash(hctx.TranscriptHasher)
	return nil
}
