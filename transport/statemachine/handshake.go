// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/ecdh"
	"hash"
	"math"

	"github.com/hrissan/dtls/circular"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/replay"
)

type handshakeContext struct {
	localRandom  [32]byte
	x25519Secret *ecdh.PrivateKey // Tons of allocations here. TODO - compute in calculator goroutine

	masterSecret                  [32]byte
	handshakeTrafficSecretSend    [32]byte // we need this to generate finished message.
	handshakeTrafficSecretReceive [32]byte // we need this to check peer's finished message.

	// it seems we do not need this protection, but standard says we must have it
	receiveNextSegmentSequenceEpoch0 replay.Window

	// for ServerHello retransmit and replay protection
	// we decided 2^16 ServerHello/ClientHello is enough for all practical purposes,
	// see dtlserrors.ErrSendEpoch0RecordSeqOverflow
	sendNextRecordSequenceEpoch0 uint16

	// state machine sets this to true or false depending on state.
	CanDeliveryMessages bool

	currentFlight byte // both send and receive

	// We need more than 1 message, otherwise we will lose them, while
	// handshake is in a state of waiting finish of offloaded calculations.
	// if full message is received, and it is the first in the queue (or queue is empty),
	// then
	receivedMessages        circular.BufferExt[partialHandshakeMsg]
	receivedMessagesStorage [constants.MaxReceiveMessagesQueue]partialHandshakeMsg

	sendQueue sendQueue

	transcriptHasher hash.Hash // when messages are added to messages, they are also added to transcriptHasher

	certificateChain handshake.MsgCertificate
}

func newHandshakeContext(hasher hash.Hash) *handshakeContext {
	hctx := &handshakeContext{
		transcriptHasher:    hasher,
		CanDeliveryMessages: true,
	}
	hctx.sendQueue.Reserve()
	return hctx
}

func (hctx *handshakeContext) firstMessageSeqInReceiveQueue(conn *ConnectionImpl) uint16 {
	if hctx.receivedMessages.Len() > int(conn.nextMessageSeqReceive) {
		panic("received messages queue invariant violated")
	}
	return conn.nextMessageSeqReceive - uint16(hctx.receivedMessages.Len())
}

func (hctx *handshakeContext) ComputeKeyShare(rnd dtlsrand.Rand) {
	var X25519Secret [32]byte
	rnd.ReadMust(X25519Secret[:])
	priv, err := ecdh.X25519().NewPrivateKey(X25519Secret[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.x25519Secret = priv
}

func (hctx *handshakeContext) ReceivedFlight(conn *ConnectionImpl, flight byte) (newFlight bool) {
	if flight <= hctx.currentFlight {
		return false
	}
	hctx.currentFlight = flight
	// implicit ack of all previous flights
	hctx.sendQueue.Clear()

	conn.keys.SendAcks.Reset()
	return true
}

func (hctx *handshakeContext) ReceivedFragment(conn *ConnectionImpl, fragment handshake.Fragment, rn record.Number) error {
	if fragment.Header.MsgType == handshake.MsgTypeZero { // we use it as a flag of not yet received message below, so check here
		return dtlserrors.ErrHandshakeMessageTypeUnknown
	}
	// Receiving any fragment of any message from the next flight will remove all acks for previous flights.
	// We must do it before we generate ack for this fragment.
	flight := MsgTypeToFlight(fragment.Header.MsgType, conn.roleServer) // zero if unknown
	conn.hctx.ReceivedFlight(conn, flight)

	messageOffset := int(fragment.Header.MsgSeq) + hctx.receivedMessages.Len() - int(conn.nextMessageSeqReceive)
	if messageOffset < 0 {
		panic("checked before calling handshakeContext.ReceivedFragment")
	}
	if messageOffset >= hctx.receivedMessages.Cap(hctx.receivedMessagesStorage[:]) {
		return nil // would be beyond queue even if we fill it
	}
	for messageOffset >= hctx.receivedMessages.Len() {
		hctx.receivedMessages.PushBack(hctx.receivedMessagesStorage[:], partialHandshakeMsg{})
		if conn.nextMessageSeqReceive == math.MaxUint16 {
			// can happen only when fragment.MsgSeq == math.MaxUint16
			return dtlserrors.ErrReceivedMessageSeqOverflow
		}
		conn.nextMessageSeqReceive++
	}
	partialMessage := hctx.receivedMessages.IndexRef(hctx.receivedMessagesStorage[:], messageOffset)
	if partialMessage.Msg.MsgType == handshake.MsgTypeZero { // the first fragment, we need to set header, allocate body
		*partialMessage = partialHandshakeMsg{
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
	conn.keys.AddAck(rn) // should ack it independent of conditions below
	if !changed {        // nothing new, save copy
		return nil
	}
	copy(partialMessage.Msg.Body[fragment.Header.FragmentOffset:], fragment.Body) // copy all bytes for simplicity
	// now we could ack the first message, so delivery all full messages
	return hctx.DeliverReceivedMessages(conn)
}

// called when fully received message or when hctx.CanDeliveryMessages change
func (hctx *handshakeContext) DeliverReceivedMessages(conn *ConnectionImpl) error {
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
func (hctx *handshakeContext) PushMessage(conn *ConnectionImpl, msg handshake.Message) error {
	if conn.nextMessageSeqSend == math.MaxUint16 {
		return dtlserrors.ErrSendMessageSeqOverflow
	}
	msg.MsgSeq = conn.nextMessageSeqSend
	conn.nextMessageSeqSend++

	hctx.sendQueue.PushMessage(msg)

	msg.AddToHash(hctx.transcriptHasher)
	return nil
}
