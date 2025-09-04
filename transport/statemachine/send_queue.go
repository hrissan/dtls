// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/circular"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

type record2Fragment struct {
	rn       record.Number
	fragment handshake.FragmentInfo
}

type sendQueue struct {
	// all messages here belong to the same flight during handshake.
	// if message in the middle is fully acked, it will stay in the buffer until it becomes
	// head or tail of buffer, only then it is removed.
	messages        circular.BufferExt[partialHandshakeMsg]
	messagesStorage [constants.MaxSendMessagesQueue]partialHandshakeMsg
	// offset in messages of the message we are sending, len(messages) if all sent
	messageOffset int
	// offset inside messages[messageOffset] or 0 if messageOffset == len(messages)
	fragmentOffset uint32

	// Not in order because we have epoch 0 and need to resend ServerHello,
	// so linear search, but it is fast, see benchmarks
	sentRecords        circular.BufferExt[record2Fragment]
	sentRecordsStorage [constants.MaxSendRecordsQueue]record2Fragment
}

func (sq *sendQueue) Reserve() {
	//uncomment if using Buffer instead of BufferExt
	//sq.sentRecords.Reserve(constants.MaxSendRecordsQueue)
	//sq.messages.Reserve(constants.MaxSendMessagesQueue)
}

func (sq *sendQueue) Len() int {
	return sq.messages.Len()
}

func (sq *sendQueue) Clear() {
	sq.messages.Clear(sq.messagesStorage[:])
	sq.messageOffset = 0
	sq.fragmentOffset = 0
	sq.sentRecords.Clear(sq.sentRecordsStorage[:])
}

func (sq *sendQueue) PushMessage(msg handshake.Message) {
	if sq.messages.Len() == sq.messages.Cap(sq.messagesStorage[:]) {
		// must be never, because no flight contains so many messages
		panic("too many messages are generated at once")
	}
	sq.messages.PushBack(sq.messagesStorage[:], partialHandshakeMsgFull(msg))
}

func (sq *sendQueue) HasDataToSend() bool {
	return sq.messageOffset < sq.messages.Len() && sq.sentRecords.Len() < sq.sentRecords.Cap(sq.sentRecordsStorage[:])
}

func (sq *sendQueue) ConstructDatagram(conn *Connection, opts *options.TransportOptions, datagram []byte) (int, error) {
	var datagramSize int
	for {
		if sq.messageOffset > sq.messages.Len() {
			panic("invariant of send queue message offset violated")
		}
		if sq.messageOffset == sq.messages.Len() {
			break
		}
		if sq.sentRecords.Len() >= sq.sentRecords.Cap(sq.sentRecordsStorage[:]) {
			break
		}
		outgoing := sq.messages.IndexRef(sq.messagesStorage[:], sq.messageOffset)
		if outgoing.Msg.MsgType == handshake.MsgTypeClientHello || outgoing.Msg.MsgType == handshake.MsgTypeServerHello {
			if conn.hctx == nil {
				// We only can send that if we are still in handshake.
				// If not, we simply pretend we sent it.
				sq.fragmentOffset = outgoing.Msg.Len32()
			}
		}
		fragmentOffset, fragmentLength := outgoing.Ass.GetFragmentFromOffset(sq.fragmentOffset)
		if fragmentLength == 0 { // fully acked since we reset our iterator
			sq.messageOffset++
			sq.fragmentOffset = 0
			return datagramSize, nil // uncomment to put ServerHello into separate datagram for wireshark
			continue
		}
		recordSize, fragmentInfo, rn, err := conn.constructHandshakeRecord(
			conn.hctx.SendSymmetricEpoch2, 2, &conn.hctx.SendNextSeqEpoch2,
			opts, datagram[datagramSize:],
			outgoing.Msg, fragmentOffset, fragmentLength)
		if err != nil {
			return 0, err
		}
		if recordSize == 0 {
			break
		}
		if fragmentInfo.FragmentLength == 0 {
			panic("constructHandshakeRecord must not send empty fragments")
		}
		// Unfortunately, not in order because we have epoch 0 and need to resend ServerHello, so linear search
		// limited to constants.MaxSendRecordsQueue due to check above
		sq.sentRecords.PushBack(sq.sentRecordsStorage[:], record2Fragment{rn: rn, fragment: fragmentInfo})
		datagramSize += recordSize
		sq.fragmentOffset += fragmentInfo.FragmentLength
	}
	return datagramSize, nil
}

func findSentRecordIndex(sentRecords *circular.Buffer[record2Fragment], rn record.Number) *handshake.FragmentInfo {
	for i := 0; i != sentRecords.Len(); i++ {
		element := sentRecords.IndexRef(i)
		if element.rn == rn {
			return &element.fragment
		}
	}
	return nil
}

func findSentRecordIndexExt(elements []record2Fragment, sentRecords *circular.BufferExt[record2Fragment], rn record.Number) *handshake.FragmentInfo {
	for i := 0; i != sentRecords.Len(); i++ {
		element := sentRecords.IndexRef(elements, i)
		if element.rn == rn {
			return &element.fragment
		}
	}
	return nil
}

func (sq *sendQueue) Ack(conn *Connection, rn record.Number) {
	fragmentPtr := findSentRecordIndexExt(sq.sentRecordsStorage[:], &sq.sentRecords, rn)
	if fragmentPtr == nil {
		return
	}
	rec := *fragmentPtr
	*fragmentPtr = handshake.FragmentInfo{} // delete in the middle
	for sq.sentRecords.Len() != 0 && sq.sentRecords.Front(sq.sentRecordsStorage[:]).fragment == (handshake.FragmentInfo{}) {
		sq.sentRecords.PopFront(sq.sentRecordsStorage[:]) // delete everything from the front
	}
	if sq.messages.Len() > int(conn.nextMessageSeqSend) { // widening
		panic("invariant violation")
	}
	// sq.messages end() is aligned with conn.nextMessageSeqSend
	index := int(rec.MsgSeq) + sq.messages.Len() - int(conn.nextMessageSeqSend) // widening
	if index < 0 || index >= sq.messages.Len() {
		return
	}
	msg := sq.messages.IndexRef(sq.messagesStorage[:], index)
	msg.Ass.AddFragment(rec.FragmentOffset, rec.FragmentLength)
	for sq.messages.Len() != 0 && sq.messages.FrontRef(sq.messagesStorage[:]).Ass.FragmentsCount() == 0 {
		// fully acknowledged
		if sq.messageOffset == 0 {
			sq.fragmentOffset = 0
		} else {
			sq.messageOffset--
		}
		sq.messages.PopFront(sq.messagesStorage[:])
	}
}
