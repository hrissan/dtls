package statemachine

import (
	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/record"
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
	sq.messages.PushBack(sq.messagesStorage[:], partialHandshakeMsg{
		Msg:        msg,
		SendOffset: 0,
		SendEnd:    uint32(len(msg.Body)),
	})
}

func (sq *sendQueue) HasDataToSend() bool {
	return sq.messageOffset < sq.messages.Len() && sq.sentRecords.Len() < sq.sentRecords.Cap(sq.sentRecordsStorage[:])
}

func (sq *sendQueue) ConstructDatagram(conn *ConnectionImpl, datagram []byte) (int, error) {
	var datagramSize int
	// we decided to first send our messages, then acks.
	// because message has a chance to ack the whole flight
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
		if sq.fragmentOffset < outgoing.SendOffset { // some were acked
			sq.fragmentOffset = outgoing.SendOffset
		}
		var sendNextSegmentSequenceEpoch0 *uint16
		if outgoing.Msg.MsgType == handshake.MsgTypeClientHello || outgoing.Msg.MsgType == handshake.MsgTypeServerHello {
			if conn.hctx != nil {
				sendNextSegmentSequenceEpoch0 = &conn.hctx.sendNextRecordSequenceEpoch0
			} else {
				// We only can send that if we are still in handshake.
				// If not, we simply pretend we sent it.
				sq.fragmentOffset = outgoing.SendEnd
			}
		}
		if !outgoing.FullyAcked() {
			if sq.fragmentOffset >= outgoing.SendEnd { // never due to combination of checks above
				panic("invariant violation")
			}
			recordSize, fragmentInfo, rn, err := conn.constructRecord(datagram[datagramSize:],
				outgoing.Msg,
				sq.fragmentOffset, outgoing.SendEnd-sq.fragmentOffset, sendNextSegmentSequenceEpoch0)
			if err != nil {
				return 0, err
			}
			if recordSize == 0 {
				break
			}
			// Unfortunately, not in order because we have epoch 0 and need to resend ServerHello, so linear search
			// limited to constants.MaxSendRecordsQueue due to check above
			sq.sentRecords.PushBack(sq.sentRecordsStorage[:], record2Fragment{rn: rn, fragment: fragmentInfo})
			datagramSize += recordSize
			sq.fragmentOffset += fragmentInfo.FragmentLength
		}
		if sq.fragmentOffset > outgoing.SendEnd {
			panic("invariant violation")
		}
		if sq.fragmentOffset == outgoing.SendEnd {
			sq.messageOffset++
			sq.fragmentOffset = 0
		}
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

func (sq *sendQueue) Ack(conn *ConnectionImpl, rn record.Number) {
	fragmentPtr := findSentRecordIndexExt(sq.sentRecordsStorage[:], &sq.sentRecords, rn)
	if fragmentPtr == nil {
		return
	}
	rec := *fragmentPtr
	*fragmentPtr = handshake.FragmentInfo{} // delete in the middle
	for sq.sentRecords.Len() != 0 && sq.sentRecords.Front(sq.sentRecordsStorage[:]).fragment == (handshake.FragmentInfo{}) {
		sq.sentRecords.PopFront(sq.sentRecordsStorage[:]) // delete everything from the front
	}
	if sq.messages.Len() > int(conn.nextMessageSeqSend) {
		panic("invariant violation")
	}
	// sq.messages end() is aligned with conn.nextMessageSeqSend
	index := int(rec.MsgSeq) + sq.messages.Len() - int(conn.nextMessageSeqSend)
	if index < 0 || index >= sq.messages.Len() {
		return
	}
	msg := sq.messages.IndexRef(sq.messagesStorage[:], index)
	msg.Ack(rec.FragmentOffset, rec.FragmentLength)
	for sq.messages.Len() != 0 && sq.messages.FrontRef(sq.messagesStorage[:]).FullyAcked() {
		if sq.messageOffset == 0 {
			sq.fragmentOffset = 0
		} else {
			sq.messageOffset--
		}
		sq.messages.PopFront(sq.messagesStorage[:])
	}
}
