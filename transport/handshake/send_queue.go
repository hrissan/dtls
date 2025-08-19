package handshake

import (
	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
)

type recordFragmentRelation struct {
	rn       format.RecordNumber
	fragment format.FragmentInfo
}

type SendQueue struct {
	// all messages here belong to the same flight during handshake.
	// if message in the middle is fully acked, it will stay in the buffer until it becomes
	// head or tail of buffer, only then it is removed.
	messages        circular.BufferExt[PartialHandshakeMsg]
	messagesStorage [constants.MaxSendMessagesQueue]PartialHandshakeMsg
	// offset in messages of the message we are sending, len(messages) if all sent
	messageOffset int
	// offset inside messages[messageOffset] or 0 if messageOffset == len(messages)
	fragmentOffset uint32

	// Not in order because we have epoch 0 and need to resend ServerHello,
	// so linear search, but it is fast, see benchmarks
	sentRecords        circular.BufferExt[recordFragmentRelation]
	sentRecordsStorage [constants.MaxSendRecordsQueue]recordFragmentRelation
}

func (sq *SendQueue) Reserve() {
	//uncomment if using Buffer instead of BufferExt
	//sq.sentRecords.Reserve(constants.MaxSendRecordsQueue)
	//sq.messages.Reserve(constants.MaxSendMessagesQueue)
}

func (sq *SendQueue) Len() int {
	return sq.messages.Len()
}

func (sq *SendQueue) Clear() {
	sq.messages.Clear(sq.messagesStorage[:])
	sq.messageOffset = 0
	sq.fragmentOffset = 0
	sq.sentRecords.Clear(sq.sentRecordsStorage[:])
}

func (sq *SendQueue) PushMessage(msg format.MessageHandshakeFragment) {
	if sq.messages.Len() == sq.messages.Cap(sq.messagesStorage[:]) {
		// must be never, because no flight contains so many messages
		panic("too many messages are generated at once")
	}
	sq.messages.PushBack(sq.messagesStorage[:], PartialHandshakeMsg{
		Msg: HandshakeMsg{
			HandshakeType: msg.Header.HandshakeType,
			MessageSeq:    msg.Header.MessageSeq,
		},
		Body:       msg.Body,
		SendOffset: 0,
		SendEnd:    msg.Header.Length,
	})
}

func (sq *SendQueue) HasDataToSend() bool {
	return sq.messageOffset < sq.messages.Len() && sq.sentRecords.Len() < sq.sentRecords.Cap(sq.sentRecordsStorage[:])
}

func (sq *SendQueue) ConstructDatagram(conn *ConnectionImpl, datagram []byte) (int, error) {
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
		if outgoing.Msg.HandshakeType == format.HandshakeTypeClientHello || outgoing.Msg.HandshakeType == format.HandshakeTypeServerHello {
			if conn.Handshake != nil {
				sendNextSegmentSequenceEpoch0 = &conn.Handshake.SendNextSegmentSequenceEpoch0
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
				outgoing.Msg, outgoing.Body,
				sq.fragmentOffset, outgoing.SendEnd-sq.fragmentOffset, sendNextSegmentSequenceEpoch0)
			if err != nil {
				return 0, err
			}
			if recordSize == 0 {
				break
			}
			// Unfortunately, not in order because we have epoch 0 and need to resend ServerHello, so linear search
			// limited to constants.MaxSendRecordsQueue due to check above
			sq.sentRecords.PushBack(sq.sentRecordsStorage[:], recordFragmentRelation{rn: rn, fragment: fragmentInfo})
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

func findSentRecordIndex(sentRecords *circular.Buffer[recordFragmentRelation], rn format.RecordNumber) *format.FragmentInfo {
	for i := 0; i != sentRecords.Len(); i++ {
		element := sentRecords.IndexRef(i)
		if element.rn == rn {
			return &element.fragment
		}
	}
	return nil
}

func findSentRecordIndexExt(elements []recordFragmentRelation, sentRecords *circular.BufferExt[recordFragmentRelation], rn format.RecordNumber) *format.FragmentInfo {
	for i := 0; i != sentRecords.Len(); i++ {
		element := sentRecords.IndexRef(elements, i)
		if element.rn == rn {
			return &element.fragment
		}
	}
	return nil
}

func (sq *SendQueue) Ack(conn *ConnectionImpl, rn format.RecordNumber) {
	fragmentPtr := findSentRecordIndexExt(sq.sentRecordsStorage[:], &sq.sentRecords, rn)
	if fragmentPtr == nil {
		return
	}
	rec := *fragmentPtr
	*fragmentPtr = format.FragmentInfo{} // delete in the middle
	for sq.sentRecords.Len() != 0 && sq.sentRecords.Front(sq.sentRecordsStorage[:]).fragment == (format.FragmentInfo{}) {
		sq.sentRecords.PopFront(sq.sentRecordsStorage[:]) // delete everything from the front
	}
	if sq.messages.Len() > int(conn.NextMessageSeqSend) {
		panic("invariant violation")
	}
	// sq.messages end() is aligned with conn.NextMessageSeqSend
	index := int(rec.MessageSeq) + sq.messages.Len() - int(conn.NextMessageSeqSend)
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
