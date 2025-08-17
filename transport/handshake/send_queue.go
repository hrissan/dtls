package handshake

import (
	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
)

type SendQueue struct {
	// all messages here belong to the same flight during handshake.
	// if message in the middle is fully acked, it will stay in the buffer until it becomes
	// head or tail of buffer, only then it is removed
	messages circular.Buffer[OutgoingHandshakeMessage]
	// offset in messages of the message we are sending, len(messages) if all sent
	messageOffset int
	// offset inside messages[messageOffset] or 0 if messageOffset == len(messages)
	fragmentOffset uint32

	// Very sad decision from committee.
	// Much better decision would be for Ack to simply contain MessageSeq, FragmentOffset, FragmentLength
	sentRecords map[format.RecordNumber]format.FragmentInfo
}

func (sq *SendQueue) Reserve() {
	sq.sentRecords = make(map[format.RecordNumber]format.FragmentInfo, constants.MaxSendRecordsQueue)
	sq.messages.Reserve(constants.MaxSendMessagesQueue)
}

func (sq *SendQueue) Len() int {
	return sq.messages.Len()
}

func (sq *SendQueue) Clear() {
	sq.messages.Clear()
	sq.messageOffset = 0
	sq.fragmentOffset = 0
	clear(sq.sentRecords)
}

func (sq *SendQueue) PushMessage(msg format.MessageHandshake) {
	if sq.messages.Len() == constants.MaxSendMessagesQueue {
		// must be never, because no flight contains so many messages
		panic("too many messages are generated at once")
	}
	sq.messages.PushBack(OutgoingHandshakeMessage{
		Header: MessageHeaderMinimal{
			HandshakeType: msg.Header.HandshakeType,
			MessageSeq:    msg.Header.MessageSeq,
		},
		Body:       msg.Body,
		SendOffset: 0,
		SendEnd:    msg.Header.Length,
	})
}

func (sq *SendQueue) ConstructDatagram(conn *ConnectionImpl, datagram []byte) (datagramSize int, addToSendQueue bool) {
	// we decided to first send our messages, then acks.
	// because message has a chance to ack the whole flight
	for {
		if sq.messageOffset > sq.messages.Len() {
			panic("invariant of send queue message offset violated")
		}
		if sq.messageOffset == sq.messages.Len() {
			break
		}
		if len(sq.sentRecords) >= constants.MaxSendRecordsQueue {
			break
		}
		outgoing := sq.messages.IndexRef(sq.messageOffset)
		if sq.fragmentOffset < outgoing.SendOffset { // some were acked
			sq.fragmentOffset = outgoing.SendOffset
		}
		if !outgoing.FullyAcked() {
			if sq.fragmentOffset >= outgoing.SendEnd { // never due to combination of checks above
				panic("invariant violation")
			}
			recordSize, fragmentInfo, rn := conn.constructRecord(datagram[datagramSize:],
				outgoing.Header, outgoing.Body,
				sq.fragmentOffset, outgoing.SendEnd-sq.fragmentOffset)
			if recordSize == 0 {
				return datagramSize, true
			}
			sq.sentRecords[rn] = fragmentInfo
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
	return
}

func (sq *SendQueue) Ack(conn *ConnectionImpl, rn format.RecordNumber) {
	rec, ok := sq.sentRecords[rn]
	if !ok {
		return
	}
	delete(sq.sentRecords, rn)
	if sq.messages.Len() > int(conn.Keys.NextMessageSeqSend) {
		panic("invariant violation")
	}
	// sq.messages end() is aligned with conn.Keys.NextMessageSeqSend
	index := int(rec.MessageSeq) + sq.messages.Len() - int(conn.Keys.NextMessageSeqSend)
	if index < 0 || index >= sq.messages.Len() {
		return
	}
	msg := sq.messages.IndexRef(index)
	msg.Ack(rec.FragmentOffset, rec.FragmentLength)
	for sq.messages.Len() != 0 && sq.messages.FrontRef().FullyAcked() {
		if sq.messageOffset == 0 {
			sq.fragmentOffset = 0
		} else {
			sq.messageOffset--
		}
		sq.messages.PopFront()
	}
}
