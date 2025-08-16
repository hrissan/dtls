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
	messagesSendQueue circular.Buffer[OutgoingHandshakeMessage]
	// offset in messagesSendQueue of the message we are sending, len(messagesSendQueue) if all sent
	SendQueueMessageOffset int
	// offset inside messagesSendQueue[SendQueueMessageOffset] or 0 if SendQueueMessageOffset == len(messagesSendQueue)
	SendQueueFragmentOffset uint32

	// Very sad decision from committee.
	// Much better decision would be for Ack to simply contain MessageSeq, FragmentOffset, FragmentLength
	sentRecords map[format.RecordNumber]format.FragmentInfo
}

func (sq *SendQueue) Reserve() {
	sq.sentRecords = make(map[format.RecordNumber]format.FragmentInfo, constants.MaxSendRecordsQueue)
	sq.messagesSendQueue.Reserve(constants.MaxSendMessagesQueue)
}

func (sq *SendQueue) Clear() {
	sq.messagesSendQueue.Clear()
	sq.SendQueueMessageOffset = 0
	sq.SendQueueFragmentOffset = 0
	clear(sq.sentRecords)
}

func (sq *SendQueue) PushMessage(msg format.MessageHandshake) {
	if sq.messagesSendQueue.Len() == constants.MaxSendMessagesQueue {
		// must be never, because no flight contains so many messages
		panic("too many messages are generated at once")
	}
	sq.messagesSendQueue.PushBack(OutgoingHandshakeMessage{
		Message:    msg,
		SendOffset: 0,
		SendEnd:    msg.Header.Length,
	})
}

func (sq *SendQueue) ConstructDatagram(conn *ConnectionImpl, datagram []byte) (datagramSize int, addToSendQueue bool) {
	// we decided to first send our messages, then acks.
	// because message has a chance to ack the whole flight
	for {
		if sq.SendQueueMessageOffset > sq.messagesSendQueue.Len() {
			panic("invariant of send queue message offset violated")
		}
		if sq.SendQueueMessageOffset == sq.messagesSendQueue.Len() {
			break
		}
		if len(sq.sentRecords) >= constants.MaxSendRecordsQueue {
			break
		}
		outgoing := sq.messagesSendQueue.IndexRef(sq.SendQueueMessageOffset)
		if sq.SendQueueFragmentOffset < outgoing.SendOffset { // some were acked
			sq.SendQueueFragmentOffset = outgoing.SendOffset
		}
		if !outgoing.FullyAcked() {
			if sq.SendQueueFragmentOffset >= outgoing.SendEnd { // never due to combination of checks above
				panic("invariant violation")
			}
			recordSize, fragmentLength, rn := conn.constructRecord(datagram[datagramSize:], outgoing.Message,
				sq.SendQueueFragmentOffset, outgoing.SendEnd-sq.SendQueueFragmentOffset)
			if recordSize == 0 {
				return datagramSize, true
			}
			sq.sentRecords[rn] = outgoing.Message.Header.FragmentInfo
			datagramSize += recordSize
			sq.SendQueueFragmentOffset += fragmentLength
		}
		if sq.SendQueueFragmentOffset > outgoing.SendEnd {
			panic("invariant violation")
		}
		if sq.SendQueueFragmentOffset == outgoing.SendEnd {
			sq.SendQueueMessageOffset++
			sq.SendQueueFragmentOffset = 0
		}
	}
	return
}
