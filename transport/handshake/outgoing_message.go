package handshake

import "github.com/hrissan/tinydtls/format"

type OutgoingHandshakeMessage struct {
	Message format.MessageHandshake
	// We support acks from both sides, but no holes for simplicity.
	// Once SendOffset == SendEnd, message is fully sent
	SendOffset uint32
	SendEnd    uint32
}

func (msg *OutgoingHandshakeMessage) FullyAcked() bool {
	return msg.SendEnd == msg.SendOffset
}

func (msg *OutgoingHandshakeMessage) Ack(fragmentOffset uint32, fragmentLength uint32) {
	fragmentEnd := fragmentOffset + fragmentLength
	if fragmentOffset < msg.SendEnd && fragmentEnd > msg.SendEnd {
		msg.SendEnd = fragmentOffset
	}
	if fragmentOffset < msg.SendOffset && fragmentEnd > msg.SendOffset {
		msg.SendOffset = fragmentEnd
	}
	// as both conditions above could be true, ends can become reversed, fix here
	if msg.SendOffset > msg.SendEnd {
		msg.SendOffset = msg.SendEnd
	}
}
