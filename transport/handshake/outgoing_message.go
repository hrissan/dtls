package handshake

type MessageHeaderMinimal struct {
	HandshakeType byte
	MessageSeq    uint16
}

type PartialHandshakeMessage struct {
	Header MessageHeaderMinimal
	Body   []byte // TODO - reuse in rope
	// We support acks from both sides, but no holes for simplicity.
	// Once SendOffset == SendEnd, message is fully sent
	SendOffset uint32
	SendEnd    uint32
}

// used for both acks, and reconstructing incoming messages, in that case it means FullyReceived
func (msg *PartialHandshakeMessage) FullyAcked() bool {
	return msg.SendEnd == msg.SendOffset
}

// used for both acks, and reconstructing incoming messages
func (msg *PartialHandshakeMessage) Ack(fragmentOffset uint32, fragmentLength uint32) (shouldAck bool, changed bool) {
	fragmentEnd := fragmentOffset + fragmentLength
	if fragmentOffset > msg.SendOffset && fragmentEnd < msg.SendEnd {
		// when receiving, we should not acknowledge this packet, we need to receive it again
		return
	}
	if fragmentOffset < msg.SendEnd && fragmentEnd >= msg.SendEnd {
		msg.SendEnd = fragmentOffset
		changed = true
	}
	if fragmentOffset <= msg.SendOffset && fragmentEnd > msg.SendOffset {
		msg.SendOffset = fragmentEnd
		changed = true
	}
	// as both conditions above could be true, ends can become reversed, fix here
	if msg.SendOffset > msg.SendEnd {
		msg.SendOffset = msg.SendEnd
	}
	shouldAck = true
	return
}
