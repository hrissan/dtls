package format

import "errors"

var ErrFinishedMessageTooBig = errors.New("finished message too big")

// TODO - use rope for all variable memory chunks
// for now after parsing those slices point to datagram, so must be copied or discarded before next datagram is read
type MessageFinished struct {
	VerifyDataLength int
	VerifyData       [64]byte // TODO - use universal MaxHashLength constant
}

func (msg *MessageFinished) MessageKind() string { return "handshake" }
func (msg *MessageFinished) MessageName() string { return "finished" }

func (msg *MessageFinished) Parse(body []byte) (err error) {
	msg.VerifyDataLength = len(body)
	if msg.VerifyDataLength > len(msg.VerifyData) {
		return ErrFinishedMessageTooBig
	}
	copy(msg.VerifyData[:], body)
	return nil
}

func (msg *MessageFinished) Write(body []byte) []byte {
	return append(body, msg.VerifyData[:msg.VerifyDataLength]...)
}
