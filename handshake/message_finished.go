package handshake

import (
	"errors"

	"github.com/hrissan/tinydtls/constants"
)

var ErrMsgFinishedTooBig = errors.New("finished message too big")

// TODO - use rope for all variable memory chunks
// for now after parsing those slices point to datagram, so must be copied or discarded before next datagram is read
type MsgFinished struct {
	VerifyDataLength int
	VerifyData       [constants.MaxHashLength]byte
}

func (msg *MsgFinished) MessageKind() string { return "handshake" }
func (msg *MsgFinished) MessageName() string { return "Finished" }

func (msg *MsgFinished) Parse(body []byte) (err error) {
	msg.VerifyDataLength = len(body)
	if msg.VerifyDataLength > len(msg.VerifyData) {
		return ErrMsgFinishedTooBig
	}
	copy(msg.VerifyData[:], body)
	return nil
}

func (msg *MsgFinished) Write(body []byte) []byte {
	return append(body, msg.VerifyData[:msg.VerifyDataLength]...)
}
