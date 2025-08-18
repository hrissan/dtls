package format

import (
	"errors"
)

// TODO - do not allow SeqNum to go over 2^48
// this is bad idea anyway, because of AEAD limits

const MessageAckHeaderSize = 2
const MessageAckRecordNumberSize = 16

var ErrAckMessageWrongSize = errors.New("ack record size not multiple of 16")

func ParseMessageAcks(body []byte) (insideBody []byte, err error) {
	var offset int
	if offset, insideBody, err = ParserReadUint16Length(body, offset); err != nil {
		return nil, err
	}
	if len(insideBody)%MessageAckRecordNumberSize != 0 {
		return insideBody, ErrAckMessageWrongSize
	}
	return insideBody, ParserReadFinish(body, offset)
}
