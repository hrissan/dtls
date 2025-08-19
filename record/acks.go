package record

import (
	"errors"

	"github.com/hrissan/tinydtls/format"
)

// TODO - do not allow SeqNum to go over 2^48
// this is bad idea anyway, because of AEAD limits

const AckRecordHeaderSize = 2
const AckRecordNumberSize = 16

var ErrAckRecordWrongSize = errors.New("ack record size not multiple of 16")

func ParseRecordAcks(body []byte) (insideBody []byte, err error) {
	var offset int
	if offset, insideBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return nil, err
	}
	if len(insideBody)%AckRecordNumberSize != 0 {
		return insideBody, ErrAckRecordWrongSize
	}
	return insideBody, format.ParserReadFinish(body, offset)
}
