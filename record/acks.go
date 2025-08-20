package record

import (
	"errors"

	"github.com/hrissan/dtls/format"
)

const AckHeaderSize = 2
const AckElementSize = 16

var ErrAckRecordWrongSize = errors.New("ack record size not multiple of 16")

func ParseAcks(body []byte) (insideBody []byte, err error) {
	var offset int
	if offset, insideBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return nil, err
	}
	if len(insideBody)%AckElementSize != 0 {
		return insideBody, ErrAckRecordWrongSize
	}
	return insideBody, format.ParserReadFinish(body, offset)
}
