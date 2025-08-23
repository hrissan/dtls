// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package record

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/hrissan/dtls/format"
)

// We do not have Ack struct, because we do not want to parse/copy record numbers.
// Instead, we provide iterator interface.
// (We do not want interface callback, as that would allocate lambda).

const AckHeaderSize = 2
const AckElementSize = 16

var ErrAckRecordWrongSize = errors.New("ack record size not multiple of 16")

type AckParser struct {
	recordBody []byte
}

// return by value to signal usage pattern
func NewAckParser(recordBody []byte) (AckParser, error) {
	offset, insideBody, err := format.ParserReadUint16Length(recordBody, 0)
	if err != nil {
		return AckParser{}, err
	}
	if len(insideBody)%AckElementSize != 0 {
		return AckParser{}, ErrAckRecordWrongSize
	}
	// can contain 0 elements [rfc9147:6.] - Note that the client sends an empty ACK message
	return AckParser{recordBody: insideBody}, format.ParserReadFinish(recordBody, offset)
}

func (p *AckParser) PopFront(epochSeqOverflowCounter *int) (rn Number, ok bool) {
	for { // we should skip records which overflow epoch of  our implementation
		if len(p.recordBody) == 0 {
			return Number{}, false
		}
		if len(p.recordBody) < AckElementSize {
			panic("parser invariant violation")
		}
		epoch := binary.BigEndian.Uint64(p.recordBody)
		seq := binary.BigEndian.Uint64(p.recordBody[8:])
		p.recordBody = p.recordBody[AckElementSize:]
		if epoch > math.MaxUint16 { // prevent overflow below
			*epochSeqOverflowCounter++ // in case someone needs this metric
			continue
		}
		if seq > MaxSeq { // prevent overflow below
			*epochSeqOverflowCounter++ // in case someone needs this metric
			continue
		}
		return NumberWith(uint16(epoch), seq), true
	}
}
