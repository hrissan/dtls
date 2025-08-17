package format

import (
	"cmp"
	"errors"
)

// TODO - do not allow SeqNum to go over 2^48
// this is bad idea anyway, because of AEAD limits

const MessageAckHeaderSize = 2
const MessageAckRecordNumberSize = 16

const maxUint48 = 0xFFFFFFFFFFFF

// two implementation, one for easy debugging, one compact

/*

type RecordNumber struct {
	epoch  uint16
	seqNum uint64
}

func RecordNumberWith(epoch uint16, seqNum uint64) RecordNumber {
	if seqNum > maxUint48 {
		panic("seqNum must not be over 2^48")
	}
	return RecordNumber{epoch: epoch, seqNum: seqNum}
}

func (r RecordNumber) Epoch() uint16 {
	return r.epoch
}

func (r RecordNumber) SeqNum() uint64 {
	return r.seqNum
}

func RecordNumberCmp(a, b RecordNumber) int {
	if c := cmp.Compare(a.epoch, b.epoch); c != 0 {
		return c
	}
	return cmp.Compare(a.seqNum, b.seqNum)
}
*/

// optimal implementation for production

type RecordNumber struct {
	epochSeqNum uint64
}

func RecordNumberWith(epoch uint16, seqNum uint64) RecordNumber {
	if seqNum > maxUint48 {
		panic("seqNum must not be over 2^48")
	}
	return RecordNumber{epochSeqNum: (uint64(epoch) << 48) + seqNum}
}

func (r RecordNumber) Epoch() uint16 {
	return uint16(r.epochSeqNum >> 48)
}

func (r RecordNumber) SeqNum() uint64 {
	return r.epochSeqNum & maxUint48
}

func RecordNumberCmp(a, b RecordNumber) int {
	return cmp.Compare(a.epochSeqNum, b.epochSeqNum)
}

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
