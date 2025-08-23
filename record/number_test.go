package record_test

import (
	"cmp"

	"github.com/hrissan/dtls/record"
)

// if you ever need to debug Number, replcae prod implementation with this one

type Number struct {
	epoch  uint16
	seqNum uint64
}

func NumberWith(epoch uint16, seqNum uint64) Number {
	if seqNum > record.MaxSeq {
		panic("seqNum must not be over 2^48")
	}
	return Number{epoch: epoch, seqNum: seqNum}
}

func (r Number) Less(other Number) bool {
	if r.epoch != other.epoch {
		return r.epoch < other.epoch
	}
	return r.seqNum < other.seqNum
}

func (r Number) Epoch() uint16 {
	return r.epoch
}

func (r Number) SeqNum() uint64 {
	return r.seqNum
}

func RecordNumberCmp(a, b Number) int {
	if c := cmp.Compare(a.epoch, b.epoch); c != 0 {
		return c
	}
	return cmp.Compare(a.seqNum, b.seqNum)
}
