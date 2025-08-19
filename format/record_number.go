package format

import "cmp"

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

func (r RecordNumber) Less(other RecordNumber) bool {
	return r.epochSeqNum < other.epochSeqNum // nicely ordered
}

func (r RecordNumber) Epoch() uint16 {
	return uint16(r.epochSeqNum >> 48)
}

func (r RecordNumber) SeqNum() uint64 {
	return r.epochSeqNum & maxUint48
}

func RecordNumberCmp(a, b RecordNumber) int {
	return cmp.Compare(a.epochSeqNum, b.epochSeqNum) // nicely ordered
}
