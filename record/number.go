package record

import "cmp"

const maxUint48 = 0xFFFFFFFFFFFF

// two implementation, one for easy debugging, one compact

/*

type Number struct {
	epoch  uint16
	seqNum uint64
}

func NumberWith(epoch uint16, seqNum uint64) Number {
	if seqNum > maxUint48 {
		panic("seqNum must not be over 2^48")
	}
	return Number{epoch: epoch, seqNum: seqNum}
}

func (r Number) Less(other Number) bool {
	if r.spoch != other.epoch {
		return r.epoch < other.epoch
	return r.seqNum < other.seqNum // nicely ordered
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
*/

// optimal implementation for production

type Number struct {
	epochSeqNum uint64
}

func NumberWith(epoch uint16, seqNum uint64) Number {
	if seqNum > maxUint48 {
		panic("seqNum must not be over 2^48")
	}
	return Number{epochSeqNum: (uint64(epoch) << 48) + seqNum}
}

func (r Number) Less(other Number) bool {
	return r.epochSeqNum < other.epochSeqNum // nicely ordered
}

func (r Number) Epoch() uint16 {
	return uint16(r.epochSeqNum >> 48)
}

func (r Number) SeqNum() uint64 {
	return r.epochSeqNum & maxUint48
}

func RecordNumberCmp(a, b Number) int {
	return cmp.Compare(a.epochSeqNum, b.epochSeqNum) // nicely ordered
}
