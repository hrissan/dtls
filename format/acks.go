package format

// TODO - do not allow SeqNum to go over 2^48
// this is bad idea without key update for AEAD anyway

const maxUint48 = 0xFFFFFFFFFFFF

// for debug uncomment simple implementation

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

/*
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
*/
