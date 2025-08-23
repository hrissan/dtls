// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package record

import "cmp"

const MaxSeq = 0xFFFFFFFFFFFF

// Our implementation pack 16-bit epoch with 48-bit sequence number for efficient storage.
// So we must prevent sequence number from ever reaching this limit.

// implementation for easy debugging is in number_test.go

type Number struct {
	epochSeqNum uint64
}

func NumberWith(epoch uint16, seqNum uint64) Number {
	if seqNum > MaxSeq {
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
	return r.epochSeqNum & MaxSeq
}

func RecordNumberCmp(a, b Number) int {
	return cmp.Compare(a.epochSeqNum, b.epochSeqNum) // nicely ordered
}
