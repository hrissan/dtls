// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package replay

import "math/bits"

const Width = 64 // set to 1..4 for fuzzing/testing

// for receiving replay protection we could save 65-th bit implicitly
// by invariant that nextReceivedSeq-1 is received.
// but for sending acks we need this structure to contain nothing, so 64-bit explicit bits.

type Window struct {
	nextReceivedSeq uint64
	received        uint64 // bits for 64 previous messages
}

func (r *Window) Reset() {
	r.nextReceivedSeq = 0
	r.received = 0
}

func (r *Window) GetNextReceivedSeq() uint64 { return r.nextReceivedSeq }

func (r *Window) GetBitCount() int { return bits.OnesCount64(r.received) }

func (r *Window) SetNextReceived(nextSeq uint64) {
	if nextSeq > r.nextReceivedSeq+Width { // efficient big jump
		r.nextReceivedSeq = nextSeq
		r.received = 0
		return
	}
	for ; nextSeq > r.nextReceivedSeq; r.nextReceivedSeq++ {
		r.received &= ^(1 << (r.nextReceivedSeq & (Width - 1)))
	}
}

func (r *Window) SetBit(seq uint64) {
	if seq >= r.nextReceivedSeq || seq+Width < r.nextReceivedSeq {
		return
	}
	r.received |= (1 << (seq & (Width - 1)))
}

func (r *Window) ClearBit(seq uint64) {
	if seq >= r.nextReceivedSeq || seq+Width < r.nextReceivedSeq {
		return
	}
	r.received &= ^(1 << (seq & (Width - 1)))
}

func (r *Window) IsSetBit(seq uint64) bool {
	if seq >= r.nextReceivedSeq {
		return false // arbitrary selected to simplify receiver
	}
	if seq+Width < r.nextReceivedSeq {
		return true // arbitrary selected to simplify receiver
	}
	return r.received&(1<<(seq&(Width-1))) != 0
}
