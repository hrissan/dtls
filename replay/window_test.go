// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package replay

import (
	"math/bits"
	"testing"
)

func TestConstant(t *testing.T) {
	if bits.OnesCount64(Width) != 1 {
		t.Fatalf("Width must be power of 2")
	}
	if Width < 1 || Width > 64 {
		t.Fatalf("Width must fit into uint64")
	}
}

type windowMirror struct {
	nextReceivedSeq uint64
	received        []byte
}

func (r *windowMirror) Reset() {
	r.nextReceivedSeq = 0
	r.received = r.received[:0]
}

func (r *windowMirror) ensure(seq uint64) *byte {
	for int(seq) >= len(r.received) {
		r.received = append(r.received, 0)
	}
	return &r.received[seq]
}

func (r *windowMirror) GetNextReceivedSeq() uint64 { return r.nextReceivedSeq }

func (r *windowMirror) SetNextReceived(nextSeq uint64) {
	if nextSeq > r.nextReceivedSeq {
		r.nextReceivedSeq = nextSeq
	}
	for s := uint64(0); s < r.nextReceivedSeq-Width; s++ {
		*r.ensure(s) = 1
	}
}

func (r *windowMirror) SetBit(seq uint64) {
	if seq >= r.nextReceivedSeq || seq+Width < r.nextReceivedSeq {
		return
	}
	*r.ensure(seq) = 1
}

func (r *windowMirror) ClearBit(seq uint64) {
	if seq >= r.nextReceivedSeq || seq+Width < r.nextReceivedSeq {
		return
	}
	*r.ensure(seq) = 0
}

func (r *windowMirror) IsSetBit(seq uint64) bool {
	if seq >= r.nextReceivedSeq {
		return false // arbitrary selected to simplify receiver
	}
	return *r.ensure(seq) != 0
}

const maxLastReceivedForFuzzing = 1024 // no benefits of larger values

func FuzzReplay(f *testing.F) {
	f.Fuzz(func(t *testing.T, commands []byte) {
		cb := Window{}
		cb2 := windowMirror{}
		nextReceived := uint64(0)
		for i := 0; i+1 < len(commands); i += 2 {
			c := commands[i]
			v := uint64(commands[i+1]) // widening
			if cb.GetNextReceivedSeq() != cb2.GetNextReceivedSeq() {
				t.FailNow()
			}
			for j := uint64(0); j < nextReceived+(Width+1)*2; j++ { // arbitrary look ahead
				if a, b := cb.IsSetBit(j), cb2.IsSetBit(j); a != b {
					t.FailNow()
				}
			}
			switch c {
			case 0:
				nextReceived = min(nextReceived+1, maxLastReceivedForFuzzing)
				cb.SetNextReceived(nextReceived)
				cb2.SetNextReceived(nextReceived)
			case 1:
				nextReceived = min(nextReceived+1, maxLastReceivedForFuzzing)
				cb.SetNextReceived(nextReceived)
				cb2.SetNextReceived(nextReceived)
				cb.SetBit(nextReceived - 1)
				cb2.SetBit(nextReceived - 1)
			case 2:
				cb.SetBit(v)
				cb2.SetBit(v)
			case 3:
				cb.ClearBit(v)
				cb2.ClearBit(v)
			case 4:
				nextReceived = min(nextReceived+v, maxLastReceivedForFuzzing)
				cb.SetNextReceived(nextReceived)
				cb2.SetNextReceived(nextReceived)
			case 5:
				if nextReceived != 0 {
					cb.ClearBit(nextReceived - 1)
					cb2.ClearBit(nextReceived - 1)
				}
			}
		}
	})
}
