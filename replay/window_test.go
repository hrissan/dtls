package replay

import (
	"math/bits"
	"testing"
)

func TestConstant(t *testing.T) {
	if bits.OnesCount64(replayWidth) != 1 {
		t.Fatalf("replayWidth must be power of 2")
	}
	if replayWidth < 1 || replayWidth > 64 {
		t.Fatalf("replayWidth must fit into uint64")
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

func (r *windowMirror) SetReceivedIsUnique(seq uint64) bool {
	if seq+1 > r.nextReceivedSeq {
		r.nextReceivedSeq = seq + 1
	}
	for s := 0; s < int(r.nextReceivedSeq)-replayWidth-1; s++ {
		*r.ensure(uint64(s)) = 1
	}
	unique := *r.ensure(seq) == 0
	*r.ensure(seq) = 1
	return unique
}

// messages >= r.nextReceivedSeq are returned as unique
func (r *windowMirror) IsUnique(seq uint64) bool {
	if seq+1 > r.nextReceivedSeq {
		return true
	}
	if len(r.received) <= int(seq) {
		return true
	}
	return r.received[seq] == 0
}

const maxLastReceivedForFuzzing = 1024 // no benefits of larger values

func FuzzReplay(f *testing.F) {
	f.Fuzz(func(t *testing.T, commands []byte) {
		cb := Window{}
		cb2 := windowMirror{}
		lastReceived := uint64(0)
		for _, c := range commands {
			if cb.GetNextReceivedSeq() != cb2.GetNextReceivedSeq() {
				t.FailNow()
			}
			for j := uint64(0); j < lastReceived+(replayWidth+1)*2; j++ { // arbitrary look ahead
				if cb.IsUnique(j) != cb2.IsUnique(j) {
					t.FailNow()
				}
			}
			switch {
			case c == 0:
				lastReceived = min(lastReceived+1, maxLastReceivedForFuzzing)
				if cb.SetReceivedIsUnique(lastReceived) != cb2.SetReceivedIsUnique(lastReceived) {
					t.FailNow()
				}
			case c < 3*(replayWidth+1):
				lastReceived = min(lastReceived+uint64(c), maxLastReceivedForFuzzing)
				if cb.SetReceivedIsUnique(lastReceived) != cb2.SetReceivedIsUnique(lastReceived) {
					t.FailNow()
				}
			default:
				if uint64(c) <= lastReceived {
					if cb.SetReceivedIsUnique(lastReceived-uint64(c)) != cb2.SetReceivedIsUnique(lastReceived-uint64(c)) {
						t.FailNow()
					}
				}
			}
		}
	})
}
