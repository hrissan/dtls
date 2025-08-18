package handshake_test

import (
	"testing"

	"github.com/hrissan/tinydtls/transport/handshake"
)

const replayWidth = 64

type ReplayMirror struct {
	nextReceivedSeq uint64
	received        []byte
}

func (r *ReplayMirror) Reset() {
	r.nextReceivedSeq = 0
	r.received = make([]byte, 1000000)
}

func (r *ReplayMirror) ensure(seq uint64) *byte {
	if len(r.received) <= int(seq) {
		r.received = append(r.received, make([]byte, int(seq)-len(r.received)+1)...)
	}
	return &r.received[seq]
}

func (r *ReplayMirror) GetNextReceivedSeq() uint64 { return r.nextReceivedSeq }

func (r *ReplayMirror) SetReceivedIsUnique(seq uint64) bool {
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
func (r *ReplayMirror) IsUnique(seq uint64) bool {
	if seq+1 > r.nextReceivedSeq {
		return true
	}
	if len(r.received) <= int(seq) {
		return true
	}
	return r.received[seq] == 0
}

func FuzzReplay(f *testing.F) {
	f.Fuzz(func(t *testing.T, commands []byte) {
		cb := handshake.Replay{}
		cb2 := ReplayMirror{}
		lastReceived := uint64(0)
		for _, c := range commands {
			if cb.GetNextReceivedSeq() != cb2.GetNextReceivedSeq() {
				t.FailNow()
			}
			for j := uint64(0); j < lastReceived+replayWidth*2; j++ { // arbitrary look ahead
				if cb.IsUnique(j) != cb2.IsUnique(j) {
					t.FailNow()
				}
			}
			switch {
			case c == 0:
				lastReceived++
				if cb.SetReceivedIsUnique(lastReceived) != cb2.SetReceivedIsUnique(lastReceived) {
					t.FailNow()
				}
			case c < 3*replayWidth:
				lastReceived += uint64(c)
				if cb.SetReceivedIsUnique(lastReceived) != cb2.SetReceivedIsUnique(lastReceived) {
					t.FailNow()
				}
			default:
				if uint64(c) <= lastReceived {
					if cb.SetReceivedIsUnique(uint64(c)) != cb2.SetReceivedIsUnique(uint64(c)) {
						t.FailNow()
					}
				}
			}
		}
	})
}
