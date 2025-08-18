package handshake

const replayWidth = 64 // set to 4 for fuzzing/testing

type Replay struct {
	nextReceivedSeq uint64 // nextReceivedSeq-1 is implicitly received
	received        uint64 // bits for 64 previous messages
}

func (r *Replay) Reset() {
	r.nextReceivedSeq = 0
	r.received = 0
}

func (r *Replay) GetNextReceivedSeq() uint64 { return r.nextReceivedSeq }

func (r *Replay) SetReceivedIsUnique(seq uint64) bool {
	if seq+1 > r.nextReceivedSeq+replayWidth { // efficient big jump
		r.nextReceivedSeq = seq + 1
		r.received = 0
		return true
	}
	if seq+1 > r.nextReceivedSeq {
		r.received |= (1 << ((r.nextReceivedSeq - 1) % replayWidth))
		r.nextReceivedSeq++
		for ; seq+1 > r.nextReceivedSeq; r.nextReceivedSeq++ {
			r.received &= ^(1 << ((r.nextReceivedSeq - 1) % replayWidth))
		}
		return true
	}
	if seq+1 == r.nextReceivedSeq {
		return false
	}
	if seq+1+replayWidth < r.nextReceivedSeq {
		return false
	}
	if r.received&(1<<(seq%replayWidth)) != 0 {
		return false
	}
	r.received |= (1 << (seq % replayWidth))
	return true
}

// messages >= r.nextReceivedSeq are returned as unique
func (r *Replay) IsUnique(seq uint64) bool {
	if seq+1 > r.nextReceivedSeq {
		return true
	}
	if seq+1 == r.nextReceivedSeq {
		return false
	}
	if seq+1+replayWidth < r.nextReceivedSeq {
		return false
	}
	return r.received&(1<<(seq%replayWidth)) == 0
}
