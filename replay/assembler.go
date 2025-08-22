package replay

import "github.com/hrissan/dtls/constants"

const healthChecks = false

type fragment struct {
	start uint32
	end   uint32
}

type Assembler struct {
	holes [constants.MaxAssemblerHoles]fragment // no overlaps, no empty holes, no holes touching
	num   int
}

func (h *fragment) isEmpty() bool {
	if h.start > h.end {
		panic("fragment ends reversed")
	}
	return h.start == h.end
}

func (h *fragment) overlapsOrTouches(other fragment) bool {
	if h.start <= other.start && h.end >= other.start {
		return true
	}
	if h.start <= other.end && h.end >= other.end {
		return true
	}
	if other.start <= h.start && other.end >= h.start {
		return true
	}
	if other.start <= h.end && other.end >= h.end {
		return true
	}
	return false
}

func (h *fragment) addFragment(other fragment) (middle bool, changed bool) {
	if other.start > h.start && other.end < h.end {
		// when receiving, we should not acknowledge this packet, we need to receive it again
		return true, false
	}
	if other.start < h.end && other.end >= h.end {
		h.end = other.start
		changed = true
	}
	if other.start <= h.start && other.end > h.start {
		h.start = other.end
		changed = true
	}
	// as both conditions above could be true, ends can become reversed, fix here
	if h.start > h.end {
		h.start = h.end
	}
	return
}

func (a *Assembler) ResetToEmpty() {
	a.num = 0
}

func (a *Assembler) ResetToFull(length uint32) {
	a.num = 1
	a.holes[0] = fragment{start: 0, end: length}
}

func (a *Assembler) Len() int {
	return a.num
}

func (a *Assembler) checkInvariants() {
	if !healthChecks {
		return
	}
	for i := 0; i < a.num; i++ {
		if a.holes[i].isEmpty() {
			panic("assembler empty fragment")
		}
		for j := 0; j < a.num; j++ {
			if i != j && a.holes[i].overlapsOrTouches(a.holes[j]) {
				panic("assembler holes overlap")
			}
		}
	}
}

func (a *Assembler) fillMirror(m []byte) []byte {
	for i := range m {
		m[i] = 1
	}
	for _, hole := range a.holes[:a.num] {
		for j := hole.start; j < hole.end; j++ {
			m[j] = 0
		}
	}
	return m
}

func (a *Assembler) GetFragmentFromOffset(fromOffset uint32) (offset uint32, length uint32) {
	var res fragment
	for _, hole := range a.holes[:a.num] {
		// search the first matching hole linearily
		if fromOffset >= hole.end {
			continue
		}
		if hole.start < fromOffset {
			hole.start = fromOffset
		}
		if healthChecks && hole.isEmpty() {
			panic("hole must not be empty here")
		}
		if res.isEmpty() || hole.start < res.start {
			res = hole
		}
	}
	_ = res.isEmpty() // check reverse
	return res.start, res.end - res.start
}

func (a *Assembler) AddFragment(offset uint32, length uint32) (shouldAck bool, changed bool) {
	other := fragment{start: offset, end: offset + length}
	if other.isEmpty() {
		return false, false // we could also panic for this
	}
	index := 0
	for index < a.num {
		cur := &a.holes[index]
		mid, ch := cur.addFragment(other)
		if mid {
			if changed || ch { // could not change any holes
				panic("assembler invariant violated")
			}
			if a.num >= len(a.holes) {
				return false, false
			}
			a.holes[a.num] = fragment{start: other.end, end: cur.end}
			a.num++
			cur.end = other.start
			a.checkInvariants()
			return true, true
		}
		changed = changed || ch
		if cur.isEmpty() {
			a.num--
			*cur = a.holes[a.num]
			a.holes[a.num] = fragment{} // help in debugging
			a.checkInvariants()
			continue
		}
		index++
	}
	return true, changed
}
