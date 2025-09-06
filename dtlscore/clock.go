// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"sync"
	"time"

	"github.com/hrissan/dtls/intrusive"
)

type Timer struct {
	// intrusive, must not be changed except by clock, protected by clock mutex
	timerHeapIndex int
	// time.Time object is larger and also has complicated comparison,
	// which might be invalid as a heap predicate
	fireTimeUnixNano int64

	fireFunc func(timer *Timer)
}

type Clock struct {
	mu       sync.Mutex
	cond     chan struct{}
	shutdown bool

	timers intrusive.IntrusiveHeap[Timer]
}

func timerHeapPred(a, b *Timer) bool {
	return a.fireTimeUnixNano < b.fireTimeUnixNano
}

func NewClock(preallocate bool, maxTimers int) *Clock {
	cl := &Clock{cond: make(chan struct{})}

	if preallocate {
		cl.timers = *intrusive.NewIntrusiveHeap(timerHeapPred, maxTimers)
	} else {
		cl.timers = *intrusive.NewIntrusiveHeap(timerHeapPred, 0)
	}
	return cl
}

func (cl *Clock) signal() {
	select {
	case cl.cond <- struct{}{}:
	default:
	}
}

func (cl *Clock) Close() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.shutdown = true
	cl.signal()
}

// blocks until Close() called
func (cl *Clock) GoRun() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	if t.Stop() {
		<-t.C
	}
	for {
		cl.mu.Lock()
		var fireDur time.Duration
		var timer *Timer
		if cl.timers.Len() != 0 {
			timer = cl.timers.Front()
			fireDur = time.Duration(timer.fireTimeUnixNano - time.Now().UnixNano())
			if fireDur <= 0 {
				timer.fireTimeUnixNano = 0
				cl.timers.PopFront()
			}
		}
		shutdown := cl.shutdown
		cl.mu.Unlock()
		if shutdown {
			return
		}
		if timer == nil {
			<-cl.cond
			continue
		}
		if fireDur <= 0 {
			timer.fireFunc(timer)
			continue
		}
		t.Reset(fireDur)
		select {
		case <-t.C:
		case <-cl.cond:
			if t.Stop() {
				<-t.C
			}
		}
	}
}

func (cl *Clock) StopTimer(timer *Timer) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.timers.Erase(timer, &timer.timerHeapIndex)
	timer.fireTimeUnixNano = 0
}

func (cl *Clock) SetTimer(timer *Timer, deadline time.Time) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	fireTimeUnixNano := deadline.UnixNano()
	if fireTimeUnixNano >= timer.fireTimeUnixNano {
		// for applications which have watchdog timers per connection,
		// which they reset/move forward on each packet.
		// we will not touch heap, timer will fire, where user will have to
		// compare with his deadline, and set timer again
		return
	}
	// TODO - 1 heap rebalance instead of 2
	cl.timers.Erase(timer, &timer.timerHeapIndex)
	timer.fireTimeUnixNano = deadline.UnixNano()
	cl.timers.Insert(timer, &timer.timerHeapIndex)
	if cl.timers.Front() == timer { // we do not care if it was not in front position before erase
		cl.signal()
	}
}
