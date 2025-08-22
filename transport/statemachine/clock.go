// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"sync"
	"time"

	"github.com/hrissan/dtls/intrusive"
	"github.com/hrissan/dtls/transport/options"
)

type Clock struct {
	mu       sync.Mutex
	cond     chan struct{}
	shutdown bool

	timers intrusive.IntrusiveHeap[Connection]
}

func timerHeapPred(a, b *Connection) bool {
	return a.FireTimeUnixNano < b.FireTimeUnixNano
}

func NewClock(opts *options.TransportOptions) *Clock {
	cl := &Clock{cond: make(chan struct{})}

	if opts.Preallocate {
		cl.timers = *intrusive.NewIntrusiveHeap(timerHeapPred, opts.MaxConnections)
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
		var conn *Connection
		if cl.timers.Len() != 0 {
			conn = cl.timers.Front()
			fireDur = time.Duration(conn.FireTimeUnixNano - time.Now().UnixNano())
			if fireDur <= 0 {
				conn.FireTimeUnixNano = 0
				cl.timers.PopFront()
			}
		}
		shutdown := cl.shutdown
		cl.mu.Unlock()
		if shutdown {
			return
		}
		if conn == nil {
			<-cl.cond
			continue
		}
		if fireDur <= 0 {
			conn.OnTimer()
			continue
		}
		t.Reset(fireDur)
		select {
		case <-t.C:
			break
		case <-cl.cond:
			if t.Stop() {
				<-t.C
			}
			continue
		}
	}
}

func (cl *Clock) StopTimer(conn *Connection) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.timers.Erase(conn, &conn.TimerHeapIndex)
	conn.FireTimeUnixNano = 0
}

func (cl *Clock) SetTimer(conn *Connection, deadline time.Time) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	fireTimeUnixNano := deadline.UnixNano()
	if fireTimeUnixNano >= conn.FireTimeUnixNano {
		// for applications which have watchdog timers per connection,
		// which they reset/move forward on each packet.
		// we will not touch heap, timer will fire, where user will have to
		// compare with his deadline, and set timer again
		return
	}
	// TODO - 1 heap rebalance instead of 2
	cl.timers.Erase(conn, &conn.TimerHeapIndex)
	conn.FireTimeUnixNano = deadline.UnixNano()
	cl.timers.Insert(conn, &conn.TimerHeapIndex)
	if cl.timers.Front() == conn { // we do not care if it was not in front position before erase
		cl.signal()
	}
}
