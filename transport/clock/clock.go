package clock

import (
	"sync"
	"time"

	"github.com/hrissan/tinydtls/intrusive"
	"github.com/hrissan/tinydtls/transport/handshake"
	"github.com/hrissan/tinydtls/transport/options"
)

type Clock struct {
	sendMu   sync.Mutex
	sendCond chan struct{}
	shutdown bool

	// hello retry request is stateless.
	// we limit (options.HelloRetryQueueSize) how many such datagrams we wish to store
	timers *intrusive.IntrusiveHeap[handshake.ConnectionImpl]
}

func heapPred(a, b *handshake.ConnectionImpl) bool {
	return a.FireTime.After(b.FireTime)
}

func NewSender(opts *options.TransportOptions) *Clock {
	cl := &Clock{sendCond: make(chan struct{})}

	if opts.Preallocate {
		cl.timers = intrusive.NewIntrusiveHeap(heapPred, opts.MaxConnections)
	} else {
		cl.timers = intrusive.NewIntrusiveHeap(heapPred, 0)
	}
	return cl
}

func (cl *Clock) signal() {
	select {
	case cl.sendCond <- struct{}{}:
	default:
	}
}

// socket must be closed by socket owner (externally)
func (cl *Clock) Close() {
	cl.sendMu.Lock()
	defer cl.sendMu.Unlock()
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
		cl.sendMu.Lock()
		var fireDur time.Duration
		var conn *handshake.ConnectionImpl
		if cl.timers.Len() != 0 {
			conn = cl.timers.Front()
			fireDur = conn.FireTime.Sub(time.Now())
			if fireDur <= 0 {
				conn.FireTime = time.Time{}
				cl.timers.PopFront()
			}
		}
		shutdown := cl.shutdown
		cl.sendMu.Unlock()
		if shutdown {
			return
		}
		if conn == nil {
			<-cl.sendCond
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
		case <-cl.sendCond:
			if t.Stop() {
				<-t.C
			}
			continue
		}
	}
}

func (cl *Clock) SetTimer(conn *handshake.ConnectionImpl, deadline time.Time) {
	cl.sendMu.Lock()
	defer cl.sendMu.Unlock()
	cl.timers.Erase(conn, &conn.TimerHeapIndex)
	conn.FireTime = deadline
	cl.timers.Insert(conn, &conn.TimerHeapIndex)
	if cl.timers.Front() == conn {
		cl.signal()
	}
}
