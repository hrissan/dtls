package sender

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/transport/options"
)

type OutgoingDatagram struct {
	data []byte // TODO - fixed size chunks carousel
	addr netip.AddrPort
}

type Sender struct {
	opts *options.TransportOptions

	sendMu       sync.Mutex
	sendCond     *sync.Cond
	sendShutdown bool

	// hello retry request is stateless.
	// we limit (options.HelloRetryQueueSize) how many such datagrams we wish to store
	helloRetryQueue []OutgoingDatagram
	helloRetryPool  [][]byte
}

func NewSender(opts *options.TransportOptions) *Sender {
	snd := &Sender{
		opts: opts,
	}
	snd.sendCond = sync.NewCond(&snd.sendMu)
	return snd
}

// socket must be closed by socket owner (externally)
func (snd *Sender) Close() {
	snd.sendMu.Lock()
	snd.sendShutdown = true
	snd.sendMu.Unlock()
	snd.sendCond.Broadcast()
}

// blocks until socket is closed (externally)
func (snd *Sender) GoRunUDP(socket *net.UDPConn) {
	var helloRetryQueue []OutgoingDatagram
	snd.sendMu.Lock()
	for {
		if !snd.sendShutdown && len(snd.helloRetryQueue) == 0 {
			snd.sendCond.Wait()
		}
		helloRetryQueue, snd.helloRetryQueue = snd.helloRetryQueue, helloRetryQueue[:0]
		sendShutdown := snd.sendShutdown
		snd.sendMu.Unlock()
		if sendShutdown {
			return
		}
		for _, od := range helloRetryQueue {
			snd.opts.Stats.SocketWriteDatagram(od.data, od.addr)
			n, err := socket.WriteToUDPAddrPort(od.data, od.addr)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				snd.opts.Stats.SocketWriteError(n, od.addr, err)
				time.Sleep(snd.opts.SocketWriteErrorDelay)
			}
		}
		snd.sendMu.Lock()
		for i, od := range helloRetryQueue {
			snd.helloRetryPool = append(snd.helloRetryPool, od.data)
			helloRetryQueue[i] = OutgoingDatagram{}
		}
	}
}

func (t *Sender) PopHelloRetryDatagram() ([]byte, bool) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if len(t.helloRetryQueue) >= t.opts.HelloRetryQueueMaxSize {
		return nil, false
	}
	var result []byte
	if pos := len(t.helloRetryPool) - 1; pos >= 0 {
		result = t.helloRetryPool[pos][:0]
		t.helloRetryPool[pos] = nil // do not leave alias
		t.helloRetryPool = t.helloRetryPool[:pos]
	}
	return result, true
}

func (snd *Sender) SendHelloRetryDatagram(datagram []byte, addr netip.AddrPort) {
	snd.sendMu.Lock()
	defer snd.sendMu.Unlock()
	snd.helloRetryQueue = append(snd.helloRetryQueue, OutgoingDatagram{data: datagram, addr: addr})
	snd.sendCond.Signal()
}
