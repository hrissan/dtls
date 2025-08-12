package sender

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/transport/handshake"
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
	helloRetryQueue circular.Buffer[OutgoingDatagram]
	helloRetryPool  [][]byte

	handshakeQueue circular.Buffer[*handshake.HandshakeConnection]
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
	defer snd.sendMu.Unlock()
	snd.sendShutdown = true
	snd.sendCond.Broadcast()
}

// blocks until socket is closed (externally)
func (snd *Sender) GoRunUDP(socket *net.UDPConn) {
	datagram := make([]byte, 65536)
	snd.sendMu.Lock()
	for {
		if !(snd.sendShutdown || snd.helloRetryQueue.Len() != 0 || snd.handshakeQueue.Len() != 0) {
			snd.sendCond.Wait()
		}
		// if we wish, we can make different ratio between sending from different queues
		var hrr OutgoingDatagram
		if snd.helloRetryQueue.Len() != 0 {
			hrr = snd.helloRetryQueue.PopFront()
		}
		var hctx *handshake.HandshakeConnection
		if snd.handshakeQueue.Len() != 0 {
			hctx = snd.handshakeQueue.PopFront()
			hctx.InSenderQueue = false
		}
		sendShutdown := snd.sendShutdown
		snd.sendMu.Unlock()
		if sendShutdown {
			return
		}
		if len(hrr.data) != 0 && !snd.sendDatagram(socket, hrr.data, hrr.addr) {
			return
		}
		datagramSize := 0
		addToSendQueue := false
		if hctx != nil {
			datagramSize, addToSendQueue = hctx.ConstructDatagram(datagram)
			if datagramSize != 0 && !snd.sendDatagram(socket, datagram[:datagramSize], hctx.Addr) {
				return
			}
			if datagramSize == 0 && addToSendQueue {
				panic("ConstructDatagram invariant violation")
			}
		}
		snd.sendMu.Lock()
		if len(hrr.data) != 0 {
			snd.helloRetryPool = append(snd.helloRetryPool, hrr.data)
		}
		if addToSendQueue {
			if !hctx.InSenderQueue {
				hctx.InSenderQueue = true
				snd.handshakeQueue.PushBack(hctx)
			}
		}
	}
}

// returns false if socket closed
func (snd *Sender) sendDatagram(socket *net.UDPConn, data []byte, addr netip.AddrPort) bool {
	snd.opts.Stats.SocketWriteDatagram(data, addr)
	n, err := socket.WriteToUDPAddrPort(data, addr)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return false
		}
		snd.opts.Stats.SocketWriteError(n, addr, err)
		time.Sleep(snd.opts.SocketWriteErrorDelay)
	}
	return true
}

func (t *Sender) PopHelloRetryDatagram() ([]byte, bool) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if t.helloRetryQueue.Len() >= t.opts.HelloRetryQueueMaxSize {
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
	snd.helloRetryQueue.PushBack(OutgoingDatagram{data: datagram, addr: addr})
	snd.sendCond.Signal()
}

func (snd *Sender) RegisterConnectionForSend(hctx *handshake.HandshakeConnection) {
	snd.sendMu.Lock()
	defer snd.sendMu.Unlock()
	if hctx.InSenderQueue {
		return
	}
	hctx.InSenderQueue = true
	snd.handshakeQueue.PushBack(hctx)
	snd.sendCond.Signal()
}
