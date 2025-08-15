package sender

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/circular"
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/transport/handshake"
	"github.com/hrissan/tinydtls/transport/options"
)

type OutgoingHRR struct {
	data *[constants.MaxOutgoingHRRDatagramLength]byte
	size int
	addr netip.AddrPort
}

type Sender struct {
	opts *options.TransportOptions

	sendMu       sync.Mutex
	sendCond     *sync.Cond
	sendShutdown bool

	// hello retry request is stateless.
	// we limit (options.HelloRetryQueueSize) how many such datagrams we wish to store
	helloRetryQueue circular.Buffer[OutgoingHRR]
	helloRetryPool  []*[constants.MaxOutgoingHRRDatagramLength]byte // stack, not circular buffer

	handshakeQueue circular.Buffer[*handshake.HandshakeConnection]
}

func NewSender(opts *options.TransportOptions) *Sender {
	snd := &Sender{
		opts: opts,
	}
	snd.sendCond = sync.NewCond(&snd.sendMu)

	if opts.Preallocate {
		snd.helloRetryQueue.Reserve(opts.MaxHelloRetryQueueSize)
		snd.helloRetryPool = make([]*[512]byte, 0, opts.MaxHelloRetryQueueSize)
		snd.handshakeQueue.Reserve(opts.MaxConnections)
	}
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
		var hrr OutgoingHRR
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
		if hrr.data != nil && !snd.sendDatagram(socket, (*hrr.data)[:hrr.size], hrr.addr) {
			return
		}
		datagramSize := 0
		addToSendQueue := false
		if hctx != nil {
			datagramSize, addToSendQueue = hctx.ConstructDatagram(datagram[:0])
			if datagramSize != 0 && !snd.sendDatagram(socket, datagram[:datagramSize], hctx.Addr) {
				return
			}
			if datagramSize == 0 && addToSendQueue {
				panic("ConstructDatagram invariant violation")
			}
		}
		snd.sendMu.Lock()
		if hrr.data != nil {
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

// returns nil if hello retry queue is at max capacity
func (t *Sender) PopHelloRetryDatagramStorage() *[constants.MaxOutgoingHRRDatagramLength]byte {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if t.helloRetryQueue.Len() >= t.opts.MaxHelloRetryQueueSize {
		return nil
	}
	if pos := len(t.helloRetryPool) - 1; pos >= 0 {
		result := t.helloRetryPool[pos]
		t.helloRetryPool[pos] = nil // do not leave alias
		t.helloRetryPool = t.helloRetryPool[:pos]
		return result
	}
	return &[constants.MaxOutgoingHRRDatagramLength]byte{}
}

func (snd *Sender) SendHelloRetryDatagram(data *[constants.MaxOutgoingHRRDatagramLength]byte, size int, addr netip.AddrPort) {
	if data == nil {
		panic("must be chunk previously allocated by PopHelloRetryDatagramStorage")
	}
	if size > len(*data) {
		panic("datagram size too big")
	}
	snd.sendMu.Lock()
	defer snd.sendMu.Unlock()
	snd.helloRetryQueue.PushBack(OutgoingHRR{data: data, size: size, addr: addr})
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
