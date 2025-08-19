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

// [rfc9147:4.4]
const MinimumPMTUv4 = 576 - 8 - 20  // minus UDP header, minus IPv4 header
const MinimumPMTUv6 = 1280 - 8 - 40 // minus UDP header, minus IPv6 header

type OutgoingHRR struct {
	data *[constants.MaxOutgoingHRRDatagramLength]byte
	size int
	addr netip.AddrPort
}

type Sender struct {
	opts *options.TransportOptions

	mu       sync.Mutex
	cond     *sync.Cond
	shutdown bool

	// hello retry request is stateless.
	// we limit (options.HelloRetryQueueSize) how many such datagrams we wish to store
	helloRetryQueue circular.Buffer[OutgoingHRR]
	helloRetryPool  []*[constants.MaxOutgoingHRRDatagramLength]byte // stack, not circular buffer

	wantToWriteQueue circular.Buffer[*statemachine.ConnectionImpl]
}

func NewSender(opts *options.TransportOptions) *Sender {
	snd := &Sender{
		opts: opts,
	}
	snd.cond = sync.NewCond(&snd.mu)

	if opts.Preallocate {
		snd.helloRetryQueue.Reserve(opts.MaxHelloRetryQueueSize)
		snd.helloRetryPool = make([]*[constants.MaxOutgoingHRRDatagramLength]byte, 0, opts.MaxHelloRetryQueueSize)
		snd.wantToWriteQueue.Reserve(opts.MaxConnections)
	}
	return snd
}

// socket must be closed by socket owner (externally)
func (snd *Sender) Close() {
	snd.mu.Lock()
	defer snd.mu.Unlock()
	snd.shutdown = true
	snd.cond.Broadcast()
}

// blocks until socket is closed (externally)
func (snd *Sender) GoRunUDP(socket *net.UDPConn) {
	datagram := make([]byte, 65536)
	snd.mu.Lock()
	for {
		if !(snd.shutdown || snd.helloRetryQueue.Len() != 0 || snd.wantToWriteQueue.Len() != 0) {
			snd.cond.Wait()
		}
		// if we wish, we can make different ratio between sending from different queues
		hrr, _ := snd.helloRetryQueue.TryPopFront()
		conn, _ := snd.wantToWriteQueue.TryPopFront()
		if conn != nil {
			conn.InSenderQueue = false
		}
		sendShutdown := snd.shutdown
		snd.mu.Unlock()
		if sendShutdown {
			return
		}
		if hrr.data != nil && !snd.sendDatagram(socket, (*hrr.data)[:hrr.size], hrr.addr) {
			return
		}
		datagramSize := 0
		addToSendQueue := false
		if conn != nil {
			datagramSize, addToSendQueue = conn.ConstructDatagram(datagram[:MinimumPMTUv4])
			if datagramSize == 0 && addToSendQueue {
				panic("ConstructDatagram invariant violation")
			}
			if datagramSize != 0 {
				if !snd.sendDatagram(socket, datagram[:datagramSize], conn.Addr) {
					// TODO - rare log
				}
			}
		}
		snd.mu.Lock()
		if hrr.data != nil {
			snd.helloRetryPool = append(snd.helloRetryPool, hrr.data)
		}
		if addToSendQueue {
			if !conn.InSenderQueue {
				conn.InSenderQueue = true
				snd.wantToWriteQueue.PushBack(conn)
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
	t.mu.Lock()
	defer t.mu.Unlock()
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
	snd.mu.Lock()
	defer snd.mu.Unlock()
	snd.helloRetryQueue.PushBack(OutgoingHRR{data: data, size: size, addr: addr})
	snd.cond.Signal()
}

func (snd *Sender) RegisterConnectionForSend(hctx *statemachine.ConnectionImpl) {
	snd.mu.Lock()
	defer snd.mu.Unlock()
	if hctx.InSenderQueue {
		return
	}
	hctx.InSenderQueue = true
	snd.wantToWriteQueue.PushBack(hctx)
	snd.cond.Signal()
}
