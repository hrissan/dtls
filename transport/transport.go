package transport

import (
	"log"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/hrissan/tinydtls/keys"
	"github.com/hrissan/tinydtls/transport/handshake"
	"github.com/hrissan/tinydtls/transport/options"
	"github.com/hrissan/tinydtls/transport/receiver"
	"github.com/hrissan/tinydtls/transport/sender"
)

type Transport struct {
	opts *options.TransportOptions

	snd *sender.Sender
	rc  *receiver.Receiver

	handshakesConnectionsMu sync.RWMutex
	// TODO - limit on max number of parallel handshakes, clear items by LRU
	// only ClientHello with correct cookie and larger timestamp replaces previous handshake here [rfc9147:5.11]
	// handshakes map[netip.AddrPort]*HandshakeContext

	// we move handshake here, once it is finished
	connections map[netip.AddrPort]*Connection
}

func NewTransport(opts *options.TransportOptions) *Transport {
	log.Printf(
		`Connection object size: %d
Handshake object size: %d
Keys size: %d
Directional Keys size: %d
Symmetric Keys size: %d`,
		unsafe.Sizeof(handshake.ConnectionImpl{}),
		unsafe.Sizeof(handshake.HandshakeConnection{}),
		unsafe.Sizeof(keys.Keys{}),
		unsafe.Sizeof(keys.DirectionKeys{}),
		unsafe.Sizeof(keys.SymmetricKeys{}))
	snd := sender.NewSender(opts)
	rc := receiver.NewReceiver(opts, snd)
	t := &Transport{
		opts:        opts,
		snd:         snd,
		rc:          rc,
		connections: map[netip.AddrPort]*Connection{},
	}
	return t
}

// socket must be closed by socket owner (externally)
func (t *Transport) Close() {
	t.rc.Close()
	t.snd.Close()
}

func (t *Transport) StartConnection(peerAddr netip.AddrPort) error {
	return t.rc.StartConnection(peerAddr)
}

// blocks until socket is closed (externally)
func (t *Transport) GoRunUDP(socket *net.UDPConn) {
	ch := make(chan struct{})
	go func() {
		t.snd.GoRunUDP(socket)
		ch <- struct{}{}
	}()
	t.rc.GoRunUDP(socket)
	<-ch
}

// for tests and tools
func OpenSocketMust(addressPort string) *net.UDPConn {
	udpAddr, err := net.ResolveUDPAddr("udp", addressPort)
	if err != nil {
		log.Fatalf("tinydtls: cannot resolve local udp address %s: %v", addressPort, err)
	}
	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("tinydtls: cannot listen to udp address %s: %v", addressPort, err)
	}
	log.Printf("tinydtls: opened socket for address %s localAddr %s\n", addressPort, socket.LocalAddr().String())
	return socket
}
