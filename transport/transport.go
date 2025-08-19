package transport

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/hrissan/tinydtls/keys"
	"github.com/hrissan/tinydtls/transport/options"
	"github.com/hrissan/tinydtls/transport/receiver"
	"github.com/hrissan/tinydtls/transport/sender"
	"github.com/hrissan/tinydtls/transport/statemachine"
)

type Transport struct {
	opts *options.TransportOptions

	snd *sender.Sender
	rc  *receiver.Receiver

	handshakesConnectionsMu sync.RWMutex
	// only ClientHello with correct cookie and larger timestamp replaces previous handshake here [rfc9147:5.11]
	// handshakes map[netip.AddrPort]*HandshakeContext

	// we move handshake here, once it is finished
	connections map[netip.AddrPort]*Connection
}

func NewTransport(opts *options.TransportOptions) *Transport {
	fmt.Printf(
		`Sizeof(various objects):
Handshake:        %d (+large buffers for message reassembly, released after successful handshake)
Connection:       %d (+960 bytes (+480 if using plaintext sequence numbers) in AES contexts)
Keys:             %d (part of Connection, contain pair of Directional Keys + Symmetric Keys for next receiving epoch)
Directional Keys: %d (Contain Symmetric Keys + Secrets for key update) 
Symmetric Keys:   %d (For TLS_AES_128_GCM_SHA256)
`,
		unsafe.Sizeof(statemachine.HandshakeConnection{}),
		unsafe.Sizeof(statemachine.ConnectionImpl{}),
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
