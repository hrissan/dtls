// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package transport

import (
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/hrissan/dtls/transport/options"
	"github.com/hrissan/dtls/transport/receiver"
	"github.com/hrissan/dtls/transport/sender"
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
		log.Fatalf("dtls: cannot resolve local udp address %s: %v", addressPort, err)
	}
	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("dtls: cannot listen to udp address %s: %v", addressPort, err)
	}
	log.Printf("dtls: opened socket for address %s localAddr %s\n", addressPort, socket.LocalAddr().String())
	return socket
}
