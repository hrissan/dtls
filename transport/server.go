package transport

import (
	"crypto/rand"
	"net"
	"net/netip"
	"sync"

	"github.com/hrissan/tinydtls/format"
)

type Server struct {
	t *Transport

	cookieSecret [32]byte // [rfc9147:5.1]
}

func NewServer(opts TransportOptions, stats Stats, socket *net.UDPConn) *Server {
	t := NewTransport(opts, stats, socket)
	s := &Server{t: t}
	t.OnClientHello = s.OnClientHello
	t.OnServerHello = s.OnServerHello
	if _, err := rand.Read(s.cookieSecret[:]); err != nil {
		panic("failed to read cookie secret crypto rand: " + err.Error())
	}
	return s
}

func (s *Server) Run() {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go s.t.goRead(&wg)
	go s.t.goWrite(&wg)
	wg.Wait()
}

func (s *Server) OnClientHello(msg format.ClientHello, addr netip.AddrPort) {
	// if does not contain cookie, generate one and send HelloRetryRequest
	// otherwise, check if cookie valid, start handshake
	// otherwise send alert
}

func (s *Server) OnServerHello(msg format.ServerHello, addr netip.AddrPort) {
	s.t.stats.ServerReceivedServerHello(addr)
	// TODO - send alert
}
