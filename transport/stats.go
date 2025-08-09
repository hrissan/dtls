package transport

import (
	"log"
	"net/netip"
	"sync/atomic"

	"github.com/hrissan/tinydtls/format"
)

type Stats interface {
	// transport layer
	SocketReadError(n int, addr netip.AddrPort, err error)
	SocketWriteError(n int, addr netip.AddrPort, err error)
	SocketReadDatagram(datagram []byte, addr netip.AddrPort)
	SocketWriteDatagram(datagram []byte, addr netip.AddrPort)

	// record layer
	// kind: plaintext, ciphertext, unknown
	BadRecord(kind string, recordOffset int, datagramLen int, addr netip.AddrPort, err error)
	// kind: handshake, ack, alert, etc.

	// message layer
	BadMessageHeader(kind string, messageOffset int, recordLen int, addr netip.AddrPort, err error)
	// kind: handshake, ack, alert, etc.
	// message: client_hello, server_hello, etc.
	BadMessage(kind string, message string, addr netip.AddrPort, err error)
	MustNotBeFragmented(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader)
	MustBeEncrypted(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader)

	// logic layer
	ClientHelloMessage(msg format.ClientHello, addr netip.AddrPort)
	ServerHelloMessage(msg format.ServerHello, addr netip.AddrPort)
	ServerReceivedServerHello(addr netip.AddrPort)
}

type StatsLog struct {
	level          atomic.Int32
	printDatagrams atomic.Bool
	printMessages  atomic.Bool
}

func NewStatsLogVerbose() *StatsLog {
	s := &StatsLog{}
	s.level.Store(1)
	s.printDatagrams.Store(true)
	s.printMessages.Store(true)
	return s
}

func (s *StatsLog) SocketReadError(n int, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: socket read error n=%d addr=%v: %v", n, addr, err)
}

func (s *StatsLog) SocketWriteError(n int, addr netip.AddrPort, err error) {
	if !s.printDatagrams.Load() {
		return
	}
	log.Printf("dtls: socket write error n=%d addr=%v: %v", n, addr, err)
}

func (s *StatsLog) SocketReadDatagram(datagram []byte, addr netip.AddrPort) {
	if !s.printDatagrams.Load() {
		return
	}
	log.Printf("dtls: socket read %d bytes from addr=%v hex(datagram): %x", len(datagram), addr, datagram)
}

func (s *StatsLog) SocketWriteDatagram(datagram []byte, addr netip.AddrPort) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: socket write %d bytes from addr=%v hex(datagram): %x", len(datagram), addr, datagram)
}

func (s *StatsLog) BadRecord(kind string, recordOffset int, datagramLen int, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: bad %s record offset=%d/%d addr=%v: %v", kind, recordOffset, datagramLen, addr, err)
}

func (s *StatsLog) BadMessageHeader(kind string, messageOffset int, recordLen int, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: bad %s message header offset=%d/%d addr=%v: %v", kind, messageOffset, recordLen, addr, err)
}

func (s *StatsLog) BadMessage(kind string, message string, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: bad %s %s message addr=%v: %v", kind, message, addr, err)
}

func (s *StatsLog) MustNotBeFragmented(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: message %s %s must not be fragmented %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) MustBeEncrypted(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: message %s %s must be encrypted %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) ServerReceivedServerHello(addr netip.AddrPort) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: server received server hello addr=%v", addr)
}

func (s *StatsLog) ClientHelloMessage(msg format.ClientHello, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: message %s addr=%v: %v", msg.MessageName(), addr, msg)
}

func (s *StatsLog) ServerHelloMessage(msg format.ServerHello, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: message %s addr=%v: %v", msg.MessageName(), addr, msg)
}
