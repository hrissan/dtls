package stats

import (
	"log"
	"net/netip"
	"sync/atomic"
	"time"

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
	MustNotBeEncrypted(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader)

	// logic layer
	ErrorServerReceivedServerHello(addr netip.AddrPort)
	ErrorClientReceivedClientHello(addr netip.AddrPort)
	ErrorClientHelloUnsupportedParams(handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort, err error)
	ErrorServerHelloUnsupportedParams(handshakeHdr format.MessageHandshakeHeader, msg format.ServerHello, addr netip.AddrPort, err error)
	ClientHelloMessage(handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort)
	ServerHelloMessage(handshakeHdr format.MessageHandshakeHeader, msg format.ServerHello, addr netip.AddrPort)
	ServerHelloRetryRequestQueueOverloaded(addr netip.AddrPort)
	CookieCreated(addr netip.AddrPort)
	CookieChecked(valid bool, age time.Duration, addr netip.AddrPort)
}

type StatsLog struct {
	level          atomic.Int32
	printDatagrams atomic.Bool
	printMessages  atomic.Bool
}

func NewStatsLogVerbose() *StatsLog {
	s := &StatsLog{}
	s.level.Store(1)
	s.printDatagrams.Store(false)
	s.printMessages.Store(true)
	return s
}

func (s *StatsLog) SocketReadError(n int, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: socket read error n=%d addr=%v: %v", n, addr, err)
}

func (s *StatsLog) SocketWriteError(n int, addr netip.AddrPort, err error) {
	if !s.printDatagrams.Load() {
		return
	}
	log.Printf("tinydtls: socket write error n=%d addr=%v: %v", n, addr, err)
}

func (s *StatsLog) SocketReadDatagram(datagram []byte, addr netip.AddrPort) {
	if !s.printDatagrams.Load() {
		return
	}
	log.Printf("tinydtls: socket read %d bytes from addr=%v hex(datagram): %x", len(datagram), addr, datagram)
}

func (s *StatsLog) SocketWriteDatagram(datagram []byte, addr netip.AddrPort) {
	if !s.printDatagrams.Load() {
		return
	}
	log.Printf("tinydtls: socket write %d bytes from addr=%v hex(datagram): %x", len(datagram), addr, datagram)
}

func (s *StatsLog) BadRecord(kind string, recordOffset int, datagramLen int, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: bad %s record offset=%d/%d addr=%v: %v", kind, recordOffset, datagramLen, addr, err)
}

func (s *StatsLog) BadMessageHeader(kind string, messageOffset int, recordLen int, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: bad %s message header offset=%d/%d addr=%v: %v", kind, messageOffset, recordLen, addr, err)
}

func (s *StatsLog) BadMessage(kind string, message string, addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: bad %s %s message addr=%v: %v", kind, message, addr, err)
}

func (s *StatsLog) MustNotBeFragmented(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: message %s %s must not be fragmented %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) MustBeEncrypted(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: message %s %s must be encrypted %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) MustNotBeEncrypted(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: message %s %s must not be encrypted %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) ErrorServerReceivedServerHello(addr netip.AddrPort) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: server received server hello addr=%v", addr)
}

func (s *StatsLog) ErrorClientReceivedClientHello(addr netip.AddrPort) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("tinydtls: client received client hello addr=%v", addr)
}

func (s *StatsLog) ErrorClientHelloUnsupportedParams(handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort, err error) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("tinydtls: message %s header=%+v has unsupported params addr=%v: %+v: %v", msg.MessageName(), handshakeHdr, addr, msg, err)
}

func (s *StatsLog) ErrorServerHelloUnsupportedParams(handshakeHdr format.MessageHandshakeHeader, msg format.ServerHello, addr netip.AddrPort, err error) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("tinydtls: message %s header=%+v has unsupported params addr=%v: %+v: %v", msg.MessageName(), handshakeHdr, addr, msg, err)
}

func (s *StatsLog) ClientHelloMessage(handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("tinydtls: message %s header=%+v addr=%v: %+v", msg.MessageName(), handshakeHdr, addr, msg)
}

func (s *StatsLog) ServerHelloMessage(handshakeHdr format.MessageHandshakeHeader, msg format.ServerHello, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("tinydtls: message %s header=%+v addr=%v: %+v", msg.MessageName(), handshakeHdr, addr, msg)
}

func (s *StatsLog) ServerHelloRetryRequestQueueOverloaded(addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("tinydtls: server hello retry request queue size overloaded addr=%v", addr)
}

func (s *StatsLog) CookieCreated(addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("tinydtls: cookie created for addr=%v", addr)
}

func (s *StatsLog) CookieChecked(valid bool, age time.Duration, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("tinydtls: cookie checked valid=%v age=%v for addr=%v", valid, age, addr)
}
