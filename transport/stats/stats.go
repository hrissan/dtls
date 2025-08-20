package stats

import (
	"log"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/hrissan/dtls/handshake"
)

// TODO - replace with tiny interface + errors from stlserrors
type Stats interface {
	Warning(addr netip.AddrPort, err error)

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
	MustNotBeFragmented(kind string, message string, addr netip.AddrPort, header handshake.FragmentHeader)
	MustBeEncrypted(kind string, message string, addr netip.AddrPort, header handshake.FragmentHeader)
	MustNotBeEncrypted(kind string, message string, addr netip.AddrPort, header handshake.FragmentHeader)

	// logic layer
	ErrorServerReceivedServerHello(addr netip.AddrPort)
	ErrorClientReceivedClientHello(addr netip.AddrPort)
	ErrorClientHelloUnsupportedParams(handshakeHdr handshake.FragmentHeader, msg handshake.MsgClientHello, addr netip.AddrPort, err error)
	ErrorServerHelloUnsupportedParams(handshakeHdr handshake.FragmentHeader, msg handshake.MsgServerHello, addr netip.AddrPort, err error)
	ClientHelloMessage(handshakeHdr handshake.FragmentHeader, msg handshake.MsgClientHello, addr netip.AddrPort)
	ServerHelloMessage(handshakeHdr handshake.FragmentHeader, msg handshake.MsgServerHello, addr netip.AddrPort)
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

func (s *StatsLog) Warning(addr netip.AddrPort, err error) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: warning addr=%v: %v", addr, err)
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
	if !s.printDatagrams.Load() {
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

func (s *StatsLog) MustNotBeFragmented(kind string, message string, addr netip.AddrPort, header handshake.FragmentHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: message %s %s must not be fragmented %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) MustBeEncrypted(kind string, message string, addr netip.AddrPort, header handshake.FragmentHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: message %s %s must be encrypted %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) MustNotBeEncrypted(kind string, message string, addr netip.AddrPort, header handshake.FragmentHeader) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: message %s %s must not be encrypted %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) ErrorServerReceivedServerHello(addr netip.AddrPort) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: server received server hello addr=%v", addr)
}

func (s *StatsLog) ErrorClientReceivedClientHello(addr netip.AddrPort) {
	if s.level.Load() < 0 {
		return
	}
	log.Printf("dtls: client received client hello addr=%v", addr)
}

func (s *StatsLog) ErrorClientHelloUnsupportedParams(handshakeHdr handshake.FragmentHeader, msg handshake.MsgClientHello, addr netip.AddrPort, err error) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: message %s header=%+v has unsupported params addr=%v: %+v: %v", msg.MessageName(), handshakeHdr, addr, msg, err)
}

func (s *StatsLog) ErrorServerHelloUnsupportedParams(handshakeHdr handshake.FragmentHeader, msg handshake.MsgServerHello, addr netip.AddrPort, err error) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: message %s header=%+v has unsupported params addr=%v: %+v: %v", msg.MessageName(), handshakeHdr, addr, msg, err)
}

func (s *StatsLog) ClientHelloMessage(handshakeHdr handshake.FragmentHeader, msg handshake.MsgClientHello, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: message %s header=%+v addr=%v: %+v", msg.MessageName(), handshakeHdr, addr, msg)
}

func (s *StatsLog) ServerHelloMessage(handshakeHdr handshake.FragmentHeader, msg handshake.MsgServerHello, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: message %s header=%+v addr=%v: %+v", msg.MessageName(), handshakeHdr, addr, msg)
}

func (s *StatsLog) ServerHelloRetryRequestQueueOverloaded(addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: server hello retry request queue size overloaded addr=%v", addr)
}

func (s *StatsLog) CookieCreated(addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: cookie created for addr=%v", addr)
}

func (s *StatsLog) CookieChecked(valid bool, age time.Duration, addr netip.AddrPort) {
	if !s.printMessages.Load() {
		return
	}
	log.Printf("dtls: cookie checked valid=%v age=%v for addr=%v", valid, age, addr)
}
