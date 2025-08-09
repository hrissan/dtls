package transport

import (
	"log"
	"net/netip"
	"sync/atomic"

	"github.com/hrissan/tinydtls/format"
)

type Stats interface {
	SocketReadError(n int, addr netip.AddrPort, err error)
	// kind: plaintext, ciphertext, unknown
	BadRecord(kind string, recordOffset int, datagramLen int, addr netip.AddrPort, err error)
	// kind: handshake, ack, alert, etc.
	BadMessageHeader(kind string, messageOffset int, recordLen int, addr netip.AddrPort, err error)
	// kind: handshake, ack, alert, etc.
	// message: client_hello, server_hello, etc.
	BadMessage(kind string, message string, addr netip.AddrPort, err error)
	MustNotBeFragmented(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader)
	MustBeEncrypted(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader)
}

type StatsLog struct {
	level atomic.Int32
}

func (s *StatsLog) SocketReadError(n int, addr netip.AddrPort, err error) {
	if s.level.Load() <= 0 {
		return
	}
	log.Printf("dtls: socket read error n=%d addr=%v: %v", n, addr, err)
}

func (s *StatsLog) BadRecord(kind string, recordOffset int, datagramLen int, addr netip.AddrPort, err error) {
	if s.level.Load() <= 0 {
		return
	}
	log.Printf("dtls: bad %s record offset=%d/%d addr=%v: %v", kind, recordOffset, datagramLen, addr, err)
}

func (s *StatsLog) BadMessageHeader(kind string, messageOffset int, recordLen int, addr netip.AddrPort, err error) {
	if s.level.Load() <= 0 {
		return
	}
	log.Printf("dtls: bad %s message header offset=%d/%d addr=%v: %v", kind, messageOffset, recordLen, addr, err)
}

func (s *StatsLog) BadMessage(kind string, message string, addr netip.AddrPort, err error) {
	if s.level.Load() <= 0 {
		return
	}
	log.Printf("dtls: bad %s %s message addr=%v: %v", kind, message, addr, err)
}

func (s *StatsLog) MustNotBeFragmented(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader) {
	if s.level.Load() <= 0 {
		return
	}
	log.Printf("dtls: message %s %s must not be fragmented %v addr=%v", kind, message, header, addr)
}

func (s *StatsLog) MustBeEncrypted(kind string, message string, addr netip.AddrPort, header format.MessageHandshakeHeader) {
	if s.level.Load() <= 0 {
		return
	}
	log.Printf("dtls: message %s %s must be encrypted %v addr=%v", kind, message, header, addr)
}
