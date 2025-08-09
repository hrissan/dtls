package transport

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/format"
)

type Server struct {
	t *Transport

	cookieState cookie.CookieState
}

func NewServer(opts TransportOptions, stats Stats, socket *net.UDPConn) *Server {
	t := NewTransport(opts, stats, socket)
	s := &Server{t: t}
	s.cookieState.SetRandomSecret()
	t.OnClientHello = s.OnClientHello
	t.OnServerHello = s.OnServerHello
	return s
}

func (s *Server) Run() {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go s.t.goRead(&wg)
	go s.t.goWrite(&wg)
	wg.Wait()
}

var ErrSupportOnlyDTLS13 = errors.New("we support only DTLS 1.3")
var ErrSupportOnlyTLS_AES_128_GCM_SHA256 = errors.New("we support only TLS_AES_128_GCM_SHA256 ciphersuite for now")
var ErrSupportOnlyX25519 = errors.New("we support only X25519 key share for now")

func IsSupportedClientHello(msg *format.ClientHello) error {
	if !msg.Extensions.SupportedVersions.DTLS_13 {
		return ErrSupportOnlyDTLS13
	}
	if !msg.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 {
		return ErrSupportOnlyTLS_AES_128_GCM_SHA256
	}
	if !msg.Extensions.SupportedGroups.X25519 {
		return ErrSupportOnlyX25519
	}
	if !msg.Extensions.KeyShare.X25519PublicKeySet {
		return ErrSupportOnlyX25519
	}
	return nil
}

func (s *Server) OnClientHello(msg format.ClientHello, addr netip.AddrPort) {
	// TODO - if client KeyShare
	if err := IsSupportedClientHello(&msg); err != nil {
		s.t.stats.ErrorClientHelloUnsupportedParams(msg, addr, err)
		// TODO - generate alert
		return
	}
	if !msg.Extensions.CookieSet {
		datagram, ok := s.t.popHelloRetryDatagram()
		if !ok {
			s.t.stats.ServerHelloRetryRequestQueueOverloaded(addr)
			// Prohibited sending alert here
			return
		}
		s.t.stats.CookieCreated(addr)
		ck := s.cookieState.CreateCookie(msg.Random, addr, time.Now())
		helloRetryRequest := format.ServerHello{
			Random:      [32]byte{},
			CipherSuite: format.CypherSuite_TLS_AES_128_GCM_SHA256,
		}
		helloRetryRequest.SetHelloRetryRequest()
		helloRetryRequest.Extensions.SupportedVersionsSet = true
		helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = format.DTLS_VERSION_13
		helloRetryRequest.Extensions.CookieSet = true
		helloRetryRequest.Extensions.Cookie = ck[:] // allocation

		recordHdr := format.PlaintextRecordHeader{
			ContentType:    format.PlaintextContentTypeHandshake,
			Epoch:          0,
			SequenceNumber: 0,
		}
		msgHeader := format.MessageHandshakeHeader{
			HandshakeType:  format.HandshakeTypeServerHello,
			Length:         0,
			MessageSeq:     0,
			FragmentOffset: 0,
			FragmentLength: 0,
		}
		// first reserve space for headers by writing with not all variables set
		datagram = recordHdr.Write(datagram, 0) // reserve space
		recordHeaderSize := len(datagram)
		datagram = msgHeader.Write(datagram) // reserve space
		msgHeaderSize := len(datagram) - recordHeaderSize
		datagram = helloRetryRequest.Write(datagram)
		msgBodySize := len(datagram) - recordHeaderSize - msgHeaderSize
		msgHeader.Length = uint32(msgBodySize)
		msgHeader.FragmentLength = msgHeader.Length
		// now overwrite reserved space
		_ = recordHdr.Write(datagram[:0], msgHeaderSize+msgBodySize)
		_ = msgHeader.Write(datagram[recordHeaderSize:recordHeaderSize])
		s.t.SendHelloRetryDatagram(datagram, addr)
		return
	}
	valid := s.cookieState.IsCookieValidBytes(msg.Random, addr, msg.Extensions.Cookie)
	s.t.stats.CookieChecked(valid, addr)
	if valid {
		// TODO - start Handshake
		return
	}
	// generate alert
}

func (s *Server) OnServerHello(msg format.ServerHello, addr netip.AddrPort) {
	s.t.stats.ErrorServerReceivedServerHello(addr)
	// TODO - send alert
}
