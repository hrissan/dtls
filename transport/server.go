package transport

import (
	"crypto/sha256"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/format"
)

type Server struct {
	t *Transport
}

func NewServer(opts TransportOptions, stats Stats, rnd dtlsrand.Rand, socket *net.UDPConn) *Server {
	t := NewTransport(opts, stats, rnd, socket)
	s := &Server{t: t}
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
var ErrClientHelloWithoutCookieMsgSeqNum = errors.New("client hello without cookie must have msg_seq_num 0")
var ErrClientHelloWithCookieMsgSeqNum = errors.New("client hello with cookie must have msg_seq_num 1")

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
	return nil
}

func (t *Transport) OnClientHello(messageData []byte, handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort) {
	if err := IsSupportedClientHello(&msg); err != nil {
		t.stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, err)
		// TODO - generate alert
		return
	}
	if !msg.Extensions.CookieSet {
		if handshakeHdr.MessageSeq != 0 {
			t.stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithoutCookieMsgSeqNum)
			// TODO - generate alert
			return
		}
		transcriptHasher := sha256.New()
		_, _ = transcriptHasher.Write(messageData[:4])
		_, _ = transcriptHasher.Write(messageData[12:])
		var transcriptHash [cookie.MaxTranscriptHashLength]byte
		transcriptHasher.Sum(transcriptHash[:0])

		datagram, ok := t.popHelloRetryDatagram()
		if !ok {
			t.stats.ServerHelloRetryRequestQueueOverloaded(addr)
			// Prohibited sending alert here
			return
		}
		t.stats.CookieCreated(addr)
		helloRetryRequest := format.ServerHello{
			Random:      [32]byte{},
			CipherSuite: format.CypherSuite_TLS_AES_128_GCM_SHA256,
		}
		helloRetryRequest.SetHelloRetryRequest()
		helloRetryRequest.Extensions.SupportedVersionsSet = true
		helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = format.DTLS_VERSION_13
		helloRetryRequest.Extensions.CookieSet = true
		helloRetryRequest.Extensions.Cookie = t.cookieState.CreateCookie(transcriptHash, addr, time.Now())
		if !msg.Extensions.KeyShare.X25519PublicKeySet {
			helloRetryRequest.Extensions.KeyShareSet = true
			helloRetryRequest.Extensions.KeyShare.KeyShareHRRSelectedGroup = format.SupportedGroup_X25519
		}
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
		t.SendHelloRetryDatagram(datagram, addr)
		return
	}
	if handshakeHdr.MessageSeq != 1 {
		t.stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithCookieMsgSeqNum)
		// TODO - generate alert
		return
	}
	if !msg.Extensions.KeyShare.X25519PublicKeySet {
		// we asked for this key_share above, but client disrespected our demand
		t.stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrSupportOnlyX25519)
		// TODO - generate alert
		return
	}
	valid, age, tanscriptHash := t.cookieState.IsCookieValid(addr, msg.Extensions.Cookie, time.Now())
	if age > t.options.CookieValidDuration {
		valid = false
	}
	t.stats.CookieChecked(valid, age, addr)
	if !valid {
		// generate alert
		return
	}
	log.Printf("start handshake transcript_hash(hex): %x", tanscriptHash)
	hctx, ok := t.handshakes[addr]
	if !ok {
		hctx = &HandshakeContext{
			LastActivity:          time.Now(),
			ServerRandom:          [32]byte{},
			NextMessageSeqReceive: 0,
			NextMessageSeqSend:    0,
		}
		t.handshakes[addr] = hctx
	}
	// TODO - start Handshake
}

func (t *Transport) OnServerHello(messageData []byte, handshakeHdr format.MessageHandshakeHeader, msg format.ServerHello, addr netip.AddrPort) {
	t.stats.ErrorServerReceivedServerHello(addr)
	// TODO - send alert
}
