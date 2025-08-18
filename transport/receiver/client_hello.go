package receiver

import (
	"crypto/sha256"
	"errors"
	"log"
	"net/netip"
	"time"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/handshake"
)

func (rc *Receiver) OnClientHello(conn *handshake.ConnectionImpl, messageBody []byte, handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort) (*handshake.ConnectionImpl, error) {
	if !rc.opts.RoleServer {
		rc.opts.Stats.ErrorClientReceivedClientHello(addr)
		return conn, dtlserrors.ErrClientHelloReceivedByClient
	}

	if err := IsSupportedClientHello(&msg); err != nil {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, err)
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	// ClientHello is stateless, so we cannot check record sequence number.
	// If client follows protocol and sends the same client hello,
	// we will reply with the same server hello.
	// so, setting record sequence number to 0 equals to retransmission of the same message
	if !msg.Extensions.CookieSet {
		if handshakeHdr.MessageSeq != 0 {
			rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithoutCookieMsgSeqNum)
			return conn, dtlserrors.ErrClientHelloUnsupportedParams
		}
		transcriptHasher := sha256.New()
		handshakeHdr.AddToHash(transcriptHasher)
		_, _ = transcriptHasher.Write(messageBody)

		var initialHelloTranscriptHash [constants.MaxHashLength]byte
		transcriptHasher.Sum(initialHelloTranscriptHash[:0])

		keyShareSet := !msg.Extensions.KeyShare.X25519PublicKeySet
		ck := rc.cookieState.CreateCookie(initialHelloTranscriptHash, keyShareSet, addr, time.Now())
		rc.opts.Stats.CookieCreated(addr)

		hrrStorage := rc.snd.PopHelloRetryDatagramStorage()
		if hrrStorage == nil {
			return conn, dtlserrors.ErrServerHelloRetryRequestQueueFull
		}
		hrrDatagram := handshake.GenerateStatelessHRR((*hrrStorage)[:0], ck, keyShareSet)
		if len(hrrDatagram) > len(*hrrStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram)
		log.Printf("serverHRRHash1: %x\n", hrrHash[:])
		rc.snd.SendHelloRetryDatagram(hrrStorage, len(hrrDatagram), addr)
		return conn, nil
	}
	if handshakeHdr.MessageSeq != 1 {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithCookieMsgSeqNum)
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	if !msg.Extensions.KeyShare.X25519PublicKeySet {
		// we asked for this key_share above, but client disrespected our demand
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrSupportOnlyX25519)
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	valid, age, initialHelloTranscriptHash, keyShareSet := rc.cookieState.IsCookieValid(addr, msg.Extensions.Cookie, time.Now())
	if !valid {
		rc.opts.Stats.CookieChecked(false, age, addr)
		return conn, dtlserrors.ErrClientHelloCookieInvalid
	}
	if age > rc.opts.CookieValidDuration {
		rc.opts.Stats.CookieChecked(false, age, addr)
		return conn, dtlserrors.ErrClientHelloCookieAge
	}

	if conn == nil {
		conn = &handshake.ConnectionImpl{
			Addr:       addr,
			RoleServer: true,
			Handshake:  nil, // will be set below
		}
		rc.handMu.Lock()
		rc.connections[addr] = conn
		rc.handMu.Unlock()
	}
	if err := conn.ReceivedClientHello(rc.opts, messageBody, handshakeHdr, msg, initialHelloTranscriptHash, keyShareSet); err != nil {
		return conn, err // TODO - close connection here
	}
	rc.snd.RegisterConnectionForSend(conn)
	return conn, nil
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
