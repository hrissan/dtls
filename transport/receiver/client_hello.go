package receiver

import (
	"crypto/sha256"
	"errors"
	"log"
	"net/netip"
	"time"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/transport/statemachine"
)

func (rc *Receiver) OnClientHello(conn *statemachine.ConnectionImpl, fragment handshake.Fragment, msgClientHello handshake.MsgClientHello, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	if !rc.opts.RoleServer {
		rc.opts.Stats.ErrorClientReceivedClientHello(addr)
		return conn, dtlserrors.ErrClientHelloReceivedByClient
	}

	if err := IsSupportedClientHello(&msgClientHello); err != nil {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(fragment.Header, msgClientHello, addr, err)
		return conn, err
	}
	// ClientHello is stateless, so we cannot check record sequence number.
	// If client follows protocol and sends the same client hello,
	// we will reply with the same server hello.
	// so, setting record sequence number to 0 equals to retransmission of the same message
	if !msgClientHello.Extensions.CookieSet {
		if fragment.Header.MsgSeq != 0 {
			rc.opts.Stats.ErrorClientHelloUnsupportedParams(fragment.Header, msgClientHello, addr, ErrClientHelloWithoutCookieMsgSeqNum)
			return conn, dtlserrors.ErrClientHelloUnsupportedParams
		}
		transcriptHasher := sha256.New()
		msg := handshake.Message{
			MsgType: fragment.Header.MsgType,
			MsgSeq:  fragment.Header.MsgSeq,
			Body:    fragment.Body,
		}
		msg.AddToHash(transcriptHasher)

		var initialHelloTranscriptHash [constants.MaxHashLength]byte
		transcriptHasher.Sum(initialHelloTranscriptHash[:0])

		keyShareSet := !msgClientHello.Extensions.KeyShare.X25519PublicKeySet
		ck := rc.cookieState.CreateCookie(initialHelloTranscriptHash, keyShareSet, addr, time.Now())
		rc.opts.Stats.CookieCreated(addr)

		hrrStorage := rc.snd.PopHelloRetryDatagramStorage()
		if hrrStorage == nil {
			return conn, dtlserrors.ErrServerHelloRetryRequestQueueFull
		}
		hrrDatagram := statemachine.GenerateStatelessHRR((*hrrStorage)[:0], ck, keyShareSet)
		if len(hrrDatagram) > len(*hrrStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram)
		log.Printf("serverHRRHash1: %x\n", hrrHash[:])
		rc.snd.SendHelloRetryDatagram(hrrStorage, len(hrrDatagram), addr)
		return conn, nil
	}
	if fragment.Header.MsgSeq != 1 {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(fragment.Header, msgClientHello, addr, ErrClientHelloWithCookieMsgSeqNum)
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	if !msgClientHello.Extensions.KeyShare.X25519PublicKeySet {
		// we asked for this key_share above, but client disrespected our demand
		return conn, dtlserrors.ErrParamsSupportKeyShare
	}
	valid, age, initialHelloTranscriptHash, keyShareSet := rc.cookieState.IsCookieValid(addr, msgClientHello.Extensions.Cookie, time.Now())
	if !valid {
		rc.opts.Stats.CookieChecked(false, age, addr)
		return conn, dtlserrors.ErrClientHelloCookieInvalid
	}
	if age > rc.opts.CookieValidDuration {
		rc.opts.Stats.CookieChecked(false, age, addr)
		return conn, dtlserrors.ErrClientHelloCookieAge
	}

	if conn == nil {
		conn = &statemachine.ConnectionImpl{
			Addr:       addr,
			RoleServer: true,
			Handshake:  nil, // will be set below
		}
		rc.handMu.Lock()
		rc.connections[addr] = conn
		rc.handMu.Unlock()
	}
	if err := conn.ReceivedClientHello2(rc.opts, fragment, msgClientHello, initialHelloTranscriptHash, keyShareSet); err != nil {
		return conn, err // TODO - close connection here
	}
	rc.snd.RegisterConnectionForSend(conn)
	return conn, nil
}

var ErrClientHelloWithoutCookieMsgSeqNum = errors.New("client hello without cookie must have msg_seq_num 0")
var ErrClientHelloWithCookieMsgSeqNum = errors.New("client hello with cookie must have msg_seq_num 1")

func IsSupportedClientHello(msg *handshake.MsgClientHello) error {
	if !msg.Extensions.SupportedVersions.DTLS_13 {
		return dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if !msg.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 {

		return dtlserrors.ErrParamsSupportCiphersuites
	}
	if !msg.Extensions.SupportedGroups.X25519 {
		return dtlserrors.ErrParamsSupportKeyShare
	}
	return nil
}
