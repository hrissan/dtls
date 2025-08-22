// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package receiver

import (
	"crypto/sha256"
	"log"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/transport/statemachine"
)

func (rc *Receiver) receivedClientHello(conn *statemachine.ConnectionImpl, msg handshake.Message, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	if !rc.opts.RoleServer {
		rc.opts.Stats.ErrorClientReceivedClientHello(addr)
		return conn, dtlserrors.ErrClientHelloReceivedByClient
	}
	var msgClientHello handshake.MsgClientHello
	if err := msgClientHello.Parse(msg.Body); err != nil {
		return conn, dtlserrors.WarnPlaintextClientHelloParsing
	}
	// rc.opts.Stats.ClientHelloMessage(msg.Header, msgClientHello, addr)

	if err := IsSupportedClientHello(&msgClientHello); err != nil {
		return conn, err
	}
	// ClientHello is stateless, so we cannot check record sequence number.
	// If client follows protocol and sends the same client hello,
	// we will reply with the same server hello.
	// so, setting record sequence number to 0 equals to retransmission of the same message
	if !msgClientHello.Extensions.CookieSet {
		if msg.MsgSeq != 0 {
			return conn, dtlserrors.ErrClientHelloUnsupportedParams
		}
		transcriptHasher := sha256.New()
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
		hrrDatagram, _ := statemachine.GenerateStatelessHRR((*hrrStorage)[:0], ck, keyShareSet)
		if len(hrrDatagram) > len(*hrrStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram)
		log.Printf("serverHRRHash1: %x\n", hrrHash[:])
		rc.snd.SendHelloRetryDatagram(hrrStorage, len(hrrDatagram), addr)
		return conn, nil
	}
	if msg.MsgSeq != 1 {
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
	// we should check all parameters above, so that we do not create connection for unsupported params
	if conn == nil {
		rc.connectionsMu.Lock()
		// TODO - get from pool
		conn = statemachine.NewServerConnection(addr)
		rc.connections[addr] = conn
		rc.connectionsMu.Unlock()
	}
	if err := conn.ReceivedClientHello2(rc.opts, msg, msgClientHello, initialHelloTranscriptHash, keyShareSet); err != nil {
		return conn, err // TODO - close connection here
	}
	rc.snd.RegisterConnectionForSend(conn)
	return conn, nil
}

func IsSupportedClientHello(msgParsed *handshake.MsgClientHello) error {
	if !msgParsed.Extensions.SupportedVersions.DTLS_13 {
		return dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if !msgParsed.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 {

		return dtlserrors.ErrParamsSupportCiphersuites
	}
	if !msgParsed.Extensions.SupportedGroups.X25519 {
		return dtlserrors.ErrParamsSupportKeyShare
	}
	return nil
}
