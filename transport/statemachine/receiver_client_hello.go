// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/transport/options"
)

func (t *Transport) receivedClientHello(conn *Connection, msg handshake.Message, addr netip.AddrPort) (*Connection, error) {
	var msgClientHello handshake.MsgClientHello
	var bindersListLength int
	if err := msgClientHello.Parse(msg.Body, &bindersListLength); err != nil {
		return conn, dtlserrors.WarnPlaintextClientHelloParsing
	}
	if !t.opts.RoleServer {
		t.opts.Stats.ErrorClientReceivedClientHello(addr)
		return conn, dtlserrors.ErrClientHelloReceivedByClient
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

		params := cookie.Params{
			TimestampUnixNano: time.Now().UnixNano(),
			KeyShareSet:       !msgClientHello.Extensions.KeyShare.X25519PublicKeySet,
		}
		transcriptHasher.Sum(params.TranscriptHash[:0])

		ck := t.cookieState.CreateCookie(params, addr)
		t.opts.Stats.CookieCreated(addr)

		hrrStorage := t.snd.PopHelloRetryDatagramStorage()
		if hrrStorage == nil {
			return conn, dtlserrors.ErrServerHelloRetryRequestQueueFull
		}
		hrrDatagram, _ := GenerateStatelessHRR((*hrrStorage)[:0], ck, params.KeyShareSet)
		if len(hrrDatagram) > len(*hrrStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram)
		fmt.Printf("serverHRRHash1: %x\n", hrrHash[:])
		t.snd.SendHelloRetryDatagram(hrrStorage, len(hrrDatagram), addr)
		return conn, nil
	}
	if msg.MsgSeq != 1 {
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	if !msgClientHello.Extensions.KeyShare.X25519PublicKeySet {
		// we asked for this key_share above, but client disrespected our demand
		return conn, dtlserrors.ErrParamsSupportKeyShare
	}
	params, err := t.cookieState.IsCookieValid(addr, msgClientHello.Extensions.Cookie, time.Now(), t.opts.CookieValidDuration)
	if err != nil {
		return conn, err
	}
	pskNum, identity, ok := selectPSKIdentity(t.opts, &msgClientHello.Extensions)
	if ok {
		fmt.Printf("server PSK selected identity %d (%q) binders length=%d\n", pskNum, identity.Identity, bindersListLength)
	}

	// we should check all parameters above, so that we do not create connection for unsupported params
	if conn == nil {
		var ha ConnectionHandler
		conn, ha = t.handler.OnNewConnection()
		conn.transport = t
		conn.addr = addr
		conn.roleServer = true
		conn.stateID = smIDClosed // explicit 0
		conn.handler = ha
		t.connections[addr] = conn
	}
	if err := conn.onClientHello2(t.opts, msg, msgClientHello, params); err != nil {
		// TODO - close/replace connection
		return conn, err
	}

	t.snd.RegisterConnectionForSend(conn)
	return conn, nil
}

func selectPSKIdentity(opts *options.TransportOptions, ext *handshake.ExtensionsSet) (int, handshake.PSKIdentity, bool) {
	if !ext.PskExchangeModesSet || !ext.PskExchangeModes.ECDHE ||
		!ext.PreSharedKeySet || opts.PSKAppendSecret == nil {
		return 0, handshake.PSKIdentity{}, false
	}
	for num, identity := range ext.PreSharedKey.Identities[:ext.PreSharedKey.IdentitiesSize] {
		var secretStorage [256]byte
		secret := opts.PSKAppendSecret(identity.Identity, secretStorage[:0]) // allocates if secret very long
		if len(secret) != 0 {
			return num, identity, true
		}
	}
	return 0, handshake.PSKIdentity{}, false
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

	if msgParsed.Extensions.PreSharedKeySet && !msgParsed.Extensions.PskExchangeModesSet {
		// [rfc8446:4.2.9]
		return dtlserrors.ErrPskKeyRequiresPskModes
	}
	return nil
}
