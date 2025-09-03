// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/safecast"
	"github.com/hrissan/dtls/transport/options"
)

func (t *Transport) receivedClientHello(conn *Connection, msg handshake.Message, addr netip.AddrPort) (*Connection, error) {
	var msgClientHello handshake.MsgClientHello
	var bindersListLength int
	if err := msgClientHello.Parse(msg.Body, &bindersListLength); err != nil {
		return conn, dtlserrors.WarnPlaintextClientHelloParsing
	}
	if bindersListLength < 0 || bindersListLength >= len(msg.Body) {
		panic("binder list length parsing invariant")
	}
	if !t.opts.RoleServer {
		t.opts.Stats.ErrorClientReceivedClientHello(addr)
		return conn, dtlserrors.ErrClientHelloReceivedByClient
	}
	// rc.opts.Stats.ClientHelloMessage(msg.Header, msgClientHello, addr)

	suiteID, err := t.IsSupportedClientHello(&msgClientHello)
	suite := ciphersuite.GetSuite(suiteID)
	if err != nil {
		return conn, err
	}
	if !msgClientHello.Extensions.CookieSet && msg.MsgSeq != 0 {
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	if msgClientHello.Extensions.CookieSet && msg.MsgSeq != 1 {
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	// ClientHello is stateless, so we cannot check record sequence number.
	// If client follows protocol and sends the same client hello,
	// we will reply with the same server hello.
	// so, setting record sequence number to 0 equals to retransmission of the same message
	if !msgClientHello.Extensions.CookieSet {
		transcriptHasher := suite.NewHasher() // allocation
		msg.AddToHash(transcriptHasher)

		params := cookie.Params{
			TimestampUnixNano: time.Now().UnixNano(),
			KeyShareSet:       !msgClientHello.Extensions.KeyShare.X25519PublicKeySet,
			CipherSuite:       suiteID,
		}
		params.TranscriptHash.SetSum(transcriptHasher)

		ck := make([]byte, 0, cookie.CookieStorageSize)
		ck = t.cookieState.AppendCookie(ck, params, addr)
		t.opts.Stats.CookieCreated(addr)

		hrrStorage := t.snd.PopHelloRetryDatagramStorage()
		if hrrStorage == nil {
			return conn, dtlserrors.ErrServerHelloRetryRequestQueueFull
		}
		hrrDatagram, _ := GenerateStatelessHRR(params, (*hrrStorage)[:0], ck)
		if len(hrrDatagram) > len(*hrrStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram) // for debug only
		fmt.Printf("serverHRRHash1: %x\n", hrrHash[:])
		t.snd.SendHelloRetryDatagram(hrrStorage, len(hrrDatagram), addr)
		return conn, nil
	}
	if !msgClientHello.Extensions.KeyShare.X25519PublicKeySet {
		// we asked for this key_share above, but client disrespected our demand
		return conn, dtlserrors.ErrParamsSupportKeyShare
	}
	params, err := t.cookieState.IsCookieValid(addr, msgClientHello.Extensions.Cookie, time.Now(), t.opts.CookieValidDuration)
	if err != nil {
		return conn, err
	}
	if params.CipherSuite != suiteID {
		// [rfc8446:4.1.2] In that case, the client MUST send the same ClientHello without modification
		return conn, dtlserrors.ErrClientHelloUnsupportedParams
	}
	// TODO - seems wolfssl always uses TLS_AES_128_GCM_SHA256 for PSK.
	// should investigate why so, check with openssl
	transcriptHasher := suite.NewHasher()
	var earlySecret ciphersuite.Hash
	pskSelected := false
	var pskSelectedIdentity uint16
	{
		var hrrDatagramStorage [constants.MaxOutgoingHRRDatagramLength]byte
		hrrDatagram, msgBody := GenerateStatelessHRR(params, hrrDatagramStorage[:0], msgClientHello.Extensions.Cookie)
		if len(hrrDatagram) > len(hrrDatagramStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram) // for debug only
		fmt.Printf("serverHRRHash2: %x\n", hrrHash[:])

		// [rfc8446:4.4.1] replace initial client hello message with its hash if HRR was used
		syntheticMessage := handshake.Message{
			MsgType: handshake.MsgTypeMessageHash,
			MsgSeq:  0, // does not affect transcript hash
			Body:    params.TranscriptHash.GetValue(),
		}
		syntheticMessage.AddToHash(transcriptHasher)
		debugPrintSum(transcriptHasher)

		// then add reconstructed HRR
		hrrMessage := handshake.Message{
			MsgType: handshake.MsgTypeServerHello,
			MsgSeq:  0, // does not affect transcript hash
			Body:    msgBody,
		}
		hrrMessage.AddToHash(transcriptHasher)
		debugPrintSum(transcriptHasher)

		// then add second client hello, but only up to binders, if they are present
		msg.AddToHashPartial(transcriptHasher, len(msg.Body)-bindersListLength)
		debugPrintSum(transcriptHasher)

		var transcriptHash ciphersuite.Hash
		transcriptHash.SetSum(transcriptHasher)

		var pskStorage [256]byte
		pskNum, psk, identity, ok := selectPSKIdentity(pskStorage[:], t.opts, &msgClientHello.Extensions)
		// [rfc8446:4.2.11]
		// Servers SHOULD NOT attempt to validate multiple binders;
		// rather, they SHOULD select a single PSK and validate solely the
		// binder that corresponds to that PSK
		if ok {
			var binderKey ciphersuite.Hash
			earlySecret, binderKey = keys.ComputeEarlySecret(suite, psk, "ext binder")
			mustBeFinished := keys.ComputeFinished(suite, binderKey, transcriptHash)
			if string(identity.Binder) == string(mustBeFinished.GetValue()) {
				pskSelected = true
				pskSelectedIdentity = pskNum
				fmt.Printf("PSK auth selected, identity %d (%q) binders length=%d\n", pskNum, identity.Identity, bindersListLength)
			}
		}

		// add hash of binders
		_, _ = transcriptHasher.Write(msg.Body[len(msg.Body)-bindersListLength:])
		debugPrintSum(transcriptHasher)
	}
	if !pskSelected {
		earlySecret, _ = keys.ComputeEarlySecret(suite, nil, "")
		fmt.Printf("certificate auth selected\n")
	}
	// we should check all parameters above, so that we do not create connection for unsupported params
	conn, err = t.finishReceivedClientHello(conn, addr,
		earlySecret, pskSelected, pskSelectedIdentity,
		msgClientHello, params, transcriptHasher)
	if conn != nil {
		t.snd.RegisterConnectionForSend(conn)
	}
	return conn, err
}

func (t *Transport) finishReceivedClientHello(conn *Connection, addr netip.AddrPort,
	earlySecret ciphersuite.Hash, pskSelected bool, pskSelectedIdentity uint16,
	msgClientHello handshake.MsgClientHello, params cookie.Params, transcriptHasher hash.Hash) (*Connection, error) {
	if conn != nil {
		// Connection could switch to closed state and be removed from the map,
		// while we were holding it, iterating through records. This is rare.
		conn.Lock()
		if conn.stateID != smIDClosed {
			defer conn.Unlock()
			return conn, conn.onClientHello2Locked(t.opts, addr,
				earlySecret, pskSelected, pskSelectedIdentity,
				msgClientHello, params, transcriptHasher)
		}
		conn.Unlock()
		// We cannot resurrect it, because we cannot remove it from random location in the pool,
		// so we forget this one, and get a new one from the pool.
		conn = nil
	}
	conn = t.getFromPool()
	if conn == nil { // TODO - print rare warning, too many connections
		return nil, nil
	}
	conn.Lock()
	defer conn.Unlock()
	return conn, conn.onClientHello2Locked(t.opts, addr,
		earlySecret, pskSelected, pskSelectedIdentity,
		msgClientHello, params, transcriptHasher)
}

func selectPSKIdentity(pskStorage []byte, opts *options.TransportOptions, ext *handshake.ExtensionsSet) (uint16, []byte, handshake.PSKIdentity, bool) {
	// We do not want to support PSK with no forward secrecy for now.
	if !ext.PskExchangeModesSet || !ext.PskExchangeModes.ECDHE ||
		!ext.PreSharedKeySet || opts.PSKAppendSecret == nil {
		return 0, nil, handshake.PSKIdentity{}, false
	}
	for num, identity := range ext.PreSharedKey.GetIdentities() {
		psk := opts.PSKAppendSecret(identity.Identity, pskStorage[:0]) // allocates if secret very long
		if len(psk) != 0 {
			return safecast.Cast[uint16](num), psk, identity, true // limited to constants.MaxPSKIdentities
		}
	}
	return 0, nil, handshake.PSKIdentity{}, false
}

func (t *Transport) IsSupportedClientHello(msgParsed *handshake.MsgClientHello) (ciphersuite.ID, error) {
	if !msgParsed.Extensions.SupportedVersions.DTLS_13 {
		return 0, dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if !msgParsed.Extensions.SupportedGroups.X25519 {
		return 0, dtlserrors.ErrParamsSupportKeyShare
	}
	if msgParsed.Extensions.PreSharedKeySet && !msgParsed.Extensions.PskExchangeModesSet {
		// [rfc8446:4.2.9]
		return 0, dtlserrors.ErrPskKeyRequiresPskModes
	}
	if msgParsed.CipherSuites.HasCypherSuite_TLS_AES_256_GCM_SHA384 && t.opts.TLS_AES_256_GCM_SHA384 {
		return ciphersuite.TLS_AES_256_GCM_SHA384, nil
	}
	if msgParsed.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 && t.opts.TLS_AES_128_GCM_SHA256 {
		return ciphersuite.TLS_AES_128_GCM_SHA256, nil
	}
	if msgParsed.CipherSuites.HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 && t.opts.TLS_CHACHA20_POLY1305_SHA256 {
		return ciphersuite.TLS_CHACHA20_POLY1305_SHA256, nil
	}
	return 0, dtlserrors.ErrParamsSupportCiphersuites
}
