// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/ecdh"
	"log"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectServerHello struct {
	smHandshake
}

func (*smHandshakeClientExpectServerHello) OnServerHello(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	hctx := conn.hctx
	if msgParsed.Extensions.SupportedVersions.SelectedVersion != handshake.DTLS_VERSION_13 {
		return dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if msgParsed.CipherSuite != handshake.CypherSuite_TLS_AES_128_GCM_SHA256 {
		return dtlserrors.ErrParamsSupportCiphersuites
	}
	if msgParsed.IsHelloRetryRequest() {
		if !msgParsed.Extensions.CookieSet {
			return dtlserrors.ErrServerHRRMustContainCookie
		}
		if msg.MsgSeq != 0 {
			return dtlserrors.ErrServerHRRMustHaveMsgSeq0
		}
		if !hctx.ReceivedFlight(conn, MessagesFlightServerHRR) { // TODO - remove "flight" from code, leave nly in state machine
			return nil
		}
		// [rfc8446:4.4.1] replace initial hello message with its hash if HRR was used
		var initialHelloTranscriptHashStorage [constants.MaxHashLength]byte
		initialHelloTranscriptHash := hctx.transcriptHasher.Sum(initialHelloTranscriptHashStorage[:0])
		hctx.transcriptHasher.Reset()
		syntheticHashData := []byte{byte(handshake.MsgTypeMessageHash), 0, 0, byte(len(initialHelloTranscriptHash))}
		_, _ = hctx.transcriptHasher.Write(syntheticHashData)
		_, _ = hctx.transcriptHasher.Write(initialHelloTranscriptHash)

		msg.AddToHash(hctx.transcriptHasher)

		clientHelloMsg := hctx.generateClientHello(true, msgParsed.Extensions.Cookie)
		return hctx.PushMessage(conn, clientHelloMsg)
	}
	// ServerHello can have messageSeq 0 or 1, depending on whether server used HRR
	if msg.MsgSeq >= 2 {
		// TODO - fatal alert. Looks dangerous for state machine
		log.Printf("ServerHello has MsgSeq >= 2, ignoring")
		return dtlserrors.ErrClientHelloUnsupportedParams
	}

	if !msgParsed.Extensions.KeyShare.X25519PublicKeySet {
		return dtlserrors.ErrParamsSupportKeyShare
	}
	if !hctx.ReceivedFlight(conn, MessagesFlightServerHello_Finished) {
		return nil
	}
	msg.AddToHash(hctx.transcriptHasher)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.transcriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	// TODO - move to calculator goroutine
	remotePublic, err := ecdh.X25519().NewPublicKey(msgParsed.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	sharedSecret, err := hctx.x25519Secret.ECDH(remotePublic)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.masterSecret, hctx.handshakeTrafficSecretSend, hctx.handshakeTrafficSecretReceive = conn.keys.ComputeHandshakeKeys(false, sharedSecret, handshakeTranscriptHash)
	conn.keys.SequenceNumberLimitExp = 5 // TODO - set for actual cipher suite. Small value is for testing.

	conn.stateID = smIDHandshakeClientExpectServerEE
	log.Printf("processed server hello")
	return nil
}
