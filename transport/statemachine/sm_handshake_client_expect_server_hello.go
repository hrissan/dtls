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

func (*smHandshakeClientExpectServerHello) OnServerHello(conn *Connection, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	if err := IsSupportedServerHello(&msgParsed); err != nil {
		return err
	}
	if msgParsed.IsHelloRetryRequest() {
		return nil // garbage or attack, ignore. TODO - return some error?s
	}
	// ServerHello can have messageSeq 0 or 1, depending on whether server used HRR
	if !hctx.serverUsedHRR && msg.MsgSeq != 0 {
		log.Printf("ServerHello after ServerHelloRetryRequest has msgSeq != 1")
		return dtlserrors.ErrClientHelloUnsupportedParams
	}
	if hctx.serverUsedHRR && msg.MsgSeq != 1 {
		log.Printf("ServerHello after ServerHelloRetryRequest has msgSeq != 1")
		return dtlserrors.ErrClientHelloUnsupportedParams
	}
	if !msgParsed.Extensions.KeyShare.X25519PublicKeySet {
		return dtlserrors.ErrParamsSupportKeyShare
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
