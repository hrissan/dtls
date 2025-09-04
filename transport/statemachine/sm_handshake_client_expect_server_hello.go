// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/ecdh"
	"fmt"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
)

type smHandshakeClientExpectServerHello struct {
	smHandshake
}

func (*smHandshakeClientExpectServerHello) OnServerHello(conn *Connection, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	if err := conn.tr.IsSupportedServerHello(&msgParsed); err != nil {
		return err
	}
	if msgParsed.IsHelloRetryRequest() {
		return nil // garbage or attack, ignore. TODO - return some error?s
	}
	if conn.keys.SuiteID != msgParsed.CipherSuite {
		return dtlserrors.ErrClientHelloUnsupportedParams
	}
	suite := conn.keys.Suite()
	// ServerHello can have messageSeq 0 or 1, depending on whether server used HRR
	if !hctx.serverUsedHRR && msg.MsgSeq != 0 {
		fmt.Printf("ServerHello after ServerHelloRetryRequest has msgSeq != 1\n")
		return dtlserrors.ErrClientHelloUnsupportedParams
	}
	if hctx.serverUsedHRR && msg.MsgSeq != 1 {
		fmt.Printf("ServerHello after ServerHelloRetryRequest has msgSeq != 1\n")
		return dtlserrors.ErrClientHelloUnsupportedParams
	}
	if !msgParsed.Extensions.KeyShare.X25519PublicKeySet {
		return dtlserrors.ErrParamsSupportKeyShare
	}
	var pskStorage [256]byte
	var psk []byte
	if msgParsed.Extensions.PreSharedKeySet && conn.tr.opts.PSKAppendSecret != nil &&
		int(msgParsed.Extensions.PreSharedKey.SelectedIdentity) < len(conn.tr.opts.PSKClientIdentities) { // widen
		psk = conn.tr.opts.PSKAppendSecret(conn.tr.opts.PSKClientIdentities[msgParsed.Extensions.PreSharedKey.SelectedIdentity], pskStorage[:0])
		hctx.pskSelected = true
	}

	msg.AddToHash(hctx.transcriptHasher)

	var handshakeTranscriptHash ciphersuite.Hash
	handshakeTranscriptHash.SetSum(hctx.transcriptHasher)

	// TODO - move to calculator goroutine
	remotePublic, err := ecdh.X25519().NewPublicKey(msgParsed.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	sharedSecret, err := hctx.x25519Secret.ECDH(remotePublic)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.earlySecret = keys.ComputeEarlySecret(conn.keys.Suite(), psk)
	hctx.masterSecret, hctx.handshakeTrafficSecretSend, hctx.handshakeTrafficSecretReceive =
		conn.keys.ComputeHandshakeKeys(suite, false, hctx.earlySecret, sharedSecret, handshakeTranscriptHash)
	hctx.SendSymmetricEpoch2 = suite.ResetSymmetricKeys(hctx.SendSymmetricEpoch2, hctx.handshakeTrafficSecretSend)
	conn.debugPrintKeys()

	conn.stateID = smIDHandshakeClientExpectEE
	fmt.Printf("processed server hello\n")
	return nil
}
