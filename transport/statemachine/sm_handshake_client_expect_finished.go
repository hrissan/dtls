// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"fmt"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
)

type smHandshakeClientExpectFinished struct {
	smHandshake
}

func (*smHandshakeClientExpectFinished) OnFinished(conn *Connection, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHash ciphersuite.Hash
	finishedTranscriptHash.SetSum(hctx.transcriptHasher)

	mustBeFinished := keys.ComputeFinished(sha256.New(), hctx.handshakeTrafficSecretReceive[:], finishedTranscriptHash)
	if string(msgParsed.VerifyData) != string(mustBeFinished.GetValue()) {
		return dtlserrors.ErrFinishedMessageVerificationFailed
	}
	fmt.Printf("finished message verify ok: %+v\n", msgParsed)
	// server finished is not part of traffic secret transcript
	msg.AddToHash(hctx.transcriptHasher)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.transcriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	conn.keys.ComputeApplicationTrafficSecret(false, hctx.masterSecret[:], handshakeTranscriptHash)
	conn.stateID = smIDPostHandshake

	// TODO - if server sent certificate_request, we should generate certificate, certificate_verify here
	return hctx.PushMessage(conn, hctx.generateFinished(conn))
}
