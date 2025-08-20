// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"log"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectFinished struct {
	smHandshake
}

func (*smHandshakeClientExpectFinished) OnFinished(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	hctx := conn.hctx
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHashStorage [constants.MaxHashLength]byte
	finishedTranscriptHash := hctx.transcriptHasher.Sum(finishedTranscriptHashStorage[:0])

	mustBeFinished := conn.keys.Receive.ComputeFinished(sha256.New(), hctx.handshakeTrafficSecretReceive[:], finishedTranscriptHash)
	if string(msgParsed.VerifyData[:msgParsed.VerifyDataLength]) != string(mustBeFinished) {
		return dtlserrors.ErrFinishedMessageVerificationFailed
	}
	log.Printf("finished message verify ok: %+v", msgParsed)
	// server finished is not part of traffic secret transcript
	msg.AddToHash(hctx.transcriptHasher)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.transcriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	conn.keys.ComputeApplicationTrafficSecret(false, hctx.masterSecret[:], handshakeTranscriptHash)
	conn.stateID = smIDPostHandshake

	// TODO - if server sent certificate_request, we should generate certificate, certificate_verify here
	return hctx.PushMessage(conn, hctx.generateFinished(conn))
}
