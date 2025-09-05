// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"fmt"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
)

type smHandshakeClientExpectFinished struct {
	smHandshake
}

func (*smHandshakeClientExpectFinished) OnFinished(conn *Connection, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	hctx := conn.hctx
	suite := conn.keys.Suite()
	hctx.receivedNextFlight(conn)
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHash ciphersuite.Hash
	finishedTranscriptHash.SetSum(hctx.transcriptHasher)

	mustBeFinished := keys.ComputeFinished(suite, hctx.handshakeTrafficSecretReceive, finishedTranscriptHash)
	if string(msgParsed.VerifyData) != string(mustBeFinished.GetValue()) {
		return dtlserrors.ErrFinishedMessageVerificationFailed
	}
	fmt.Printf("finished message verify ok: %+v\n", msgParsed)
	msg.AddToHash(hctx.transcriptHasher)

	var handshakeTranscriptHash ciphersuite.Hash
	handshakeTranscriptHash.SetSum(hctx.transcriptHasher)

	conn.keys.ComputeApplicationTrafficSecret(suite, false, hctx.masterSecret, handshakeTranscriptHash)

	if conn.keys.NewReceiveKeysSet { // should be [2] [.] here
		panic("at this point there must be no new key set")
	}
	if err := conn.generateNewReceiveKeys(); err != nil { // [2] [.] -> [2] [3]
		panic("we must be able to generate new keys receive here")
	}

	conn.stateID = smIDHandshakeClientExpectFinishedAck
	conn.keys.SendSymmetric = conn.keys.Suite().ResetSymmetricKeys(conn.keys.SendSymmetric, conn.keys.SendApplicationTrafficSecret)
	conn.keys.SendEpoch = 3
	conn.debugPrintKeys()

	// TODO - if server sent certificate_request, we should generate certificate, certificate_verify here
	return hctx.PushMessage(conn, hctx.generateFinished(conn))
}
