// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"log"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
)

type smHandshakeServerExpectFinished struct {
	smHandshake
}

func (*smHandshakeServerExpectFinished) OnFinished(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHashStorage [constants.MaxHashLength]byte
	finishedTranscriptHash := hctx.transcriptHasher.Sum(finishedTranscriptHashStorage[:0])

	mustBeFinished := keys.ComputeFinished(sha256.New(), hctx.handshakeTrafficSecretReceive[:], finishedTranscriptHash)
	if string(msgParsed.VerifyData[:msgParsed.VerifyDataLength]) != string(mustBeFinished) {
		return dtlserrors.ErrFinishedMessageVerificationFailed
	}
	log.Printf("finished message verify ok: %+v", msgParsed)
	// if conn.hctx.sendQueue.Len() == 0 && conn.keys.Send.Symmetric.Epoch == 2 {
	conn.keys.Send.Symmetric.ComputeKeys(conn.keys.Send.ApplicationTrafficSecret[:])
	conn.keys.Send.Symmetric.Epoch = 3
	conn.keys.SendNextSegmentSequence = 0
	conn.hctx = nil
	// TODO - why wolf closes connection if we send application data immediately
	// in the same datagram as ack. Reproduce on the latest version of us?
	//conn.Handler = &exampleHandler{toSend: "Hello from server\n"}
	conn.Handler = &exampleHandler{}
	conn.handlerHasMoreData = true
	conn.stateID = smIDPostHandshake
	// }
	return nil
}
