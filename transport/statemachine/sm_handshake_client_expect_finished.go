package statemachine

import (
	"crypto/sha256"
	"log"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/handshake"
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
	if conn.roleServer {
		if conn.hctx != nil && conn.hctx.sendQueue.Len() == 0 && conn.keys.Send.Symmetric.Epoch == 2 {
			conn.keys.Send.Symmetric.ComputeKeys(conn.keys.Send.ApplicationTrafficSecret[:])
			conn.keys.Send.Symmetric.Epoch = 3
			conn.keys.SendNextSegmentSequence = 0
			conn.hctx = nil
			// TODO - why wolf closes connection if we send application data immediately?
			//conn.Handler = &exampleHandler{toSend: "Hello from server\n"}
			conn.Handler = &exampleHandler{}
			conn.handlerHasMoreData = true
			conn.stateID = smIDPostHandshake
		}
		return nil
	}
	// server finished is not part of traffic secret transcript
	msg.AddToHash(hctx.transcriptHasher)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.transcriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	conn.keys.ComputeApplicationTrafficSecret(false, hctx.masterSecret[:], handshakeTranscriptHash)
	conn.stateID = smIDPostHandshake

	// TODO - if server sent certificate_request, we should generate certificate, certificate_verify here
	return hctx.PushMessage(conn, hctx.generateFinished(conn))
}
