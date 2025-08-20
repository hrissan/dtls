package statemachine

import (
	"crypto/sha256"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/handshake"
)

func (hctx *handshakeContext) GenerateFinished(conn *ConnectionImpl) handshake.Message {
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHashStorage [constants.MaxHashLength]byte
	finishedTranscriptHash := hctx.transcriptHasher.Sum(finishedTranscriptHashStorage[:0])

	mustBeFinished := conn.keys.Send.ComputeFinished(sha256.New(), hctx.handshakeTrafficSecretSend[:], finishedTranscriptHash)

	msg := handshake.MsgFinished{
		VerifyDataLength: len(mustBeFinished),
	}
	copy(msg.VerifyData[:], mustBeFinished)
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeFinished,
		Body:    messageBody,
	}
}
