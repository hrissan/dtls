package statemachine

import (
	"crypto/sha256"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/handshake"
)

func (hctx *HandshakeConnection) GenerateFinished(conn *ConnectionImpl) handshake.MessageHandshakeFragment {
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHashStorage [constants.MaxHashLength]byte
	finishedTranscriptHash := hctx.TranscriptHasher.Sum(finishedTranscriptHashStorage[:0])

	mustBeFinished := conn.Keys.Send.ComputeFinished(sha256.New(), hctx.HandshakeTrafficSecretSend[:], finishedTranscriptHash)

	msg := handshake.MsgFinished{
		VerifyDataLength: len(mustBeFinished),
	}
	copy(msg.VerifyData[:], mustBeFinished)
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return handshake.MessageHandshakeFragment{
		Header: handshake.HandshakeMsgFragmentHeader{
			HandshakeType: handshake.HandshakeTypeFinished,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}
}
