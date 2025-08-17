package handshake

import (
	"crypto/sha256"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
)

func (hctx *HandshakeConnection) GenerateFinished(conn *ConnectionImpl) format.MessageHandshake {
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHashStorage [constants.MaxHashLength]byte
	finishedTranscriptHash := hctx.TranscriptHasher.Sum(finishedTranscriptHashStorage[:0])

	mustBeFinished := conn.Keys.Send.ComputeFinished(sha256.New(), hctx.HandshakeTrafficSecretSend[:], finishedTranscriptHash)

	msg := format.MessageFinished{
		VerifyDataLength: len(mustBeFinished),
	}
	copy(msg.VerifyData[:], mustBeFinished)
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeFinished,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}
}
