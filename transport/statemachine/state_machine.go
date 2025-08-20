package statemachine

import (
	"crypto/sha256"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/handshake"
)

func (hctx *handshakeContext) generateFinished(conn *ConnectionImpl) handshake.Message {
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

// If we have no connection (conn == null)
// client:
//   * -> ignore, those are either attack or retransmissions from previous connection
// server:
//   plaintext ClientHello
//     w/o cookie or key_share
//       if params supported
//         send ServerHelloRetryRequest
//       if params not supported
//         send stateless error (correct alert code)
//     with cookie
//       old timestamp or invalid cookie
//         send stateless alert (replay or attack)
//       correct cookie timestamp
//         create connection, add to map, create handshake, send ServerHello [statemachine]
//   plaintext *
//     send stateless alert (replay or attack)
//   plaintext ack
//     ignore
//   plaintext alert
//     ignore

// If we have connection, but not yet established (hctx != null)
// both:

// If we have Connection established (hctx == null), both peers already destroyed their epoch < 3 keys
// both:
//   encrypted KeyUpdate -> start key update
//   encrypted application data -> deliver
// server: (either attacker, or client who lost/closed association and wants a new connection)
//   plaintext ClientHello w/o cookie ->
//     send encrypted empty ack + send ServerHelloRetryRequest, remember cookie timestamp in connection
//   plaintext ClientHello w old cookie timestamp or invalid cookie ->
//     replay or attack, do nothing
//   plaintext ClientHello w correct cookie timestamp ->
//     destroy connection without sending alert + start handshake
//     we could have completely separate handshake state machine, so would auth client
//     before destroying old connection, but that requires 2 complete sets of keys/secrets
//     and complicated logic, so do it later or never.
//   plaintext ServerHello -> ignore, send warning
//   * -> close
// client:
//   encrypted NewSessionTicket -> deliver
//   * -> close
