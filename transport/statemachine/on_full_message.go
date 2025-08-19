package statemachine

import (
	"crypto/sha256"
	"crypto/x509"
	"log"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/signature"
)

// change into PartialHandshakeMsg
func (hctx *HandshakeConnection) receivedFullMessage(conn *ConnectionImpl, msg handshake.Message) error {
	switch msg.MsgType {
	case handshake.MsgTypeServerHello:
		if conn.RoleServer {
			return dtlserrors.ErrServerHelloReceivedByServer
		}
		var msgServerHello handshake.MsgServerHello
		if err := msgServerHello.Parse(msg.Body); err != nil {
			return dtlserrors.WarnPlaintextServerHelloParsing
		}
		return hctx.onServerHello(conn, msg, msgServerHello)
	case handshake.MsgTypeEncryptedExtensions:
		if conn.RoleServer {
			return dtlserrors.ErrEncryptedExtensionsReceivedByServer
		}
		var msgExtensions handshake.ExtensionsSet
		if err := msgExtensions.ParseOutside(msg.Body, false, true, false); err != nil {
			return dtlserrors.ErrExtensionsMessageParsing
		}
		log.Printf("encrypted extensions parsed: %+v", msgExtensions)
		msg.AddToHash(hctx.TranscriptHasher)
		return nil
	case handshake.MsgTypeCertificate:
		var msgCertificate handshake.MsgCertificate
		if err := msgCertificate.Parse(msg.Body); err != nil {
			return dtlserrors.ErrCertificateMessageParsing
		}
		// We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, send acks,
		// then offload ECC to separate core and trigger state machine depending on result
		log.Printf("certificate parsed: %+v", msgCertificate)
		hctx.certificateChain = msgCertificate
		msg.AddToHash(hctx.TranscriptHasher)
		return nil
	case handshake.MsgTypeCertificateVerify:
		var msgCertificateVerify handshake.MsgCertificateVerify
		if err := msgCertificateVerify.Parse(msg.Body); err != nil {
			return dtlserrors.ErrCertificateVerifyMessageParsing
		}
		// TODO - We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, probably send ack,
		// then offload ECC to separate core and trigger state machine depending on result
		// But, for now we check here
		if hctx.certificateChain.CertificatesLength == 0 {
			return dtlserrors.ErrCertificateChainEmpty
		}
		if msgCertificateVerify.SignatureScheme != handshake.SignatureAlgorithm_RSA_PSS_RSAE_SHA256 {
			// TODO - more algorithms
			return dtlserrors.ErrCertificateAlgorithmUnsupported
		}
		// [rfc8446:4.4.3] - certificate verification
		var certVerifyTranscriptHashStorage [constants.MaxHashLength]byte
		certVerifyTranscriptHash := hctx.TranscriptHasher.Sum(certVerifyTranscriptHashStorage[:0])

		// TODO - offload to calc goroutine here
		var sigMessageHashStorage [constants.MaxHashLength]byte
		sigMessageHash := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash, sigMessageHashStorage[:0])

		cert, err := x509.ParseCertificate(hctx.certificateChain.Certificates[0].CertData) // TODO - reuse certificates
		if err != nil {
			return dtlserrors.ErrCertificateLoadError
		}
		if err := signature.VerifySignature_RSA_PSS_RSAE_SHA256(cert, sigMessageHash, msgCertificateVerify.Signature); err != nil {
			return dtlserrors.ErrCertificateSignatureInvalid
		}
		log.Printf("certificate verify ok: %+v", msgCertificateVerify)
		msg.AddToHash(hctx.TranscriptHasher)
		return nil
	case handshake.MsgTypeFinished:
		var msgFinished handshake.MsgFinished
		if err := msgFinished.Parse(msg.Body); err != nil {
			return dtlserrors.ErrFinishedMessageParsing
		}
		// [rfc8446:4.4.4] - finished
		var finishedTranscriptHashStorage [constants.MaxHashLength]byte
		finishedTranscriptHash := hctx.TranscriptHasher.Sum(finishedTranscriptHashStorage[:0])

		mustBeFinished := conn.Keys.Receive.ComputeFinished(sha256.New(), hctx.HandshakeTrafficSecretReceive[:], finishedTranscriptHash)
		if string(msgFinished.VerifyData[:msgFinished.VerifyDataLength]) != string(mustBeFinished) {
			return dtlserrors.ErrFinishedMessageVerificationFailed
		}
		log.Printf("finished message verify ok: %+v", msgFinished)
		if conn.RoleServer {
			if conn.Handshake != nil && conn.Handshake.SendQueue.Len() == 0 && conn.Keys.Send.Symmetric.Epoch == 2 {
				conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
				conn.Keys.Send.Symmetric.Epoch = 3
				conn.Keys.SendNextSegmentSequence = 0
				conn.Handshake = nil
				// TODO - why wolf closes connection if we send application data immediately?
				//conn.Handler = &exampleHandler{toSend: "Hello from server\n"}
				conn.Handler = &exampleHandler{}
				conn.HandlerHasMoreData = true
				// we need conn.Handshake here to send acks for last client flight.
				// we will set conn.Handshake to 0 when we switch to epoch 3
				// TODO - move acks to Connection?
			}
			return nil
		}
		// server finished is not part of traffic secret transcript
		msg.AddToHash(hctx.TranscriptHasher)

		var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
		handshakeTranscriptHash := hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])

		conn.Keys.ComputeApplicationTrafficSecret(false, hctx.MasterSecret[:], handshakeTranscriptHash)

		// TODO - if server sent certificate_request, we should generate certificate, certificate_verify here
		return hctx.PushMessage(conn, hctx.GenerateFinished(conn))
	case handshake.MsgTypeClientHello:
	case handshake.MsgTypeKeyUpdate:
	case handshake.MsgTypeNewSessionTicket:
		panic("handled in ConnectionImpl.ProcessHandshake")
	default:
		// TODO - process all messages in standard, generate error for the rest
		log.Printf("TODO - encrypted message type %d not supported", msg.MsgType)
	}
	return nil
}
