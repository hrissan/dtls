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

func (hctx *handshakeContext) receivedFullMessage(conn *ConnectionImpl, msg handshake.Message) error {
	switch msg.MsgType {
	case handshake.MsgTypeServerHello:
		if conn.roleServer {
			return dtlserrors.ErrServerHelloReceivedByServer
		}
		var msgParsed handshake.MsgServerHello
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.WarnPlaintextServerHelloParsing
		}
		return conn.State().OnServerHello(conn, msg, msgParsed)
	case handshake.MsgTypeEncryptedExtensions:
		if conn.roleServer {
			return dtlserrors.ErrEncryptedExtensionsReceivedByServer
		}
		var msgParsed handshake.ExtensionsSet
		if err := msgParsed.ParseOutside(msg.Body, false, true, false); err != nil {
			return dtlserrors.ErrExtensionsMessageParsing
		}
		log.Printf("encrypted extensions parsed: %+v", msgParsed)
		msg.AddToHash(hctx.transcriptHasher)
		return conn.State().OnEncryptedExtensions(conn, msg, msgParsed)
	case handshake.MsgTypeCertificate:
		var msgParsed handshake.MsgCertificate
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.ErrCertificateMessageParsing
		}
		// We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, send acks,
		// then offload ECC to separate core and trigger state machine depending on result
		log.Printf("certificate parsed: %+v", msgParsed)
		hctx.certificateChain = msgParsed
		msg.AddToHash(hctx.transcriptHasher)
		return conn.State().OnCertificate(conn, msg, msgParsed)
	case handshake.MsgTypeCertificateVerify:
		var msgParsed handshake.MsgCertificateVerify
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.ErrCertificateVerifyMessageParsing
		}
		// TODO - We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, probably send ack,
		// then offload ECC to separate core and trigger state machine depending on result
		// But, for now we check here
		if hctx.certificateChain.CertificatesLength == 0 {
			return dtlserrors.ErrCertificateChainEmpty
		}
		if msgParsed.SignatureScheme != handshake.SignatureAlgorithm_RSA_PSS_RSAE_SHA256 {
			// TODO - more algorithms
			return dtlserrors.ErrCertificateAlgorithmUnsupported
		}
		// [rfc8446:4.4.3] - certificate verification
		var certVerifyTranscriptHashStorage [constants.MaxHashLength]byte
		certVerifyTranscriptHash := hctx.transcriptHasher.Sum(certVerifyTranscriptHashStorage[:0])

		// TODO - offload to calc goroutine here
		var sigMessageHashStorage [constants.MaxHashLength]byte
		sigMessageHash := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash, sigMessageHashStorage[:0])

		cert, err := x509.ParseCertificate(hctx.certificateChain.Certificates[0].CertData) // TODO - reuse certificates
		if err != nil {
			return dtlserrors.ErrCertificateLoadError
		}
		if err := signature.VerifySignature_RSA_PSS_RSAE_SHA256(cert, sigMessageHash, msgParsed.Signature); err != nil {
			return dtlserrors.ErrCertificateSignatureInvalid
		}
		log.Printf("certificate verify ok: %+v", msgParsed)
		msg.AddToHash(hctx.transcriptHasher)
		return conn.State().OnCertificateVerify(conn, msg, msgParsed)
	case handshake.MsgTypeFinished:
		var msgParsed handshake.MsgFinished
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.ErrFinishedMessageParsing
		}

		return conn.State().OnFinished(conn, msg, msgParsed)
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
