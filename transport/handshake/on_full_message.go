package handshake

import (
	"crypto/sha256"
	"crypto/x509"
	"log"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/signature"
)

func (hctx *HandshakeConnection) receivedFullMessage(conn *ConnectionImpl, handshakeHdr format.MessageHandshakeHeader, body []byte) error {
	switch handshakeHdr.HandshakeType {
	case format.HandshakeTypeEncryptedExtensions:
		var msg format.ExtensionsSet
		if err := msg.ParseOutside(body, false, true, false); err != nil {
			return dtlserrors.ErrExtensionsMessageParsing
		}
		log.Printf("encrypted extensions parsed: %+v", msg)
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(body)
		return nil
	case format.HandshakeTypeCertificate:
		var msg format.MessageCertificate
		if err := msg.Parse(body); err != nil {
			return dtlserrors.ErrCertificateMessageParsing
		}
		// We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, probably send ack,
		// then offload ECC to separate core and trigger state machine depending on result
		log.Printf("certificate parsed: %+v", msg)
		hctx.certificateChain = msg
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(body)
		return nil
	case format.HandshakeTypeCertificateVerify:
		var msg format.MessageCertificateVerify
		if err := msg.Parse(body); err != nil {
			return dtlserrors.ErrCertificateVerifyMessageParsing
		}
		// TODO - We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, probably send ack,
		// then offload ECC to separate core and trigger state machine depending on result
		// But, for now we check here
		if hctx.certificateChain.CertificatesLength == 0 {
			return dtlserrors.ErrCertificateChainEmpty
		}
		if msg.SignatureScheme != format.SignatureAlgorithm_RSA_PSS_RSAE_SHA256 {
			// TODO - more algorithms
			return dtlserrors.ErrCertificateAlgorithmUnsupported
		}
		// [rfc8446:4.4.3] - certificate verification
		var certVerifyTranscriptHashStorage [constants.MaxHashLength]byte
		certVerifyTranscriptHash := hctx.TranscriptHasher.Sum(certVerifyTranscriptHashStorage[:0])
		sigMessage := []byte("                                                                " +
			"TLS 1.3, server CertificateVerify")
		sigMessage = append(sigMessage, 0)
		sigMessage = append(sigMessage, certVerifyTranscriptHash...)

		sigMessageHash := sha256.Sum256(sigMessage)
		// TODO - offload to calc goroutine here
		var sigMessageHashStorage [constants.MaxHashLength]byte
		sigMessageHash2 := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash, sigMessageHashStorage[:0])

		// TODO - remove inplace calculation
		if string(sigMessageHash[:]) != string(sigMessageHash2[:]) {
			panic("hren")
		}

		cert, err := x509.ParseCertificate(hctx.certificateChain.Certificates[0].CertData) // TODO - reuse certificates
		if err != nil {
			return dtlserrors.ErrCertificateLoadError
		}
		if err := signature.VerifySignature_RSA_PSS_RSAE_SHA256(cert, sigMessageHash2, msg.Signature); err != nil {
			return dtlserrors.ErrCertificateSignatureInvalid
		}
		log.Printf("certificate verify parsed: %+v", msg)
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(body)
		return nil
	case format.HandshakeTypeFinished:
		var msg format.MessageFinished
		if err := msg.Parse(body); err != nil {
			return dtlserrors.ErrFinishedMessageParsing
		}
		// [rfc8446:4.4.4] - finished
		var finishedTranscriptHashStorage [constants.MaxHashLength]byte
		finishedTranscriptHash := hctx.TranscriptHasher.Sum(finishedTranscriptHashStorage[:0])

		mustBeFinished := conn.Keys.Receive.ComputeFinished(sha256.New(), hctx.HandshakeTrafficSecretReceive[:], finishedTranscriptHash)
		if string(msg.VerifyData[:msg.VerifyDataLength]) != string(mustBeFinished) {
			return dtlserrors.ErrFinishedMessageVerificationFailed
		}
		log.Printf("finished message verify ok: %+v", msg)
		if conn.RoleServer {
			if conn.Handshake != nil && conn.Handshake.SendQueue.Len() == 0 && conn.Keys.Send.Symmetric.Epoch == 2 {
				conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
				conn.Keys.Send.Symmetric.Epoch++
				conn.Keys.Send.NextSegmentSequence = 0
				//conn.Handshake = nil // TODO - reuse into pool
				conn.Handler = &exampleHandler{toSend: "Hello from server\n"}
				conn.HandlerHasMoreData = true
			}
			return nil
		}
		// server finished is not part of traffic secret transcript
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(body)
		// TODO - on server, secrets must be calculated, when sending server finished, not here

		var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
		handshakeTranscriptHash := hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])

		conn.Keys.ComputeApplicationTrafficSecret(false, hctx.MasterSecret[:], handshakeTranscriptHash)

		// TODO - if server sent certificate_request, we should generate certificate, certificate_verify here
		hctx.PushMessage(conn, hctx.GenerateFinished(conn))
		return nil
	case format.HandshakeTypeClientHello:
	case format.HandshakeTypeServerHello:
	case format.HandshakeTypeKeyUpdate:
	case format.HandshakeTypeNewSessionTicket:
		panic("handled in ProcessCiphertextRecord")
	default:
		// TODO - process message in standard, generate error for the rest
		log.Printf("TODO - encrypted message type %d not supported", handshakeHdr.HandshakeType)
	}
	return nil
}
