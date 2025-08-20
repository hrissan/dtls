// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"crypto/x509"
	"log"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/signature"
)

type smHandshakeClientExpectCertVerify struct {
	smHandshake
}

func (*smHandshakeClientExpectCertVerify) OnCertificateVerify(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgCertificateVerify) error {
	hctx := conn.hctx
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
	conn.stateID = smIDHandshakeClientExpectServerFinished
	return nil
}
