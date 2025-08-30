// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/x509"
	"fmt"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/signature"
)

type smHandshakeClientExpectCertVerify struct {
	smHandshake
}

func (*smHandshakeClientExpectCertVerify) OnCertificateVerify(conn *Connection, msg handshake.Message, msgParsed handshake.MsgCertificateVerify) error {
	hctx := conn.hctx
	suite := conn.keys.Suite()
	hctx.receivedNextFlight(conn)
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
	var certVerifyTranscriptHash ciphersuite.Hash
	certVerifyTranscriptHash.SetSum(hctx.transcriptHasher)

	// TODO - offload to calc goroutine here
	sigMessageHash := signature.CalculateCoveredContentHash(suite.NewHasher(), certVerifyTranscriptHash.GetValue())

	cert, err := x509.ParseCertificate(hctx.certificateChain.Certificates[0].CertData) // TODO - reuse certificates
	if err != nil {
		return dtlserrors.ErrCertificateLoadError
	}
	if err := signature.VerifySignature_RSA_PSS_RSAE_SHA256(cert, sigMessageHash.GetValue(), msgParsed.Signature); err != nil {
		return dtlserrors.ErrCertificateSignatureInvalid
	}
	fmt.Printf("certificate verify ok: %+v\n", msgParsed)
	msg.AddToHash(hctx.transcriptHasher)
	conn.stateID = smIDHandshakeClientExpectServerFinished
	return nil
}
