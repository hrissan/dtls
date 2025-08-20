// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package signature

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/hrissan/dtls/dtlsrand"
)

// worth reading and understanding
// https://crypto.stackexchange.com/questions/58680/whats-the-difference-between-rsa-pss-pss-and-rsa-pss-rsae-schemes

var ErrCertificateWrongPublicKeyType = errors.New("certificate has wrong public key type")

func CreateSignature_RSA_PSS_RSAE_SHA256(rand dtlsrand.Rand, priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.SignPSS(rand, priv, crypto.SHA256, data, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

func verifySignature_RSA_PSS_RSAE_SHA256(rsaPublicKey *rsa.PublicKey, data []byte, signature []byte) error {
	return rsa.VerifyPSS(rsaPublicKey, crypto.SHA256, data, signature, nil)
}

func VerifySignature_RSA_PSS_RSAE_SHA256(cert *x509.Certificate, data []byte, signature []byte) error {
	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ErrCertificateWrongPublicKeyType
	}
	return verifySignature_RSA_PSS_RSAE_SHA256(rsaPublicKey, data, signature)
	//&rsa.PSSOptions{
	//	SaltLength: rsa.PSSSaltLengthAuto,
	//}
}
