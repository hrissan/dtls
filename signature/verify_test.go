package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/hrissan/tinydtls/dtlsrand"
)

func TestSimple(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("%v", err)
	}
	publicKey := &privateKey.PublicKey

	message := []byte("Something to sign")
	hashed := sha256.Sum256(message)

	sig, err := CreateSignature_RSA_PSS_RSAE_SHA256(dtlsrand.CryptoRand(), privateKey, hashed[:])
	if err != nil {
		t.Errorf("%v", err)
	}

	err = verifySignature_RSA_PSS_RSAE_SHA256(publicKey, hashed[:], sig)
	if err != nil {
		t.Errorf("%v", err)
	}
}
