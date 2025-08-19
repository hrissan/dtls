package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/hrissan/tinydtls/dtlsrand"
)

// cpu: 13th Gen Intel(R) Core(TM) i7-1360P
// Benchmark_RSA_PSS_RSAE_SHA256_Sign-16      	    1400	    852992 ns/op	    1744 B/op	      11 allocs/op
// Benchmark_RSA_PSS_RSAE_SHA256_Verify-16    	   44079	     25245 ns/op	    1099 B/op	      11 allocs/op

func Test_RSA_PSS_RSAE_SHA256(t *testing.T) {
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

func Benchmark_RSA_PSS_RSAE_SHA256_Sign(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Errorf("%v", err)
	}
	publicKey := &privateKey.PublicKey

	message := []byte("Something to sign")
	hashed := sha256.Sum256(message)

	var sig []byte

	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		sig, err = CreateSignature_RSA_PSS_RSAE_SHA256(dtlsrand.CryptoRand(), privateKey, hashed[:])
		if err != nil {
			b.Errorf("%v", err)
		}
	}
	err = verifySignature_RSA_PSS_RSAE_SHA256(publicKey, hashed[:], sig)
	if err != nil {
		b.Errorf("%v", err)
	}
}

func Benchmark_RSA_PSS_RSAE_SHA256_Verify(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Errorf("%v", err)
	}
	publicKey := &privateKey.PublicKey

	message := []byte("Something to sign")
	hashed := sha256.Sum256(message)

	sig, err := CreateSignature_RSA_PSS_RSAE_SHA256(dtlsrand.CryptoRand(), privateKey, hashed[:])
	if err != nil {
		b.Errorf("%v", err)
	}
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		err := verifySignature_RSA_PSS_RSAE_SHA256(publicKey, hashed[:], sig)
		if err != nil {
			b.Errorf("%v", err)
		}
	}
}
