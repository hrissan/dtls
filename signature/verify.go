package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hrissan/tinydtls/dtlsrand"
)

// worth reading and understanding
// https://crypto.stackexchange.com/questions/58680/whats-the-difference-between-rsa-pss-pss-and-rsa-pss-rsae-schemes

var ErrCertificateWrongPublicKeyType = errors.New("certificate has wrong public key type")

func CreateSignature_RSA_PSS_RSAE_SHA256(rand dtlsrand.Rand, priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.SignPSS(rand, priv, crypto.SHA256, data, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	//&rsa.PSSOptions{
	//	SaltLength: rsa.PSSSaltLengthAuto,
	//	Hash:       crypto.SHA256,
	//}
}

func VerifySignature_RSA_PSS_RSAE_SHA256(cert *x509.Certificate, data []byte, signature []byte) error {
	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ErrCertificateWrongPublicKeyType
	}
	return rsa.VerifyPSS(rsaPublicKey, crypto.SHA256, data, signature, nil)
	//&rsa.PSSOptions{
	//	SaltLength: rsa.PSSSaltLengthAuto,
	//	Hash:       crypto.SHA256,
	//}
}

func test() {
	// 1. Генерация RSA ключа
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Ошибка генерации ключа:", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// 2. Подготавливаем данные для подписи
	message := []byte("Это сообщение для подписи")
	hashed := sha256.Sum256(message)

	// 3. Подпись данных с использованием RSA-PSS
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		fmt.Println("Ошибка подписи:", err)
		return
	}

	fmt.Println("Подпись:", signature)

	// 4. Проверка подписи
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		fmt.Println("Ошибка проверки подписи:", err)
		return
	}

	fmt.Println("Подпись успешно проверена")
}
