package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

var ErrCertificateWrongPublicKeyType = errors.New("certificate has wrong public key type")

func VerifySignature_RSA_PSS_RSAE_SHA256(cert *x509.Certificate, data []byte, signature []byte) error {
	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return ErrCertificateWrongPublicKeyType
	}
	return rsa.VerifyPSS(rsaPublicKey, crypto.SHA256, data[:], signature, nil)
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
