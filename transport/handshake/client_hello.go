package handshake

import (
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/sha256"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/signature"
	"github.com/hrissan/tinydtls/transport/options"
)

func (conn *ConnectionImpl) ReceivedClientHello(opts *options.TransportOptions, messageBody []byte,
	handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello,
	initialHelloTranscriptHash [constants.MaxHashLength]byte, keyShareSet bool) error {

	conn.mu.Lock()
	defer conn.mu.Unlock()
	// TODO - lock conn here
	if conn.Handshake != nil {
		// TODO - replace older handshakes with the new ones (by cookie age or other parameters)
		return nil
	}
	hctx := NewHandshakeConnection(sha256.New())
	conn.Handshake = hctx

	conn.Handshake.SendNextSegmentSequenceEpoch0 = 1 // sequence 0 was HRR

	conn.Keys.NextMessageSeqSend = 1    // message 0 was HRR
	conn.Keys.NextMessageSeqReceive = 2 // message 0, 1 were initial client_hello, client_hello
	// TODO - check if the same handshake by storing (age, initialHelloTranscriptHash, keyShareSet)
	{
		var hrrDatagramStorage [constants.MaxOutgoingHRRDatagramLength]byte
		hrrDatagram := GenerateStatelessHRR(hrrDatagramStorage[:0], msg.Extensions.Cookie, keyShareSet)
		if len(hrrDatagram) > len(hrrDatagramStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram)
		log.Printf("serverHRRHash2: %x\n", hrrHash[:])

		// [rfc8446:4.4.1] replace initial client hello message with its hash if HRR was used
		syntheticHashData := []byte{format.HandshakeTypeMessageHash, 0, 0, sha256.Size}
		_, _ = hctx.TranscriptHasher.Write(syntheticHashData)
		_, _ = hctx.TranscriptHasher.Write(initialHelloTranscriptHash[:sha256.Size])
		debugPrintSum(hctx.TranscriptHasher)
		// then add reconstructed HRR
		addMessageDataTranscript(hctx.TranscriptHasher, hrrDatagram[13:]) // skip record header
		debugPrintSum(hctx.TranscriptHasher)
		// then add second client hello
		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(messageBody)
		debugPrintSum(hctx.TranscriptHasher)
	}
	log.Printf("start handshake keyShareSet=%v initial hello transcript hash(hex): %x", keyShareSet, initialHelloTranscriptHash)
	opts.Rnd.ReadMust(hctx.LocalRandom[:])
	hctx.ComputeKeyShare(opts.Rnd)

	serverHello := format.ServerHello{
		Random:      hctx.LocalRandom,
		CipherSuite: format.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	serverHello.Extensions.SupportedVersionsSet = true
	serverHello.Extensions.SupportedVersions.SelectedVersion = format.DTLS_VERSION_13
	serverHello.Extensions.KeyShareSet = true
	serverHello.Extensions.KeyShare.X25519PublicKeySet = true
	copy(serverHello.Extensions.KeyShare.X25519PublicKey[:], hctx.X25519Secret.PublicKey().Bytes())
	// TODO - get body from the rope
	serverHelloBody := serverHello.Write(nil)
	serverHelloMessage := format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeServerHello,
			Length:        uint32(len(serverHelloBody)),
		},
		Body: serverHelloBody,
	}
	_ = hctx.ReceivedFlight(conn, MessagesFlightClientHello2)

	hctx.PushMessage(conn, serverHelloMessage)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	// TODO - move to calculator goroutine
	remotePublic, err := ecdh.X25519().NewPublicKey(msg.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	sharedSecret, err := hctx.X25519Secret.ECDH(remotePublic)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.MasterSecret, hctx.HandshakeTrafficSecretSend, hctx.HandshakeTrafficSecretReceive = conn.Keys.ComputeHandshakeKeys(true, sharedSecret, handshakeTranscriptHash)
	conn.Keys.SequenceNumberLimitExp = 5 // TODO - set for actual cipher suite. Small value is for testing.

	hctx.PushMessage(conn, generateEncryptedExtensions())

	hctx.PushMessage(conn, generateServerCertificate(opts))

	// TODO - offload to calculator goroutine
	msgCertificateVerify, err := generateServerCertificateVerify(opts, hctx)
	if err != nil {
		return err // TODO - test on this path. Should close connection immediately
	}
	hctx.PushMessage(conn, msgCertificateVerify)

	hctx.PushMessage(conn, hctx.GenerateFinished(conn))

	handshakeTranscriptHash = hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])
	conn.Keys.ComputeApplicationTrafficSecret(true, hctx.MasterSecret[:], handshakeTranscriptHash)
	return nil
}

func debugPrintSum(hasher hash.Hash) {
	var ha [constants.MaxHashLength]byte
	hasher.Sum(ha[:0])
	log.Printf("%x\n", ha[:])
}

func addMessageDataTranscript(transcriptHasher hash.Hash, messageData []byte) {
	_, _ = transcriptHasher.Write(messageData[:4])
	_, _ = transcriptHasher.Write(messageData[12:])
}

// we must generate the same server hello, because we are stateless, but this message is in transcript
// TODO - pass selected parameters here from receiver
func GenerateStatelessHRR(datagram []byte, ck cookie.Cookie, keyShareSet bool) []byte {
	helloRetryRequest := format.ServerHello{
		CipherSuite: format.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	helloRetryRequest.SetHelloRetryRequest()
	helloRetryRequest.Extensions.SupportedVersionsSet = true
	helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = format.DTLS_VERSION_13
	if keyShareSet {
		helloRetryRequest.Extensions.KeyShareSet = true
		helloRetryRequest.Extensions.KeyShare.KeyShareHRRSelectedGroup = format.SupportedGroup_X25519
	}
	helloRetryRequest.Extensions.CookieSet = true
	helloRetryRequest.Extensions.Cookie = ck
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		SequenceNumber: 0,
	}
	msgHeader := format.MessageHandshakeHeader{
		HandshakeType: format.HandshakeTypeServerHello,
		Length:        0,
		FragmentInfo: format.FragmentInfo{
			MessageSeq:     0,
			FragmentOffset: 0,
			FragmentLength: 0,
		},
	}
	// first reserve space for headers by writing with not all variables set
	datagram = recordHdr.Write(datagram, 0) // reserve space
	recordHeaderSize := len(datagram)
	datagram = msgHeader.Write(datagram) // reserve space
	msgHeaderSize := len(datagram) - recordHeaderSize
	datagram = helloRetryRequest.Write(datagram)
	msgBodySize := len(datagram) - recordHeaderSize - msgHeaderSize
	msgHeader.Length = uint32(msgBodySize)
	msgHeader.FragmentLength = msgHeader.Length
	// now overwrite reserved space
	_ = recordHdr.Write(datagram[:0], msgHeaderSize+msgBodySize)
	_ = msgHeader.Write(datagram[recordHeaderSize:recordHeaderSize])
	return datagram
}

func generateEncryptedExtensions() format.MessageHandshake {
	ee := format.ExtensionsSet{
		SupportedGroupsSet: true,
	}
	ee.SupportedGroups.SECP256R1 = true
	ee.SupportedGroups.SECP384R1 = true
	ee.SupportedGroups.SECP512R1 = true
	ee.SupportedGroups.X25519 = true

	messageBody := ee.Write(nil, false, false, false) // TODO - reuse message bodies in a rope
	return format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeEncryptedExtensions,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}
}

func generateServerCertificate(opts *options.TransportOptions) format.MessageHandshake {
	msg := format.MessageCertificate{
		CertificatesLength: len(opts.ServerCertificate.Certificate),
	}
	for i, certData := range opts.ServerCertificate.Certificate {
		msg.Certificates[i].CertData = certData // those slices are not retained beyond this func
	}
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeCertificate,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}
}

func generateServerCertificateVerify(opts *options.TransportOptions, hctx *HandshakeConnection) (format.MessageHandshake, error) {
	msg := format.MessageCertificateVerify{
		SignatureScheme: format.SignatureAlgorithm_RSA_PSS_RSAE_SHA256,
	}

	// [rfc8446:4.4.3] - certificate verification
	var certVerifyTranscriptHashStorage [constants.MaxHashLength]byte
	certVerifyTranscriptHash := hctx.TranscriptHasher.Sum(certVerifyTranscriptHashStorage[:0])

	var sigMessageHashStorage [constants.MaxHashLength]byte
	sigMessageHash := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash, sigMessageHashStorage[:0])

	privateRsa := opts.ServerCertificate.PrivateKey.(*rsa.PrivateKey)
	sig, err := signature.CreateSignature_RSA_PSS_RSAE_SHA256(opts.Rnd, privateRsa, sigMessageHash)
	if err != nil {
		log.Printf("create signature error: %v", err)
		return format.MessageHandshake{}, dtlserrors.ErrCertificateVerifyMessageSignature
	}
	msg.Signature = sig
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope

	return format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeCertificateVerify,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}, nil
}
