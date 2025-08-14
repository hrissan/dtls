package receiver

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"hash"
	"log"
	"net/netip"
	"time"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/signature"
	"github.com/hrissan/tinydtls/transport/handshake"
	"golang.org/x/crypto/curve25519"
)

func (rc *Receiver) OnClientHello(messageBody []byte, handshakeHdr format.MessageHandshakeHeader, msg format.ClientHello, addr netip.AddrPort) {
	if !rc.opts.RoleServer {
		rc.opts.Stats.ErrorClientReceivedClientHello(addr)
		// TODO - send alert
		return
	}

	if err := IsSupportedClientHello(&msg); err != nil {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, err)
		// TODO - generate alert
		return
	}
	if !msg.Extensions.CookieSet {
		if handshakeHdr.MessageSeq != 0 {
			rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithoutCookieMsgSeqNum)
			// TODO - generate alert
			return
		}
		transcriptHasher := sha256.New()
		handshakeHdr.AddToHash(transcriptHasher)
		_, _ = transcriptHasher.Write(messageBody)
		//addMessageDataTranscript(transcriptHasher, messageBody)
		var initialHelloTranscriptHash [constants.MaxHashLength]byte
		transcriptHasher.Sum(initialHelloTranscriptHash[:0])

		keyShareSet := !msg.Extensions.KeyShare.X25519PublicKeySet
		ck := rc.cookieState.CreateCookie(initialHelloTranscriptHash, keyShareSet, addr, time.Now())
		rc.opts.Stats.CookieCreated(addr)

		hrrDatagram, _ := rc.snd.PopHelloRetryDatagram()
		hrrDatagram = generateStatelessHRR(hrrDatagram, ck, keyShareSet)
		hrrHash := sha256.Sum256(hrrDatagram)
		log.Printf("serverHRRHash: %x\n", hrrHash[:])
		rc.snd.SendHelloRetryDatagram(hrrDatagram, addr)
		return
	}
	if handshakeHdr.MessageSeq != 1 {
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrClientHelloWithCookieMsgSeqNum)
		// TODO - generate alert
		return
	}
	if !msg.Extensions.KeyShare.X25519PublicKeySet {
		// we asked for this key_share above, but client disrespected our demand
		rc.opts.Stats.ErrorClientHelloUnsupportedParams(handshakeHdr, msg, addr, ErrSupportOnlyX25519)
		// TODO - generate alert
		return
	}
	valid, age, initialHelloTranscriptHash, keyShareSet := rc.cookieState.IsCookieValid(addr, msg.Extensions.Cookie, time.Now())
	if age > rc.opts.CookieValidDuration {
		valid = false
	}
	rc.opts.Stats.CookieChecked(valid, age, addr)
	if !valid {
		// generate alert
		return
	}

	hctx, ok := rc.handshakes[addr]
	if ok { // TODO - replace older handshakes with the new ones (by cookie age)
		return
	}
	//rc.previousCode(localRandom, x25519key, messageBody, handshakeHdr, msg, addr, initialHelloTranscriptHash, keyShareSet)

	hctx = &handshake.HandshakeConnection{
		Addr:             addr,
		RoleServer:       true,
		TranscriptHasher: sha256.New(),
	}
	hctx.Keys.NextEpoch0SequenceReceive = 1 // TODO - get from plaintext record we received
	hctx.Keys.NextEpoch0SequenceSend = 1    // sequence 0 was HRR
	hctx.Keys.NextMessageSeqSend = 1        // message 0 was HRR
	hctx.Keys.NextMessageSeqReceive = 2     // message 0, 1 were initial client_hello, client_hello
	rc.handshakes[addr] = hctx
	// TODO - check if the same handshake by storing (age, initialHelloTranscriptHash, keyShareSet)
	{
		var hrrDatagramStorage [constants.MaxOutgoingHRRDatagramLength]byte
		hrrDatagram := generateStatelessHRR(hrrDatagramStorage[:0], msg.Extensions.Cookie, keyShareSet)
		if len(hrrDatagram) > len(hrrDatagramStorage) {
			panic("Large HRR datagram must not be generated")
		}
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
	rc.opts.Rnd.ReadMust(hctx.Keys.LocalRandom[:])
	rc.opts.Rnd.ReadMust(hctx.Keys.X25519Secret[:])
	hctx.Keys.ComputeKeyShare()

	serverHello := format.ServerHello{
		Random:      hctx.Keys.LocalRandom,
		CipherSuite: format.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	serverHello.Extensions.SupportedVersionsSet = true
	serverHello.Extensions.SupportedVersions.SelectedVersion = format.DTLS_VERSION_13
	serverHello.Extensions.KeyShareSet = true
	serverHello.Extensions.KeyShare.X25519PublicKeySet = true
	serverHello.Extensions.KeyShare.X25519PublicKey = hctx.Keys.X25519Public
	// TODO - get body from the rope
	serverHelloBody := serverHello.Write(nil)
	serverHelloMessage := format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeServerHello,
			Length:        uint32(len(serverHelloBody)),
		},
		Body: serverHelloBody,
	}
	hctx.PushMessage(handshake.MessagesFlightServerHello, serverHelloMessage)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	sharedSecret, err := curve25519.X25519(hctx.Keys.X25519Secret[:], msg.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.Keys.ComputeHandshakeKeys(sharedSecret, handshakeTranscriptHash)

	hctx.PushMessage(handshake.MessagesFlightServerHello, rc.generateEncryptedExtensions(hctx))

	hctx.PushMessage(handshake.MessagesFlightServerHello, rc.generateServerCertificate(hctx))

	hctx.PushMessage(handshake.MessagesFlightServerHello, rc.generateServerCertificateVerify(hctx))

	hctx.PushMessage(handshake.MessagesFlightServerHello, rc.generateServerFinished(hctx))

	// TODO - compute application data secret here, compute keys as soon as previous epoch not needed
	//handshakeTranscriptHash = hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])
	//hctx.Keys.ComputeServerApplicationKeys(handshakeTranscriptHash)
	//hctx.Keys.ComputeClientApplicationKeys()

	rc.snd.RegisterConnectionForSend(hctx)
}

func debugPrintSum(hasher hash.Hash) {
	var ha [constants.MaxHashLength]byte
	hasher.Sum(ha[:0])
	log.Printf("%x\n", ha[:])
}

var ErrSupportOnlyDTLS13 = errors.New("we support only DTLS 1.3")
var ErrSupportOnlyTLS_AES_128_GCM_SHA256 = errors.New("we support only TLS_AES_128_GCM_SHA256 ciphersuite for now")
var ErrSupportOnlyX25519 = errors.New("we support only X25519 key share for now")
var ErrClientHelloWithoutCookieMsgSeqNum = errors.New("client hello without cookie must have msg_seq_num 0")
var ErrClientHelloWithCookieMsgSeqNum = errors.New("client hello with cookie must have msg_seq_num 1")

func IsSupportedClientHello(msg *format.ClientHello) error {
	if !msg.Extensions.SupportedVersions.DTLS_13 {
		return ErrSupportOnlyDTLS13
	}
	if !msg.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 {
		return ErrSupportOnlyTLS_AES_128_GCM_SHA256
	}
	if !msg.Extensions.SupportedGroups.X25519 {
		return ErrSupportOnlyX25519
	}
	return nil
}

// we must generate the same server hello, because we are stateless, but this message is in transcript
func generateStatelessHRR(datagram []byte, ck cookie.Cookie, keyShareSet bool) []byte {
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
		Epoch:          0,
		SequenceNumber: 0,
	}
	msgHeader := format.MessageHandshakeHeader{
		HandshakeType:  format.HandshakeTypeServerHello,
		Length:         0,
		MessageSeq:     0,
		FragmentOffset: 0,
		FragmentLength: 0,
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

func addMessageDataTranscript(transcriptHasher hash.Hash, messageData []byte) {
	_, _ = transcriptHasher.Write(messageData[:4])
	_, _ = transcriptHasher.Write(messageData[12:])
}

func (rc *Receiver) generateEncryptedExtensions(hctx *handshake.HandshakeConnection) format.MessageHandshake {
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

func (rc *Receiver) generateServerCertificate(hctx *handshake.HandshakeConnection) format.MessageHandshake {
	msg := format.MessageCertificate{
		CertificatesLength: len(rc.opts.ServerCertificate.Certificate),
	}
	for i, certData := range rc.opts.ServerCertificate.Certificate {
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

func (rc *Receiver) generateServerCertificateVerify(hctx *handshake.HandshakeConnection) format.MessageHandshake {
	msg := format.MessageCertificateVerify{
		SignatureScheme: format.SignatureAlgorithm_RSA_PSS_RSAE_SHA256,
	}

	// [rfc8446:4.4.3] - certificate verification
	var certVerifyTranscriptHashStorage [constants.MaxHashLength]byte
	certVerifyTranscriptHash := hctx.TranscriptHasher.Sum(certVerifyTranscriptHashStorage[:0])

	var sigMessageHashStorage [constants.MaxHashLength]byte
	sigMessageHash := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash, sigMessageHashStorage[:0])

	privateRsa := rc.opts.ServerCertificate.PrivateKey.(*rsa.PrivateKey)
	sig, err := signature.CreateSignature_RSA_PSS_RSAE_SHA256(rc.opts.Rnd, privateRsa, sigMessageHash)
	if err != nil {
		log.Printf("create signature error: %v", err)
		// TODO - now what? Close connection probably.
	}
	msg.Signature = sig
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope

	return format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeCertificateVerify,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}
}

func (rc *Receiver) generateServerFinished(hctx *handshake.HandshakeConnection) format.MessageHandshake {
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHashStorage [constants.MaxHashLength]byte
	finishedTranscriptHash := hctx.TranscriptHasher.Sum(finishedTranscriptHashStorage[:0])

	mustBeFinished := hctx.Keys.ComputeServerFinished(sha256.New(), finishedTranscriptHash)

	msg := format.MessageFinished{
		VerifyDataLength: len(mustBeFinished),
	}
	copy(msg.VerifyData[:], mustBeFinished)
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeFinished,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}
}
