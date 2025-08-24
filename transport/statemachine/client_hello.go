// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/safecast"
	"github.com/hrissan/dtls/signature"
	"github.com/hrissan/dtls/transport/options"
)

func debugPrintSum(hasher hash.Hash) {
	var ha [constants.MaxHashLength]byte
	hasher.Sum(ha[:0])
	fmt.Printf("%x\n", ha[:])
}

// we must generate the same server hello, because we are stateless, but this message is in transcript
// TODO - pass selected parameters here from receiver
func GenerateStatelessHRR(datagram []byte, ck cookie.Cookie, keyShareSet bool) ([]byte, []byte) {
	helloRetryRequest := handshake.MsgServerHello{
		CipherSuite: handshake.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	helloRetryRequest.SetHelloRetryRequest()
	helloRetryRequest.Extensions.SupportedVersionsSet = true
	helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = handshake.DTLS_VERSION_13
	if keyShareSet {
		helloRetryRequest.Extensions.KeyShareSet = true
		helloRetryRequest.Extensions.KeyShare.HRRSelectedGroup = handshake.SupportedGroup_X25519
	}
	helloRetryRequest.Extensions.CookieSet = true
	helloRetryRequest.Extensions.Cookie = ck
	recordHdr := record.PlaintextHeader{
		ContentType:    record.RecordTypeHandshake,
		SequenceNumber: 0,
	}
	// first reserve space for headers by writing with not all variables set
	datagram = append(datagram, make([]byte, record.PlaintextRecordHeaderSize+handshake.FragmentHeaderSize)...) // reserve space
	datagram = helloRetryRequest.Write(datagram)
	msgBody := datagram[record.PlaintextRecordHeaderSize+handshake.FragmentHeaderSize:]

	// now overwrite reserved space
	da := recordHdr.Write(datagram[:0], safecast.Cast[uint16](handshake.FragmentHeaderSize+len(msgBody)))

	msgHeader := handshake.FragmentHeader{
		MsgType: handshake.MsgTypeServerHello,
		Length:  safecast.Cast[uint32](len(msgBody)),
		FragmentInfo: handshake.FragmentInfo{
			MsgSeq:         0,
			FragmentOffset: 0,
			FragmentLength: safecast.Cast[uint32](len(msgBody)),
		},
	}

	_ = msgHeader.Write(da)
	return datagram, msgBody
}

func generateEncryptedExtensions() handshake.Message {
	ee := handshake.ExtensionsSet{
		SupportedGroupsSet: true,
	}
	ee.SupportedGroups.SECP256R1 = true
	ee.SupportedGroups.SECP384R1 = true
	ee.SupportedGroups.SECP512R1 = true
	ee.SupportedGroups.X25519 = true

	messageBody := ee.Write(nil, false, false, false) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeEncryptedExtensions,
		Body:    messageBody,
	}
}

func generateServerCertificate(opts *options.TransportOptions) handshake.Message {
	msg := handshake.MsgCertificate{
		CertificatesLength: len(opts.ServerCertificate.Certificate),
	}
	for i, certData := range opts.ServerCertificate.Certificate {
		msg.Certificates[i].CertData = certData // those slices are not retained beyond this func
	}
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeCertificate,
		Body:    messageBody,
	}
}

func generateServerCertificateVerify(opts *options.TransportOptions, hctx *handshakeContext) (handshake.Message, error) {
	msg := handshake.MsgCertificateVerify{
		SignatureScheme: handshake.SignatureAlgorithm_RSA_PSS_RSAE_SHA256,
	}

	// [rfc8446:4.4.3] - certificate verification
	var certVerifyTranscriptHashStorage [constants.MaxHashLength]byte
	certVerifyTranscriptHash := hctx.transcriptHasher.Sum(certVerifyTranscriptHashStorage[:0])

	var sigMessageHashStorage [constants.MaxHashLength]byte
	sigMessageHash := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash, sigMessageHashStorage[:0])

	privateRsa := opts.ServerCertificate.PrivateKey.(*rsa.PrivateKey)
	sig, err := signature.CreateSignature_RSA_PSS_RSAE_SHA256(opts.Rnd, privateRsa, sigMessageHash)
	if err != nil {
		fmt.Printf("create signature error: %v\n", err)
		return handshake.Message{}, dtlserrors.ErrCertificateVerifyMessageSignature
	}
	msg.Signature = sig
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope

	return handshake.Message{
		MsgType: handshake.MsgTypeCertificateVerify,
		Body:    messageBody,
	}, nil
}

func (conn *Connection) onClientHello2(opts *options.TransportOptions,
	msg handshake.Message, msgClientHello handshake.MsgClientHello,
	params cookie.Params, transcriptHasher hash.Hash) error {

	if params.Age <= conn.cookieAge {
		return nil
	}
	// Attacker cannot control age for addr, so will not be able to disrupt connection by sending
	// rogue packets. But they can disrupt connection if they can respond with valid cookie.
	// Big TODO - parallel handshake and fully working connection until we verify client identity
	if conn.stateID != smIDClosed {
		// TODO - close connection here, and start a new one.
		return nil
	}

	hctx := newHandshakeContext(transcriptHasher)
	conn.hctx = hctx

	// formally this is the next flight, but as there were no state, do not call it
	// hctx.receivedNextFlight(conn)

	conn.hctx.sendNextRecordSequenceEpoch0 = 1 // sequence 0 was HRR

	conn.nextMessageSeqSend = 1    // message 0 was HRR
	conn.nextMessageSeqReceive = 2 // message 0, 1 were initial client_hello, client_hello
	fmt.Printf("start handshake keyShareSet=%v initial hello transcript hash(hex): %x\n", params.KeyShareSet, params.TranscriptHash)
	opts.Rnd.ReadMust(hctx.localRandom[:])
	hctx.ComputeKeyShare(opts.Rnd)

	serverHello := handshake.MsgServerHello{
		Random:      hctx.localRandom,
		CipherSuite: handshake.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	serverHello.Extensions.SupportedVersionsSet = true
	serverHello.Extensions.SupportedVersions.SelectedVersion = handshake.DTLS_VERSION_13
	serverHello.Extensions.KeyShareSet = true
	serverHello.Extensions.KeyShare.X25519PublicKeySet = true
	copy(serverHello.Extensions.KeyShare.X25519PublicKey[:], hctx.x25519Secret.PublicKey().Bytes())
	// TODO - get body from the rope
	serverHelloBody := serverHello.Write(nil)
	serverHelloMessage := handshake.Message{
		MsgType: handshake.MsgTypeServerHello,
		Body:    serverHelloBody,
	}

	if err := hctx.PushMessage(conn, serverHelloMessage); err != nil {
		return err
	}

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.transcriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	// TODO - move to calculator goroutine
	remotePublic, err := ecdh.X25519().NewPublicKey(msgClientHello.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	sharedSecret, err := hctx.x25519Secret.ECDH(remotePublic)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.masterSecret, hctx.handshakeTrafficSecretSend, hctx.handshakeTrafficSecretReceive =
		conn.keys.ComputeHandshakeKeys(true, sharedSecret, handshakeTranscriptHash)
	conn.keys.SequenceNumberLimitExp = 5 // TODO - set for actual cipher suite. Small value is for testing.

	if err := hctx.PushMessage(conn, generateEncryptedExtensions()); err != nil {
		return err
	}

	if err := hctx.PushMessage(conn, generateServerCertificate(opts)); err != nil {
		return err
	}

	// TODO - offload to calculator goroutine
	msgCertificateVerify, err := generateServerCertificateVerify(opts, hctx)
	if err != nil {
		return err // TODO - test on this path. Should close connection immediately
	}
	if err := hctx.PushMessage(conn, msgCertificateVerify); err != nil {
		return err
	}

	if err := hctx.PushMessage(conn, hctx.generateFinished(conn)); err != nil {
		return err
	}

	handshakeTranscriptHash = hctx.transcriptHasher.Sum(handshakeTranscriptHashStorage[:0])
	conn.keys.ComputeApplicationTrafficSecret(true, hctx.masterSecret[:], handshakeTranscriptHash)
	conn.stateID = smIDHandshakeServerExpectFinished
	return nil
}
