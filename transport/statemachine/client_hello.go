// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
	"net/netip"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/safecast"
	"github.com/hrissan/dtls/signature"
	"github.com/hrissan/dtls/transport/options"
)

func debugPrintSum(hasher hash.Hash) {
	var ha ciphersuite.Hash
	ha.SetSum(hasher)
	fmt.Printf("%x\n", ha.GetValue())
}

// we must generate the same server hello, because we are stateless, but this message is in transcript
func GenerateStatelessHRR(params cookie.Params, datagram []byte, ck []byte) ([]byte, []byte) {
	helloRetryRequest := handshake.MsgServerHello{
		CipherSuite: params.CipherSuite,
	}
	helloRetryRequest.SetHelloRetryRequest()
	helloRetryRequest.Extensions.SupportedVersionsSet = true
	helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = handshake.DTLS_VERSION_13
	if params.KeyShareSet {
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

	messageBody := ee.Write(nil, false, false, false, nil) // TODO - reuse message bodies in a rope
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

func generateServerCertificateVerify(opts *options.TransportOptions, conn *Connection, hctx *handshakeContext) (handshake.Message, error) {
	msg := handshake.MsgCertificateVerify{
		SignatureScheme: handshake.SignatureAlgorithm_RSA_PSS_RSAE_SHA256,
	}

	// [rfc8446:4.4.3] - certificate verification
	var certVerifyTranscriptHash ciphersuite.Hash
	certVerifyTranscriptHash.SetSum(hctx.transcriptHasher)

	sigMessageHash := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash.GetValue())

	privateRsa := opts.ServerCertificate.PrivateKey.(*rsa.PrivateKey)
	sig, err := signature.CreateSignature_RSA_PSS_RSAE_SHA256(opts.Rnd, privateRsa, sigMessageHash.GetValue())
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

func (conn *Connection) onClientHello2Locked(opts *options.TransportOptions, addr netip.AddrPort,
	earlySecret ciphersuite.Hash, pskSelected bool, pskSelectedIdentity uint16,
	msgClientHello handshake.MsgClientHello, params cookie.Params,
	transcriptHasher hash.Hash, clientEarlyTrafficSecret ciphersuite.Hash) error {

	if conn.stateID != smIDClosed {
		// Attacker cannot control age for addr, so will not be able to disrupt connection by sending
		// rogue packets. But they can disrupt connection if they can respond with valid cookie.
		// Big TODO - parallel handshake and fully working connection until we verify client identity
		if params.TimestampUnixNano <= conn.cookieTimestampUnixNano {
			return nil // simply ignore
		}
		conn.resetToClosedLocked(false)
	}
	conn.stateID = smIDHandshakeServerCalcServerHello2
	conn.keys.SuiteID = params.CipherSuite
	conn.addr = addr
	conn.cookieTimestampUnixNano = params.TimestampUnixNano
	conn.tr.addToMap(conn, addr)

	hctx := newHandshakeContext(transcriptHasher)
	conn.hctx = hctx

	suite := conn.keys.Suite()
	// formally this is the next flight, but as there were no state, do not call it
	// hctx.receivedNextFlight(conn)

	conn.hctx.sendNextRecordSequenceEpoch0 = 1 // sequence 0 was HRR

	conn.nextMessageSeqSend = 1    // message 0 was HRR
	conn.nextMessageSeqReceive = 2 // message 0, 1 were initial client_hello, client_hello
	fmt.Printf("start handshake keyShareSet=%v initial hello transcript hash(hex): %x\n", params.KeyShareSet, params.TranscriptHash)
	opts.Rnd.ReadMust(hctx.localRandom[:])
	hctx.ComputeKeyShare(opts.Rnd)
	hctx.earlySecret = earlySecret

	if clientEarlyTrafficSecret != (ciphersuite.Hash{}) {
		conn.keys.ReceiveSymmetric = suite.ResetSymmetricKeys(conn.keys.ReceiveSymmetric, clientEarlyTrafficSecret)
		conn.keys.ReceiveEpoch = 1
	}
	fmt.Printf("server early traffic secret: %x\n", clientEarlyTrafficSecret)

	serverHello := handshake.MsgServerHello{
		Random:      hctx.localRandom,
		CipherSuite: params.CipherSuite,
	}
	serverHello.Extensions.SupportedVersionsSet = true
	serverHello.Extensions.SupportedVersions.SelectedVersion = handshake.DTLS_VERSION_13
	serverHello.Extensions.KeyShareSet = true
	serverHello.Extensions.KeyShare.X25519PublicKeySet = true
	copy(serverHello.Extensions.KeyShare.X25519PublicKey[:], hctx.x25519Secret.PublicKey().Bytes())

	serverHello.Extensions.PreSharedKeySet = pskSelected
	serverHello.Extensions.PreSharedKey.SelectedIdentity = pskSelectedIdentity

	// TODO - get body from the rope
	serverHelloBody := serverHello.Write(nil)
	serverHelloMessage := handshake.Message{
		MsgType: handshake.MsgTypeServerHello,
		Body:    serverHelloBody,
	}

	if err := hctx.PushMessage(conn, serverHelloMessage); err != nil {
		panic("pushing ServerHello must never fail")
	}

	var handshakeTranscriptHash ciphersuite.Hash
	handshakeTranscriptHash.SetSum(hctx.transcriptHasher)

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
		conn.keys.ComputeHandshakeKeys(suite, true, hctx.earlySecret, sharedSecret, handshakeTranscriptHash)

	if err := hctx.PushMessage(conn, generateEncryptedExtensions()); err != nil {
		return err
	}

	if !pskSelected {
		if err := hctx.PushMessage(conn, generateServerCertificate(opts)); err != nil {
			return err
		}

		// TODO - offload to calculator goroutine
		msgCertificateVerify, err := generateServerCertificateVerify(opts, conn, hctx)
		if err != nil {
			return err // TODO - test on this path. Should close connection immediately
		}
		if err := hctx.PushMessage(conn, msgCertificateVerify); err != nil {
			return err
		}
	}
	if err := hctx.PushMessage(conn, hctx.generateFinished(conn)); err != nil {
		return err
	}

	handshakeTranscriptHash.SetSum(hctx.transcriptHasher)
	conn.keys.ComputeApplicationTrafficSecret(suite, true, hctx.masterSecret, handshakeTranscriptHash)

	conn.stateID = smIDHandshakeServerExpectFinished
	conn.handler.OnConnectLocked()
	return nil
}
