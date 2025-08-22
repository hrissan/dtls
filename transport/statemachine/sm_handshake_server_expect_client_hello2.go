// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/ecdh"
	"crypto/sha256"
	"log"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/transport/options"
)

type smHandshakeServerExpectClientHello2 struct {
	smHandshake
}

func (*smHandshakeServerExpectClientHello2) OnClientHello2(conn *ConnectionImpl, opts *options.TransportOptions,
	msg handshake.Message, msgClientHello handshake.MsgClientHello,
	initialHelloTranscriptHash [constants.MaxHashLength]byte, keyShareSet bool) error {

	// TODO - replace older handshakes with the new ones (by cookie age or other parameters)
	// attacker cannot control age for addr, so will not be able to disrupt connection by sending
	// rogue packets
	hctx := newHandshakeContext(sha256.New())
	conn.hctx = hctx

	// formally this is the next flight, but as there were no state, do not call it
	// hctx.receivedNextFlight(conn)

	conn.hctx.sendNextRecordSequenceEpoch0 = 1 // sequence 0 was HRR

	conn.nextMessageSeqSend = 1    // message 0 was HRR
	conn.nextMessageSeqReceive = 2 // message 0, 1 were initial client_hello, client_hello
	// TODO - check if the same handshake by storing (age, initialHelloTranscriptHash, keyShareSet)
	{
		var hrrDatagramStorage [constants.MaxOutgoingHRRDatagramLength]byte
		hrrDatagram, msgBody := GenerateStatelessHRR(hrrDatagramStorage[:0], msgClientHello.Extensions.Cookie, keyShareSet)
		if len(hrrDatagram) > len(hrrDatagramStorage) {
			panic("Large HRR datagram must not be generated")
		}
		hrrHash := sha256.Sum256(hrrDatagram)
		log.Printf("serverHRRHash2: %x\n", hrrHash[:])

		// [rfc8446:4.4.1] replace initial client hello message with its hash if HRR was used
		syntheticMessage := handshake.Message{
			MsgType: handshake.MsgTypeMessageHash,
			MsgSeq:  0, // does not affect transcript hash
			Body:    initialHelloTranscriptHash[:sha256.Size],
		}
		syntheticMessage.AddToHash(hctx.transcriptHasher)
		debugPrintSum(hctx.transcriptHasher)

		// then add reconstructed HRR
		hrrMessage := handshake.Message{
			MsgType: handshake.MsgTypeServerHello,
			MsgSeq:  0, // does not affect transcript hash
			Body:    msgBody,
		}
		hrrMessage.AddToHash(hctx.transcriptHasher)
		debugPrintSum(hctx.transcriptHasher)

		// then add second client hello
		msg.AddToHash(hctx.transcriptHasher)
		debugPrintSum(hctx.transcriptHasher)
	}
	log.Printf("start handshake keyShareSet=%v initial hello transcript hash(hex): %x", keyShareSet, initialHelloTranscriptHash)
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
	hctx.masterSecret, hctx.handshakeTrafficSecretSend, hctx.handshakeTrafficSecretReceive = conn.keys.ComputeHandshakeKeys(true, sharedSecret, handshakeTranscriptHash)
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
