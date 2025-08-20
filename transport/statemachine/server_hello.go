package statemachine

import (
	"crypto/ecdh"
	"log"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/record"
)

func (conn *ConnectionImpl) ReceivedServerHelloFragment(fragment handshake.Fragment, rn record.Number) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.hctx == nil {
		return nil // retransmission, while connection already established
	}
	if fragment.Header.MsgSeq < conn.FirstMessageSeqInReceiveQueue() {
		// all messages before were processed by us in the state we already do not remember,
		// so we must acknowledge unconditionally and do nothing.
		conn.keys.AddAck(rn)
		return nil
	}
	return conn.hctx.ReceivedFragment(conn, fragment, rn)
}

func (hctx *handshakeContext) onServerHello(conn *ConnectionImpl, msg handshake.Message, serverHello handshake.MsgServerHello) error {
	if serverHello.Extensions.SupportedVersions.SelectedVersion != handshake.DTLS_VERSION_13 {
		return dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if serverHello.CipherSuite != handshake.CypherSuite_TLS_AES_128_GCM_SHA256 {
		return dtlserrors.ErrParamsSupportCiphersuites
	}
	if serverHello.IsHelloRetryRequest() {
		if !serverHello.Extensions.CookieSet {
			return dtlserrors.ErrServerHRRMustContainCookie
		}
		if !hctx.ReceivedFlight(conn, MessagesFlightServerHRR) {
			return nil
		}
		// [rfc8446:4.4.1] replace initial hello message with its hash if HRR was used
		var initialHelloTranscriptHashStorage [constants.MaxHashLength]byte
		initialHelloTranscriptHash := hctx.transcriptHasher.Sum(initialHelloTranscriptHashStorage[:0])
		hctx.transcriptHasher.Reset()
		syntheticHashData := []byte{byte(handshake.MsgTypeMessageHash), 0, 0, byte(len(initialHelloTranscriptHash))}
		_, _ = hctx.transcriptHasher.Write(syntheticHashData)
		_, _ = hctx.transcriptHasher.Write(initialHelloTranscriptHash)

		msg.AddToHash(hctx.transcriptHasher)

		clientHelloMsg := hctx.GenerateClientHello(true, serverHello.Extensions.Cookie)
		return hctx.PushMessage(conn, clientHelloMsg)
	}
	// ServerHello can have messageSeq 0 or 1, depending on whether server used HRR
	if msg.MsgSeq >= 2 {
		// TODO - fatal alert. Looks dangerous for state machine
		log.Printf("ServerHello has MsgSeq >= 2, ignoring")
		return dtlserrors.ErrClientHelloUnsupportedParams
	}

	if !serverHello.Extensions.KeyShare.X25519PublicKeySet {
		return dtlserrors.ErrParamsSupportKeyShare
	}
	if !hctx.ReceivedFlight(conn, MessagesFlightServerHello_Finished) {
		return nil
	}
	msg.AddToHash(hctx.transcriptHasher)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.transcriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	// TODO - move to calculator goroutine
	remotePublic, err := ecdh.X25519().NewPublicKey(serverHello.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	sharedSecret, err := hctx.x25519Secret.ECDH(remotePublic)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.masterSecret, hctx.handshakeTrafficSecretSend, hctx.handshakeTrafficSecretReceive = conn.keys.ComputeHandshakeKeys(false, sharedSecret, handshakeTranscriptHash)
	conn.keys.SequenceNumberLimitExp = 5 // TODO - set for actual cipher suite. Small value is for testing.

	log.Printf("processed server hello")
	return nil
}

func (hctx *handshakeContext) GenerateClientHello(setCookie bool, ck cookie.Cookie) handshake.Message {
	// [rfc8446:4.1.2] the client MUST send the same ClientHello without modification, except as follows
	clientHello := handshake.MsgClientHello{
		Random: hctx.localRandom,
	}
	clientHello.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 = true
	clientHello.Extensions.SupportedVersionsSet = true
	clientHello.Extensions.SupportedVersions.DTLS_13 = true
	clientHello.Extensions.SupportedGroupsSet = true
	clientHello.Extensions.SupportedGroups.X25519 = true
	clientHello.Extensions.SupportedGroups.SECP256R1 = false
	clientHello.Extensions.SupportedGroups.SECP384R1 = false
	clientHello.Extensions.SupportedGroups.SECP512R1 = false

	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	clientHello.Extensions.KeyShareSet = true
	clientHello.Extensions.KeyShare.X25519PublicKeySet = true
	copy(clientHello.Extensions.KeyShare.X25519PublicKey[:], hctx.x25519Secret.PublicKey().Bytes())

	// We need signature algorithms to sign and check certificate_verify,
	// so we need to support lots of them.
	// TODO - set only those we actually support
	clientHello.Extensions.SignatureAlgorithmsSet = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP256r1_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP384r1_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP512r1_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PKCS1_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PKCS1_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PKCS1_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_RSAE_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_PSS_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_RSAE_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_PSS_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_RSAE_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_PSS_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.ED25519 = false
	clientHello.Extensions.SignatureAlgorithms.ED448 = false
	clientHello.Extensions.EncryptThenMacSet = false // not needed in DTLS1.3, but wolf sends it

	if setCookie {
		clientHello.Extensions.CookieSet = true
		clientHello.Extensions.Cookie = ck
	}

	messageBody := clientHello.Write(nil) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeClientHello,
		Body:    messageBody,
	}
}
