package receiver

import (
	"crypto/ecdh"
	"errors"
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/handshake"
)

var ErrServerHRRContainsNoCookie = errors.New("server HRR contains no cookie")

func (rc *Receiver) OnServerHello(conn *handshake.ConnectionImpl, messageBody []byte, handshakeHdr format.MessageHandshakeHeader, serverHello format.ServerHello, addr netip.AddrPort, rn format.RecordNumber) error {
	if rc.opts.RoleServer {
		rc.opts.Stats.ErrorServerReceivedServerHello(addr)
		return dtlserrors.ErrServerHelloReceivedByServer
	}
	if conn == nil {
		return dtlserrors.ErrServerHelloNoActiveConnection
	}

	if err := rc.onServerHello(conn, messageBody, handshakeHdr, serverHello, addr, rn); err != nil {
		return err
	}
	rc.snd.RegisterConnectionForSend(conn)
	return nil
}

func (rc *Receiver) onServerHello(conn *handshake.ConnectionImpl, messageBody []byte, handshakeHdr format.MessageHandshakeHeader, serverHello format.ServerHello, addr netip.AddrPort, rn format.RecordNumber) error {
	if conn.Handshake == nil {
		return nil // retransmission after connection already established, ignore
	}
	hctx := conn.Handshake
	if serverHello.Extensions.SupportedVersions.SelectedVersion != format.DTLS_VERSION_13 {
		return dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if serverHello.CipherSuite != format.CypherSuite_TLS_AES_128_GCM_SHA256 {
		return dtlserrors.ErrParamsSupportCiphersuites
	}
	// TODO - should we check received record sequence number?
	if serverHello.IsHelloRetryRequest() {
		// HRR is never acked, because there is no context on server for that
		if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
			return dtlserrors.ErrClientHelloUnsupportedParams
		}
		if handshakeHdr.MessageSeq != 0 {
			// TODO - fatal alert. Looks dangerous for state machine
			log.Printf("ServerHelloRetryRequest has MessageSeq != 0, ignoring")
			return dtlserrors.ErrClientHelloUnsupportedParams
		}
		conn.Keys.NextMessageSeqReceive++ // never overflows due to check above
		if !serverHello.Extensions.CookieSet {
			return dtlserrors.ErrServerHRRMustContainCookie
		}
		if !hctx.ReceivedFlight(conn, handshake.MessagesFlightServerHRR) {
			return nil
		}
		// [rfc8446:4.4.1] replace initial hello message with its hash if HRR was used
		var initialHelloTranscriptHashStorage [constants.MaxHashLength]byte
		initialHelloTranscriptHash := hctx.TranscriptHasher.Sum(initialHelloTranscriptHashStorage[:0])
		hctx.TranscriptHasher.Reset()
		syntheticHashData := []byte{format.HandshakeTypeMessageHash, 0, 0, byte(len(initialHelloTranscriptHash))}
		_, _ = hctx.TranscriptHasher.Write(syntheticHashData)
		_, _ = hctx.TranscriptHasher.Write(initialHelloTranscriptHash)

		handshakeHdr.AddToHash(hctx.TranscriptHasher)
		_, _ = hctx.TranscriptHasher.Write(messageBody)

		clientHelloMsg := rc.generateClientHello(hctx, true, serverHello.Extensions.Cookie)
		hctx.PushMessage(conn, clientHelloMsg)
		return nil
	}
	// ServerHello can have messageSeq 0 or 1, depending on whether server used HRR
	if handshakeHdr.MessageSeq < conn.Keys.NextMessageSeqReceive {
		hctx.AddAck(handshakeHdr.MessageSeq, rn)
		return nil // repeat of server hello, because we did not ack it yet
	}
	if handshakeHdr.MessageSeq > conn.Keys.NextMessageSeqReceive {
		return nil // not expecting message
	}
	if handshakeHdr.MessageSeq >= 2 {
		// TODO - fatal alert. Looks dangerous for state machine
		log.Printf("ServerHello has MessageSeq >= 2, ignoring")
		return dtlserrors.ErrClientHelloUnsupportedParams
	}
	conn.Keys.NextMessageSeqReceive++ // never overflows due to check above

	if !serverHello.Extensions.KeyShare.X25519PublicKeySet {
		return dtlserrors.ErrParamsSupportKeyShare
	}
	if !hctx.ReceivedFlight(conn, handshake.MessagesFlightServerHello_Finished) {
		return nil
	}
	handshakeHdr.AddToHash(hctx.TranscriptHasher)
	_, _ = hctx.TranscriptHasher.Write(messageBody)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	// TODO - move to calculator goroutine
	remotePublic, err := ecdh.X25519().NewPublicKey(serverHello.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	sharedSecret, err := hctx.X25519Secret.ECDH(remotePublic)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	hctx.MasterSecret, hctx.HandshakeTrafficSecretSend, hctx.HandshakeTrafficSecretReceive = conn.Keys.ComputeHandshakeKeys(false, sharedSecret, handshakeTranscriptHash)
	conn.Keys.SequenceNumberLimitExp = 5 // TODO - set for actual cipher suite. Small value is for testing.

	log.Printf("processed server hello")
	return nil
}

func (rc *Receiver) generateClientHello(hctx *handshake.HandshakeConnection, setCookie bool, ck cookie.Cookie) format.MessageHandshake {
	// [rfc8446:4.1.2] the client MUST send the same ClientHello without modification, except as follows
	clientHello := format.ClientHello{
		Random: hctx.LocalRandom,
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
	copy(clientHello.Extensions.KeyShare.X25519PublicKey[:], hctx.X25519Secret.PublicKey().Bytes())

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
	return format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeClientHello,
			Length:        uint32(len(messageBody)),
		},
		Body: messageBody,
	}
}
