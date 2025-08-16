package receiver

import (
	"errors"
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/handshake"
	"golang.org/x/crypto/curve25519"
)

var ErrServerHRRContainsNoCookie = errors.New("server HRR contains no cookie")

func (rc *Receiver) OnServerHello(messageBody []byte, handshakeHdr format.MessageHandshakeHeader, serverHello format.ServerHello, addr netip.AddrPort) {
	if rc.opts.RoleServer {
		rc.opts.Stats.ErrorServerReceivedServerHello(addr)
		// TODO - send alert
		return
	}
	hctxToSend, err := rc.onServerHello(messageBody, handshakeHdr, serverHello, addr)
	if hctxToSend != nil { // motivation: do not register under our lock
		rc.snd.RegisterConnectionForSend(hctxToSend)
	}
	if err != nil {
		rc.opts.Stats.ErrorServerHelloUnsupportedParams(handshakeHdr, serverHello, addr, err)
		// TODO - send alert
	}
}

func (rc *Receiver) onServerHello(messageBody []byte, handshakeHdr format.MessageHandshakeHeader, serverHello format.ServerHello, addr netip.AddrPort) (*handshake.ConnectionImpl, error) {
	rc.handMu.Lock()
	conn := rc.connections[addr]
	rc.handMu.Unlock()
	if conn == nil {
		// TODO - send alert here
		return nil, nil
	}
	if conn.Handshake == nil {
		// TODO - send alert here
		return nil, nil
	}
	hctx := conn.Handshake
	if serverHello.Extensions.SupportedVersions.SelectedVersion != format.DTLS_VERSION_13 {
		return nil, ErrSupportOnlyDTLS13
	}
	if serverHello.CipherSuite != format.CypherSuite_TLS_AES_128_GCM_SHA256 {
		return nil, ErrSupportOnlyTLS_AES_128_GCM_SHA256
	}
	if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
		return nil, nil // not expecting message
	}
	conn.Keys.NextMessageSeqReceive++

	if serverHello.IsHelloRetryRequest() {
		if !serverHello.Extensions.CookieSet {
			return nil, ErrServerHRRContainsNoCookie
		}
		if hctx.SendQueueFlight() >= handshake.MessagesFlightClientHello2 {
			return nil, nil
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
		hctx.PushMessage(conn, handshake.MessagesFlightClientHello2, clientHelloMsg)
		return conn, nil
	}
	if !serverHello.Extensions.KeyShare.X25519PublicKeySet {
		return nil, ErrSupportOnlyX25519
	}
	if hctx.SendQueueFlight() >= handshake.MessagesFlightServerHello_Finished {
		return nil, nil
	}
	hctx.AckFlight(handshake.MessagesFlightServerHello_Finished)
	handshakeHdr.AddToHash(hctx.TranscriptHasher)
	_, _ = hctx.TranscriptHasher.Write(messageBody)

	var handshakeTranscriptHashStorage [constants.MaxHashLength]byte
	handshakeTranscriptHash := hctx.TranscriptHasher.Sum(handshakeTranscriptHashStorage[:0])

	// TODO - move to calculator goroutine
	sharedSecret, err := curve25519.X25519(hctx.X25519Secret[:], serverHello.Extensions.KeyShare.X25519PublicKey[:])
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	masterSecret := conn.Keys.ComputeHandshakeKeys(false, sharedSecret, handshakeTranscriptHash)
	copy(hctx.MasterSecret[:], masterSecret)

	log.Printf("TODO - process server hello")
	return nil, nil
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
	clientHello.Extensions.KeyShare.X25519PublicKey = hctx.X25519Public

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
