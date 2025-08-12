package receiver

import (
	"errors"
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/handshake"
)

var ErrServerHRRContainsNoCookie = errors.New("server HRR contains no cookie")

func (rc *Receiver) OnServerHello(messageData []byte, handshakeHdr format.MessageHandshakeHeader, serverHello format.ServerHello, addr netip.AddrPort) {
	if rc.opts.RoleServer {
		rc.opts.Stats.ErrorServerReceivedServerHello(addr)
		// TODO - send alert
		return
	}
	hctxToSend, err := rc.onServerHello(messageData, handshakeHdr, serverHello, addr)
	if hctxToSend != nil { // motivation: do not register under our lock
		rc.snd.RegisterConnectionForSend(hctxToSend)
	}
	if err != nil {
		rc.opts.Stats.ErrorServerHelloUnsupportedParams(handshakeHdr, serverHello, addr, err)
		// TODO - send alert
	}
}

func (rc *Receiver) onServerHello(messageData []byte, handshakeHdr format.MessageHandshakeHeader, serverHello format.ServerHello, addr netip.AddrPort) (*handshake.HandshakeConnection, error) {
	rc.handMu.Lock()
	defer rc.handMu.Unlock()
	hctx := rc.handshakes[addr]
	if hctx == nil {
		// TODO - send alert here
		return nil, nil
	}
	if serverHello.Extensions.SupportedVersions.SelectedVersion != format.DTLS_VERSION_13 {
		return nil, ErrSupportOnlyDTLS13
	}
	if serverHello.CipherSuite != format.CypherSuite_TLS_AES_128_GCM_SHA256 {
		return nil, ErrSupportOnlyTLS_AES_128_GCM_SHA256
	}

	if serverHello.IsHelloRetryRequest() {
		if !serverHello.Extensions.CookieSet {
			return nil, ErrServerHRRContainsNoCookie
		}
		clientHelloMsg := rc.generateClientHello(hctx, true, serverHello.Extensions.Cookie)
		hctx.PushMessage(handshake.MessagesFlightClientHello2, clientHelloMsg)
		return hctx, nil
	}
	log.Printf("TODO - process server hello")
	return nil, nil
}

func (rc *Receiver) generateClientHello(hctx *handshake.HandshakeConnection, setCookie bool, ck cookie.Cookie) format.MessageHandshake {
	// [rfc8446:4.1.2] the client MUST send the same ClientHello without modification, except as follows
	clientHello := format.ClientHello{
		Random: hctx.Keys.LocalRandom,
	}
	clientHello.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 = true
	clientHello.Extensions.SupportedVersionsSet = true
	clientHello.Extensions.SupportedVersions.DTLS_13 = true
	clientHello.Extensions.SupportedGroupsSet = true
	clientHello.Extensions.SupportedGroups.SECP256R1 = false
	clientHello.Extensions.SupportedGroups.SECP384R1 = false
	clientHello.Extensions.SupportedGroups.SECP521R1 = false
	clientHello.Extensions.SupportedGroups.X25519 = true

	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	clientHello.Extensions.KeyShareSet = true
	clientHello.Extensions.KeyShare.X25519PublicKeySet = true
	clientHello.Extensions.KeyShare.X25519PublicKey = hctx.Keys.X25519Public

	clientHello.Extensions.SignatureAlgorithmsSet = true // TODO - set only those we actually support
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP256r1_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP384r1_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP512r1_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SHA1 = false // insecure, TODO - remove from our code?
	clientHello.Extensions.SignatureAlgorithms.ED25519 = false
	clientHello.Extensions.SignatureAlgorithms.ED448 = false
	// clientHello.Extensions.EncryptThenMacSet = true // not needed in DTLS1.3, but wolf sends it

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
