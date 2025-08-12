package receiver

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/handshake"
	"github.com/hrissan/tinydtls/transport/options"
	"github.com/hrissan/tinydtls/transport/sender"
	"golang.org/x/crypto/curve25519"
)

var ErrServerCannotStartConnection = errors.New("server can start connection")

// Receiver also performs stateless logic

type Receiver struct {
	opts        *options.TransportOptions
	cookieState cookie.CookieState
	snd         *sender.Sender

	mu           sync.Mutex
	sendCond     *sync.Cond
	sendShutdown bool

	handMu sync.Mutex
	// TODO - limit on max number of parallel handshakes, clear items by LRU
	// only ClientHello with correct cookie and larger timestamp replaces previous handshake here [rfc9147:5.11]
	handshakes map[netip.AddrPort]*handshake.HandshakeConnection

	// we move handshake here, once it is finished
	//connections map[netip.AddrPort]*Connection

}

func NewReceiver(opts *options.TransportOptions, snd *sender.Sender) *Receiver {
	rc := &Receiver{
		opts:       opts,
		snd:        snd,
		handshakes: map[netip.AddrPort]*handshake.HandshakeConnection{},
	}
	rc.cookieState.SetRand(opts.Rnd)
	return rc
}

// socket must be closed by socket owner (externally)
func (rc *Receiver) Close() {
}

// blocks until socket is closed (externally)
func (rc *Receiver) GoRunUDP(socket *net.UDPConn) {
	datagram := make([]byte, 65536)
	for {
		n, addr, err := socket.ReadFromUDPAddrPort(datagram)
		if n != 0 { // do not check for an error here
			rc.opts.Stats.SocketReadDatagram(datagram[:n], addr)
			rc.processDatagram(datagram[:n], addr)
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			rc.opts.Stats.SocketReadError(n, addr, err)
			time.Sleep(rc.opts.SocketReadErrorDelay)
		}
	}
}

func (rc *Receiver) processDatagram(datagram []byte, addr netip.AddrPort) {
	recordOffset := 0                  // Multiple DTLS records MAY be placed in a single datagram [rfc9147:4.3]
	for recordOffset < len(datagram) { // read records one by one
		fb := datagram[recordOffset]
		if format.IsCiphertextRecord(fb) {
			var hdr format.CiphertextRecordHeader
			n, cid, body, err := hdr.Parse(datagram[recordOffset:], rc.opts.CIDLength) // TODO - CID
			if err != nil {
				rc.opts.Stats.BadRecord("ciphertext", recordOffset, len(datagram), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			recordOffset += n
			rc.processCiphertextRecord(hdr, cid, body, addr) // errors inside do not conflict with our ability to process next record
			continue
		}
		if format.IsPlaintextRecord(fb) {
			var hdr format.PlaintextRecordHeader
			n, body, err := hdr.Parse(datagram[recordOffset:])
			if err != nil {
				rc.opts.Stats.BadRecord("plaintext", recordOffset, len(datagram), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			recordOffset += n
			rc.processPlaintextRecord(hdr, body, addr) // errors inside do not conflict with our ability to process next record
			continue
		}
		rc.opts.Stats.BadRecord("unknown", recordOffset, len(datagram), addr, format.ErrRecordTypeFailedToParse)
		// TODO: alert here, and we cannot continue to the next record.
		return
	}
}

func (rc *Receiver) StartConnection(peerAddr netip.AddrPort) error {
	if rc.opts.RoleServer {
		return ErrServerCannotStartConnection
	}
	ha, err := rc.startConnection(peerAddr)
	if ha != nil { // motivation: do not register under our lock
		rc.snd.RegisterConnectionForSend(ha)
	}
	return err
}

func (rc *Receiver) startConnection(peerAddr netip.AddrPort) (*handshake.HandshakeConnection, error) {
	rc.handMu.Lock()
	defer rc.handMu.Unlock()
	ha := rc.handshakes[peerAddr]
	if ha != nil {
		return nil, nil // for now will wait for previous handshake timeout first
	}

	ha = &handshake.HandshakeConnection{Addr: peerAddr}
	rc.handshakes[peerAddr] = ha

	clientHello := format.ClientHello{}
	rc.opts.Rnd.Read(clientHello.Random[:])
	clientHello.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 = true
	clientHello.Extensions.SupportedVersionsSet = true
	clientHello.Extensions.SupportedVersions.DTLS_13 = true
	clientHello.Extensions.SupportedGroupsSet = true
	clientHello.Extensions.SupportedGroups.SECP256R1 = false
	clientHello.Extensions.SupportedGroups.SECP384R1 = false
	clientHello.Extensions.SupportedGroups.SECP521R1 = false
	clientHello.Extensions.SupportedGroups.X25519 = true

	// We'd like to not create key_share here before getting HRR, but wolfssl responds with "missing extenstion" alert
	clientHello.Extensions.KeyShareSet = true
	clientHello.Extensions.KeyShare.X25519PublicKeySet = true
	rc.opts.Rnd.Read(ha.Keys.X25519Secret[:])
	x25519Public, err := curve25519.X25519(ha.Keys.X25519Secret[:], curve25519.Basepoint)
	if err != nil {
		panic("curve25519.X25519 failed")
	}
	copy(clientHello.Extensions.KeyShare.X25519PublicKey[:], x25519Public)

	clientHello.Extensions.SignatureAlgorithmsSet = true // TODO - set only those we actually support
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP256r1_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP384r1_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP512r1_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SHA1 = false // insecure, TODO - remove from our code?
	clientHello.Extensions.SignatureAlgorithms.ED25519 = false
	clientHello.Extensions.SignatureAlgorithms.ED448 = false
	// clientHello.Extensions.EncryptThenMacSet = true // not needed in DTLS1.3, but wolf sends it

	ha.MessagesFlight = handshake.MessagesFlightClientHello1

	messageBody := clientHello.Write(nil) // TODO - reuse message bodies in a rope
	msg := format.MessageHandshake{
		Header: format.MessageHandshakeHeader{
			HandshakeType: format.HandshakeTypeClientHello,
			Length:        uint32(len(messageBody)),
			MessageSeq:    0, // TODO - set automatically from Keys
		},
		Body: messageBody,
	}
	ha.MessagesSendQueue = append(ha.MessagesSendQueue, msg)
	return ha, nil
}
