package receiver

import (
	"crypto/sha256"
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
			n, cid, seqNum, header, body, err := hdr.Parse(datagram[recordOffset:], rc.opts.CIDLength) // TODO - CID
			if err != nil {
				rc.opts.Stats.BadRecord("ciphertext", recordOffset, len(datagram), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			recordOffset += n
			rc.deprotectCiphertextRecord(hdr, cid, seqNum, header, body, addr) // errors inside do not conflict with our ability to process next record
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
	hctxToSend, err := rc.startConnection(peerAddr)
	if hctxToSend != nil { // motivation: do not register under our lock
		rc.snd.RegisterConnectionForSend(hctxToSend)
	}
	return err
}

func (rc *Receiver) startConnection(peerAddr netip.AddrPort) (*handshake.HandshakeConnection, error) {
	rc.handMu.Lock()
	defer rc.handMu.Unlock()
	hctx := rc.handshakes[peerAddr]
	if hctx != nil {
		return nil, nil // for now will wait for previous handshake timeout first
	}

	hctx = &handshake.HandshakeConnection{
		Addr:             peerAddr,
		RoleServer:       false,
		TranscriptHasher: sha256.New(),
	}
	rc.handshakes[peerAddr] = hctx

	rc.opts.Rnd.Read(hctx.Keys.LocalRandom[:])
	rc.opts.Rnd.Read(hctx.Keys.X25519Secret[:])
	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	hctx.Keys.ComputeKeyShare()
	clientHelloMsg := rc.generateClientHello(hctx, false, cookie.Cookie{})
	hctx.PushMessage(handshake.MessagesFlightClientHello1, clientHelloMsg)
	return hctx, nil
}
