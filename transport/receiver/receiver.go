package receiver

import (
	"crypto/sha256"
	"errors"
	"log"
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
	// only ClientHello with correct cookie and larger timestamp replaces previous handshake here [rfc9147:5.11]
	connections map[netip.AddrPort]*handshake.ConnectionImpl

	// TODO - limit on max number of parallel handshakes, clear items by LRU
	// handshakesPool circular.Buffer[*handshake.HandshakeConnection] - TODO

	// we move handshake here, once it is finished
	//connections map[netip.AddrPort]*Connection

}

func NewReceiver(opts *options.TransportOptions, snd *sender.Sender) *Receiver {
	rc := &Receiver{
		opts:        opts,
		snd:         snd,
		connections: map[netip.AddrPort]*handshake.ConnectionImpl{},
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
	var conn *handshake.ConnectionImpl
	connSet := false

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
			if !connSet { // look up connection only once per datagram, not record
				rc.handMu.Lock()
				conn = rc.connections[addr]
				rc.handMu.Unlock()
				connSet = true
			}
			if conn != nil {
				log.Printf("dtls: got ciphertext %v cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, body)
				registerInSender := conn.ProcessCiphertextRecord(rc.opts, hdr, cid, seqNum, header, body, addr) // errors inside do not conflict with our ability to process next record
				if registerInSender {
					rc.snd.RegisterConnectionForSend(conn) // TODO - postpone all responses until full datagram processed
				}
			}
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

var ErrConnectionInProgress = errors.New("connection is in progress")

func (rc *Receiver) startConnection(addr netip.AddrPort) (*handshake.ConnectionImpl, error) {
	rc.handMu.Lock()
	defer rc.handMu.Unlock()
	conn := rc.connections[addr]
	if conn != nil {
		return nil, ErrConnectionInProgress // for now will wait for previous handshake timeout first
	} // TODO - if this is long going handshake, clear and start again?

	// TODO - get from pool
	hctx := &handshake.HandshakeConnection{
		TranscriptHasher: sha256.New(),
	}
	conn = &handshake.ConnectionImpl{
		Addr:       addr,
		RoleServer: false,
		Handshake:  hctx,
	}
	rc.connections[addr] = conn

	rc.opts.Rnd.ReadMust(hctx.LocalRandom[:])
	rc.opts.Rnd.ReadMust(hctx.X25519Secret[:])
	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	hctx.ComputeKeyShare()
	clientHelloMsg := rc.generateClientHello(hctx, false, cookie.Cookie{})
	hctx.PushMessage(conn, handshake.MessagesFlightClientHello1, clientHelloMsg)
	return conn, nil
}
