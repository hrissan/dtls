package receiver

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/record"
	"github.com/hrissan/tinydtls/transport/options"
	"github.com/hrissan/tinydtls/transport/sender"
	"github.com/hrissan/tinydtls/transport/statemachine"
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
	connections map[netip.AddrPort]*statemachine.ConnectionImpl

	// TODO - limit on max number of parallel handshakes, clear items by LRU
	// handshakesPool circular.Buffer[*statemachine.handshakeContext] - TODO

	// we move handshake here, once it is finished
	//connections map[netip.AddrPort]*Connection

}

func NewReceiver(opts *options.TransportOptions, snd *sender.Sender) *Receiver {
	rc := &Receiver{
		opts:        opts,
		snd:         snd,
		connections: map[netip.AddrPort]*statemachine.ConnectionImpl{},
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
	conn, err := rc.processDatagramImpl(datagram, addr)
	if conn != nil {
		if err != nil {
			log.Printf("TODO - send alert and close connection: %v", err)
		} else {
			if conn.HasDataToSend() {
				// We postpone sending responses until full datagram processed
				rc.snd.RegisterConnectionForSend(conn)
			}
		}
	} else {
		rc.opts.Stats.Warning(addr, err)
		// TODO - alert is must here, otherwise client will not know we forgot their connection
	}
}

func (rc *Receiver) processDatagramImpl(datagram []byte, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	// look up always for simplicity
	rc.handMu.Lock()
	conn := rc.connections[addr]
	rc.handMu.Unlock()

	recordOffset := 0                  // Multiple DTLS records MAY be placed in a single datagram [rfc9147:4.3]
	for recordOffset < len(datagram) { // read records one by one
		fb := datagram[recordOffset]
		switch {
		case record.IsCiphertextRecord(fb):
			var hdr record.Ciphertext
			n, err := hdr.Parse(datagram[recordOffset:], rc.opts.CIDLength)
			if err != nil {
				rc.opts.Stats.BadRecord("ciphertext", recordOffset, len(datagram), addr, err)
				rc.opts.Stats.Warning(addr, dtlserrors.WarnCiphertextRecordParsing)
				// Anyone can send garbage, ignore.
				// We cannot continue to the next record.
				return conn, nil
			}
			recordOffset += n
			// log.Printf("dtls: got ciphertext %v cid(hex): %x from %v, body(hex): %x", hdr., cid, addr, body)
			if conn == nil {
				rc.opts.Stats.Warning(addr, dtlserrors.WarnCiphertextNoConnection)
				// TODO - stateless alert
				// Continue - may be there is ClientHello in the next record?
				continue
			}
			err = conn.ReceivedCiphertextRecord(rc.opts, hdr)
			if err != nil {
				return conn, err
			}
			// Minor problems inside record do not conflict with our ability to process next record
			continue
		case fb == record.RecordTypeAlert ||
			fb == record.RecordTypeHandshake ||
			fb == record.RecordTypeAck:
			// [rfc9147:4.1], but it seems acks must always be encrypted in DTLS1.3?
			// TODO - contact DTLS team to clarify standard
			var hdr record.Plaintext
			n, err := hdr.Parse(datagram[recordOffset:])
			if err != nil {
				rc.opts.Stats.BadRecord("plaintext", recordOffset, len(datagram), addr, err)
				rc.opts.Stats.Warning(addr, dtlserrors.WarnPlaintextRecordParsing)
				// Anyone can send garbage, ignore.
				// We cannot continue to the next record.
				return conn, nil
			}
			recordOffset += n
			// TODO - should we check/remove replay received record sequence number?
			// how to do this without state?
			switch hdr.ContentType {
			case record.RecordTypeAlert:
				if conn != nil { // Will not respond with alert, otherwise endless cycle
					if err := conn.ReceivedAlert(false, hdr.Body); err != nil {
						// Anyone can send garbage, do not change state
						rc.opts.Stats.Warning(addr, err)
					}
				}
			case record.RecordTypeAck:
				log.Printf("dtls: got ack record (plaintext) %d bytes from %v, message(hex): %x", len(hdr.Body), addr, hdr.Body)
				// unencrypted acks can only acknowledge unencrypted messaged, so very niche, we simply ignore them
			case record.RecordTypeHandshake:
				conn, err = rc.receivedPlaintextHandshake(conn, hdr, addr)
				if err != nil { // we do not believe plaintext, so only warnings
					rc.opts.Stats.Warning(addr, err)
				}
			}
			// send (stateless) alert
			// Anyone can send garbage, ignore.
			// Errors inside do not conflict with our ability to process next record
			continue
		default:
			rc.opts.Stats.BadRecord("unknown", recordOffset, len(datagram), addr, record.ErrRecordTypeFailedToParse)
			rc.opts.Stats.Warning(addr, dtlserrors.WarnUnknownRecordType)
			// Anyone can send garbage, ignore.
			// We cannot continue to the next record.
			return conn, nil
		}
	}
	return conn, nil
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

func (rc *Receiver) startConnection(addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	rc.handMu.Lock()
	defer rc.handMu.Unlock()
	conn := rc.connections[addr]
	if conn != nil {
		return nil, ErrConnectionInProgress // for now will wait for previous handshake timeout first
	} // TODO - if this is long going handshake, clear and start again?

	conn, err := statemachine.NewClientConnection(addr, rc.opts)
	if err != nil {
		return nil, err
	}
	rc.connections[addr] = conn
	return conn, nil
}
