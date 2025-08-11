package receiver

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/options"
	"github.com/hrissan/tinydtls/transport/sender"
)

// Receiver also performs stateless logic

type Receiver struct {
	opts        *options.TransportOptions
	cookieState cookie.CookieState
	snd         *sender.Sender
}

func NewReceiver(opts *options.TransportOptions, snd *sender.Sender) *Receiver {
	rc := &Receiver{opts: opts, snd: snd}
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
