package transport

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/tinydtls/format"
)

type Transport struct {
	stats   Stats
	options TransportOptions

	cIDLength int // We use fixed size connection ID, so we can parse ciphertext records easily [rfc9147:9.1]

	handshakesConnectionsMu sync.RWMutex
	// TODO - limit on max number of parallel handshakes, clear items by LRU
	// only ClientHello with correct cookie replaces previous handshake here [rfc9147:5.11]
	handshakes map[netip.AddrPort]*HandshakeContext

	// we move handshake here, once it is finished
	connections map[netip.AddrPort]*Connection

	sendMu       sync.Mutex
	sendCond     *sync.Cond
	sendShutdown bool
	// hello retry request is stateless.
	// we limit (options.HelloRetryQueueSize) how many such datagrams we wish to store
	helloRetryQueue []OutgoingDatagram

	socket *net.UDPConn // TODO: move to another layer, so Transport does not depend on UDP

	OnClientHello func(msg format.ClientHello, addr netip.AddrPort)
	OnServerHello func(msg format.ServerHello, addr netip.AddrPort)
}

func NewTransport(opts TransportOptions, stats Stats, socket *net.UDPConn) *Transport {
	t := &Transport{
		stats:       stats,
		options:     opts,
		socket:      socket,
		handshakes:  map[netip.AddrPort]*HandshakeContext{},
		connections: map[netip.AddrPort]*Connection{},
	}
	t.sendCond = sync.NewCond(&t.sendMu)
	return t
}

func (t *Transport) Close() {
	t.sendMu.Lock()
	t.sendShutdown = true
	t.sendMu.Unlock()
	t.sendCond.Broadcast()

	_ = t.socket.Close()
}

func (t *Transport) goWrite(wg *sync.WaitGroup) {
	defer wg.Done()
	var helloRetryQueue []OutgoingDatagram
	t.sendMu.Lock()
	for {
		if !t.sendShutdown && len(t.helloRetryQueue) == 0 {
			t.sendCond.Wait()
		}
		helloRetryQueue, t.helloRetryQueue = t.helloRetryQueue, helloRetryQueue[:0]
		sendShutdown := t.sendShutdown
		t.sendMu.Unlock()
		if sendShutdown {
			return
		}
		for _, od := range helloRetryQueue {
			t.stats.SocketWriteDatagram(od.data, od.addr)
			n, err := t.socket.WriteToUDPAddrPort(od.data, od.addr)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				t.stats.SocketWriteError(n, od.addr, err)
				time.Sleep(t.options.SocketWriteErrorDelay)
			}
		}
		t.sendMu.Lock()
	}
}

func (t *Transport) goRead(wg *sync.WaitGroup) {
	defer wg.Done()
	datagram := make([]byte, 65536)
	for {
		n, addr, err := t.socket.ReadFromUDPAddrPort(datagram)
		if n != 0 { // do not check for an error here
			t.stats.SocketReadDatagram(datagram[:n], addr)
			t.processDatagram(datagram[:n], addr)
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.stats.SocketReadError(n, addr, err)
			time.Sleep(t.options.SocketReadErrorDelay)
		}
	}
}

func (t *Transport) processDatagram(datagram []byte, addr netip.AddrPort) {
	recordOffset := 0                  // Multiple DTLS records MAY be placed in a single datagram [rfc9147:4.3]
	for recordOffset < len(datagram) { // read records one by one
		fb := datagram[recordOffset]
		if format.IsCiphertextRecord(fb) {
			var hdr format.CiphertextRecordHeader
			n, cid, body, err := hdr.Parse(datagram[recordOffset:], t.cIDLength) // TODO - CID
			if err != nil {
				t.stats.BadRecord("ciphertext", recordOffset, len(datagram), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			recordOffset += n
			t.processCiphertextRecord(hdr, cid, body, addr) // errors inside do not conflict with our ability to process next record
			continue
		}
		if format.IsPlaintextRecord(fb) {
			var hdr format.PlaintextRecordHeader
			n, body, err := hdr.Parse(datagram[recordOffset:])
			if err != nil {
				t.stats.BadRecord("plaintext", recordOffset, len(datagram), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			recordOffset += n
			t.processPlaintextRecord(hdr, body, addr) // errors inside do not conflict with our ability to process next record
			continue
		}
		t.stats.BadRecord("unknown", recordOffset, len(datagram), addr, format.ErrRecordTypeFailedToParse)
		// TODO: alert here, and we cannot continue to the next record.
		return
	}
}

func (t *Transport) processPlaintextRecord(hdr format.PlaintextRecordHeader, record []byte, addr netip.AddrPort) {
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(record) {
		switch hdr.ContentType {
		case format.PlaintextContentTypeAlert:
			log.Printf("dtls: got alert %v from %v, record(hex): %x", hdr, addr, record)
		case format.PlaintextContentTypeHandshake:
			log.Printf("dtls: got handshake %v from %v, record(hex): %x", hdr, addr, record)
			var handshakeHdr format.MessageHandshakeHeader
			n, body, err := handshakeHdr.Parse(record)
			if err != nil {
				t.stats.BadMessageHeader("handshake", messageOffset, len(record), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			messageOffset += n
			switch handshakeHdr.HandshakeType {
			case format.HandshakeTypeClientHello:
				var msg format.ClientHello
				if handshakeHdr.IsFragmented() {
					t.stats.MustNotBeFragmented(msg.MessageKind(), msg.MessageName(), addr, handshakeHdr)
					// TODO: alert here
					continue
				}
				if err := msg.Parse(body); err != nil {
					t.stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
					// TODO: alert here
					continue
				}
				t.stats.ClientHelloMessage(msg, addr)
				t.OnClientHello(msg, addr)
			case format.HandshakeTypeServerHello:
				var msg format.ServerHello
				if handshakeHdr.IsFragmented() {
					t.stats.MustNotBeFragmented(msg.MessageKind(), msg.MessageName(), addr, handshakeHdr)
					// TODO: alert here
					continue
				}
				if err := msg.Parse(body); err != nil {
					t.stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
					// TODO: alert here
					continue
				}
				t.stats.ServerHelloMessage(msg, addr)
				t.OnServerHello(msg, addr)
			default:
				t.stats.MustBeEncrypted("handshake", format.HandshakeTypeToName(handshakeHdr.HandshakeType), addr, handshakeHdr)
			}
		case format.PlaintextContentTypeAck:
			log.Printf("dtls: got ack %v from %v, record(hex): %x", hdr, addr, record)
		default:
			panic("unknown content type")
		}
	}
}

func (t *Transport) processCiphertextRecord(hdr format.CiphertextRecordHeader, cid []byte, body []byte, addr netip.AddrPort) {
	log.Printf("dtls: got ciphertext %v cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, body)
}
