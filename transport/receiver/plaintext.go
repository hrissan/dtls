package receiver

import (
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
)

func (rc *Receiver) processPlaintextRecord(hdr format.PlaintextRecordHeader, record []byte, addr netip.AddrPort) error {
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(record) {
		messageData := record[messageOffset:]
		switch hdr.ContentType {
		case format.PlaintextContentTypeAlert:
			log.Printf("dtls: got alert %v from %v, message(hex): %x", hdr, addr, messageData)
			return nil // TODO - more checks
		case format.PlaintextContentTypeHandshake:
			log.Printf("dtls: got handshake %v from %v, message(hex): %x", hdr, addr, messageData)
			var handshakeHdr format.MessageHandshakeHeader
			n, body, err := handshakeHdr.ParseWithBody(messageData)
			if err != nil {
				rc.opts.Stats.BadMessageHeader("handshake", messageOffset, len(record), addr, err)
				// we cannot continue to the next record.
				return dtlserrors.WarnPlaintextHandshakeMessageHeaderParsing
			}
			messageData = messageData[:n]
			messageOffset += n
			switch handshakeHdr.HandshakeType {
			case format.HandshakeTypeClientHello:
				// we ignore handshakeHdr.MessageSeq here, will be 0 (initial hello) or 1 (for hello after HRR).
				// TODO - check
				var msg format.ClientHello
				if handshakeHdr.IsFragmented() {
					rc.opts.Stats.MustNotBeFragmented(msg.MessageKind(), msg.MessageName(), addr, handshakeHdr)
					// we can continue to the next message, but state machine will be broken
					return dtlserrors.WarnClientHelloFragmented
				}
				if err := msg.Parse(body); err != nil {
					rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
					return dtlserrors.WarnPlaintextClientHelloParsing
				}
				rc.opts.Stats.ClientHelloMessage(handshakeHdr, msg, addr)
				rc.OnClientHello(body, handshakeHdr, msg, addr)
				// TODO - return err from rc.OnClientHello
			case format.HandshakeTypeServerHello:
				// we ignore handshakeHdr.MessageSeq here, will be 0
				// TODO - check
				var msg format.ServerHello
				if handshakeHdr.IsFragmented() {
					rc.opts.Stats.MustNotBeFragmented(msg.MessageKind(), msg.MessageName(), addr, handshakeHdr)
					// we can continue to the next message, but state machine will be broken
					return dtlserrors.WarnServerHelloFragmented
				}
				if err := msg.Parse(body); err != nil {
					rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
					return dtlserrors.WarnPlaintextServerHelloParsing
				}
				rc.opts.Stats.ServerHelloMessage(handshakeHdr, msg, addr)
				rc.OnServerHello(body, handshakeHdr, msg, addr, format.RecordNumberWith(0, hdr.SequenceNumber))
				// TODO - return err from rc.OnServerHello
			default:
				rc.opts.Stats.MustBeEncrypted("handshake", format.HandshakeTypeToName(handshakeHdr.HandshakeType), addr, handshakeHdr)
				// we can continue to the next message, but state machine will be broken
				return dtlserrors.WarnHandshakeMessageMustBeEncrypted
			}
		default: // never, because checked in format.IsPlaintextRecord()
			panic("unknown content type")
		}
	}
	return nil
}
