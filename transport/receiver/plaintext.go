package receiver

import (
	"net/netip"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/handshake"
)

func (rc *Receiver) processPlaintextHandshake(conn *handshake.ConnectionImpl, hdr format.PlaintextRecordHeader, recordData []byte, addr netip.AddrPort) (*handshake.ConnectionImpl, error) {
	// log.Printf("dtls: got handshake record (plaintext) %d bytes from %v, message(hex): %x", len(recordData), addr, recordData)
	if len(recordData) == 0 {
		// [rfc8446:5.1] Implementations MUST NOT send zero-length fragments of Handshake types, even if those fragments contain padding
		return conn, dtlserrors.ErrHandshakeReecordEmpty
	}
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(recordData) {
		// log.Printf("dtls: got handshake message %v from %v, message(hex): %x", hdr, addr, messageData)
		var handshakeHdr format.MessageFragmentHeader
		n, body, err := handshakeHdr.ParseWithBody(recordData[messageOffset:])
		if err != nil {
			rc.opts.Stats.BadMessageHeader("handshake", messageOffset, len(recordData), addr, err)
			// we cannot continue to the next record.
			return conn, dtlserrors.WarnPlaintextHandshakeMessageHeaderParsing
		}
		messageOffset += n
		switch handshakeHdr.HandshakeType {
		case format.HandshakeTypeClientHello:
			// on error, we could continue to the next fragment, but state machine will be broken, so we do not
			var msg format.ClientHello
			if handshakeHdr.IsFragmented() {
				rc.opts.Stats.MustNotBeFragmented(msg.MessageKind(), msg.MessageName(), addr, handshakeHdr)
				return conn, dtlserrors.WarnClientHelloFragmented
			}
			if err := msg.Parse(body); err != nil {
				rc.opts.Stats.BadMessage(msg.MessageKind(), msg.MessageName(), addr, err)
				return conn, dtlserrors.WarnPlaintextClientHelloParsing
			}
			rc.opts.Stats.ClientHelloMessage(handshakeHdr, msg, addr)
			conn, err = rc.OnClientHello(conn, body, handshakeHdr, msg, addr)
			if err != nil {
				return conn, err
			}
		case format.HandshakeTypeServerHello:
			// on error, we could continue to the next fragment, but state machine will be broken, so we do not
			if conn == nil {
				return conn, dtlserrors.ErrServerHelloNoActiveConnection
			}
			if err = conn.ProcessServerHello(handshakeHdr, body, format.RecordNumberWith(0, hdr.SequenceNumber)); err != nil {
				return conn, err
			}
		default:
			rc.opts.Stats.MustBeEncrypted("handshake", format.HandshakeTypeToName(handshakeHdr.HandshakeType), addr, handshakeHdr)
			// we can continue to the next message, but state machine will be broken
			return conn, dtlserrors.WarnHandshakeMessageMustBeEncrypted
		}
	}
	return conn, nil
}
