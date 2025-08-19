package receiver

import (
	"net/netip"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/record"
	"github.com/hrissan/tinydtls/transport/statemachine"
)

func (rc *Receiver) processPlaintextHandshake(conn *statemachine.ConnectionImpl, hdr record.Plaintext, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	// log.Printf("dtls: got handshake record (plaintext) %d bytes from %v, message(hex): %x", len(recordData), addr, recordData)
	if len(hdr.Body) == 0 {
		// [rfc8446:5.1] Implementations MUST NOT send zero-length fragments of Handshake types, even if those fragments contain padding
		return conn, dtlserrors.ErrHandshakeReecordEmpty
	}
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(hdr.Body) {
		// log.Printf("dtls: got handshake message %v from %v, message(hex): %x", hdr, addr, messageData)
		var fragment handshake.Fragment
		n, err := fragment.Parse(hdr.Body[messageOffset:])
		if err != nil {
			rc.opts.Stats.BadMessageHeader("handshake", messageOffset, len(hdr.Body), addr, err)
			// we cannot continue to the next record.
			return conn, dtlserrors.WarnPlaintextHandshakeMessageHeaderParsing
		}
		messageOffset += n
		switch fragment.Header.MsgType {
		case handshake.MsgTypeClientHello:
			// on error, we could continue to the next fragment, but state machine will be broken, so we do not
			var msgClientHello handshake.MsgClientHello
			if fragment.Header.IsFragmented() {
				rc.opts.Stats.MustNotBeFragmented(msgClientHello.MessageKind(), msgClientHello.MessageName(), addr, fragment.Header)
				return conn, dtlserrors.WarnClientHelloFragmented
			}
			if err := msgClientHello.Parse(fragment.Body); err != nil {
				rc.opts.Stats.BadMessage(msgClientHello.MessageKind(), msgClientHello.MessageName(), addr, err)
				return conn, dtlserrors.WarnPlaintextClientHelloParsing
			}
			rc.opts.Stats.ClientHelloMessage(fragment.Header, msgClientHello, addr)
			msg := handshake.Message{
				MsgType: fragment.Header.MsgType,
				MsgSeq:  fragment.Header.MsgSeq,
				Body:    fragment.Body,
			}
			conn, err = rc.OnClientHello(conn, msg, msgClientHello, addr)
			if err != nil {
				return conn, err
			}
		case handshake.MsgTypeServerHello:
			// on error, we could continue to the next fragment, but state machine will be broken, so we do not
			if conn == nil {
				return conn, dtlserrors.ErrServerHelloNoActiveConnection
			}
			if err = conn.ReceivedServerHelloFragment(fragment, record.NumberWith(0, hdr.SequenceNumber)); err != nil {
				return conn, err
			}
		default:
			rc.opts.Stats.MustBeEncrypted("handshake", handshake.MsgTypeToName(fragment.Header.MsgType), addr, fragment.Header)
			// we can continue to the next message, but state machine will be broken
			return conn, dtlserrors.WarnHandshakeMessageMustBeEncrypted
		}
	}
	return conn, nil
}
