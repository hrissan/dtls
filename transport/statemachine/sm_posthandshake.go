package statemachine

import (
	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/record"
	"github.com/hrissan/tinydtls/transport/options"
)

type smPostHandshake struct{}

func (*smPostHandshake) OnHandshakeMsgFragment(conn *ConnectionImpl, opts *options.TransportOptions,
	fragment handshake.Fragment, rn record.Number) error {
	if fragment.Header.MsgSeq < conn.nextMessageSeqReceive {
		// all messages before were processed by us in the state we already do not remember,
		// so we must acknowledge unconditionally and do nothing.
		conn.keys.AddAck(rn)
		return nil
	}
	if fragment.Header.MsgSeq > conn.nextMessageSeqReceive {
		return nil // no message queue post hondshake, ignore
	}
	if fragment.Header.IsFragmented() {
		// we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		opts.Stats.Warning(conn.addr, dtlserrors.WarnPostHandshakeMessageFragmented)
		return nil
	}
	switch fragment.Header.MsgType {
	case handshake.MsgTypeClientHello:
		panic("TODO - should not be called")
	case handshake.MsgTypeServerHello:
		panic("TODO - should not be called")
	case handshake.MsgTypeNewSessionTicket:
		if err := conn.receivedNewSessionTicket(opts, fragment, rn); err != nil {
			return err
		}
	case handshake.MsgTypeKeyUpdate:
		if err := conn.receivedKeyUpdate(opts, fragment, rn); err != nil {
			return err
		}
	}
	return dtlserrors.ErrPostHandshakeMessageDuringHandshake
}

func (*smPostHandshake) OnClientHello2(conn *ConnectionImpl, opts *options.TransportOptions,
	msg handshake.Message, msgClientHello handshake.MsgClientHello,
	initialHelloTranscriptHash [constants.MaxHashLength]byte, keyShareSet bool) error {
	panic("implement or remove")
}

func (*smPostHandshake) OnServerHello(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	panic("implement or remove")
}

func (*smPostHandshake) OnEncryptedExtensions(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.ExtensionsSet) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}

func (*smPostHandshake) OnCertificate(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgCertificate) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}

func (*smPostHandshake) OnCertificateVerify(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgCertificateVerify) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}

func (*smPostHandshake) OnFinished(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}
