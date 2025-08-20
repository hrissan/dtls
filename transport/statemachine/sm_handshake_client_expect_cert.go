package statemachine

import (
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectCert struct {
	smHandshake
}

func (*smHandshakeClientExpectCert) OnCertificate(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgCertificate) error {
	conn.hctx.certificateChain = msgParsed
	conn.stateID = smIDHandshakeClientExpectServerCertVerify
	return nil
}
