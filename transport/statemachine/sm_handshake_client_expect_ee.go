package statemachine

import (
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectEE struct {
	smHandshake
}

func (*smHandshakeClientExpectEE) OnEncryptedExtensions(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.ExtensionsSet) error {
	conn.stateID = smIDHandshakeClientExpectServerCert
	return nil
}
