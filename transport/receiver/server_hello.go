package receiver

import (
	"errors"
	"net/netip"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/handshake"
)

var ErrServerHRRContainsNoCookie = errors.New("server HRR contains no cookie")

func (rc *Receiver) OnServerHello(conn *handshake.ConnectionImpl, messageBody []byte, handshakeHdr format.MessageHandshakeHeader, serverHello format.ServerHello, addr netip.AddrPort, rn format.RecordNumber) error {
	if rc.opts.RoleServer {
		rc.opts.Stats.ErrorServerReceivedServerHello(addr)
		return dtlserrors.ErrServerHelloReceivedByServer
	}
	if conn == nil {
		return dtlserrors.ErrServerHelloNoActiveConnection
	}

	if err := conn.OnServerHello(messageBody, handshakeHdr, serverHello, addr, rn); err != nil {
		return err
	}
	rc.snd.RegisterConnectionForSend(conn)
	return nil
}
