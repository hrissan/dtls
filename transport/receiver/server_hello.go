package receiver

import (
	"net/netip"

	"github.com/hrissan/tinydtls/format"
)

func (rc *Receiver) OnServerHello(messageData []byte, handshakeHdr format.MessageHandshakeHeader, msg format.ServerHello, addr netip.AddrPort) {
	if rc.opts.RoleServer {
		rc.opts.Stats.ErrorServerReceivedServerHello(addr)
		// TODO - send alert
		return
	}
}
