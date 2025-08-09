package transport

import "net/netip"

type OutgoingDatagram struct {
	data []byte
	addr netip.Addr
}
