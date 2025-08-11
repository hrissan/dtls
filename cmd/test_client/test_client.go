package main

import (
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/transport"
)

func main() {
	socket := transport.OpenSocketMust("127.0.0.1:")

	stats := transport.NewStatsLogVerbose()
	opts := transport.DefaultTransportOptions()
	rnd := dtlsrand.CryptoRand()
	t := transport.NewTransport(opts, stats, rnd, socket, false)

	peerAddr, err := netip.ParseAddrPort("127.0.0.1:11111")
	if err != nil {
		log.Panic("tinydtls: cannot parse peer address: ", err)
	}
	t.StartConnection(peerAddr)

	t.Run()
}
