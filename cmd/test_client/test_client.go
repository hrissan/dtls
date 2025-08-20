package main

import (
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/transport"
	"github.com/hrissan/tinydtls/transport/options"
	"github.com/hrissan/tinydtls/transport/statemachine"
	"github.com/hrissan/tinydtls/transport/stats"
)

func main() {
	statemachine.PrintSizeofInfo()

	socket := transport.OpenSocketMust("127.0.0.1:")

	st := stats.NewStatsLogVerbose()
	rnd := dtlsrand.CryptoRand()
	opts := options.DefaultTransportOptions(false, rnd, st)
	t := transport.NewTransport(opts)

	peerAddr, err := netip.ParseAddrPort("127.0.0.1:11111")
	if err != nil {
		log.Panic("tinydtls: cannot parse peer address: ", err)
	}
	_ = t.StartConnection(peerAddr)

	t.GoRunUDP(socket)
}
