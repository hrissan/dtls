package main

import (
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/transport"
	"github.com/hrissan/tinydtls/transport/options"
	"github.com/hrissan/tinydtls/transport/stats"
)

func main() {
	socket := transport.OpenSocketMust("127.0.0.1:11111")

	st := stats.NewStatsLogVerbose()
	rnd := dtlsrand.CryptoRand()
	opts := options.DefaultTransportOptions(true, rnd, st)
	t := transport.NewTransport(opts)

	t.GoRunUDP(socket)
}
