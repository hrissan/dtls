package main

import (
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/transport"
)

func main() {
	socket := transport.OpenSocketMust("127.0.0.1:11111")

	stats := transport.NewStatsLogVerbose()
	opts := transport.DefaultTransportOptions()
	rnd := dtlsrand.CryptoRand()
	t := transport.NewTransport(opts, stats, rnd, socket, true)

	t.Run()
}
