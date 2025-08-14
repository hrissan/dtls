package main

import (
	"log"

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

	if err := opts.LoadServerCertificate("../wolfssl-examples/certs/server-cert.pem", "../wolfssl-examples/certs/server-key.pem"); err != nil {
		log.Fatal(err)
	}
	t := transport.NewTransport(opts)

	t.GoRunUDP(socket)
}
