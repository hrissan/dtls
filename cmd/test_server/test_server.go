package main

import (
	"log"

	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/transport"
	"github.com/hrissan/dtls/transport/options"
	"github.com/hrissan/dtls/transport/statemachine"
	"github.com/hrissan/dtls/transport/stats"
)

func main() {
	statemachine.PrintSizeofInfo()

	socket := transport.OpenSocketMust("127.0.0.1:11111")

	st := stats.NewStatsLogVerbose()
	rnd := dtlsrand.CryptoRand()
	opts := options.DefaultTransportOptions(true, rnd, st)

	if err := opts.LoadServerCertificate(
		"../../wolfssl-examples/certs/server-cert.pem",
		"../../wolfssl-examples/certs/server-key.pem"); err != nil {
		log.Fatal(err)
	}
	t := transport.NewTransport(opts)

	t.GoRunUDP(socket)
}
