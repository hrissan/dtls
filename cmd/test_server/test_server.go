// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package main

import (
	"log"

	"github.com/hrissan/dtls/cmd/chat"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/transport/options"
	"github.com/hrissan/dtls/transport/sockets"
	"github.com/hrissan/dtls/transport/statemachine"
	"github.com/hrissan/dtls/transport/stats"
)

func main() {
	statemachine.PrintSizeofInfo()

	socket := sockets.OpenSocketMust("127.0.0.1:11111")

	st := stats.NewStatsLogVerbose()
	rnd := dtlsrand.CryptoRand()
	opts := options.DefaultTransportOptions(true, rnd, st)

	opts.ServerDisableHRR = true
	opts.PSKAppendSecret = chat.PSKAppendSecret

	if err := opts.LoadServerCertificate(
		"../../wolfssl-examples/certs/server-cert.pem",
		"../../wolfssl-examples/certs/server-key.pem"); err != nil {
		log.Fatal(err)
	}
	room := chat.NewRoom()
	t := statemachine.NewTransport(opts, room)

	t.GoRunUDP(socket)
}
