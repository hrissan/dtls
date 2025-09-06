// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package main

import (
	"log"

	"github.com/hrissan/dtls/cmd/chat"
	"github.com/hrissan/dtls/dtlscore"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/transport/sockets"
	"github.com/hrissan/dtls/transport/stats"
)

func main() {
	dtlscore.PrintSizeofInfo()

	socket := sockets.OpenSocketMust("127.0.0.1:11111")

	st := stats.NewStatsLogVerbose()
	rnd := dtlsrand.CryptoRand()
	opts := dtlscore.DefaultTransportOptions(true, rnd, st)

	opts.ALPN = [][]byte{[]byte("toyrpc/0.2"), []byte("toyrpc/0.3")}
	opts.ServerDisableHRR = true
	opts.PSKAppendSecret = chat.PSKAppendSecret

	if err := opts.LoadServerCertificate(
		"../../wolfssl-examples/certs/server-cert.pem",
		"../../wolfssl-examples/certs/server-key.pem"); err != nil {
		log.Fatal(err)
	}
	room := chat.NewRoom()
	t := dtlscore.NewTransport(opts, room)

	t.GoRunUDP(socket)
}
