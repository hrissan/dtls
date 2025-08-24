// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package main

import (
	"fmt"
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

	opts.PSKIdentity = "Server_identity"
	opts.PSKAppendSecret = func(peerIdentity []byte, scratch []byte) []byte {
		fmt.Printf("PSK peer identity %s\n", peerIdentity)
		return append(scratch, 0x1a, 0x2b, 0x3c, 0x4d) // matches wolfssl examples to test interop
	}

	if err := opts.LoadServerCertificate(
		"../../wolfssl-examples/certs/server-cert.pem",
		"../../wolfssl-examples/certs/server-key.pem"); err != nil {
		log.Fatal(err)
	}
	room := chat.NewRoom()
	t := statemachine.NewTransport(opts, room)

	t.GoRunUDP(socket)
}
