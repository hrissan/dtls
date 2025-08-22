// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package main

import (
	"log"
	"net/netip"

	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/transport"
	"github.com/hrissan/dtls/transport/options"
	"github.com/hrissan/dtls/transport/statemachine"
	"github.com/hrissan/dtls/transport/stats"
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
		log.Panic("dtls: cannot parse peer address: ", err)
	}
	_, _ = t.StartConnection(peerAddr)

	t.GoRunUDP(socket)
}
