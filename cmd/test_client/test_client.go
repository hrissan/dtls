// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package main

import (
	"log"
	"net/netip"

	"github.com/hrissan/dtls/cmd/chat"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/transport/options"
	"github.com/hrissan/dtls/transport/sockets"
	"github.com/hrissan/dtls/transport/statemachine"
	"github.com/hrissan/dtls/transport/stats"
)

func main() {
	//if len(os.Args) != 2 {
	//	fmt.Printf("usage test_client <chat_name>")
	//}
	statemachine.PrintSizeofInfo()

	socket := sockets.OpenSocketMust("127.0.0.1:")

	st := stats.NewStatsLogVerbose()
	rnd := dtlsrand.CryptoRand()
	opts := options.DefaultTransportOptions(false, rnd, st)

	room := chat.NewClient()
	t := statemachine.NewTransport(opts, room)

	peerAddr, err := netip.ParseAddrPort("127.0.0.1:11111")
	if err != nil {
		log.Panic("dtls: cannot parse peer address: ", err)
	}
	_, _ = t.StartConnection(peerAddr)

	t.GoRunUDP(socket)
}
