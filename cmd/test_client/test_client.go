// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package main

import (
	"fmt"

	"github.com/hrissan/dtls"
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

	opts.PSKClientIdentities = []string{chat.PSKClientIdentity}
	opts.PSKAppendSecret = chat.PSKAppendSecret

	t := statemachine.NewTransport(opts, nil)
	// client := chat.NewClient(t)

	//peerAddr, err := netip.ParseAddrPort("127.0.0.1:11111")
	//if err != nil {
	//	log.Panic("dtls: cannot parse peer address: ", err)
	//}
	// go client.GoStart(t, peerAddr)

	t.GoRunUDP(socket)

	dtlsConn, err := dtls.Dial(t, "udp", "127.0.0.1:11111")
	chat.Check(err)
	defer func() {
		chat.Check(dtlsConn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	chat.Chat(dtlsConn)
}
