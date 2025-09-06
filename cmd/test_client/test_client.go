// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package main

import (
	"fmt"

	"github.com/hrissan/dtls"
	"github.com/hrissan/dtls/cmd/chat"
	"github.com/hrissan/dtls/dtlscore"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/dtlsudp"
	"github.com/hrissan/dtls/transport/stats"
)

func main() {
	//if len(os.Args) != 2 {
	//	fmt.Printf("usage test_client <chat_name>")
	//}
	dtlscore.PrintSizeofInfo()

	socket := dtlsudp.OpenSocketMust("127.0.0.1:")

	st := stats.NewStatsLogVerbose()
	rnd := dtlsrand.CryptoRand()
	opts := dtlscore.DefaultTransportOptions(false, rnd, st)

	opts.ALPN = [][]byte{[]byte("toyrpc/0.1"), []byte("toyrpc/0.2")}
	opts.PSKClientIdentities = append(opts.PSKClientIdentities, []byte(chat.PSKClientIdentity))
	opts.PSKAppendSecret = chat.PSKAppendSecret

	snd := dtlsudp.NewSender(opts)
	t := dtlscore.NewTransport(opts, snd, nil)
	// client := chat.NewClient(t)

	//peerAddr, err := netip.ParseAddrPort("127.0.0.1:11111")
	//if err != nil {
	//	log.Panic("dtls: cannot parse peer address: ", err)
	//}
	// go client.GoStart(t, peerAddr)

	go func() {
		dtlsConn, err := dtls.DialTimeoutEarlyData(t, "udp4", "127.0.0.1:11111",
			0, []byte("Early (0-RTT) data"))
		chat.Check(err)
		defer func() {
			chat.Check(dtlsConn.Close())
		}()

		fmt.Println("Connected; type 'exit' to shutdown gracefully")

		// Simulate a chat session
		chat.Chat(dtlsConn)

		t.Shutdown()
	}()

	dtlsudp.GoRunUDP(t, opts, snd, socket)
}
