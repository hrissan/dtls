// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlsudp

import (
	"fmt"
	"log"
	"net"

	"github.com/hrissan/dtls/dtlscore"
)

// for tests and tools
func OpenSocketMust(addressPort string) *net.UDPConn {
	udpAddr, err := net.ResolveUDPAddr("udp", addressPort)
	if err != nil {
		log.Fatalf("dtls: cannot resolve local udp address %s: %v", addressPort, err)
	}
	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("dtls: cannot listen to udp address %s: %v", addressPort, err)
	}
	fmt.Printf("dtls: opened socket for address %s localAddr %s\n", addressPort, socket.LocalAddr().String())
	return socket
}

// Blocks until t.Shutdown()
// Closes socket as part of orderd shutdown, so receiver blocked in Read can stop.
func GoRunUDP(t *dtlscore.Transport, opts *dtlscore.Options, snd *sender, socket *net.UDPConn) {
	ch := make(chan struct{}, 1)
	go func() {
		snd.GoRunUDP(socket)
		// on shutdown, sender first sends all alerts, then exits goroutine
		_ = socket.Close() // so receiver also exits
		ch <- struct{}{}
	}()
	GoRunReceiverUDP(t, opts, socket)
	<-ch
}
