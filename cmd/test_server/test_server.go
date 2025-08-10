package main

import (
	"log"
	"net"

	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/transport"
)

func main() {
	address := "127.0.0.1:11111"
	log.Printf("test_server started on %s\n", address)

	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		log.Fatalf("cannot resolve local udp address %s: %v", address, err)
	}
	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("cannot listen to udp address %s: %v", address, err)
	}

	stats := transport.NewStatsLogVerbose()
	opts := transport.DefaultTransportOptions()
	rnd := dtlsrand.CryptoRand()
	s := transport.NewServer(opts, stats, rnd, socket)

	s.Run()
}
