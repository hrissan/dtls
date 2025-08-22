package sockets

import (
	"log"
	"net"
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
	log.Printf("dtls: opened socket for address %s localAddr %s\n", addressPort, socket.LocalAddr().String())
	return socket
}
