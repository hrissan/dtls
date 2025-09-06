// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlsudp

import (
	"errors"
	"net"
	"time"

	"github.com/hrissan/dtls/dtlscore"
)

/*
	type ControlMessage struct {
		TTL     int        // time-to-live, receiving only
		Src     netip.Addr // source address, specifying only
		Dst     netip.Addr // destination address, receiving only
		IfIndex int        // interface index, must be 1 <= value when specifying
	}

var ErrParseControlMessage = errors.New("failed to parse control message")

// very platform-dependent

	func (msg *ControlMessage) parseCMsg(header *unix.Cmsghdr, data []byte) {
		if header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO && len(data) >= 12 {
			msg.IfIndex = int(binary.LittleEndian.Uint32(data))
			msg.Dst = netip.AddrFrom4([4]byte(data[4:8]))
			msg.Src = netip.AddrFrom4([4]byte(data[8:12]))
		}
		if header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO && len(data) >= 20 {
			msg.Src = netip.AddrFrom16([16]byte(data[:16]))
			msg.IfIndex = int(binary.LittleEndian.Uint32(data[16:20]))
		}
	}

// very platform-dependent

	func (msg *ControlMessage) parseCMsgs(oob []byte) (nCmgs int, _ error) {
		// |<- ControlMessageSpace --------------->|
		// |<- controlMessageLen ---------->|      |
		// |<- controlHeaderLen ->|         |      |
		// +---------------+------+---------+------+
		// |    Header     | PadH |  Data   | PadD |
		// +---------------+------+---------+------+
		for len(oob) != 0 {
			controlHeaderLen := unix.CmsgLen(0)
			if controlHeaderLen > len(oob) {
				return nCmgs, ErrParseControlMessage
			}
			header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
			controlMessageLen := int(header.Len)
			if controlMessageLen < controlHeaderLen || controlMessageLen > len(oob) {
				return nCmgs, ErrParseControlMessage
			}
			body := oob[controlHeaderLen:controlMessageLen]
			msg.parseCMsg(header, body)
			nCmgs++
			controlMessageSpace := unix.CmsgSpace(len(body))
			if controlMessageSpace > len(oob) {
				break // last padding is optional
			}
			oob = oob[controlMessageSpace:]
		}
		return nCmgs, nil
	}
func (t *Transport) setOptions(file *os.File) {
	// set both, any might fail
	// we must reply from the interface we received packet from.
	// https://github.com/golang/go/issues/36421
	_ = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	_ = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_PKTINFO, 1)
	// See explanation in sender, why options below do not work as intended on Linux
	// _ = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_RECVERR, 1)
	// _ = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR, 1)
}
func platformExperiments() {
	syscallSocket, err := socket.SyscallConn()
	if err != nil {
		panic("socket failed to get raw socket: " + err.Error())
	}
	_ = syscallSocket.Read(func(fd uintptr) (done bool) {
		n, oobn, _, from, err := unix.Recvmsg(int(fd), datagram, oob, unix.MSG_ERRQUEUE)
		if err == nil {
			fmt.Printf("received MSG_ERRQUEUE n=%d oobn=%d bytes from %v\n", n, oobn, from)
		}
		return true
	})
}
*/
// blocks until socket is closed (externally)
func GoRunReceiverUDP(t *dtlscore.Transport, opts *dtlscore.Options, socket *net.UDPConn) {
	//file, err := socket.File()
	//if err != nil {
	//	panic("socket failed to get file descriptor: " + err.Error())
	//}
	//defer file.Close()
	//t.setOptions(file)
	datagram := make([]byte, 65536)
	//oob := make([]byte, 4096)
	for {
		n, addr, err := socket.ReadFromUDPAddrPort(datagram)
		//n, _, _, addr, err := socket.ReadMsgUDPAddrPort(datagram, oob)
		//var cm2 ControlMessage
		//if nCmsg, err2 := cm2.parseCMsgs(oob[:oobn]); err2 != nil {
		//	fmt.Printf("err parsing cm2: %v\n", err2)
		//} else {
		//	fmt.Printf("cm2 %d: pktinfo: %v %v %v\n", nCmsg, cm2.Src, cm2.Dst, cm2.IfIndex)
		//}
		if n != 0 { // do not check for an error here
			shutdown := t.ReceivedDatagram(datagram[:n], addr, err)
			if shutdown { // stop processing of datagrams
				return
			}
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(opts.SocketReadErrorDelay)
		}
	}
}
