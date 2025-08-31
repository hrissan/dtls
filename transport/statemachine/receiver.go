// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
)

var ErrServerCannotStartConnection = errors.New("server can not start connection")
var ErrTransportClosing = errors.New("transport is shutting down")

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
func (t *Transport) goRunReceiverUDP(socket *net.UDPConn) {
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
			shutdown := t.ProcessDatagram(datagram[:n], addr, err)
			if shutdown { // stop processing of datagrams
				return
			}
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(t.opts.SocketReadErrorDelay)
		}
	}
}

func (t *Transport) ProcessDatagram(datagram []byte, addr netip.AddrPort, err error) (shutdown bool) {
	t.opts.Stats.SocketReadDatagram(datagram, addr)
	if err != nil {
		t.opts.Stats.SocketReadError(len(datagram), addr, err)
	}
	if len(datagram) == 0 {
		return false
	}

	conn, err := t.processDatagramImpl(datagram, addr)
	if err == ErrTransportClosing {
		return true
	}
	if conn != nil {
		if err != nil {
			// TODO - return *dtlserrors.Error instead of error, so we cannot
			// return generic error by accident
			if dtlserrors.IsFatal(err) {
				fmt.Printf("fatal error: TODO - send alert and close connection: %v\n", err)
			} else {
				t.opts.Stats.Warning(addr, err)
			}
		} else {
			// TODO - return bool from processDatagramImpl instead, do not take lock 2nd time
			if conn.hasDataToSend() {
				// We postpone sending responses until full datagram processed
				t.snd.RegisterConnectionForSend(conn)
			}
		}
	} else {
		t.opts.Stats.Warning(addr, err)
		// TODO - alert is must here, otherwise client will not know we forgot their connection
	}
	return false
}

func (t *Transport) processDatagramImpl(datagram []byte, addr netip.AddrPort) (*Connection, error) {
	// We look up on each datagram unconditionally to simplify logic in this function and functions it calls.
	// If conn is nil, on server the only place where it can be added is receivedClientHello.
	// on client the only place where it can be added is StartConnection.
	// We could have transport which plays both roles at once, but we need to track connections separately.
	t.mu.Lock()
	conn := t.connMap[addr]
	shutdown := t.shutdown
	t.mu.Unlock()
	if shutdown {
		return nil, ErrTransportClosing
	}

	recordOffset := 0                  // Multiple DTLS records MAY be placed in a single datagram [rfc9147:4.3]
	for recordOffset < len(datagram) { // read records one by one
		fb := datagram[recordOffset]
		switch {
		case record.IsEncryptedRecord(fb):
			var hdr record.Encrypted
			n, err := hdr.Parse(datagram[recordOffset:], t.opts.CIDLength)
			if err != nil {
				t.opts.Stats.BadRecord("ciphertext", recordOffset, len(datagram), addr, err)
				// Anyone can send garbage, ignore.
				// We cannot continue to the next record.
				return conn, dtlserrors.WarnCiphertextRecordParsing
			}
			recordOffset += n
			// fmt.Printf("dtls: got ciphertext %v cid(hex): %x from %v, body(hex): %x", hdr., cid, addr, body)
			if conn == nil {
				// We can continue. but we do not, most likely there is more encrypted records
				return conn, dtlserrors.WarnCiphertextNoConnection
			}
			err = conn.receivedCiphertextRecord(t.opts, hdr)
			if dtlserrors.IsFatal(err) { // manual check in the loop, otherwise simply return
				return conn, err
			} else if err != nil {
				t.opts.Stats.Warning(addr, err)
			}
			// Minor problems inside record do not conflict with our ability to process next record
			continue
		case fb == record.RecordTypeAlert ||
			fb == record.RecordTypeHandshake ||
			fb == record.RecordTypeAck:
			// [rfc9147:4.1], but it seems acks must always be encrypted in DTLS1.3?
			// TODO - contact DTLS team to clarify standard
			var hdr record.Plaintext
			n, err := hdr.Parse(datagram[recordOffset:])
			if err != nil {
				t.opts.Stats.BadRecord("plaintext", recordOffset, len(datagram), addr, err)
				// Anyone can send garbage, ignore.
				// We cannot continue to the next record.
				return conn, dtlserrors.WarnPlaintextRecordParsing
			}
			recordOffset += n
			// TODO - should we check/remove replayed received record sequence number?
			// how to do this without state?
			conn, err = t.receivedPlaintextRecord(conn, hdr, addr)
			if err != nil { // we do not believe plaintext, so only warnings
				t.opts.Stats.Warning(addr, err)
			}
			// Anyone can send garbage, ignore.
			// Error here does not conflict with our ability to process next record
			continue
		default:
			t.opts.Stats.BadRecord("unknown", recordOffset, len(datagram), addr, record.ErrRecordTypeFailedToParse)
			// Anyone can send garbage, ignore.
			// We cannot continue to the next record.
			return conn, dtlserrors.WarnUnknownRecordType
		}
	}
	return conn, nil
}

var ErrConnectionInProgress = errors.New("client connection is in progress")
var ErrRegisterConnectionTwice = errors.New("client connection is registered in transport twice")

func (t *Transport) StartConnection(conn *Connection, handler ConnectionHandler, addr netip.AddrPort) error {
	if t.opts.RoleServer { // TODO - combined in/out transport
		return ErrServerCannotStartConnection
	}
	if err := conn.startConnection(t, handler, addr); err != nil {
		return err
	}
	t.snd.RegisterConnectionForSend(conn)
	return nil
}
