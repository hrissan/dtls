// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"sync"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/record"
)

// Contains absolute minimum of what's mandatory for after handshake finished
// keys, record replay buffer, ack queue for KeyUpdate and NewSessionTicket messages
// all other information is in handshakeContext structure and will be reused
// after handshake finish
type Connection struct {
	// variables are arranged in a way to reduce sizeof()
	tr      *Transport
	handler ConnectionHandler

	// variables below mu are protected by mu, except where noted
	mu   sync.Mutex
	addr netip.AddrPort // cleared when conn is removed from map, set when added
	keys keys.Keys

	// connection with newer cookie replaces previous one
	cookieTimestampUnixNano int64

	// We do not support received messages of this kind to be fragmented,
	// because we do not want to allocate memory for reassembly,
	// Also we do not want to support sending them fragmented, because we do not want to track
	// rn -> fragment relations. We simply track 1 rn per message type instead.
	sentKeyUpdateRN        record.Number // if != 0, already sent, on resend overwrite rn
	sentNewSessionTicketRN record.Number // if != 0, already sent, on resend overwrite rn

	hctx *handshakeContext // handshakeContext content is also protected by mutex above

	// Messages are protocol above records, these counters do not reset for connection lifetime.
	// If any reaches 2^16, connection will be closed by both peers.
	nextMessageSeqSend    uint16
	nextMessageSeqReceive uint16

	sendNewSessionTicketMessageSeq uint16 // != 0 if set. Sent using stateless sender to avoid storing message here
	sendKeyUpdateMessageSeq        uint16 // != 0 if set
	sendKeyUpdateUpdateRequested   bool   // fully defines content of KeyUpdate we are sending

	sendAlert record.Alert // if Level == 0, do not need to send an alert

	stateID stateMachineStateID // index in global table
	// intrusive, must not be changed except by sender, protected by sender mutex
	inSenderQueue bool
}

func (conn *Connection) Lock()   { conn.mu.Lock() }
func (conn *Connection) Unlock() { conn.mu.Unlock() }

func (conn *Connection) AddrLocked() netip.AddrPort {
	return conn.addr
}

// sender interface, never call outside of sender statemachine
func (conn *Connection) SenderRemoveFromQueue() {
	// protected by sender's lock
	conn.inSenderQueue = false
}

// sender interface, never call outside of sender statemachine
func (conn *Connection) SenderAddToQueue() bool {
	// protected by sender's lock
	if conn.inSenderQueue {
		return false
	}
	conn.inSenderQueue = true
	return true
}

func (conn *Connection) SenderConstructDatagram(datagram []byte) (addr netip.AddrPort, datagramSize int, addToSendQueue bool) {
	return conn.constructDatagram(conn.tr.opts, datagram)
}

// if we want some logic once during transition to shutdown, use returned value
func (conn *Connection) ShutdownLocked(alert record.Alert) (switchedToShutdown bool) {
	if conn.stateID == smIDClosed || conn.stateID == smIDShutdown {
		return false
	}
	conn.sendAlert = alert
	conn.stateID = smIDShutdown

	// cancel handshake
	conn.hctx = nil // TODO - reuse

	// cancel post-handshake messages
	conn.sendNewSessionTicketMessageSeq = 0
	conn.sendKeyUpdateMessageSeq = 0
	conn.sendKeyUpdateUpdateRequested = false

	// we could optimize sometimes by avoiding lock in sender, but shutdowns are rare
	conn.SignalWriteable()
	return true
}

// must not touch transport mutex, otherwise deadlock
func (conn *Connection) Shutdown(alert record.Alert) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	_ = conn.ShutdownLocked(alert)
}

// so we do not forget to prepare vars for reuse
func (conn *Connection) resetToClosedLocked(returnToPool bool) {
	if conn.stateID == smIDClosed {
		return
	}
	conn.stateID = smIDClosed

	conn.tr.removeFromMap(conn, conn.addr, returnToPool)
	conn.addr = netip.AddrPort{}

	conn.keys = keys.Keys{}
	conn.cookieTimestampUnixNano = 0

	conn.sentKeyUpdateRN = record.Number{}
	conn.sentNewSessionTicketRN = record.Number{}

	conn.hctx = nil // TODO - reuse

	conn.nextMessageSeqSend = 0
	conn.nextMessageSeqReceive = 0

	conn.sendNewSessionTicketMessageSeq = 0
	conn.sendKeyUpdateMessageSeq = 0
	conn.sendKeyUpdateUpdateRequested = false

	conn.sendAlert = record.Alert{}

	// for now, call exactly once for each !closed -> closed change
	// TODO - call only if we called OnConnectLocked
	conn.handler.OnDisconnectLocked(nil)
}

func (conn *Connection) startConnection(tr *Transport, handler ConnectionHandler, addr netip.AddrPort) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.stateID != smIDClosed {
		return ErrConnectionInProgress
	}
	hctx := newHandshakeContext(nil) // TODO - take from pool
	tr.opts.Rnd.ReadMust(hctx.localRandom[:])
	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	hctx.ComputeKeyShare(tr.opts.Rnd)

	conn.tr = tr
	conn.handler = handler

	conn.stateID = smIDHandshakeClientExpectServerHRR
	conn.addr = addr
	conn.tr.addToMap(conn, addr)

	conn.hctx = hctx

	clientHelloMsg := hctx.generateClientHello(conn, true, tr.opts, false, nil)

	if err := hctx.PushMessageNoHasher(conn, clientHelloMsg); err != nil {
		conn.hctx = nil // TODO - reuse
		return err
	}
	return nil
}

func (conn *Connection) debugPrintKeys() {
	sendEpoch2 := "."
	sendSeq2 := "."
	if conn.hctx != nil && conn.hctx.SendSymmetricEpoch2 != nil {
		sendEpoch2 = "2"
		sendSeq2 = strconv.Itoa(int(conn.hctx.SendNextSeqEpoch2)) // widening
	}
	receiveEpoch := conn.keys.ReceiveEpoch
	receiveSeq := conn.keys.ReceiveNextSeq.GetNextReceivedSeq()
	receiveEpoch2 := "."
	receiveSeq2 := "."
	if conn.keys.NewReceiveKeysSet {
		receiveEpoch2 = strconv.Itoa(int(receiveEpoch)) // widening
		receiveEpoch--
		receiveSeq2 = strconv.Itoa(int(conn.keys.NewReceiveNextSeq.GetNextReceivedSeq())) // truncate
	}
	fmt.Printf("send [%d:%d] (hctx=[%s:%s]) receive [%d:%d] [%s:%s]\n",
		conn.keys.SendEpoch, conn.keys.SendNextSeq, sendEpoch2, sendSeq2,
		receiveEpoch, receiveSeq, receiveEpoch2, receiveSeq2)
}

func (conn *Connection) state() StateMachine { return stateMachineStates[conn.stateID] }

func (conn *Connection) keyUpdateInProgress() bool {
	return conn.sendKeyUpdateMessageSeq != 0
}

// TODO - remove after testing
func (conn *Connection) DebugKeyUpdateLocked(updateRequested bool) {
	if err := conn.keyUpdateStart(updateRequested); err != nil {
		fmt.Printf("dtls: DebugKeyUpdateLocked returned error: %v\n", err)
		return
	}
	fmt.Printf("dtls: DebugKeyUpdateLocked updateRequested: %v\n", updateRequested)
	conn.SignalWriteable()
}

func (conn *Connection) keyUpdateStart(updateRequested bool) error {
	if conn.keyUpdateInProgress() {
		return nil
	}
	if conn.nextMessageSeqSend == math.MaxUint16 {
		return dtlserrors.ErrSendMessageSeqOverflow
	}
	conn.sendKeyUpdateMessageSeq = conn.nextMessageSeqSend
	conn.sentKeyUpdateRN = record.Number{}
	conn.sendKeyUpdateUpdateRequested = updateRequested
	conn.nextMessageSeqSend++ // never due to check above
	fmt.Printf("KeyUpdate started (updateRequested=%v), messageSeq: %d\n", updateRequested, conn.sendKeyUpdateMessageSeq)
	return nil
}
