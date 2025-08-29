// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/netip"
	"sync"

	"github.com/hrissan/dtls/cookie"
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
	mu   sync.Mutex     // TODO - check that mutex is alwasy taken
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
	// intrusive, must not be changed except by clock, protected by clock mutex
	timerHeapIndex int
	// time.Time object is larger and also has complicated comparison,
	// which might be invalid as a heap predicate
	fireTimeUnixNano int64
}

func (conn *Connection) Lock()   { conn.mu.Lock() }
func (conn *Connection) Unlock() { conn.mu.Unlock() }

func (conn *Connection) AddrLocked() netip.AddrPort {
	return conn.addr
}

func (conn *Connection) ShutdownLocked(err error) {
	if conn.shutdownLockedShouldSignal(err) {
		conn.SignalWriteable()
	}
}

func (conn *Connection) shutdownLockedShouldSignal(err error) bool {
	if conn.stateID == smIDClosed || conn.stateID == smIDShutdown {
		return false
	}
	// TODO - send stateless encrypted alert and destroy connection
	conn.stateID = smIDShutdown
	return true
}

func (conn *Connection) Shutdown(err error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.ShutdownLocked(err)
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

func (conn *Connection) startConnection(tr *Transport, handlser ConnectionHandler, addr netip.AddrPort) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.stateID != smIDClosed {
		return ErrConnectionInProgress
	}
	hctx := newHandshakeContext(sha256.New()) // TODO - take from pool
	tr.opts.Rnd.ReadMust(hctx.localRandom[:])
	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	hctx.ComputeKeyShare(tr.opts.Rnd)

	conn.tr = tr
	conn.addr = addr
	conn.handler = handlser
	conn.stateID = smIDHandshakeClientExpectServerHRR
	conn.hctx = hctx

	clientHelloMsg := hctx.generateClientHello(false, cookie.Cookie{})

	if err := hctx.PushMessage(conn, clientHelloMsg); err != nil {
		conn.hctx = nil // TODO - reuse
		return err
	}
	return nil
}

func (conn *Connection) state() StateMachine { return stateMachineStates[conn.stateID] }

func (conn *Connection) onReceiverClose() netip.AddrPort {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	// TODO - call user code if needed
	addr := conn.addr
	conn.addr = netip.AddrPort{}
	return addr
}

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

func (conn *Connection) onTimer() {
}

type exampleHandler struct {
	toSend string
}

func (h *exampleHandler) OnDisconnect(err error) {

}

func (h *exampleHandler) OnWriteRecord(recordData []byte) (recordSize int, send bool, addToSendQueue bool) {
	toSend := copy(recordData, h.toSend)
	h.toSend = h.toSend[toSend:]
	return toSend, toSend != 0, len(h.toSend) > 0
}

func (h *exampleHandler) OnReadApplicationRecord(record []byte) error {
	return nil
}
