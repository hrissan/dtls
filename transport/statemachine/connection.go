// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"log"
	"math"
	"net/netip"
	"sync"
	"time"

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
	transport *Transport
	// variables below mu are protected by mu, except where noted
	mu        sync.Mutex     // TODO - check that mutex is alwasy taken
	addr      netip.AddrPort // changes very rarely
	cookieAge time.Duration
	keys      keys.Keys

	// We do not support received messages of this kind to be fragmented,
	// because we do not want to allocate memory for reassembly,
	// Also we do not want to support sending them fragmented, because we do not want to track
	// rn -> fragment relations. We simply track 1 rn per message type instead.
	sentKeyUpdateRN        record.Number // if != 0, already sent, on resend overwrite rn
	sentNewSessionTicketRN record.Number // if != 0, already sent, on resend overwrite rn

	hctx    *handshakeContext // handshakeContext content is also protected by mutex above
	handler ConnectionHandler

	// Messages are protocol above records, these counters do not reset for connection lifetime.
	// If any reaches 2^16, connection will be closed by both peers.
	nextMessageSeqSend    uint16
	nextMessageSeqReceive uint16

	sendNewSessionTicketMessageSeq uint16 // != 0 if set. Sent using stateless sender to avoid storing message here
	sendKeyUpdateMessageSeq        uint16 // != 0 if set
	sendKeyUpdateUpdateRequested   bool   // fully defines content of KeyUpdate we are sending

	roleServer bool                // TODO - remove
	stateID    stateMachineStateID // index in global table
	// set when user signals it has data, clears after OnWriteRecord returns false
	handlerWriteable bool

	// intrusive, must not be changed except by sender, protected by sender mutex
	inSenderQueue bool
	// intrusive, must not be changed except by receiver, protected by receiver mutex
	inReceiverClosingQueue bool
	// intrusive, must not be changed except by clock, protected by clock mutex
	timerHeapIndex int
	// time.Time object is larger and also has complicated comparison,
	// which might be invalid as a heap predicate
	fireTimeUnixNano int64
}

func NewServerConnection(tr *Transport, addr netip.AddrPort) *Connection {
	return &Connection{
		transport:  tr,
		addr:       addr,
		roleServer: true,
		stateID:    smIDClosed, // explicit 0
	}
}

func NewClientConnection(tr *Transport, addr netip.AddrPort) (*Connection, error) {
	// TODO - take from pool, limit # of outstanding handshakes
	hctx := newHandshakeContext(sha256.New())
	tr.opts.Rnd.ReadMust(hctx.localRandom[:])
	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	hctx.ComputeKeyShare(tr.opts.Rnd)

	// TODO - take from pool, limit # of connections
	conn := &Connection{
		transport:  tr,
		addr:       addr,
		roleServer: false,
		stateID:    smIDHandshakeClientExpectServerHRR,
		hctx:       hctx,
	}
	clientHelloMsg := hctx.generateClientHello(false, cookie.Cookie{})

	if err := hctx.PushMessage(conn, clientHelloMsg); err != nil {
		// If you start returning nil, err from this function, do not forget to return conn and hctx to the pool
		panic("push message for client hello must always succeed")
	}
	return conn, nil
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
	log.Printf("KeyUpdate started (updateRequested=%v), messageSeq: %d", updateRequested, conn.sendKeyUpdateMessageSeq)
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
