// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"
	"log"
	"math"
	"net/netip"
	"sync"

	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

type ConnectionHandler interface {
	// application must remove connection from all data structures
	// connection will be reused and become invalid immediately after method returns
	OnDisconnect(err error)

	// if connection was register for send with transport, this method will be called
	// in the near future. record is allocated and resized to maximum size application
	// is allowed to write.
	// Application sets send = true, if it filled record. recordSize is # of bytes filled
	// (recordSize can be 0 to send 0-size record, if recordSize > len(record), then panic)
	// Application sets moreData if it still has more data to send.
	// Application can set send = false, and moreData = true only in case it did not want
	// to send short record (application may prefer to send longer record on the next call).
	OnWriteApplicationRecord(record []byte) (recordSize int, send bool, moreData bool)

	// every record sent will be delivered as is. Sent empty records are delivered as empty records.
	// record points to buffer inside transport and must not be retained.
	// bytes are guaranteed to be valid only during the call.
	// if application returns error, connection close will be initiated, expect OnDisconnect in the near future.
	OnReadApplicationRecord(record []byte) error
}

// Contains absolute minimum of what's mandatory for after handshake finished
// keys, record replay buffer, ack queue for KeyUpdate and NewSessionTicket messages
// all other information is in handshakeContext structure and will be reused
// after handshake finish
type ConnectionImpl struct {
	// variables below mu are protected by mu, except where noted
	mu   sync.Mutex     // TODO - check that mutex is alwasy taken
	addr netip.AddrPort // changes very rarely
	keys keys.Keys

	// We do not support received messages of this kind to be fragmented,
	// because we do not want to allocate memory for reassembly,
	// Also we do not want to support sending them fragmented, because we do not want to track
	// rn -> fragment relations. We simply track 1 rn per message type instead.
	sentKeyUpdateRN        record.Number // if != 0, already sent, on resend overwrite rn
	sentNewSessionTicketRN record.Number // if != 0, already sent, on resend overwrite rn

	hctx    *handshakeContext // handshakeContext content is also protected by mutex above
	Handler ConnectionHandler

	// Messages are protocol above records, these counters do not reset for connection lifetime.
	// If any reaches 2^16, connection will be closed by both peers.
	nextMessageSeqSend    uint16
	nextMessageSeqReceive uint16

	sendNewSessionTicketMessageSeq uint16 // != 0 if set. Sent using stateless sender to avoid storing message here
	sendKeyUpdateMessageSeq        uint16 // != 0 if set
	sendKeyUpdateUpdateRequested   bool   // fully defines content of KeyUpdate we are sending

	roleServer bool                // changes very rarely
	stateID    stateMachineStateID // index in global table
	// set when user signals it has data, clears after OnWriteRecord returns false
	handlerHasMoreData bool

	// intrusive, must not be changed except by sender, protected by sender mutex
	InSenderQueue bool
	// intrusive, must not be changed except by clock, protected by clock mutex
	TimerHeapIndex int
	// time.Time object is larger and also has complicated comparison,
	// which might be invalid as a heap predicate
	FireTimeUnixNano int64
}

func NewServerConnection(addr netip.AddrPort) *ConnectionImpl {
	return &ConnectionImpl{
		addr:       addr,
		roleServer: true,
		stateID:    smIDHandshakeServerExpectClientHello2,
	}
}

func NewClientConnection(addr netip.AddrPort, opts *options.TransportOptions) (*ConnectionImpl, error) {
	// TODO - take from pool, limit # of outstanding handshakes
	hctx := newHandshakeContext(sha256.New())
	opts.Rnd.ReadMust(hctx.localRandom[:])
	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	hctx.ComputeKeyShare(opts.Rnd)

	// TODO - take from pool, limit # of connections
	conn := &ConnectionImpl{
		addr:       addr,
		roleServer: false,
		stateID:    smIDHandshakeClientExpectServerHello,
		hctx:       hctx,
	}
	clientHelloMsg := hctx.generateClientHello(false, cookie.Cookie{})

	if err := hctx.PushMessage(conn, clientHelloMsg); err != nil {
		// If you start returning nil, err from this function, do not forget to return conn and hctx to the pool
		panic("push message for client hello must always succeed")
	}
	return conn, nil
}

func (conn *ConnectionImpl) Addr() netip.AddrPort { return conn.addr }
func (conn *ConnectionImpl) State() StateMachine  { return stateMachineStates[conn.stateID] }

func (conn *ConnectionImpl) keyUpdateInProgress() bool {
	return conn.sendKeyUpdateMessageSeq != 0
}

func (conn *ConnectionImpl) keyUpdateStart(updateRequested bool) error {
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

func (conn *ConnectionImpl) OnTimer() {
}

type exampleHandler struct {
	toSend string
}

func (h *exampleHandler) OnDisconnect(err error) {

}

func (h *exampleHandler) OnWriteApplicationRecord(recordData []byte) (recordSize int, send bool, addToSendQueue bool) {
	toSend := copy(recordData, h.toSend)
	h.toSend = h.toSend[toSend:]
	return toSend, toSend != 0, len(h.toSend) > 0
}

func (h *exampleHandler) OnReadApplicationRecord(record []byte) error {
	return nil
}
