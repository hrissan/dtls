package statemachine

import (
	"crypto/sha256"
	"log"
	"math"
	"net/netip"
	"sync"

	"github.com/hrissan/tinydtls/cookie"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/keys"
	"github.com/hrissan/tinydtls/record"
	"github.com/hrissan/tinydtls/transport/options"
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
	sendKeyUpdateRN        record.Number // if != 0, already sent, on resend overwrite rn
	sendNewSessionTicketRN record.Number // if != 0, already sent, on resend overwrite rn

	hctx    *handshakeContext // content is also protected by mutex above
	Handler ConnectionHandler

	// this counter does not reset with a new epoch
	nextMessageSeqSend    uint16
	nextMessageSeqReceive uint16

	sendNewSessionTicketMessageSeq uint16 // != 0 if set
	sendKeyUpdateMessageSeq        uint16 // != 0 if set
	sendKeyUpdateUpdateRequested   bool   // fully defines content of KeyUpdate we are sending

	roleServer         bool                // changes very rarely
	stateID            stateMachineStateID // index in global table
	handlerHasMoreData bool                // set when user signals it has data, clears after OnWriteRecord returns false

	InSenderQueue    bool  // intrusive, must not be changed except by sender, protected by sender mutex
	TimerHeapIndex   int   // intrusive, must not be changed except by clock, protected by clock mutex
	FireTimeUnixNano int64 // time.Time object is larger and might be invalid as a heap predicate
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

func (conn *ConnectionImpl) firstMessageSeqInReceiveQueue() uint16 {
	if conn.hctx == nil { // connection has no queue and processes full messages one by one
		return conn.nextMessageSeqReceive
	}
	if conn.hctx.receivedMessages.Len() > int(conn.nextMessageSeqReceive) {
		panic("received messages queue invariant violated")
	}
	return conn.nextMessageSeqReceive - uint16(conn.hctx.receivedMessages.Len())
}

func (conn *ConnectionImpl) startKeyUpdate(updateRequested bool) error {
	if conn.sendKeyUpdateMessageSeq != 0 {
		return nil // KeyUpdate in progress
	}
	if conn.nextMessageSeqSend == math.MaxUint16 {
		return dtlserrors.ErrSendMessageSeqOverflow
	}
	conn.sendKeyUpdateMessageSeq = conn.nextMessageSeqSend
	conn.sendKeyUpdateRN = record.Number{}
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
