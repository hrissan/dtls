package statemachine

import (
	"log"
	"math"
	"net/netip"
	"sync"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
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
// all other information is in HandshakeContext structure and will be reused
// after handshake finish
type ConnectionImpl struct {
	// variables below mu are protected by mu, except where noted
	mu   sync.Mutex     // TODO - check that mutex is alwasy taken
	Addr netip.AddrPort // changes very rarely
	Keys keys.Keys

	// We do not support received messages of this kind to be fragmented,
	// because we do not want to allocate memory for reassembly,
	// Also we do not want to support sending them fragmented, because we do not want to track
	// rn -> fragment relations. We simply track 1 rn per message type instead.
	sendKeyUpdateRN        format.RecordNumber // if != 0, already sent, on resend overwrite rn
	sendNewSessionTicketRN format.RecordNumber // if != 0, already sent, on resend overwrite rn

	Handshake *HandshakeConnection // content is also protected by mutex above
	Handler   ConnectionHandler

	// this counter does not reset with a new epoch
	NextMessageSeqSend    uint16
	NextMessageSeqReceive uint16

	sendNewSessionTicketMessageSeq uint16 // != 0 if set
	sendKeyUpdateMessageSeq        uint16 // != 0 if set
	sendKeyUpdateUpdateRequested   bool   // fully defines content of KeyUpdate we are sending

	RoleServer         bool // changes very rarely
	HandlerHasMoreData bool // set when user signals it has data, clears after OnWriteRecord returns false

	InSenderQueue    bool  // intrusive, must not be changed except by sender, protected by sender mutex
	TimerHeapIndex   int   // intrusive, must not be changed except by clock, protected by clock mutex
	FireTimeUnixNano int64 // time.Time object is larger and might be invalid as a heap predicate
}

func (conn *ConnectionImpl) FirstMessageSeqInReceiveQueue() uint16 {
	if conn.Handshake == nil { // connection has no queue and processes full messages one by one
		return conn.NextMessageSeqReceive
	}
	if conn.Handshake.receivedMessages.Len() > int(conn.NextMessageSeqReceive) {
		panic("received messages queue invariant violated")
	}
	return conn.NextMessageSeqReceive - uint16(conn.Handshake.receivedMessages.Len())
}

func (conn *ConnectionImpl) startKeyUpdate(updateRequested bool) error {
	if conn.sendKeyUpdateMessageSeq != 0 {
		return nil // KeyUpdate in progress
	}
	if conn.NextMessageSeqSend == math.MaxUint16 {
		return dtlserrors.ErrSendMessageSeqOverflow
	}
	conn.sendKeyUpdateMessageSeq = conn.NextMessageSeqSend
	conn.sendKeyUpdateRN = format.RecordNumber{}
	conn.sendKeyUpdateUpdateRequested = updateRequested
	conn.NextMessageSeqSend++ // never due to check above
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

func (h *exampleHandler) OnWriteApplicationRecord(record []byte) (recordSize int, send bool, addToSendQueue bool) {
	toSend := copy(record, h.toSend)
	h.toSend = h.toSend[toSend:]
	return toSend, toSend != 0, len(h.toSend) > 0
}

func (h *exampleHandler) OnReadApplicationRecord(record []byte) error {
	return nil
}
