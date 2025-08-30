package dtls

import (
	"io"
	"net"
	"time"

	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/statemachine"
)

// toy implementation - not optimized at all, unlike core
// we store no empty records, because they violate io.Reader contract

const maxRecordsBuffer = 10

type Conn struct {
	tc         statemachine.Connection
	localAddr  net.Addr
	remoteAddr net.Addr

	closed    bool // if true, both channels are closed
	closeErr  error
	condRead  chan struct{}
	condWrite chan struct{}
	condDial  chan struct{}
	reading   [][]byte
	writing   [][]byte
}

func newConn(localAddr net.Addr, remoteAddr net.Addr) *Conn {
	return &Conn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		condRead:   make(chan struct{}, 1),
		condWrite:  make(chan struct{}, 1),
		condDial:   make(chan struct{}, 1),
	}
}

var _ net.Conn = &Conn{}
var _ io.ReadWriter = &Conn{}

func signalCond(cond chan struct{}) {
	select {
	case cond <- struct{}{}:
	default:
	}
}

func (c *Conn) LocalAddr() net.Addr                { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *Conn) SetDeadline(t time.Time) error      { return nil } // TODO
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil } // TODO
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil } // TODO

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.tc.Lock()
	defer c.tc.Unlock()
	for {
		if c.closed {
			return 0, net.ErrClosed
		}
		if len(c.reading) == 0 {
			c.tc.Unlock()
			<-c.condRead
			c.tc.Lock()
			continue
		}
		if len(c.reading[0]) == 0 {
			panic("empty record")
		}
		copied := copy(b, c.reading[0])
		c.reading[0] = c.reading[0][copied:]
		if len(c.reading[0]) == 0 {
			c.reading = c.reading[1:]
		}
		return copied, nil
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 { // we store no empty records, because they violate io.Reader contract
		return 0, nil
	}
	if len(b) > record.MaxPlaintextRecordLength { // limit outgoing buffer
		b = b[:record.MaxPlaintextRecordLength]
	}
	c.tc.Lock()
	defer c.tc.Unlock()
	for {
		if c.closed {
			return 0, net.ErrClosed
		}
		if len(c.writing) >= maxRecordsBuffer { // arbitrary
			c.tc.Unlock()
			<-c.condWrite
			c.tc.Lock()
			continue
		}
		c.writing = append(c.writing, append([]byte{}, b...))
		c.tc.SignalWriteable()
		return len(b), nil
	}
}

func (c *Conn) Close() error {
	c.tc.Lock()
	defer c.tc.Unlock()
	c.closeLocked(nil)
	return c.closeErr
}

func (c *Conn) closeLocked(err error) {
	if c.closed {
		return
	}
	c.closed = true
	c.closeErr = err
	close(c.condRead)
	close(c.condWrite)
	c.tc.SignalWriteable()
}

func (c *Conn) OnStartConnectionFailedLocked(err error) {
	signalCond(c.condDial)
}

func (c *Conn) OnConnectLocked() {
	signalCond(c.condDial)
}

func (c *Conn) OnDisconnectLocked(err error) {
	c.closeLocked(err)
}

func (c *Conn) OnWriteRecordLocked(recordBody []byte) (recordSize int, send bool, signalWriteable bool, err error) {
	if c.closed {
		return 0, false, false, net.ErrClosed
	}
	if len(c.writing) == 0 {
		return 0, false, false, nil
	}
	if len(c.writing[0]) == 0 {
		panic("empty record")
	}
	recordSize = copy(recordBody, c.writing[0])
	c.writing[0] = c.writing[0][recordSize:]
	if len(c.writing[0]) == 0 {
		c.writing = c.writing[1:]
		signalCond(c.condWrite)
	}
	return recordSize, true, false, nil
}

func (conn *Conn) OnReadRecordLocked(recordBody []byte) error {
	if conn.closed {
		return io.EOF
	}
	if len(recordBody) == 0 {
		return nil // we do not store empty records, they violate io.Reader contract
	}
	if len(conn.reading) >= maxRecordsBuffer {
		return nil // we are losing records, because no one is reading on our side
	}
	conn.reading = append(conn.reading, append([]byte{}, recordBody...))
	signalCond(conn.condRead)
	return nil
}
