package chat

import (
	"fmt"
	"strings"
	"sync"

	"github.com/hrissan/dtls/transport/statemachine"
)

type Conn struct {
	statemachine.Connection

	chatRoom *Room

	messagesToSend []string // protected by chatRoom lock
}

func (conn *Conn) OnConnectLocked() {
	conn.chatRoom.connections[conn] = struct{}{}
}

func (conn *Conn) OnDisconnectLocked(err error) {
	delete(conn.chatRoom.connections, conn)
}

func (conn *Conn) OnWriteRecordLocked(recordBody []byte) (recordSize int, send bool, signalWriteable bool) {
	conn.chatRoom.mu.Lock()
	defer conn.chatRoom.mu.Unlock()
	return onWriteMessages(&conn.messagesToSend, recordBody)
}

func (conn *Conn) OnReadRecordLocked(recordBody []byte) error {
	if len(recordBody) == 0 {
		return nil
	}
	conn.chatRoom.mu.Lock()
	defer conn.chatRoom.mu.Unlock()

	switch strings.TrimSpace(string(recordBody)) {
	case "upds":
		conn.DebugKeyUpdateLocked(false)
	case "updsr":
		conn.DebugKeyUpdateLocked(true)
	}
	fmt.Printf("chat room mesage from %q, sending to %d buddies: %q\n", conn.AddrLocked(), len(conn.chatRoom.connections), recordBody)
	for buddy := range conn.chatRoom.connections {
		buddy.messagesToSend = append(buddy.messagesToSend, fmt.Sprintf("%s says: %s", conn.AddrLocked(), recordBody))
		buddy.SignalWriteable()
	}
	return nil
}

// transport handler
type Room struct {
	mu          sync.Mutex
	connections map[*Conn]struct{}
}

func NewRoom() *Room {
	return &Room{connections: map[*Conn]struct{}{}}
}

func (ch *Room) OnNewConnection() (*statemachine.Connection, statemachine.ConnectionHandler) {
	conn := &Conn{chatRoom: ch}
	return &conn.Connection, conn
}

func onWriteMessages(messagesToSend *[]string, recordBody []byte) (recordSize int, send bool, moreData bool) {
	if len(*messagesToSend) == 0 {
		return 0, false, false
	}
	msg := (*messagesToSend)[0]
	toSend := copy(recordBody, msg)
	msg = msg[toSend:]
	if len(msg) == 0 {
		*messagesToSend = (*messagesToSend)[1:]
	}
	return toSend, true, len(*messagesToSend) != 0
}
