package chat

import (
	"fmt"
	"sync"

	"github.com/hrissan/dtls/transport/statemachine"
)

type ChatConnection struct {
	statemachine.Connection

	chat *ChatRoom

	messagesToSend []string
}

func (conn *ChatConnection) OnConnect() {
	conn.chat.connections[conn] = struct{}{}
}

func (conn *ChatConnection) OnDisconnect(err error) {
	delete(conn.chat.connections, conn)
}

func (conn *ChatConnection) OnWriteRecord(recordBody []byte) (recordSize int, send bool, moreData bool) {
	if len(conn.messagesToSend) == 0 {
		return 0, false, false
	}
	msg := conn.messagesToSend[0]
	toSend := copy(recordBody, msg)
	msg = msg[toSend:]
	if len(msg) == 0 {
		conn.messagesToSend = conn.messagesToSend[1:]
	}
	return toSend, true, len(conn.messagesToSend) != 0
}

func (conn *ChatConnection) OnReadRecord(recordBody []byte) error {
	if len(recordBody) == 0 {
		return nil
	}
	conn.chat.mu.Lock()
	defer conn.chat.mu.Unlock()
	fmt.Printf("received, sending to %d buddies: %q", len(conn.chat.connections), recordBody)
	for buddy := range conn.chat.connections {
		if buddy != conn {
			buddy.messagesToSend = append(buddy.messagesToSend, string(recordBody))
			conn.SetWriteable()
		}
	}
	return nil
}

// transport handler
type ChatRoom struct {
	mu          sync.Mutex
	connections map[*ChatConnection]struct{}
}

func NewChatRoom() *ChatRoom {
	return &ChatRoom{connections: map[*ChatConnection]struct{}{}}
}

func (ch *ChatRoom) OnNewConnection() (*statemachine.Connection, statemachine.ConnectionHandler) {
	conn := &ChatConnection{chat: ch}
	return &conn.Connection, conn
}
