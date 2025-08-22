package chat

import (
	"fmt"
	"sync"

	"github.com/hrissan/dtls/transport"
	"github.com/hrissan/dtls/transport/statemachine"
)

// connection
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

func (conn *ChatConnection) OnWriteApplicationRecord(record []byte) (recordSize int, send bool, moreData bool) {
	conn.chat.mu.Lock()
	defer conn.chat.mu.Unlock()
	fmt.Printf("received, sending to %d buddies: %q", len(conn.chat.connections), record)
	for buddy := range conn.chat.connections {
		if buddy != conn {
			buddy.messagesToSend = append(buddy.messagesToSend, string(record))
			conn.chat.tr.StartWriting(&buddy.Connection)
		}
	}
}

func (conn *ChatConnection) OnReadApplicationRecord(record []byte) error {

}

// transport handler
type ChatRoom struct {
	mu          sync.Mutex
	connections map[*ChatConnection]struct{}
	tr          *transport.Transport
}

func NewChat() *ChatRoom {
	return &ChatRoom{connections: map[*ChatConnection]struct{}{}}
}

func (ch *ChatRoom) OnNewConnection() *statemachine.Connection {
	conn := &ChatConnection{chat: ch}
	conn.SetHandler(conn)
	return &conn.Connection
}
