package chat

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hrissan/dtls/transport/statemachine"
)

type ClientConn struct {
	statemachine.Connection

	messagesToSend []string
}

func (conn *ClientConn) OnConnectLocked() {
	fmt.Printf("chat client connected\n")
	go conn.run()
}

func (conn *ClientConn) OnDisconnectLocked(err error) {
	fmt.Printf("chat client disconnected\n")
	os.Exit(0)
}

func (conn *ClientConn) OnWriteRecordLocked(recordBody []byte) (recordSize int, send bool, signalWriteable bool) {
	return onWriteMessages(&conn.messagesToSend, recordBody)
}

func (conn *ClientConn) OnReadRecordLocked(recordBody []byte) error {
	if len(recordBody) == 0 {
		return nil
	}
	fmt.Printf("chat client received message: %q\n", recordBody)
	return nil
}

func (conn *ClientConn) run() {
	reader := bufio.NewReader(os.Stdin)

	for {
		text, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("chat client error reading from stdin: %v\n", err)
			conn.Shutdown()
			return
		}
		text = strings.TrimSpace(text)
		if strings.TrimSpace(text) == "exit" {
			conn.Shutdown()
			return
		}
		conn.addMessage(text)
	}
}

func (conn *ClientConn) addMessage(msg string) {
	conn.Lock()
	defer conn.Unlock()
	if msg == "updc" {
		conn.DebugKeyUpdateLocked(false)
		return
	}
	if msg == "updcr" {
		conn.DebugKeyUpdateLocked(true)
		return
	}

	conn.messagesToSend = append(conn.messagesToSend, msg)
	fmt.Printf("chat client message from keyboard: %q\n", msg)

	conn.SignalWriteable()
}

// transport handler
type Client struct {
}

func NewClient() *Client {
	return &Client{}
}

func (ch *Client) OnNewConnection() (*statemachine.Connection, statemachine.ConnectionHandler) {
	conn := &ClientConn{}
	return &conn.Connection, conn
}
