package chat

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Check is a helper to throw errors in the examples.
func Check(err error) {
	var netError net.Error
	if errors.As(err, &netError) && netError.Temporary() { //nolint:staticcheck
		fmt.Printf("Warning: %v\n", err)
	} else if err != nil {
		fmt.Printf("error: %v\n", err)
		panic(err)
	}
}

// Chat simulates a simple text chat session over the connection.
func Chat(conn io.ReadWriter) {
	go func() {
		b := make([]byte, 128)

		for {
			n, err := conn.Read(b)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			Check(err)
			fmt.Printf("Got message: %s\n", string(b[:n]))
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	for {
		text, err := reader.ReadString('\n')
		Check(err)

		if strings.TrimSpace(text) == "exit" {
			return
		}

		_, err = conn.Write([]byte(text))
		if errors.Is(err, net.ErrClosed) {
			return
		}
		Check(err)
	}
}

/*

type ClientConn struct {
	statemachine.Connection

	chatClient *Client

	messagesToSend []string
	shouldBeClosed bool
}

func (conn *ClientConn) OnConnectLocked() {
	fmt.Printf("chat client connected\n")
	go conn.run()
}

func (conn *ClientConn) OnDisconnectLocked(err error) {
	fmt.Printf("chat client disconnected\n")
}

func (conn *ClientConn) OnStartConnectionFailed(err error) {
	fmt.Printf("chat client connection unsuccessful with error: %v\n", err)
	time.AfterFunc(time.Second*5, func() {
		if err :=conn.chatClient.t.StartConnection()
	})
}

func (conn *ClientConn) OnWriteRecordLocked(recordBody []byte) (recordSize int, send bool, signalWriteable bool, err error) {
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

func (conn *ClientConn) close() {
	conn.Lock()
	defer conn.Unlock()
	conn.shouldBeClosed = true
	conn.SignalWriteable()
}

// transport handler
type Client struct {
	mu              sync.Mutex
	t               *statemachine.Transport
	connectedClient *ClientConn
}

func NewClient(t *statemachine.Transport) *Client {
	return &Client{t: t}
}

func (ch *Client) OnNewConnection() (*statemachine.Connection, statemachine.ConnectionHandler) {
	conn := &ClientConn{chatClient: ch}
	return &conn.Connection, conn
}

func (conn *Client) GoStart(t *statemachine.Transport, addr netip.AddrPortNum) {
	for {
		t.StartConnection()
	}
}

*/
