package handshake

type Message struct {
	MsgType MsgType
	MsgSeq  uint16
	Body    []byte // TODO - reuse in rope
}
