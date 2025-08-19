package format

type MessageHandshakeFragment struct {
	Header HandshakeMsgFragmentHeader
	Body   []byte // TODO - reuse in rope
}
