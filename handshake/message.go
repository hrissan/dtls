package handshake

type MessageHandshakeFragment struct {
	Header HandshakeMsgFragmentHeader
	Body   []byte // TODO - reuse in rope
}
