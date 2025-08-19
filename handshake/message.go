package handshake

type MessageHandshakeFragment struct {
	Header MsgFragmentHeader
	Body   []byte // TODO - reuse in rope
}
