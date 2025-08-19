package format

type MessageHandshakeFragment struct {
	Header MessageFragmentHeader
	Body   []byte // TODO - reuse in rope
}
