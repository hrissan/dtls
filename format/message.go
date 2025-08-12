package format

type MessageHandshake struct {
	Header MessageHandshakeHeader
	Body   []byte // TODO - reuse in rope
}
