package format

// TODO - rename into fragment
type MessageHandshake struct {
	Header MessageHandshakeHeader
	Body   []byte // TODO - reuse in rope
}
