package handshake

type Fragment struct {
	Header FragmentHeader
	Body   []byte // TODO - reuse in rope
}
