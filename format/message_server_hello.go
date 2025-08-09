package format

type ServerHello struct {
}

func (msg *ServerHello) MessageKind() string { return "handshake" }
func (msg *ServerHello) MessageName() string { return "server_hello" }

func (msg *ServerHello) Parse(body []byte) error {
	return nil
}
