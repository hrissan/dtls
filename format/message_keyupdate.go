package format

import "errors"

var ErrKeyUpdateRequestInvalid = errors.New("KeyUpdate request_update invalid value")

type MessageKeyUpdate struct {
	UpdateRequested bool
}

func (msg *MessageKeyUpdate) MessageKind() string { return "handshake" }
func (msg *MessageKeyUpdate) MessageName() string { return "KeyUpdate" }

func (msg *MessageKeyUpdate) Parse(body []byte) (err error) {
	var offset int
	var requestUpdate byte
	if offset, requestUpdate, err = ParserReadByte(body, offset); err != nil {
		return err
	}
	switch requestUpdate {
	case 0:
		msg.UpdateRequested = false
	case 1:
		msg.UpdateRequested = true
	default:
		return ErrKeyUpdateRequestInvalid
	}
	return ParserReadFinish(body, offset)
}

func (msg *MessageKeyUpdate) Write(body []byte) []byte {
	if msg.UpdateRequested {
		return append(body, 1)
	}
	return append(body, 0)
}
