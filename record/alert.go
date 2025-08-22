package record

import (
	"errors"

	"github.com/hrissan/dtls/format"
)

var ErrAlertLevelParsing = errors.New("alert level failed to parse")

type Alert struct {
	Fatal       bool
	Description byte
}

func (msg *Alert) Parse(body []byte) (err error) {
	offset := 0
	var level byte
	if offset, level, err = format.ParserReadByte(body, offset); err != nil {
		return err
	}
	switch level {
	case 1:
		msg.Fatal = false
	case 2:
		msg.Fatal = true
	default:
		return ErrAlertLevelParsing
	}
	if offset, msg.Description, err = format.ParserReadByte(body, offset); err != nil {
		return err
	}
	// we do not classify descriptions yet. TODO - some logic
	return format.ParserReadFinish(body, offset)
}
