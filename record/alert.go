// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package record

import (
	"errors"

	"github.com/hrissan/dtls/format"
)

var ErrAlertLevelParsing = errors.New("alert level failed to parse")

const AlertSize = 2

const (
	// we use 0 as "no alert" indicator
	AlerLevelWarning = 1
	AlerLevelFatal   = 2
)

type Alert struct {
	Level       byte
	Description byte
}

func (msg *Alert) IsFatal() bool {
	return msg.Level == AlerLevelFatal
}

func AlertCloseNormal() Alert { return Alert{Level: 2, Description: 0} }

func (msg *Alert) Parse(body []byte) (err error) {
	offset := 0
	var level byte
	if offset, level, err = format.ParserReadByte(body, offset); err != nil {
		return err
	}
	switch level {
	case AlerLevelWarning, AlerLevelFatal:
		msg.Level = level
	default:
		return ErrAlertLevelParsing
	}
	if offset, msg.Description, err = format.ParserReadByte(body, offset); err != nil {
		return err
	}
	// we do not classify descriptions yet. TODO - some logic
	return format.ParserReadFinish(body, offset)
}

func (msg *Alert) Write(body []byte) []byte {
	switch msg.Level {
	case AlerLevelWarning, AlerLevelFatal:
		return append(body, msg.Level, msg.Description)
	default:
		panic("should not write alert with level not in standard")
	}
}
