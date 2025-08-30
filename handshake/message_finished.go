// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

// after parsing, those slices point to datagram, so must be copied or
// discarded before next datagram is read
type MsgFinished struct {
	VerifyData []byte
}

func (msg *MsgFinished) MessageKind() string { return "handshake" }
func (msg *MsgFinished) MessageName() string { return "Finished" }

func (msg *MsgFinished) Parse(body []byte) (err error) {
	msg.VerifyData = body
	return nil
}

func (msg *MsgFinished) Write(body []byte) []byte {
	return append(body, msg.VerifyData...)
}
