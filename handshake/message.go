// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"encoding/binary"
	"hash"

	"github.com/hrissan/dtls/safecast"
)

type Message struct {
	MsgType MsgType
	MsgSeq  uint16
	Body    []byte // TODO - reuse in rope
}

func (msg *Message) Len32() uint32 {
	return safecast.Cast[uint32](len(msg.Body))
}

// MsgSeq is not part of original TLSv3.0, so not included in transcript
func (msg *Message) AddToHash(transcriptHasher hash.Hash) {
	msg.AddToHashPartial(transcriptHasher, len(msg.Body))
}

func (msg *Message) AddToHashPartial(transcriptHasher hash.Hash, partialLength int) {
	if len(msg.Body) > 0xFFFFFF {
		panic("message body too large")
	}
	var result [4]byte
	first4Bytes := (uint32(msg.MsgType) << 24) + uint32(len(msg.Body)) // widening, safe due to check above
	binary.BigEndian.PutUint32(result[:], first4Bytes)
	_, _ = transcriptHasher.Write(result[:])
	_, _ = transcriptHasher.Write(msg.Body[:partialLength])
	return
}
