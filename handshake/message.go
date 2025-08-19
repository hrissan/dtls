package handshake

import (
	"encoding/binary"
	"hash"
)

type Message struct {
	MsgType MsgType
	MsgSeq  uint16
	Body    []byte // TODO - reuse in rope
}

// only first 2 fields are part of transcript hash
func (msg *Message) AddToHash(transcriptHasher hash.Hash) {
	if len(msg.Body) > 0xFFFFFF {
		panic("message body too large")
	}
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], (uint32(msg.MsgType)<<24)+uint32(len(msg.Body)))
	_, _ = transcriptHasher.Write(result[:])
	return
}
