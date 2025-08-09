package format

import "encoding/binary"

func AppendUint24(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	if tmp[0] != 0 {
		panic("AppendUint24 value out of range")
	}
	return append(b, tmp[1:]...)
}

func AppendUint48(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	if tmp[0] != 0 || tmp[1] != 0 {
		panic("AppendUint48 value out of range")
	}
	return append(b, tmp[2:]...)
}

func MarkUin16Offset(body []byte) ([]byte, int) {
	body = append(body, 0, 0)
	return body, len(body)
}

func FillUin16Offset(body []byte, mark int) {
	binary.BigEndian.PutUint16(body[mark-2:], uint16(len(body)-mark))
}
