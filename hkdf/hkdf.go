// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on RFC 5869

// TODO - rewrite to avoid allocations

package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// TODO - remove allocations
func HMAC(key, data []byte, h hash.Hash) []byte {
	mirror := hmac.New(sha256.New, key) // TODO - actually use h
	_, _ = mirror.Write(data)
	return mirror.Sum(nil)
}

func Extract(hasher hash.Hash, salt, keymaterial []byte) []byte {
	return HMAC(salt, keymaterial, hasher)
}

func Expand(hasher hash.Hash, keymaterial, info []byte, outlength int) []byte {
	n := (outlength + hasher.Size() + 1) / hasher.Size()
	result := []byte{}
	T := []byte{}
	for i := 1; i <= n; i++ {
		T = append(T, info...)
		T = append(T, byte(i))
		T = HMAC(keymaterial, T, hasher)
		result = append(result, T...)
	}
	return result[:outlength]
}

func ExpandLabel(hasher hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	hkdflabel := make([]byte, 0)
	hkdflabel = append(hkdflabel, byte(length>>8))
	hkdflabel = append(hkdflabel, byte(length))
	hkdflabel = append(hkdflabel, byte(len(label)+6))
	hkdflabel = append(hkdflabel, "dtls13"...)
	hkdflabel = append(hkdflabel, label...)
	hkdflabel = append(hkdflabel, byte(len(context)))
	hkdflabel = append(hkdflabel, context...)
	return Expand(hasher, secret, hkdflabel, length)
}
