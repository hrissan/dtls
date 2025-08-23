// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package safecast

import (
	"errors"
	"strconv"
)

// Based on https://github.com/fortio/safecast
// We are dependency-free, so cannot reference module directly

type Integer interface {
	~uintptr |
		~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

func Append[Arg Integer](w []byte, arg Arg, base int) []byte {
	switch v := any(arg).(type) {
	case int:
		return strconv.AppendInt(w, int64(v), base)
	case int8:
		return strconv.AppendInt(w, int64(v), base)
	case int16:
		return strconv.AppendInt(w, int64(v), base)
	case int32:
		return strconv.AppendInt(w, int64(v), base)
	case int64:
		return strconv.AppendInt(w, v, base)
	case uint:
		return strconv.AppendUint(w, uint64(v), base)
	case uint8:
		return strconv.AppendUint(w, uint64(v), base)
	case uint16:
		return strconv.AppendUint(w, uint64(v), base)
	case uint32:
		return strconv.AppendUint(w, uint64(v), base)
	case uint64:
		return strconv.AppendUint(w, v, base)
	case uintptr:
		return strconv.AppendUint(w, uint64(v), base)
	default:
		panic("must be never")
	}
}

var ErrIntegerOverflowSign = errors.New("integer overflow - loss of sign")
var ErrIntegerOverflow = errors.New("integer overflow")

func TryCast[Result Integer, Arg Integer](arg Arg) (Result, error) {
	argPositive := arg > 0
	converted := Result(arg)
	if argPositive != (converted > 0) {
		return converted, ErrIntegerOverflowSign // return converted to examine
	}
	if Arg(converted) != arg {
		return converted, ErrIntegerOverflow // return converted to examine
	}
	return converted, nil
}

func Cast[Result Integer, Arg Integer](arg Arg) Result {
	argPositive := arg > 0
	converted := Result(arg)
	if argPositive != (converted > 0) {
		panic("integer overflow - loss of sign")
	}
	if Arg(converted) != arg {
		panic("integer overflow")
	}
	return converted
}
