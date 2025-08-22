// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package constants

// We want fixed-size storage for hashes, as we want to do as few allocations as possible
// We set some practical size, if we ever need larger hashes, we will increase this constant
const MaxHashLength = 32

// Limited as a protection against too much work for signature checking
const MaxCertificateChainLength = 16

const MaxOutgoingHRRDatagramLength = 512

// we will not send more records until some are acknowledged
const MaxSendRecordsQueue = 16

const MaxSendMessagesQueue = 8
const MaxReceiveMessagesQueue = 8

const MaxAssemblerHoles = 4 // minimal useful value 2

// We do not want to send 25 bytes of headers at the end of datagram to send 1 byte of body.
// If there is not enough space to send headers plus MinFragmentBodySize bytes,
// of body, we will send it in the next datagram.
const MinFragmentBodySize = 32

const AEADSealSize = 16 // TODO - include into our gcm wrapper
