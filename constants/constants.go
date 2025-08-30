// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package constants

// We want fixed-size storage for hashes, as we want to do as few allocations as possible
// We set some practical size, if we ever need larger hashes, we will increase this constant
const MaxHashLength = 48

// Limited as a protection against too much work for signature checking
const MaxCertificateChainLength = 16

const MaxOutgoingHRRDatagramLength = 512

// we will not send more records until some are acknowledged
const MaxSendRecordsQueue = 16

const MaxSendMessagesQueue = 8
const MaxReceiveMessagesQueue = 8

// Minimal useful value is 2, so when packet loss happens and next fragment arrives,
// we can add another hole, and continue receiving.
// [xxxx...............]   <-- received fragments so far, this is a single hole
// .....---.............   <-- lost fragment
// ........[xxx]........   <-- first packet after packet loss
// [xxxx....xxx........]   <-- state after second hole created.
//
// 3 allows to fit 3 holes + count into 32 bytes, and we can lose 2 independent fragments
// [xxxx..xxxx....xxx..]   <-- we can receive fragments at 6 positions.
const MaxAssemblerHoles = 3

// We do not want to send 25 bytes of headers at the end of datagram to send 1 byte of body.
// If there is not enough space to send headers plus MinFragmentBodySize bytes,
// of body, we will send it in the next datagram.
const MinFragmentBodySize = 32

const MaxPSKIdentities = 32

// Our implementation's limit. Mostly for checking automatic key update works.
// Should be >32 even in tests, otherwise KeyUpdate cannot complete before reaching hard limit.
const MaxProtectionLimitSend = 32
const MaxProtectionLimitReceive = 32

const AEADSealSize = 16 // TODO - include into our gcm wrapper
