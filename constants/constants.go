package constants

// We want fixed-size storage for hashes, as we want to do as few allocations as possible
// We set some practical size, if we ever need larger hashes, we will increase this constant
const MaxHashLength = 32

// Limited as a protection against too much work for signature checking
const MaxCertificateChainLength = 16

const MaxOutgoingHRRDatagramLength = 512

const MaxSendAcksConnection = 4 // do not make too small or large
const MaxSendAcksHandshake = 16 // do not make too large, we use linear search for set of acks

const MaxSendMessagesQueue = 8

// we will not send more records until some are acknowledged
const MaxSendRecordsQueue = 16

// We do not want to send 25 bytes of headers at the end of datagram to send 1 byte of body.
// If there is not enough space to send headers plus MinFragmentBodySize bytes,
// of body, we will send it in the next datagram.
const MinFragmentBodySize = 32

const AEADSealSize = 16 // TODO - include into our gcm wrapper
