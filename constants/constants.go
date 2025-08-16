package constants

// We want fixed-size storage for hashes, as we want to do as few allocations as possible
// We set some practical size, if we ever need larger hashes, we will increase this constant
// for particular build
const MaxHashLength = 32

// Limited as a protection against too much work for signature checking
const MaxCertificateChainLength = 16

const MaxOutgoingHRRDatagramLength = 512

const MaxSendAcks = 32

// If there is very little space at the end of datagram, we do not want
// to send 25 bytes of headers to send 1 byte of body.
// If there is not enough space to send headers plus MinFragmentBodySize bytes
// of body, we will send it in the next datagram.
const MinFragmentBodySize = 32

const AEADSealSize = 16 // TODO - include into our gcm wrapper
