package constants

// We want fixed-size storage for hashes, as we want to do as few allocations as possible
// We set some practical size, if we ever need larger hashes, we will increase this constant
// for particular build
const MaxHashLength = 32

// Limited as a protection against too much work for signature checking
const MaxCertificateChainLength = 16
