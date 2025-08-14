# tinydtls

# requirements

## semantic

DTLS 1.3 only, no support for older standards.

Very few dependencies, ideally zero.

Must interoperate with other known implementations. TODO - integration tests with OpenSSL, WolfSSL, BoringSSL, rusty-dtls, etc.

Implement only extensions we really need, or which are easy to support,

Implement only mandatory and useful crypto algorithms, elliptic groups, etc.

Must defend against simple attacks.

Checking validity of certification chain is not a priority for now, but must be correctly implemented later.

## technical

Use standard Go crypto and crypto/x509, which we have no desire to reimplement.

Code as simple and fast as possible, without resorting to dirty tricks.

No unsafe code of our own (except in standard crypto, we do not control).

Must make zero allocations on the fast paths, almost zero allocations on slow paths (except in standard crypto, we do not control).

Must be fixed memory for everything. Every object allocated on heap must be recycled indefinitely (except in standard crypto, we do not control). 

Must use as little memory per established connection as possible (1.5 kilobytes?). We need this implementation for mesh with at least 100K connections per service, so literally every byte counts.
TODO - benchmark and fill in number here after connection actually works.

Must have separate memory limit for established connections.
If the limit is reached, new handshakes cannot start.

Note: We can save half memory for AES context by implementing "Plaintext Sequence Numbers" extension.
https://datatracker.ietf.org/doc/html/draft-pismenny-tls-dtls-plaintext-sequence-number-02

Must have separate memory limit for handshake contexts.
If the limit is reached, new handshakes cannot start (handshakes which did not complete in reasonable time are cancelled to free memory for new handshakes).

Must implement some fairness, so one connection cannot easily dominate.

Must offload heavy computations (ECC, etc.) to separate goroutines, so latency of established connections does not suffer too much.

Must have state machine/sans network core and fuzzing tests with packet drops/reordering.

All parsers/incoming path must be fuzzed.

## design

There is reading goroutine, writing goroutine, timers goroutine, and ECC offload goroutines. They communicate using mutexes, and wake each other with condvars and channels.

Those goroutines block on mutexes only, but for the short time to make quick update of the state machine.

They never wait on something, while holding a mutex, and they do not wait each other, they simply run a common state machine together.

We do not stick to golang's philosophy of communication using blocking channels, because it has a lot of drawbacks for the task we are solving.

### reading goroutine

Reads packet into the single buffer it owns, parses inplace.

For stateless messages, creates and adds responses to the dedicated queue (subject to separate memory limit) and wakes up sending goroutine. 

For stateful messages, finds/creates connection context, decrypts records in place,
then triggers connection state machine, which sometimes wakes up sending goroutine.

If heavy computations are required, instead of waking up sending goroutine,
sets flag and wakes up computations goroutine,
which makes computations first, then clears flag and wakes up sending goroutine.

### writing goroutine

Maintains a round-robin queue of all connections (max size of the queue is equal to # of connections).
Wakes up, pops a connection from the queue then asks it to generate a datagram.
Sends the datagram, then if connection state needs to send more datagrams, adds connection to the back of the queue. 

Also has a separate queue of stateless responses. Mixes them in some ratio (1:1 for now) with datagrams created by connections.

### computations goroutine

Maintains a round-robin queue of all connections, which need heavy computations (max size of the queue is equal to # of handshakes).
Pops a connection from the queue, then calls OnCompute function on the connection,
which might change state and wake up sending goroutine or add connection back to the computations goroutine.

### timers goroutine

Maintains a list of connections with timer set (max size of the queue is equal to # of handshakes).
When timer expires, calls OnTimer function on connection,
which might change state and wake up some other goroutine or set timer again.

We do not want to use complicated data structures, like B-tree or intrusive heap.

So we have only 2 simple queues for short (50ms) and long (1s) timers, each sorted by expiration time simply because of the push order.

When we set 5-second timer, we'd set timer deadline to +5s, but add it to the 1s queue.

Goroutine will wake up and examine timers at the head of both queues.
If the timer reached deadline, it fires timer, otherwise adds to the queue again, until deadline is reached.

Then goroutine will select how long it should sleep, set timer and wait on both timer and wake-up struct{} channel.

If timer is added with deadline less than sleep deadline, wake-up channel is signalled.

Each connection can be added to both queues, but only once to each one.

TODO - maybe we need 3 or 4 queues with different timeouts ladder.

## Links to other implementations

https://github.com/syncsynchalt/tincan-tls

https://dtls.xargs.org/#server-certificate-datagram/annotated

## (D)TLS 1.3 promotions

Advantages to Using TLS 1.3 https://www.wolfssl.com/docs/tls13/

What’s new in DTLS 1.3 https://www.wolfssl.com/whats-new-dtls-1-3/

## References

The Datagram Transport Layer Security (DTLS) Protocol Version 1.3 https://www.rfc-editor.org/rfc/rfc9147.html

The Transport Layer Security (TLS) Protocol Version 1.3 https://www.rfc-editor.org/rfc/rfc8446

HMAC-based Extract-and-Expand Key Derivation Function (HKDF) https://datatracker.ietf.org/doc/html/rfc5869

Example Handshake Traces for TLS 1.3 https://www.rfc-editor.org/rfc/rfc8448.html

An Interface and Algorithms for Authenticated Encryption https://datatracker.ietf.org/doc/html/rfc5116

TLS 1.3 Authentication and Integrity-Only Cipher Suites https://www.rfc-editor.org/rfc/rfc9150.html

Elliptic Curves for Security https://www.rfc-editor.org/rfc/rfc7748

Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS) https://www.rfc-editor.org/rfc/rfc7919

Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier https://www.rfc-editor.org/rfc/rfc8422

Transport Layer Security (TLS) Extensions: Extension Definitions https://www.rfc-editor.org/rfc/rfc6066

# for now, tested against wolfssl

Howto test with Wolfssl.

% git clone --filter=blob:none https://github.com/wolfSSL/wolfssl.git

wolfssl % ./autogen.sh

add --enable-debug if you want detailed log
wolfssl % ./configure CFLAGS="-DOPENSSL_EXTRA -DHAVE_SECRET_CALLBACK -DWOLFSSL_KEYLOG_EXPORT_WARNED -DSHOW_SECRETS -DWOLFSSL_SSLKEYLOGFILE" --enable-dtls13 --enable-dtls --enable-tls13 --enable-session-ticket --enable-dtlscid --enable-curve25519

wolfssl %  sudo make install

% git clone https://github.com/wolfSSL/wolfssl-examples.git

edit wolfssl-examples/dtls/Makefile
CFLAGS   = -Wall -I/home/user/devbox/wolfssl
LIBS     = -L/home/user/devbox/wolfssl/src/.libs -lm

edit wolfssl-examples/dtls/client-dtls13.c and wolfssl-examples/dtls/server-dtls13.c
void print_secret(const WOLFSSL* ssl, const char* line) {
    fprintf(stderr, "%s\n", line);
}
    wolfSSL_CTX_set_keylog_callback(ctx, print_secret);


wolfssl-examples/dtls %  make server-dtls13 client-dtls13

wolfssl-examples/dtls %  LD_LIBRARY_PATH=/home/user/devbox/wolfssl/src/.libs ./server-dtls13

wolfssl-examples/dtls %  LD_LIBRARY_PATH=/home/user/devbox/wolfssl/src/.libs ./client-dtls13 127.0.0.1

# if we are successful

Adding TLS 1.3 seems easy, as TLS is DTLS without complicated datagram state machine.

This might be helpful if we ever need TLS with exotic cipher suites (ShangMi, GOST, etc.).

# scratchpad for notes

example of 'finished' flight from wolfssl

encrypted extensions message
0800001400020000000000140012000a000e000c001900180017001d00150100

certificate message
0b0004f500030000000004f5000004f10004ec308204e8308203d0a003020102020101300d06092a864886f70d01010b0500308194310b30090603550406130255533110300e06035504080c074d6f6e74616e613110300e06035504070c07426f7a656d616e3111300f060355040a0c08536177746f6f746831133011060355040b0c0a436f6e73756c74696e673118301606035504030c0f7777772e776f6c6673736c2e636f6d311f301d06092a864886f70d0109011610696e666f40776f6c6673736c2e636f6d301e170d3232313231363231313734395a170d3235303931313231313734395a308190310b30090603550406130255533110300e06035504080c074d6f6e74616e613110300e06035504070c07426f7a656d616e3110300e060355040a0c07776f6c6653534c3110300e060355040b0c07537570706f72743118301606035504030c0f7777772e776f6c6673736c2e636f6d311f301d06092a864886f70d0109011610696e666f40776f6c6673736c2e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100c09508e15741f2716db7d24541270165c645aef2bc2430b895ce2f4ed6f61c88bc7c9ffba8677ffe5c9c5175f78aca07e7352f8fe1bd7bc02f7cab64a817fcca5d7bbae021e5722e6f2e86d89573daac1b53b95f3fd7190d254fe16363518b0b643fad43b8a51c5c34b3ae00a063c5f67f0b59687873a68c18a9026dafc319012eb810e3c6cc40b469a3463369876ec4bb17a6f3e8ddad73bc7b2f21b5fd66510cbd54b3e16d5f1cbc2373d109038914d210b964c32ad0a1964abce1d41a5bc7a0c0c163780f443730329680322395a177ba13d29773e25d25c96a0dc33960a4b4b069424209e9d808bc3320b35822a7aaebc4e1e66183c5d296dfd9d04fadd70203010001a382014530820141301d0603551d0e04160414b31132c9929884e2c9f8d03b6e0342ca1f0e8e3c3081d40603551d230481cc3081c98014278e671174c3261d3fed3363b3a4d81d30e5e8d5a1819aa48197308194310b30090603550406130255533110300e06035504080c074d6f6e74616e613110300e06035504070c07426f7a656d616e3111300f060355040a0c08536177746f6f746831133011060355040b0c0a436f6e73756c74696e673118301606035504030c0f7777772e776f6c6673736c2e636f6d311f301d06092a864886f70d0109011610696e666f40776f6c6673736c2e636f6d82142c80cedb479d0766923d68d7caac904fca69414b300c0603551d13040530030101ff301c0603551d1104153013820b6578616d706c652e636f6d87047f000001301d0603551d250416301406082b0601050507030106082b06010505070302300d06092a864886f70d01010b05000382010100b910f0befec8675e7d0f3633c7172a01c4bb74834cbcbbe2ba92823ad92d8c0ee3751bc014aa401ea8117d949c3d747a3b167bd89df0e87d1dfa3b144220e305a3fdb10cf12ac400508d1e97936ade8213249e2bfa0885e34f40fd63c73de9bd6f7c039885feb4515d7f8c83b3ad4a88e9f34c338477d3023559e34e64a1b7bbfbf8fb142aae36bfd982e7cb984816c881d6a0f17414e3744a724af16fddbe861e20f30516831faa7c59359724b827b7569f302e90e019e021ca9d3fda990794794953145ca22c565bb255685c1f91589acd53b5ea635a724941cc769f8835860d605de591bdac6fcfd59227724a21f458988e3bd229e6eefae6b06c8b1ee0540000

certificate verify scheme = 2052
0f000104000400000000010408040100337cfd865b60e8befe4ff4cf303cc0d93c1233295c3448c85bdde6696892640a6dec55542a75ce1bf83a48472da792f7f00ad54355b6597f1e9e1973ef5f38c9b678e17f88296db493f6f2366ffa2d1cff703d1fb6a66f4300106c40e88baf053f7f1951a3f3e31d2802dd6ead649e2bb90c083dfacef648995dc1127bce8819d939320db84addd7b89d845d6bb05e7ed0b8dc700fa6993440eda24ac31ccd9e2a0e904e573f2713e4d3280fe8e391c0e51f95d29bfb090a4c192cde34ff3d49121a5e7c44e5b8a25fed1f9ab25d6c6832c46dd34ba783b9f0eb9cad15c42249ede2ebce370dc0a4a0335e9ec954381be2657ba9cf3b7a239c0e32db49c92927

finished
140000200005000000000020dd278dfec50399c5bfb18fb0b3ef3312a695087a8c3961056ea19675126ee1f8
