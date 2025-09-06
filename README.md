# dtls

Very much work in progress - this is only demo for now with no API.

# requirements

## semantic

DTLS 1.3 only, no support for older standards.

Very few dependencies, ideally zero.

Must interoperate with other known implementations.

Implement only extensions we really need, or which are easy to support,

Implement only mandatory and useful crypto algorithms, elliptic groups, etc.

Must defend against simple attacks.

Checking validity of certification chain is not a priority for now, but must be correctly implemented later.

## technical

Use standard Go crypto and crypto/x509, which we have no desire to reimplement.

Code as simple and fast as possible, without resorting to dirty tricks.

No unsafe code of our own (except in standard crypto, we do not control).

Must make zero allocations on the fast paths, almost zero allocations on slow paths (except in standard crypto, we do not control).

Must be fixed memory for most objects. Most objects allocated on heap must be recycled indefinitely. 

Must use as little memory per established connection as possible (1.5 kilobytes). We need this implementation for mesh with at least 100K connections per service, so literally every byte counts.

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

Maintains an intrusive heap of connections with timer set (max size of the queue is equal to # of handshakes).
When timer expires, calls OnTimer function on connection,
which might change state and wake up some other goroutine or set timer again.

Connection must remember fire time under lock, because timers goroutine can call OnTimer even
after timer is removed from heap.

## Links to other implementations

https://github.com/syncsynchalt/tincan-tls

https://dtls.xargs.org/#server-certificate-datagram/annotated

## (D)TLS 1.3 promotions

Advantages to Using TLS 1.3 https://www.wolfssl.com/docs/tls13/

What's new in DTLS 1.3 https://www.wolfssl.com/whats-new-dtls-1-3/

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

ChaCha20 and Poly1305 for IETF Protocols https://www.rfc-editor.org/rfc/rfc8439#section-2.8

AEAD Cipher Suites - An Interface and Algorithms for Authenticated Encryption https://www.rfc-editor.org/rfc/rfc5116#section-5

# for now, tested against wolfssl

Howto test with Wolfssl.

% git clone --filter=blob:none https://github.com/wolfSSL/wolfssl.git

wolfssl % ./autogen.sh

add --enable-debug if you want detailed log
wolfssl % ./configure CFLAGS="-DWOLFSSL_DTLS13_NO_HRR_ON_RESUME -DOPENSSL_EXTRA -DHAVE_SECRET_CALLBACK -DWOLFSSL_KEYLOG_EXPORT_WARNED -DSHOW_SECRETS -DWOLFSSL_SSLKEYLOGFILE" --enable-earlydata --enable-dtls13 --enable-dtls --enable-tls13 --enable-session-ticket --enable-dtlscid --enable-curve25519 --enable-psk --enable-alpn

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

Actually, golang 24 built-in TLS 1.3 does not support external PSK, which we also need.

# Implemented

## Protocol features

* 3 mandatory ciphers (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256).

* 1 of 2 mandatory key share groups (X25519). SECP256R1 is coming soon (TODO).

* PSK-based auth (with ECDHE) on both server and client.

## API features

* Event-based API for very efficient servers and clients.

* Golang-style standard API for not so efficient clients (for servers coming soon).

* Early data support on both server and client (with API to decide which data can be sent early).

# TODO list (not in particular order)

* Better separate state machine from UDP

* Separate connection multiplexing into separate component, so that golang-style client API connections can work without common transport object.

* Certificate-based (mutual) auth (at least, partially - no callback for cert verification)

* Support retransmissions, actually start/stop retransmission timers based on connection state

* (Not planned, we want forward secrecy) PSK-only key exchange mode.

* NewSessionTicket and resuming sessions support for both server and client

* Harmonize errors. Before error is returned, log (rare) offending context (message/record data, etc.)

* Process fatal errors to terminate connections.

* Replay protection for plaintext records (?).

* Support client certificates request / response

* Pack several handshake message into single record (now they are in separate)

* Integration tests against OpenSSL, BoringSSL, rusty-dtls, etc.

* Support SNI extension

* Support Application-Layer Protocol Negotiation Extension
  https://datatracker.ietf.org/doc/html/rfc7301
  Would be great to select our RPC protocol version, and do not invent our own header

* Fuzz all data structures

* Fuzz incoming path

* Server + client connections together with packet loss and reordering

* Make handshake state machine more explicit

* Rearrange/refactor code

* Send and receive alerts

* Test with 2 or more sockets listening on different interfaces

* (Not planned) Connection ID

* Protect against connection disruption by off-path attacker.
If client receives unencrypted alert, this might be result of
either server restarted and forgot connection, or
attacker sending packet to client.
Client has to send client_hello, but if server still has connection,
it will send encrypted empty ack, then server_hello.
When client receives fresh encrypted ack, it will cancel new connection
establishment and instead continue connection it already has.
We have to test this algorithm during fuzzing.

* Protect against handshake disruption by off-path attacker.
If client or server receive unencrypted alert during handshake, 
we should mostly ignore it.

* Use rope for all variable memory chunks

* use actual types for various objects (type CipherSuite, etc. Instead of uint16.)

* limit max number of parallel handshakes, clear items by LRU

* limit on how much memory single handshake uses for all messages

* offload long calculations (ECC, RSA, etc.) to separate goroutine(s)

* throughput and latency benchmarks, comparison with UDP without encryption. 

* implement key log writer https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
