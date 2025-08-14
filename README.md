# tinydtls

# requirements

## semantic

DTLS 1.3 only, no support for older standards.

Very few dependencies, ideally zero.

Must interoperate with other known implementations. TODO - integration tests with OpenSSL, WolfSSL, BoringSSL, rusty-dtls, etc.

Implement only extensions we really need, or which are easy to support,

Implement only mandatory and useful crypto algorithms, elliptic groups, etc.

Must defend against simple attacks.

## technical

Use standard Go crypto and crypto/x509, which we have no desire to reimplement.

Code as simple and fast as possible, without resorting to dirty tricks.

No unsafe code of our own (except in standard crypto, we do not control).

Must make zero allocations on the fast paths, almost zero allocations on slow paths (except in standard crypto, we do not control).

Must be fixed memory for everything. Every object allocated on heap must be recycled indefinitely (except in standard crypto, we do not control). 

Must use as little memory per established connection as possible (1.5 kilobytes?). TODO - benchmark and fill in number here after connection actually works.

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

There is reading goroutine, writing goroutine, timers goroutine, and ECC offload goroutines. They communicate using mutexes, condvars and channels, but do not block each other.

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
Wakes up, pops a connection from the queue then aska it to generate a datagram. 
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

When we set 5-second timer, we'd set timeout deadline to +5s, but add it to 1s queue.

After expiration, if we reached deadline, we fire timer, but if we did not, we add to the queue again, until deadline is reached.

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
