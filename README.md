# tinydtls
As small and fast as possible

# tested against wolfssl

Howto test with Wolfssl.

% git clone --filter=blob:none https://github.com/wolfSSL/wolfssl.git

wolfssl % ./autogen.sh

wolfssl % ./configure --enable-dtls13 --enable-dtls --enable-tls13 --enable-session-ticket --enable-dtlscid --enable-curve25519

wolfssl %  sudo make install

% git clone https://github.com/wolfSSL/wolfssl-examples.git

edit wolfssl-examples/dtls/Makefile
CFLAGS   = -Wall -I/home/user/devbox/wolfssl
LIBS     = -L/home/user/devbox/wolfssl/src/.libs -lm

edit wolfssl-examples/dtls/client-dtls13.c and request x25519 key share 
    if (wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519) != SSL_SUCCESS) {
        fprintf(stderr, "unable to set x25519 key share\n");
        goto cleanup;
    }

wolfssl-examples/dtls %  make server-dtls13 client-dtls13

wolfssl-examples/dtls %  LD_LIBRARY_PATH=/home/user/devbox/wolfssl/src/.libs ./server-dtls13

wolfssl-examples/dtls %  LD_LIBRARY_PATH=/home/user/devbox/wolfssl/src/.libs ./client-dtls13 127.0.0.1
