# tinydtls
As small and fast as possible

# tested against wolfssl

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
