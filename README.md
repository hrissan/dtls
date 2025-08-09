# tinydtls
As small and fast as possible

# tested against wolfssl

Howto test with Wolfssl.

% git clone --filter=blob:none https://github.com/wolfSSL/wolfssl.git

wolfssl % ./autogen.sh

wolfssl % ./configure --enable-dtls13 --enable-dtls --enable-tls13 --enable-session-ticket --enable-dtlscid

wolfssl %  sudo make install

% git clone https://github.com/wolfSSL/wolfssl-examples.git

edit wolfssl-examples/dtls/Makefile
CFLAGS   = -Wall -I/home/user/devbox/wolfssl
LIBS     = -L/home/user/devbox/wolfssl/src/.libs -lm

wolfssl-examples/dtls %  make server-dtls13 client-dtls13

wolfssl-examples/dtls %  LD_LIBRARY_PATH=/home/user/devbox/wolfssl/src/.libs ./server-dtls13

wolfssl-examples/dtls %  LD_LIBRARY_PATH=/home/user/devbox/wolfssl/src/.libs ./client-dtls13 127.0.0.1
