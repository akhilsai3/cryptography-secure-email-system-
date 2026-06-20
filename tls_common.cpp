// tls_common.cpp
//
// Implementation of the shared TLS transport layer. See tls_common.h for
// the public interface, scope, and trust-model notes.

#include "tls_common.h"

#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <atomic>
#include <iostream>

namespace {
std::atomic<bool> g_initialized{false};
}

void tls_global_init() {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) {
        return; // already initialized
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// ---------------------------------------------------------------------
// Server-side
// ---------------------------------------------------------------------

SSL_CTX* tls_create_server_ctx(const char* cert_path, const char* key_path) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Self-signed certs only, no legacy protocol versions.
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "tls_create_server_ctx: private key does not match certificate ("
                  << key_path << " / " << cert_path << ")" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

SSL* tls_server_accept(int raw_fd, SSL_CTX* server_ctx) {
    if (raw_fd < 0 || !server_ctx) {
        if (raw_fd >= 0) close(raw_fd);
        return nullptr;
    }

    SSL* ssl = SSL_new(server_ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        close(raw_fd);
        return nullptr;
    }

    SSL_set_fd(ssl, raw_fd);

    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(raw_fd);
        return nullptr;
    }

    return ssl;
}

// ---------------------------------------------------------------------
// Client-side
// ---------------------------------------------------------------------

SSL_CTX* tls_create_client_ctx(const char* trusted_bundle_path) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Trust ONLY the certs in this bundle - no system/OS CA store. See
    // the trust-model note in tls_common.h for why hostname verification
    // is intentionally skipped (pinned self-signed certs, not CA-issued).
    if (SSL_CTX_load_verify_locations(ctx, trusted_bundle_path, nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 2);

    return ctx;
}

SSL* tls_client_connect(const char* ip, int port, SSL_CTX* client_ctx) {
    if (!client_ctx) return nullptr;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return nullptr;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        close(sock);
        return nullptr;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        return nullptr;
    }

    SSL* ssl = SSL_new(client_ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        close(sock);
        return nullptr;
    }

    SSL_set_fd(ssl, sock);

    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }

    // Belt-and-suspenders: SSL_connect() already fails the handshake when
    // SSL_VERIFY_PEER is set and verification fails, but check explicitly
    // too so a future change to the verify mode can't silently weaken this.
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        std::cerr << "tls_client_connect: certificate verification failed for "
                  << ip << ":" << port << std::endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }

    return ssl;
}

// ---------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------

int tls_send(SSL* ssl, const char* data, size_t len) {
    if (!ssl || len == 0) return 0;
    return SSL_write(ssl, data, static_cast<int>(len));
}

int tls_recv(SSL* ssl, char* buf, size_t len) {
    if (!ssl || len == 0) return 0;
    int n = SSL_read(ssl, buf, static_cast<int>(len));
    if (n > 0) return n;

    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) {
        return 0; // peer sent close_notify - orderly shutdown, same as recv()==0
    }
    return -1; // SSL_ERROR_SYSCALL / SSL_ERROR_SSL / etc. - hard error, same as recv()<0
}

std::string tls_read_line(SSL* ssl) {
    std::string line;
    char c;
    while (true) {
        int n = tls_recv(ssl, &c, 1);
        if (n <= 0) break;
        if (c == '\n') break;
        line += c;
    }
    return line;
}

void tls_set_recv_timeout(SSL* ssl, int seconds) {
    if (!ssl) return;
    int fd = SSL_get_fd(ssl);
    if (fd < 0) return;

    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void tls_close(SSL* ssl) {
    if (!ssl) return;
    int fd = SSL_get_fd(ssl);
    // Single-call "quiet" shutdown: callers here are thread-per-connection
    // handlers tearing down after a finished exchange, not a long-lived
    // session that needs a full bidirectional close_notify handshake. This
    // mirrors the original code's close(), which didn't wait for anything
    // from the peer either.
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (fd >= 0) close(fd);
}
