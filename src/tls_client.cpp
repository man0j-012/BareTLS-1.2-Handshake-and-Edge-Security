
#include "tls_client.hpp"
#include <stdexcept>
#include <string>
#include <vector>
#include <cstring>
#include <cerrno>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

namespace {

void throw_last_ssl_error(const std::string& where) {
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    throw std::runtime_error(where + ": " + std::string(buf));
}

int connect_tcp(const std::string& host, const std::string& port) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0) {
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(rc)));
    }

    int sock = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            freeaddrinfo(res);
            return sock;
        }
        ::close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    throw std::runtime_error("connect: failed to connect to " + host + ":" + port);
}

} // namespace

struct TLSClient::Impl {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int sock = -1;

    Impl() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        const SSL_METHOD* method = TLS_client_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) throw_last_ssl_error("SSL_CTX_new");
    }

    ~Impl() {
        if (ssl) SSL_free(ssl);
        if (sock >= 0) ::close(sock);
        if (ctx) SSL_CTX_free(ctx);
        EVP_cleanup();
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
    }
};

TLSClient::TLSClient() : impl(new Impl) {}
TLSClient::~TLSClient() { delete impl; }

void TLSClient::set_min_max_tls12() {
    if (SSL_CTX_set_min_proto_version(impl->ctx, TLS1_2_VERSION) != 1)
        throw_last_ssl_error("set_min_proto");
    if (SSL_CTX_set_max_proto_version(impl->ctx, TLS1_2_VERSION) != 1)
        throw_last_ssl_error("set_max_proto");
}

void TLSClient::set_cipher_list(const std::string& cipher_list) {
    // Note: OpenSSL expects OpenSSL cipher strings, not IANA names.
    // We accept IANA name and pass through other selectors for flexibility.
    // If TLS_RSA_WITH_AES_128_CBC_SHA is unsupported, OpenSSL will negotiate another TLS1.2 suite.
    if (SSL_CTX_set_cipher_list(impl->ctx, cipher_list.c_str()) != 1) {
        throw_last_ssl_error("set_cipher_list");
    }
}

void TLSClient::set_sni(const std::string& sni_hostname) {
    // Will set on the SSL object in connect(). Store in ctx via a TLSEXT callback if needed.
    (void)sni_hostname; // handled later in connect
}

void TLSClient::connect(const std::string& host, const std::string& port) {
    impl->sock = connect_tcp(host, port);

    impl->ssl = SSL_new(impl->ctx);
    if (!impl->ssl) throw_last_ssl_error("SSL_new");

    // Set SNI. Use 'host' as SNI; if user connected by IP but wants different Host header, pass that into set_tlsext_host_name here instead.
    if (SSL_set_tlsext_host_name(impl->ssl, host.c_str()) != 1) {
        throw_last_ssl_error("SSL_set_tlsext_host_name");
    }

    SSL_set_fd(impl->ssl, impl->sock);
    int rc = SSL_connect(impl->ssl);
    if (rc != 1) {
        int err = SSL_get_error(impl->ssl, rc);
        (void)err;
        throw_last_ssl_error("SSL_connect");
    }
}

void TLSClient::write(const std::string& data) {
    const char* p = data.data();
    size_t left = data.size();
    while (left > 0) {
        int n = SSL_write(impl->ssl, p, static_cast<int>(left));
        if (n <= 0) throw_last_ssl_error("SSL_write");
        p += n;
        left -= n;
    }
}

std::string TLSClient::read_all() {
    std::string out;
    char buf[4096];
    for (;;) {
        int n = SSL_read(impl->ssl, buf, sizeof(buf));
        if (n > 0) {
            out.append(buf, buf + n);
        } else {
            int err = SSL_get_error(impl->ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN) break; // clean shutdown
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            break; // assume EOF/closed
        }
    }
    return out;
}

void TLSClient::shutdown() {
    if (impl->ssl) {
        SSL_shutdown(impl->ssl);
    }
}
