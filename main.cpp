#include <iostream>
#include <array>
#include <nghttp2/nghttp2.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/ssl.h>

class StringRef {
public:
    using traits_type = std::char_traits<char>;
    using value_type = traits_type::char_type;
    using allocator_type = std::allocator<char>;
    using size_type = std::allocator_traits<allocator_type>::size_type;
    using difference_type =
            std::allocator_traits<allocator_type>::difference_type;
    using const_reference = const value_type &;
    using const_pointer = const value_type *;
    using const_iterator = const_pointer;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    constexpr StringRef() : base(""), len(0) {}
    explicit StringRef(const std::string &s) : base(s.c_str()), len(s.size()) {}
    explicit StringRef(const char *s) : base(s), len(strlen(s)) {}
    constexpr StringRef(const char *s, size_t n) : base(s), len(n) {}
    template <typename CharT>
    constexpr StringRef(const CharT *s, size_t n)
            : base(reinterpret_cast<const char *>(s)), len(n) {}
    template <typename InputIt>
    StringRef(InputIt first, InputIt last)
            : base(reinterpret_cast<const char *>(&*first)),
              len(std::distance(first, last)) {}
    template <typename InputIt>
    StringRef(InputIt *first, InputIt *last)
            : base(reinterpret_cast<const char *>(first)),
              len(std::distance(first, last)) {}
    template <typename CharT, size_t N>
    constexpr static StringRef from_lit(const CharT (&s)[N]) {
        return StringRef{s, N - 1};
    }
    static StringRef from_maybe_nullptr(const char *s) {
        if (s == nullptr) {
            return StringRef();
        }

        return StringRef(s);
    }

    constexpr const_iterator begin() const { return base; };
    constexpr const_iterator cbegin() const { return base; };

    constexpr const_iterator end() const { return base + len; };
    constexpr const_iterator cend() const { return base + len; };

    const_reverse_iterator rbegin() const {
        return const_reverse_iterator{base + len};
    }
    const_reverse_iterator crbegin() const {
        return const_reverse_iterator{base + len};
    }

    const_reverse_iterator rend() const { return const_reverse_iterator{base}; }
    const_reverse_iterator crend() const { return const_reverse_iterator{base}; }

    constexpr const char *c_str() const { return base; }
    constexpr size_type size() const { return len; }
    constexpr bool empty() const { return len == 0; }
    constexpr const_reference operator[](size_type pos) const {
        return *(base + pos);
    }

    std::string str() const { return std::string(base, len); }
    const uint8_t *byte() const {
        return reinterpret_cast<const uint8_t *>(base);
    }

private:
    const char *base;
    size_type len;
};

inline bool operator==(const StringRef &lhs, const StringRef &rhs) {
    return lhs.size() == rhs.size() &&
           std::equal(std::begin(lhs), std::end(lhs), std::begin(rhs));
}

inline bool operator==(const StringRef &lhs, const std::string &rhs) {
    return lhs.size() == rhs.size() &&
           std::equal(std::begin(lhs), std::end(lhs), std::begin(rhs));
}

inline bool operator==(const std::string &lhs, const StringRef &rhs) {
    return rhs == lhs;
}

inline bool operator==(const StringRef &lhs, const char *rhs) {
    return lhs.size() == strlen(rhs) &&
           std::equal(std::begin(lhs), std::end(lhs), rhs);
}

inline bool operator==(const char *lhs, const StringRef &rhs) {
    return rhs == lhs;
}

inline bool operator!=(const StringRef &lhs, const StringRef &rhs) {
    return !(lhs == rhs);
}

inline bool operator!=(const StringRef &lhs, const std::string &rhs) {
    return !(lhs == rhs);
}

inline bool operator!=(const std::string &lhs, const StringRef &rhs) {
    return !(rhs == lhs);
}

inline bool operator!=(const StringRef &lhs, const char *rhs) {
    return !(lhs == rhs);
}

inline bool operator!=(const char *lhs, const StringRef &rhs) {
    return !(rhs == lhs);
}

inline bool operator<(const StringRef &lhs, const StringRef &rhs) {
    return std::lexicographical_compare(std::begin(lhs), std::end(lhs),
                                        std::begin(rhs), std::end(rhs));
}

inline std::ostream &operator<<(std::ostream &o, const StringRef &s) {
    return o.write(s.c_str(), s.size());
}

inline std::string &operator+=(std::string &lhs, const StringRef &rhs) {
    lhs.append(rhs.c_str(), rhs.size());
    return lhs;
}

template <typename T, size_t N> constexpr size_t str_size(T (&)[N]) {
    return N - 1;
}

// nghttp2 callback for receiving headers
static int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                              void *user_data) {
    std::cout << "Header: " << std::string((char *) name, namelen) << ": " << std::string((char *) value, valuelen)
              << std::endl;
    return 0;
}

// Function to send a simple HTTP/2 response
static int send_response(nghttp2_session *session, int32_t stream_id) {
    nghttp2_nv headers[] = {
            {(uint8_t *) "status",         (uint8_t *) "200", 6,  3, NGHTTP2_NV_FLAG_NONE},
            {(uint8_t *) "content-length", (uint8_t *) "5",   14, 1, NGHTTP2_NV_FLAG_NONE},
    };
    nghttp2_data_provider data_prov;
    data_prov.source.ptr = (uint8_t *) "Hello";
    int rv = nghttp2_submit_response(session, stream_id, headers, 2, &data_prov);
    if (rv != 0) {
        std::cout << "Failed to submit response: " << nghttp2_strerror(rv) << std::endl;
    } else {
        std::cout << "Response submitted successfully." << std::endl;
    }
    return rv;
}

// nghttp2 callback when a frame is received
static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    std::cout << "Received frame: " << frame->hd.type << std::endl;
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        // A request has been fully received; send a response.
        send_response(session, frame->hd.stream_id);
    }
    return 0;
}

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    // Use "h2" directly; no need for length prefix
    if (SSL_select_next_proto((unsigned char **) out, outlen, (unsigned char *) "h2", 2, in, inlen) !=
        OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
    auto *socket = (boost::asio::ip::tcp::socket *)user_data;
    boost::asio::write(*socket, boost::asio::buffer(data, length));
    return (ssize_t)length;
}

// nghttp2 callback for receiving data chunks
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
    std::cout << "Received data chunk: " << std::string((char *) data, len) << std::endl;
    // Prepare the response
    nghttp2_nv hdrs[] = { { (uint8_t *)":status", (uint8_t *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE } };

    nghttp2_data_provider data_provider;
    data_provider.source.fd = 0;  // No file descriptor

    // Submit the response
    nghttp2_submit_response(session, stream_id, hdrs, 1, &data_provider);
    return 0;
}

static int select_alpn_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg) {
    // Check if HTTP/2 is among the client's ALPN protocols
    unsigned int i;
    for (i = 0; i < inlen; i += in[i] + 1) {
        if (in[i] == 2 && memcmp(&in[i + 1], "h2", 2) == 0) {
            *out = &in[i + 1];
            *outlen = 2;
            std::cout << "ALPN selected HTTP/2" << std::endl;
            return SSL_TLSEXT_ERR_OK;
        }
    }
    std::cout << "ALPN did not find a match" << std::endl;
    return SSL_TLSEXT_ERR_NOACK;
}

constexpr char DEFAULT_CIPHER_LIST[] =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-"
        "AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-"
        "POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-"
        "AES256-GCM-SHA384";

constexpr auto NGHTTP2_H2_ALPN = StringRef::from_lit("\x2h2");
constexpr auto NGHTTP2_H2 = StringRef::from_lit("h2");

// The additional HTTP/2 protocol ALPN protocol identifier we also
// supports for our applications to make smooth migration into final
// h2 ALPN ID.
constexpr auto NGHTTP2_H2_16_ALPN = StringRef::from_lit("\x5h2-16");
constexpr auto NGHTTP2_H2_16 = StringRef::from_lit("h2-16");

constexpr auto NGHTTP2_H2_14_ALPN = StringRef::from_lit("\x5h2-14");
constexpr auto NGHTTP2_H2_14 = StringRef::from_lit("h2-14");

constexpr size_t NGHTTP2_MAX_UINT64_DIGITS = str_size("18446744073709551615");

std::vector<unsigned char> get_default_alpn() {
    auto res = std::vector<unsigned char>(NGHTTP2_H2_ALPN.size() +
                                          NGHTTP2_H2_16_ALPN.size() +
                                          NGHTTP2_H2_14_ALPN.size());
    auto p = std::begin(res);

    p = std::copy_n(std::begin(NGHTTP2_H2_ALPN), NGHTTP2_H2_ALPN.size(), p);
    p = std::copy_n(std::begin(NGHTTP2_H2_16_ALPN), NGHTTP2_H2_16_ALPN.size(), p);
    p = std::copy_n(std::begin(NGHTTP2_H2_14_ALPN), NGHTTP2_H2_14_ALPN.size(), p);

    return res;
}

std::vector<unsigned char> &get_alpn_token() {
    static auto alpn_token = get_default_alpn();
    return alpn_token;
}

bool select_proto(const unsigned char **out, unsigned char *outlen,
                  const unsigned char *in, unsigned int inlen,
                  const StringRef &key) {
    for (auto p = in, end = in + inlen; p + key.size() <= end; p += *p + 1) {
        if (std::equal(std::begin(key), std::end(key), p)) {
            *out = p + 1;
            *outlen = *p;
            return true;
        }
    }
    return false;
}

bool select_h2(const unsigned char **out, unsigned char *outlen,
               const unsigned char *in, unsigned int inlen) {
    return select_proto(out, outlen, in, inlen, NGHTTP2_H2_ALPN) ||
           select_proto(out, outlen, in, inlen, NGHTTP2_H2_16_ALPN) ||
           select_proto(out, outlen, in, inlen, NGHTTP2_H2_14_ALPN);
}

int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
    if (!select_h2(out, outlen, in, inlen)) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

// Function to configure the SSL context to use ALPN
void configure_ssl_context(boost::asio::ssl::context &ctx) {
    ctx.set_options(boost::asio::ssl::context::tlsv13);
    ctx.use_certificate_chain_file("/Users/kirillzhukov/Downloads/server.pem");
    ctx.use_private_key_file("/Users/kirillzhukov/Downloads/server.key", boost::asio::ssl::context::pem);

    boost::system::error_code ec;
    ec.clear();
    auto ssl_opts = ((uint64_t) 1 << (uint64_t) 16);

    SSL_CTX_set_options(ctx.native_handle(), ssl_opts);
    SSL_CTX_set_mode(ctx.native_handle(), SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ctx.native_handle(), SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_set_cipher_list(ctx.native_handle(), DEFAULT_CIPHER_LIST);

#ifndef OPENSSL_NO_EC
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    auto ecdh = pkey;

    if (ecdh) {
        SSL_CTX_set_tmp_ecdh(ctx.native_handle(), ecdh);
        EVP_PKEY_free(ecdh);
    }
#endif /* OPENSSL_NO_EC */

#ifndef OPENSSL_NO_NEXTPROTONEG
    SSL_CTX_set_next_protos_advertised_cb(
            ctx.native_handle(),
            [](SSL *s, const unsigned char **data, unsigned int *len, void *arg) {
                auto &token = get_alpn_token();

                *data = token.data();
                *len = token.size();

                return SSL_TLSEXT_ERR_OK;
            },
            nullptr);
#endif // !OPENSSL_NO_NEXTPROTONEG

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    // ALPN selection callback
    SSL_CTX_set_alpn_select_cb(ctx.native_handle(), alpn_select_proto_cb, nullptr);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
}

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::io_service &io_service, boost::asio::ssl::context &context)
            : socket_(io_service, context) {
        nghttp2_session_callbacks *callbacks;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
        nghttp2_session_server_new(&session_, callbacks, this);
        nghttp2_session_callbacks_del(callbacks);
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> &socket() {
        return socket_;
    }

    void start() {
        do_handshake();
    }

private:
    void do_handshake() {
        auto self(shared_from_this());
        socket_.async_handshake(boost::asio::ssl::stream_base::server,
                                [this, self](const boost::system::error_code &error) {
                                    if (error) {
                                        std::cout << "SSL Handshake failed: " << error.message() << std::endl;
                                        return;
                                    }
                                    std::cout << "SSL Handshake successful." << std::endl;
                                    // Print SSL details
                                    SSL *ssl = socket_.native_handle();
                                    std::cout << "SSL Version: " << SSL_get_version(ssl) << std::endl;
                                    std::cout << "SSL Cipher: " << SSL_get_cipher_name(ssl) << std::endl;
                                    // Get ALPN protocol to check for HTTP/2
                                    const unsigned char *alpn_protocol = nullptr;
                                    unsigned int alpn_len = 0;
                                    SSL_get0_alpn_selected(ssl, &alpn_protocol, &alpn_len);
                                    if (alpn_len == 2 && memcmp("h2", alpn_protocol, 2) == 0) {
                                        std::cout << "ALPN selected protocol: HTTP/2" << std::endl;
                                    } else {
                                        std::cout << "ALPN did not select HTTP/2. Selected: "
                                                  << std::string((const char *) alpn_protocol, alpn_len) << std::endl;
                                    }
                                    do_read();
                                });
    }

    void do_read() {
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_),
                                [this, self](boost::system::error_code ec, std::size_t length) {
                                    if (!ec) {
                                        std::cout << "Data received: " << length << " bytes." << std::endl;
                                        ssize_t rv = nghttp2_session_mem_recv(session_, (uint8_t *) data_.data(),
                                                                              length);
                                        if (rv < 0) {
                                            std::cout << "nghttp2_session_mem_recv failed: " << nghttp2_strerror(rv)
                                                      << std::endl;
                                            return;
                                        }
                                        do_read();
                                    }
                                });
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
    std::array<char, 8192> data_;
    nghttp2_session *session_;
};

int main() {
    boost::asio::io_service io_service;
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv13);
    configure_ssl_context(ctx);

    boost::asio::ip::tcp::acceptor acceptor(io_service,
                                            boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 8080));

    std::function<void()> do_accept;
    do_accept = [&]() {
        auto session = std::make_shared<Session>(io_service, ctx);
        acceptor.async_accept(session->socket().lowest_layer(), [&, session](boost::system::error_code ec) {
            if (!ec) {
                std::cout << "Connection accepted." << std::endl;
                session->start();
            }
            do_accept();
        });
    };

    do_accept();
    io_service.run();

    return 0;
}
