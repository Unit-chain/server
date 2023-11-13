//
// Created by Kirill Zhukov on 31.10.2023.
//

#ifndef TCPSOCKETTEST_CTX_UTIL_H
#define TCPSOCKETTEST_CTX_UTIL_H

#ifdef __linux__
#include <cstdlib>
#endif
#include "boost/asio/ssl.hpp"
#include "boost/log/trivial.hpp"
#include "nghttp2/nghttp2.h"

constexpr char DEFAULT_CIPHER_LIST[] =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-"
        "AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-"
        "POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-"
        "AES256-GCM-SHA384";

//constexpr unsigned char NGHTTP2_H2_ALPN[] = {2, 'h', '2'};
//constexpr unsigned char NGHTTP2_H2_16_ALPN[] = {5, 'h', '2', '-', '1', '6'};
//constexpr unsigned char NGHTTP2_H2_14_ALPN[] = {5, 'h', '2', '-', '1', '4'};
//
//std::vector<unsigned char> alpn_token;
//
//void initialize_alpn_token() {
//    alpn_token.reserve(sizeof(NGHTTP2_H2_ALPN) + sizeof(NGHTTP2_H2_16_ALPN) + sizeof(NGHTTP2_H2_14_ALPN));
//    alpn_token.insert(alpn_token.end(), std::begin(NGHTTP2_H2_ALPN), std::end(NGHTTP2_H2_ALPN));
//    alpn_token.insert(alpn_token.end(), std::begin(NGHTTP2_H2_16_ALPN), std::end(NGHTTP2_H2_16_ALPN));
//    alpn_token.insert(alpn_token.end(), std::begin(NGHTTP2_H2_14_ALPN), std::end(NGHTTP2_H2_14_ALPN));
//}

constexpr unsigned char ALPN_COMBINED[] = {
        2, 'h', '2',
        5, 'h', '2', '-', '1', '6',
        5, 'h', '2', '-', '1', '4'
};

#if OPENSSL_VERSION_NUMBER >= 0x10002000L

static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
    int rv;
    (void) ssl;
    (void) arg;

    rv = nghttp2_select_next_protocol((unsigned char **) out, outlen, in, inlen);

    if (rv != 1) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

static void create_ssl_ctx(boost::asio::ssl::context &ctx, const char *key_file, const char *cert_file) {
    boost::system::error_code ec;
    ec.clear();
    auto ssl_opts = ((uint64_t) 1 << (uint64_t) 16);

    try {
        ctx.use_certificate_chain_file(cert_file);
        ctx.use_private_key_file(key_file, boost::asio::ssl::context::pem);
    } catch (std::exception &e) {
        BOOST_LOG_TRIVIAL(error) << e.what();
        std::exit(EXIT_FAILURE);
    }

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
                *data = ALPN_COMBINED;
                *len = sizeof(ALPN_COMBINED);
                return SSL_TLSEXT_ERR_OK;
            },
            nullptr);
#endif // !OPENSSL_NO_NEXTPROTONEG

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    // ALPN selection callback
    SSL_CTX_set_alpn_select_cb(ctx.native_handle(), alpn_select_proto_cb, nullptr);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
    BOOST_LOG_TRIVIAL(info) << "success";
}

#endif //TCPSOCKETTEST_CTX_UTIL_H
