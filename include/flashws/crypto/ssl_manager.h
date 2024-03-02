#pragma once
#include "flashws/utils/singleton.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

namespace fws {

    class SSLManager : public Singleton<SSLManager> {
    public:

        [[nodiscard]] bool is_inited() const {
            return is_inited_;
        }

        SSL_CTX *ctx() const {
            return ctx_;
        }

        /**
         * This function must be called before using TLSSocket function calls
         * @param certfile
         * @param keyfile
         * @return
         */
        int Init(bool should_verify, const char * certfile, const char* keyfile, const char* ca_file_path) {
            if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
                SetErrorFormatStr("Failed to initialize OpenSSL\n");
                return -1;
            }

            /* create the SSL server context */
            // TODO: ERR_error_string is not safe in this way
            ctx_ = SSL_CTX_new(TLS_method());
            if (!ctx_) {
                SetErrorFormatStr("SSL_CTX_new failed: %s", ERR_error_string(ERR_get_error(), nullptr));
                return -1;
            }

            SSL_CTX_set_read_ahead(ctx_, 1);
            SSL_CTX_set_mode(ctx_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

            if (!SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION)) {
                SetErrorFormatStr("SSL_CTX_set_min_proto_version failed: %s",
                                  ERR_error_string(ERR_get_error(), nullptr));
                return -1;
            }

            /* Load certificate and private key files, and check consistency */
            if (certfile && keyfile) {
                if (SSL_CTX_use_certificate_file(ctx_, certfile, SSL_FILETYPE_PEM) != 1) {
                    SetErrorFormatStr("SSL_CTX_use_certificate_file failed: %s",
                                      ERR_error_string(ERR_get_error(), nullptr));
                    ERR_clear_error();
                    return -1;
                }

                if (SSL_CTX_use_PrivateKey_file(ctx_, keyfile, SSL_FILETYPE_PEM) != 1) {
                    SetErrorFormatStr("SSL_CTX_use_PrivateKey_file failed: %s",
                                      ERR_error_string(ERR_get_error(), nullptr));
                    ERR_clear_error();
                    return -1;
                }

                /* Make sure the key and certificate file match. */
                if (SSL_CTX_check_private_key(ctx_) != 1) {
                    SetErrorFormatStr("SSL_CTX_check_private_key failed: %s",
                                      ERR_error_string(ERR_get_error(), nullptr));
                    ERR_clear_error();
                    return -1;
                }

            }

            if (ca_file_path) {
                if (!SSL_CTX_load_verify_locations(ctx_, ca_file_path, nullptr)) {
                    SetErrorFormatStr("Failed to load CA file: %s", ERR_error_string(ERR_get_error(), nullptr));
                    ERR_clear_error();
                    return -1;
                }
            }
            else if (should_verify) {
                if (!SSL_CTX_set_default_verify_paths(ctx_)) {
                    SetErrorFormatStr("Failed to set default CA paths: %s", ERR_error_string(ERR_get_error(), nullptr));
                    return -1;
                }
            }

            if (should_verify) {
                SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
            }


//            const char* ca_file_name = "/etc/ssl/certs/ca-certificates.crt";
//            STACK_OF(X509_NAME) *ca_list;
//            ca_list = SSL_load_client_CA_file(ca_file_name);
//            if(ca_list == NULL) {
//                printf("Error creating ca list from %s\n", ca_file_name);
//                return -1;
//            }
//            SSL_CTX_set_client_CA_list(ctx_, ca_list);


//            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, [](int preverify_ok, X509_STORE_CTX* x509_ctx) -> int {
//                if (!preverify_ok) {
//                    ERR_print_errors_fp(stdout);
//                    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
//                    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
//                    int err = X509_STORE_CTX_get_error(x509_ctx);
//                    // Log error, certificate, depth, etc.
//                    SetErrorFormatStr("Certificate verification failed: %s, depth: %d, err: %d",
//                                      ERR_error_string(err, nullptr), depth, err);
//                    printf("%s\n",GetErrorStrP());
//                    return 0;
//                }
//                return preverify_ok; // You can return 0 to fail the verification forcibly
//            });



            is_inited_ = true;
            return 0;
        }
    protected:
        SSL_CTX *ctx_ = nullptr;
        bool is_inited_ = false;
    }; // class SSLManager

}; // namespace fws