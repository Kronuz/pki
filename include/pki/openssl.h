// Owning handles for the OpenSSL objects pki passes around.
#pragma once

#include <memory>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace pki {

template <typename T, void (*Free)(T*)>
struct OpenSSLDeleter {
	void operator()(T* p) const noexcept { Free(p); }
};

using Bio = std::unique_ptr<BIO, OpenSSLDeleter<BIO, BIO_free_all>>;
using Key = std::unique_ptr<EVP_PKEY, OpenSSLDeleter<EVP_PKEY, EVP_PKEY_free>>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, OpenSSLDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using Certificate = std::unique_ptr<X509, OpenSSLDeleter<X509, X509_free>>;
using Request = std::unique_ptr<X509_REQ, OpenSSLDeleter<X509_REQ, X509_REQ_free>>;

}  // namespace pki
