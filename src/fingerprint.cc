#include "pki/fingerprint.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "pki/refusal.h"

namespace pki {

namespace {

Digest sha256(const unsigned char* bytes, int length, const char* what) {
	if (length <= 0) { crypto_failure(std::string("cannot encode ") + what); }
	Digest digest{};
	unsigned int size = 0;
	if (EVP_Digest(bytes, static_cast<std::size_t>(length), digest.data(), &size, EVP_sha256(), nullptr) != 1 || size != digest.size()) {
		crypto_failure(std::string("cannot hash ") + what);
	}
	return digest;
}

struct Encoded {
	unsigned char* bytes = nullptr;
	int length = 0;
	~Encoded() { OPENSSL_free(bytes); }
};

}  // namespace

Digest spki_sha256(const X509* certificate) {
	Encoded encoded;
	const X509_PUBKEY* spki = X509_get_X509_PUBKEY(certificate);
	encoded.length = spki ? i2d_X509_PUBKEY(spki, &encoded.bytes) : -1;
	return sha256(encoded.bytes, encoded.length, "the certificate's public key");
}

Digest spki_sha256(const EVP_PKEY* key) {
	Encoded encoded;
	encoded.length = i2d_PUBKEY(key, &encoded.bytes);
	return sha256(encoded.bytes, encoded.length, "the public key");
}

Digest der_sha256(const X509* certificate) {
	Encoded encoded;
	encoded.length = i2d_X509(certificate, &encoded.bytes);
	return sha256(encoded.bytes, encoded.length, "the certificate");
}

std::string hex(const Digest& digest) {
	static constexpr char digits[] = "0123456789abcdef";
	std::string out;
	out.reserve(digest.size() * 2);
	for (unsigned char byte : digest) {
		out.push_back(digits[byte >> 4]);
		out.push_back(digits[byte & 0xF]);
	}
	return out;
}

}  // namespace pki
