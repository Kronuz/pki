// Fingerprints (D10): the SHA-256 of a SubjectPublicKeyInfo's DER, SYS-2's SPKI pin, and
// the SHA-256 of a certificate's DER, Detent's voter pin today. Both print as 64
// lowercase hex digits. X509_pubkey_digest hashes only the key's bits, another value.
#pragma once

#include <array>
#include <string>

#include "pki/openssl.h"

namespace pki {

using Digest = std::array<unsigned char, 32>;

// i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate)), hashed.
Digest spki_sha256(const X509* certificate);
// i2d_PUBKEY(key), hashed: the same bytes a certificate over KEY carries.
Digest spki_sha256(const EVP_PKEY* key);
// The certificate's DER, hashed: consensus's certificate_fingerprint.
Digest der_sha256(const X509* certificate);

std::string hex(const Digest& digest);

}  // namespace pki
