// Keys and their encryption at rest (D4): ECDSA P-256 generated; P-384, or RSA 2,048 to
// 4,096 bits under --allow-rsa, accepted from a request; CA keys as PKCS#8 under PBES2
// with AES-256-CBC and scrypt N = 2^14, r = 8, p = 1, read back through OSSL_STORE.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "pki/openssl.h"
#include "pki/secret.h"

namespace pki {

enum class KeyKind { p256, p384, rsa };

// Refuses every key D4 does not accept, naming it and the rule.
KeyKind check_key_type(const EVP_PKEY* key, bool allow_rsa);

// "P-256", "P-384", "RSA 2048", or what OpenSSL names another key.
std::string describe_key(const EVP_PKEY* key);

// A new ECDSA P-256 key.
Key generate_key();

// N = 2^14, r = 8, p = 1 (16 MiB): the most OpenSSL's PKCS#8 reader takes, since its
// 32 MiB default limit refuses N = 2^15 on write and on read.
inline constexpr std::uint64_t scrypt_n = std::uint64_t{1} << 14;
inline constexpr std::uint64_t scrypt_r = 8;
inline constexpr std::uint64_t scrypt_p = 1;

// Key files are read whole up to 16 KiB, which holds the largest accepted key, an RSA
// 4,096 key's PKCS#8 PEM, several times over.
inline constexpr std::size_t key_file_max_bytes = 16 * 1024;

// PEM "ENCRYPTED PRIVATE KEY" under the passphrase, with D4's parameters.
Secret encrypt_private_key(const EVP_PKEY* key, const Secret& passphrase);

// PEM "PRIVATE KEY", unprotected: node keys, and --no-passphrase fixtures.
Secret plain_private_key(const EVP_PKEY* key);

// Loads the private key in PEM through OSSL_STORE; PASSPHRASE may be null for an
// unprotected key. SHOWN names the file in refusals.
Key load_private_key(const Secret& pem, const Secret* passphrase, const std::string& shown);

// Seconds one derivation at D4's parameters takes on this host, which `init` prints.
double derivation_seconds();

}  // namespace pki
