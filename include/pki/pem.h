// Public PEM files: certificates, requests, and public keys, as fingerprint, check, and
// show read them. Private keys are refused here; they go through the key-file checks.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "pki/openssl.h"

namespace pki {

struct PublicObject {
	enum class Kind { certificate, request, public_key };
	Kind kind;
	Certificate certificate;  // Kind::certificate
	Request request;          // Kind::request
	Key key;                  // Kind::public_key, and a request's key
};

// Each object's DER is at most 64 KiB, reactor::tls's cap on a peer's whole certificate
// list (reactor_tls.h), so no consumer would take a larger one.
inline constexpr std::size_t pem_object_max_bytes = 64 * 1024;

// Every certificate, request, and public key in PATH, in order; other PEM objects are
// skipped. Refuses a private key, a damaged object, and a file with none of them.
std::vector<PublicObject> read_public_objects(const std::string& path);

// The certificates in PATH; refuses a file with none.
std::vector<Certificate> read_certificates(const std::string& path);

}  // namespace pki
