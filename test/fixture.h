// The tests' checks and fixtures: certificates made with OpenSSL directly, scratch
// directories under the build tree, and the openssl beside the linked library.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "pki/openssl.h"
#include "pki/refusal.h"

namespace fixture {

extern int failures;
extern int checks;

void report(bool ok, const char* expression, const char* file, int line);
int finish(const char* suite);

#define CHECK(expression) ::fixture::report(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

// Runs BODY and checks that it throws a pki::Refusal with REASON; returns its message.
std::string refused(pki::Reason reason, const std::function<void()>& body, const char* file, int line);
#define CHECK_REFUSED(reason, body) ::fixture::refused(reason, [&] { body; }, __FILE__, __LINE__)
// Runs BODY and checks that it throws nothing.
void accepted(const std::function<void()>& body, const char* what, const char* file, int line);
#define CHECK_ACCEPTED(body) ::fixture::accepted([&] { body; }, #body, __FILE__, __LINE__)

bool contains(std::string_view haystack, std::string_view needle);

// A fresh directory under the working directory (the build tree), at mode 0700.
std::string scratch(const std::string& name);

void write_file(const std::string& path, std::string_view bytes, mode_t mode);
std::string read_file(const std::string& path);

// A supplementary group of the caller other than its effective group, or -1.
gid_t other_group();

// Runs a shell command; returns its exit status and fills OUTPUT with its stdout.
int shell(const std::string& command, std::string* output = nullptr);
std::string openssl();  // the openssl CLI the tests use, quoted for the shell

// Certificates signed by a fixture CA with OpenSSL directly, for the rows pki's own
// signing (step 2) does not yet serve.
pki::Key key_of(const char* type);  // "P-256", "P-384", "P-521", "RSA-1024", "RSA-2048", "RSA-4096", "ED25519"
pki::Certificate make_ca(EVP_PKEY* key, std::int64_t not_before, std::int64_t not_after);
pki::Certificate make_leaf(X509* ca, EVP_PKEY* ca_key, EVP_PKEY* key, std::int64_t not_before, std::int64_t not_after,
	std::uint64_t serial = 2);
std::string pem_of(const X509* certificate);
std::string pem_of_public_key(const EVP_PKEY* key);

}  // namespace fixture
