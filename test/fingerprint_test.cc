// D10 and T10's cases that need no signing by pki: the SPKI digest is the SHA-256 of the
// SubjectPublicKeyInfo DER, not X509_pubkey_digest's; the DER digest is the certificate's.
#include <iostream>
#include <string>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "fixture.h"
#include "pki/fingerprint.h"

using fixture::contains;

namespace {

// The last whitespace-separated token of openssl dgst's output.
std::string digest_of(const std::string& output) {
	auto end = output.find_last_not_of(" \n");
	auto start = output.find_last_of(" =", end);
	return output.substr(start + 1, end - start);
}

bool lowercase_hex(const std::string& text) {
	if (text.size() != 64) { return false; }
	for (char c : text) {
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { return false; }
	}
	return true;
}

}  // namespace

int main() {
	std::string base = fixture::scratch("fingerprint");
	auto ca_key = fixture::key_of("P-256");
	auto ca = fixture::make_ca(ca_key.get(), 1700000000, 1900000000);
	auto key = fixture::key_of("P-256");
	auto leaf = fixture::make_leaf(ca.get(), ca_key.get(), key.get(), 1700000000, 1800000000, 2);
	std::string leaf_file = base + "/leaf.pem";
	fixture::write_file(leaf_file, fixture::pem_of(leaf.get()), 0644);

	std::string spki = pki::hex(pki::spki_sha256(leaf.get()));
	std::string der = pki::hex(pki::der_sha256(leaf.get()));
	CHECK(lowercase_hex(spki));
	CHECK(lowercase_hex(der));

	// The CLI's SPKI DER, hashed.
	std::string out;
	CHECK(fixture::shell(fixture::openssl() + " x509 -in '" + leaf_file + "' -pubkey -noout | " + fixture::openssl() +
		" pkey -pubin -outform DER | " + fixture::openssl() + " dgst -sha256", &out) == 0);
	CHECK(digest_of(out) == spki);

	// The CLI's certificate DER, hashed.
	out.clear();
	CHECK(fixture::shell(fixture::openssl() + " x509 -in '" + leaf_file + "' -outform DER | " + fixture::openssl() + " dgst -sha256", &out) == 0);
	CHECK(digest_of(out) == der);

	// X509_pubkey_digest hashes only the key's bits: another value (SR12).
	pki::Digest bits{};
	unsigned int length = 0;
	CHECK(X509_pubkey_digest(leaf.get(), EVP_sha256(), bits.data(), &length) == 1);
	CHECK(length == 32);
	CHECK(pki::hex(bits) != spki);

	// The key's SPKI is the certificate's.
	CHECK(pki::hex(pki::spki_sha256(key.get())) == spki);

	// A same-key renewal keeps the SPKI digest and changes the DER digest.
	auto renewed = fixture::make_leaf(ca.get(), ca_key.get(), key.get(), 1750000000, 1850000000, 3);
	CHECK(pki::hex(pki::spki_sha256(renewed.get())) == spki);
	CHECK(pki::hex(pki::der_sha256(renewed.get())) != der);

	// One key under two CAs: one SPKI digest, two DER digests.
	auto other_ca_key = fixture::key_of("P-256");
	auto other_ca = fixture::make_ca(other_ca_key.get(), 1700000000, 1900000000);
	auto cross = fixture::make_leaf(other_ca.get(), other_ca_key.get(), key.get(), 1700000000, 1800000000, 2);
	CHECK(pki::hex(pki::spki_sha256(cross.get())) == spki);
	CHECK(pki::hex(pki::der_sha256(cross.get())) != der);

	// Another key, another SPKI digest.
	auto stranger = fixture::key_of("P-256");
	CHECK(pki::hex(pki::spki_sha256(stranger.get())) != spki);

	// RSA and P-384 keys hash their SPKI DER the same way.
	for (const char* type : {"P-384", "RSA-2048"}) {
		auto k = fixture::key_of(type);
		auto l = fixture::make_leaf(ca.get(), ca_key.get(), k.get(), 1700000000, 1800000000, 4);
		std::string file = base + "/other.pem";
		fixture::write_file(file, fixture::pem_of(l.get()), 0644);
		out.clear();
		CHECK(fixture::shell(fixture::openssl() + " x509 -in '" + file + "' -pubkey -noout | " + fixture::openssl() +
			" pkey -pubin -outform DER | " + fixture::openssl() + " dgst -sha256", &out) == 0);
		CHECK(digest_of(out) == pki::hex(pki::spki_sha256(l.get())));
	}

	return fixture::finish("pki_fingerprint");
}
