// The entry point (D1, D14): usage, --consumer, fingerprint (D10), and check (D11) with
// their exit statuses, through pki::run as each consumer's binary calls it.
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "fixture.h"
#include "pki/fingerprint.h"
#include "pki/key.h"
#include "pki/pki.h"

using fixture::contains;

namespace {

struct Result {
	int status;
	std::string out;
	std::string err;
};

Result run(pki::Consumer consumer, std::vector<std::string> args) {
	args.insert(args.begin(), "kronuz-pki");
	std::ostringstream out, err;
	int status = pki::run(consumer, args, out, err);
	return {status, out.str(), err.str()};
}

Result run(std::vector<std::string> args) { return run(pki::Consumer::unset, std::move(args)); }

void usage() {
	auto r = run({});
	CHECK(r.status == pki::exit_refused);
	CHECK(contains(r.err, "usage: kronuz-pki [--consumer xapiand|detent] COMMAND"));
	r = run({"help"});
	CHECK(r.status == pki::exit_ok);
	CHECK(contains(r.out, "fingerprint FILE"));
	r = run(pki::Consumer::xapiand, {"help"});
	CHECK(r.status == pki::exit_ok);
	CHECK(!contains(r.out, "--consumer"));
	r = run({"frobnicate"});
	CHECK(r.status == pki::exit_refused);
	CHECK(contains(r.err, "refused (usage): unknown command \"frobnicate\""));
	r = run({"version"});
	CHECK(r.status == pki::exit_ok);
	CHECK(contains(r.out, "pki 0.1.0\n"));
	CHECK(contains(r.out, "OpenSSL"));

	CHECK(run({"--consumer", "xapiand", "help"}).status == pki::exit_ok);
	CHECK(run({"--consumer", "detent", "help"}).status == pki::exit_ok);
	r = run({"--consumer", "strata", "help"});
	CHECK(r.status == pki::exit_refused);
	CHECK(contains(r.err, "--consumer takes xapiand or detent"));
	CHECK(run({"--consumer"}).status == pki::exit_refused);
	// A consumer's binary fixes the consumer: --consumer is not a command there.
	r = run(pki::Consumer::detent, {"--consumer", "xapiand", "help"});
	CHECK(r.status == pki::exit_refused);
	CHECK(contains(r.err, "unknown command \"--consumer\""));
}

pki::Request make_request(EVP_PKEY* key) {
	pki::Request request(X509_REQ_new());
	X509_REQ_set_version(request.get(), 0);
	X509_REQ_set_pubkey(request.get(), key);
	X509_REQ_sign(request.get(), key, EVP_sha256());
	return request;
}

std::string pem_of_request(X509_REQ* request) {
	pki::Bio bio(BIO_new(BIO_s_mem()));
	PEM_write_bio_X509_REQ(bio.get(), request);
	char* data = nullptr;
	long length = BIO_get_mem_data(bio.get(), &data);
	return std::string(data, static_cast<std::size_t>(length));
}

void fingerprint(const std::string& base) {
	auto ca_key = fixture::key_of("P-256");
	auto ca = fixture::make_ca(ca_key.get(), 1700000000, 1900000000);
	auto key = fixture::key_of("P-256");
	auto leaf = fixture::make_leaf(ca.get(), ca_key.get(), key.get(), 1700000000, 1800000000);
	std::string bundle = base + "/bundle.pem";
	fixture::write_file(bundle, fixture::pem_of(leaf.get()) + fixture::pem_of(ca.get()), 0644);

	auto r = run({"fingerprint", bundle});
	CHECK(r.status == pki::exit_ok);
	std::string expected = "certificate 1\nspki-sha256 " + pki::hex(pki::spki_sha256(leaf.get())) + "\nder-sha256 " +
		pki::hex(pki::der_sha256(leaf.get())) + "\ncertificate 2\nspki-sha256 " + pki::hex(pki::spki_sha256(ca.get())) +
		"\nder-sha256 " + pki::hex(pki::der_sha256(ca.get())) + "\n";
	CHECK(r.out == expected);

	// A request and a public key print the same SPKI digest as the certificate.
	auto request = make_request(key.get());
	std::string request_file = base + "/node.csr";
	fixture::write_file(request_file, pem_of_request(request.get()), 0644);
	r = run({"fingerprint", request_file});
	CHECK(r.status == pki::exit_ok);
	CHECK(r.out == "request 1\nspki-sha256 " + pki::hex(pki::spki_sha256(leaf.get())) + "\n");
	std::string public_file = base + "/node.pub";
	fixture::write_file(public_file, fixture::pem_of_public_key(key.get()), 0644);
	r = run({"fingerprint", public_file});
	CHECK(r.out == "public-key 1\nspki-sha256 " + pki::hex(pki::spki_sha256(leaf.get())) + "\n");

	// Refusals, each beside the accepted bundle above.
	std::string private_file = base + "/node.key";
	auto plain = pki::plain_private_key(key.get());
	fixture::write_file(private_file, plain.view(), 0600);
	r = run({"fingerprint", private_file});
	CHECK(r.status == pki::exit_refused);
	CHECK(contains(r.err, "refused (pem)"));
	CHECK(contains(r.err, "holds a private key"));
	CHECK(r.out.empty());
	std::string empty = base + "/empty.pem";
	fixture::write_file(empty, "", 0644);
	CHECK(contains(run({"fingerprint", empty}).err, "holds no certificate, request, or public key"));
	std::string damaged = base + "/damaged.pem";
	std::string text = fixture::pem_of(leaf.get());
	text[text.size() / 2] = '*';
	fixture::write_file(damaged, text, 0644);
	CHECK(contains(run({"fingerprint", damaged}).err, "refused (pem)"));
	CHECK(contains(run({"fingerprint", base + "/missing.pem"}).err, "refused (file-open)"));
	CHECK(contains(run({"fingerprint", base}).err, "refused (file-not-regular)"));
	CHECK(contains(run({"fingerprint"}).err, "refused (usage)"));
	CHECK(contains(run({"fingerprint", bundle, bundle}).err, "refused (usage)"));
}

void check(const std::string& base) {
	constexpr std::int64_t day = 86400;
	constexpr std::int64_t issuance = 1800000000;
	auto ca_key = fixture::key_of("P-256");
	auto ca = fixture::make_ca(ca_key.get(), issuance - day, issuance + 1826 * day);
	auto key = fixture::key_of("P-256");
	auto leaf = fixture::make_leaf(ca.get(), ca_key.get(), key.get(), issuance - 3600, issuance + 365 * day);
	std::string file = base + "/leaf.pem";
	fixture::write_file(file, fixture::pem_of(leaf.get()), 0644);
	auto at = [&](std::int64_t t, std::vector<std::string> args) {
		::setenv("PKI_TEST_NOW", std::to_string(t).c_str(), 1);
		args.insert(args.begin(), "check");
		auto r = run(std::move(args));
		::unsetenv("PKI_TEST_NOW");
		return r;
	};

	auto r = at(issuance, {file});
	CHECK(r.status == pki::exit_ok);
	CHECK(r.out == "certificate 1 valid not-before 2027-01-15T07:00:00Z not-after 2028-01-15T08:00:00Z (365 days left)\n");
	// Five sixths of the life is 304.16 days after issuance.
	r = at(issuance + 304 * day, {file});
	CHECK(r.status == pki::exit_ok);
	r = at(issuance + 305 * day, {file});
	CHECK(r.status == pki::exit_found);
	CHECK(contains(r.out, "certificate 1 expiring"));
	CHECK(contains(r.out, "(60 days left)"));
	r = at(issuance + 365 * day - 31 * day, {file, "--within", "30d"});
	CHECK(r.status == pki::exit_ok);
	r = at(issuance + 365 * day - 29 * day, {"--within", "30d", file});
	CHECK(r.status == pki::exit_found);
	CHECK(contains(r.out, "expiring"));
	r = at(issuance + 366 * day, {file});
	CHECK(r.status == pki::exit_found);
	CHECK(contains(r.out, "certificate 1 expired"));
	CHECK(!contains(r.out, "days left"));
	r = at(issuance - 2 * 3600, {file});
	CHECK(r.status == pki::exit_found);
	CHECK(contains(r.out, "not-yet-valid"));

	// A bundle: one expired certificate among valid ones is found.
	auto old_leaf = fixture::make_leaf(ca.get(), ca_key.get(), key.get(), issuance - 400 * day, issuance - day, 7);
	std::string bundle = base + "/mixed.pem";
	fixture::write_file(bundle, fixture::pem_of(leaf.get()) + fixture::pem_of(old_leaf.get()), 0644);
	r = at(issuance, {bundle});
	CHECK(r.status == pki::exit_found);
	CHECK(contains(r.out, "certificate 1 valid"));
	CHECK(contains(r.out, "certificate 2 expired"));

	r = at(issuance, {file, "--within", "30x"});
	CHECK(r.status == pki::exit_refused);
	CHECK(contains(r.err, "refused (duration)"));
	CHECK(at(issuance, {file, "--within"}).status == pki::exit_refused);
	CHECK(at(issuance, {}).status == pki::exit_refused);
	CHECK(at(issuance, {file, file}).status == pki::exit_refused);
	CHECK(contains(at(issuance, {file, "--days", "3"}).err, "check does not take --days"));
	auto request_only = base + "/request-only.pem";
	fixture::write_file(request_only, fixture::pem_of_public_key(key.get()), 0644);
	CHECK(contains(at(issuance, {request_only}).err, "holds no certificate"));
}

}  // namespace

int main() {
	std::string base = fixture::scratch("command");
	usage();
	fingerprint(base);
	check(base);
	return fixture::finish("pki_command");
}
