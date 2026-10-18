// D11 and T5's verification cases: a leaf's bounds as OpenSSL's verifier and the CLI see
// them, never at notAfter itself, where 3.6 and 4.0 differ; standing, durations, the clock.
#include <cstdlib>
#include <iostream>
#include <string>

#include <openssl/x509_vfy.h>

#include "fixture.h"
#include "pki/expiry.h"

using fixture::contains;
using pki::Reason;
using pki::Standing;

namespace {

constexpr std::int64_t issuance = 1800000000;  // 2027-01-15T08:00:00Z
constexpr std::int64_t day = 86400;
constexpr std::int64_t not_before = issuance - 3600;
constexpr std::int64_t not_after = issuance + 365 * day;

int verify_at(X509* ca, X509* leaf, std::int64_t at) {
	X509_STORE* store = X509_STORE_new();
	X509_STORE_add_cert(store, ca);
	X509_STORE_CTX* context = X509_STORE_CTX_new();
	X509_STORE_CTX_init(context, store, leaf, nullptr);
	X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(context), static_cast<time_t>(at));
	int ok = X509_verify_cert(context);
	int error = ok == 1 ? X509_V_OK : X509_STORE_CTX_get_error(context);
	X509_STORE_CTX_free(context);
	X509_STORE_free(store);
	return error;
}

void verification_bounds(const std::string& base) {
	auto ca_key = fixture::key_of("P-256");
	auto ca = fixture::make_ca(ca_key.get(), issuance - 10 * day, issuance + 1826 * day);
	auto key = fixture::key_of("P-256");
	auto leaf = fixture::make_leaf(ca.get(), ca_key.get(), key.get(), not_before, not_after);

	CHECK(verify_at(ca.get(), leaf.get(), issuance - 3599) == X509_V_OK);
	CHECK(verify_at(ca.get(), leaf.get(), issuance - 3601) == X509_V_ERR_CERT_NOT_YET_VALID);
	CHECK(verify_at(ca.get(), leaf.get(), not_after - 1) == X509_V_OK);
	CHECK(verify_at(ca.get(), leaf.get(), not_after + 1) == X509_V_ERR_CERT_HAS_EXPIRED);

	std::string ca_file = base + "/ca.pem";
	std::string leaf_file = base + "/leaf.pem";
	fixture::write_file(ca_file, fixture::pem_of(ca.get()), 0644);
	fixture::write_file(leaf_file, fixture::pem_of(leaf.get()), 0644);
	auto cli = [&](std::int64_t at) {
		return fixture::shell(fixture::openssl() + " verify -attime " + std::to_string(at) + " -CAfile '" + ca_file + "' '" +
			leaf_file + "' > /dev/null 2>&1");
	};
	CHECK(cli(issuance - 3599) == 0);
	CHECK(cli(issuance - 3601) != 0);
	CHECK(cli(not_after - 1) == 0);
	CHECK(cli(not_after + 1) != 0);

	auto v = pki::validity(leaf.get());
	CHECK(v.not_before == not_before);
	CHECK(v.not_after == not_after);
}

void standings() {
	pki::Validity v{not_before, not_after};
	std::int64_t life = not_after - not_before;
	std::int64_t threshold = not_before + life / 6 * 5;
	CHECK(pki::standing(v, not_before - 1, std::nullopt) == Standing::not_yet_valid);
	CHECK(pki::standing(v, not_before, std::nullopt) == Standing::valid);
	CHECK(pki::standing(v, threshold - 1, std::nullopt) == Standing::valid);
	CHECK(pki::standing(v, threshold, std::nullopt) == Standing::expiring);
	// Five sixths of a 365-day leaf (with its hour of lag) is about 61 days before notAfter.
	CHECK((not_after - threshold) / day == 60);
	CHECK(pki::standing(v, not_after - 1, std::nullopt) == Standing::expiring);
	CHECK(pki::standing(v, not_after, std::nullopt) == Standing::expired);
	CHECK(pki::standing(v, not_after + 1, std::nullopt) == Standing::expired);

	std::int64_t within = 30 * day;
	CHECK(pki::standing(v, not_after - within - 1, within) == Standing::valid);
	CHECK(pki::standing(v, not_after - within, within) == Standing::expiring);
	CHECK(pki::standing(v, issuance, within) == Standing::valid);
	CHECK(pki::standing(v, issuance, 400 * day) == Standing::expiring);
	CHECK(pki::name(Standing::not_yet_valid) == "not-yet-valid");
}

void durations() {
	CHECK(pki::parse_duration("30d") == 30 * day);
	CHECK(pki::parse_duration("12h") == 12 * 3600);
	CHECK(pki::parse_duration("90m") == 90 * 60);
	CHECK(pki::parse_duration("3600s") == 3600);
	CHECK(pki::parse_duration("0d") == 0);
	for (const char* bad : {"", "d", "30", "30x", "-1d", "1.5d", "30D", " 30d", "30d ", "d30"}) {
		CHECK(contains(CHECK_REFUSED(Reason::duration, pki::parse_duration(bad)), "a count and a unit"));
	}
	CHECK(contains(CHECK_REFUSED(Reason::duration, pki::parse_duration("3\x1b[0md")), "\"3\\x1b[0md\""));
	CHECK(pki::parse_duration("2932896d") == 2932896 * day);
	CHECK(contains(CHECK_REFUSED(Reason::duration, pki::parse_duration("2932897d")), "9999-12-31"));
	CHECK_REFUSED(Reason::duration, pki::parse_duration("99999999999999999999999s"));
	CHECK(pki::parse_duration("253402300799s") == pki::latest_time);
	CHECK_REFUSED(Reason::duration, pki::parse_duration("253402300800s"));
}

void clocks() {
	CHECK(pki::format_time(0) == "1970-01-01T00:00:00Z");
	CHECK(pki::format_time(issuance) == "2027-01-15T08:00:00Z");
	CHECK(pki::format_time(pki::latest_time) == "9999-12-31T23:59:59Z");
	::unsetenv("PKI_TEST_NOW");
	std::int64_t real = pki::now();
	CHECK(real > 1700000000);
	::setenv("PKI_TEST_NOW", "1234567890", 1);
	CHECK(pki::now() == 1234567890);
	::unsetenv("PKI_TEST_NOW");
}

}  // namespace

int main() {
	std::string base = fixture::scratch("expiry");
	verification_bounds(base);
	standings();
	durations();
	clocks();
	return fixture::finish("pki_expiry");
}
