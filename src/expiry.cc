#include "pki/expiry.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <openssl/asn1.h>
#include <openssl/x509.h>

#include "pki/refusal.h"

namespace pki {

namespace {

std::int64_t seconds_of(const ASN1_TIME* time, const char* what) {
	std::unique_ptr<ASN1_TIME, OpenSSLDeleter<ASN1_TIME, ASN1_TIME_free>> epoch(ASN1_TIME_set(nullptr, 0));
	int days = 0;
	int seconds = 0;
	if (time == nullptr || !epoch || ASN1_TIME_diff(&days, &seconds, epoch.get(), time) != 1) {
		crypto_failure(std::string("cannot read the certificate's ") + what);
	}
	return std::int64_t{days} * 86400 + seconds;
}

}  // namespace

Validity validity(const X509* certificate) {
	return {seconds_of(X509_get0_notBefore(certificate), "notBefore"), seconds_of(X509_get0_notAfter(certificate), "notAfter")};
}

Standing standing(const Validity& validity, std::int64_t now, std::optional<std::int64_t> within) {
	if (now < validity.not_before) { return Standing::not_yet_valid; }
	if (now >= validity.not_after) { return Standing::expired; }
	std::int64_t from = within ? validity.not_after - *within
		: validity.not_before + (validity.not_after - validity.not_before) / 6 * 5;
	return now >= from ? Standing::expiring : Standing::valid;
}

std::string_view name(Standing standing) noexcept {
	switch (standing) {
		case Standing::valid: return "valid";
		case Standing::expiring: return "expiring";
		case Standing::expired: return "expired";
		case Standing::not_yet_valid: return "not-yet-valid";
	}
	return "unknown";
}

std::int64_t parse_duration(std::string_view text) {
	auto refuse = [&]() -> std::int64_t {
		throw Refusal(Reason::duration, "cannot read the duration \"" + std::string(text) +
			"\"; give a count and a unit, s, m, h, or d, such as 30d");
	};
	if (text.size() < 2) { return refuse(); }
	std::int64_t unit = 0;
	switch (text.back()) {
		case 's': unit = 1; break;
		case 'm': unit = 60; break;
		case 'h': unit = 3600; break;
		case 'd': unit = 86400; break;
		default: return refuse();
	}
	std::int64_t count = 0;
	for (char c : text.substr(0, text.size() - 1)) {
		if (c < '0' || c > '9') { return refuse(); }
		count = count * 10 + (c - '0');
		if (count > latest_time / unit) {
			throw Refusal(Reason::duration, "the duration \"" + std::string(text) + "\" runs past 9999-12-31, the latest time X.509 encodes");
		}
	}
	return count * unit;
}

std::string format_time(std::int64_t seconds) {
	std::time_t t = static_cast<std::time_t>(seconds);
	std::tm tm{};
	if (::gmtime_r(&t, &tm) == nullptr) { return std::to_string(seconds); }
	char buffer[32];
	std::snprintf(buffer, sizeof buffer, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
	return buffer;
}

std::int64_t now() {
#ifdef PKI_TEST_HOOKS
	if (const char* fixed = std::getenv("PKI_TEST_NOW")) { return std::strtoll(fixed, nullptr, 10); }
#endif
	return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace pki
