// Expiry visibility (D11): a certificate is expiring past five sixths of its life, or
// within a given span of its notAfter. The clock is the host's; test builds alone read
// PKI_TEST_NOW.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "pki/openssl.h"

namespace pki {

struct Validity {
	std::int64_t not_before;  // seconds since the epoch, UTC
	std::int64_t not_after;
};

enum class Standing { valid, expiring, expired, not_yet_valid };

Validity validity(const X509* certificate);

// Not yet valid before notBefore; expired from notAfter on, where OpenSSL 3.6 refuses
// (4.0 accepts); expiring within WITHIN seconds of notAfter, or past five sixths of its
// life without one.
Standing standing(const Validity& validity, std::int64_t now, std::optional<std::int64_t> within);

std::string_view name(Standing standing) noexcept;

// The latest time X.509 encodes, 9999-12-31T23:59:59Z (RFC 5280's GeneralizedTime): the
// cap on a duration, so none overflows a time pki compares.
inline constexpr std::int64_t latest_time = 253402300799;

// "30d", "12h", "90m", "3600s": a count and one unit. Refuses anything else, and a span
// past latest_time.
std::int64_t parse_duration(std::string_view text);

// YYYY-MM-DDTHH:MM:SSZ.
std::string format_time(std::int64_t seconds);

// The clock every command reads.
std::int64_t now();

}  // namespace pki
