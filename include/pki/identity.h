// The identity (D5): a SPIFFE ID, spiffe://<trust domain>/<consumer>/<node | client>/<name>,
// with one byte form. Nothing is percent-encoded or normalized; a verifier builds the
// expected string and compares bytes.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "pki/pki.h"

namespace pki {

enum class Role { server, peer, client };

std::string_view name(Role role) noexcept;

// "server", "peer", or "client"; refuses anything else.
Role parse_role(std::string_view text);

// SPIFFE-ID.md §2.3 caps a trust domain at 255 bytes. A Xapiand name is capped at 511,
// the most its node file round-trips (`char buf[512]`, src/manager.cc).
inline constexpr std::size_t trust_domain_max_bytes = 255;
inline constexpr std::size_t node_name_max_bytes = 511;

// The trust domain of CLUSTER: 1 to 255 bytes of [A-Za-z0-9._-], lowercased per byte.
// Refuses any other cluster name with the rule (PKI-R25).
std::string trust_domain(std::string_view cluster);

// The identity's last segment. Xapiand: the node name, ASCII-lowercased per byte as
// Xapiand compares names (Xapiand's rule; SPIFFE paths allow uppercase), then 1 to 511
// bytes of [a-z0-9._-], neither "." nor "..". Detent: the voter id in decimal, 1 to
// 2^64 - 1, without leading zeros.
std::string identity_name(Consumer consumer, std::string_view name);

// spiffe://<trust domain>/<consumer>/<node | client>/<name>: `node` for server and peer
// leaves, `client` for client leaves. TRUST_DOMAIN must come from trust_domain().
std::string identity(std::string_view trust_domain, Consumer consumer, Role role, std::string_view name);

// A verifier's comparison: bytes, never a parse or a normalization of PRESENTED.
inline bool same_identity(std::string_view expected, std::string_view presented) noexcept { return expected == presented; }

}  // namespace pki
