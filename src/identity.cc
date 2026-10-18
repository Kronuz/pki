#include "pki/identity.h"

#include <cstdint>
#include <limits>

#include "chars.hh"
#include "pki/refusal.h"

namespace pki {

namespace {

// SPIFFE-ID.md §2.1 and §2.2's characters, after lowercasing.
constexpr bool spiffe_char(char c) noexcept {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

std::string lowered(std::string_view text) {
	std::string out;
	out.reserve(text.size());
	for (char c : text) { out.push_back(chars::tolower(c)); }
	return out;
}

bool all_spiffe(std::string_view text) noexcept {
	for (char c : text) {
		if (!spiffe_char(c)) { return false; }
	}
	return true;
}

std::string node_name(std::string_view name) {
	std::string out = lowered(name);
	if (out.empty() || out.size() > node_name_max_bytes || !all_spiffe(out) || out == "." || out == "..") {
		throw Refusal(Reason::identity_name, "the node name " + quoted(name) +
			" is not accepted; a name is 1 to 511 of the letters a-z (any case), digits, '.', '-', and '_', "
			"and neither \".\" nor \"..\"");
	}
	return out;
}

std::string voter_id(std::string_view name) {
	auto refuse = [&]() -> std::string {
		throw Refusal(Reason::identity_name, "the voter id " + quoted(name) +
			" is not accepted; a voter id is a decimal from 1 to 18446744073709551615, without leading zeros");
	};
	if (name.empty() || name.front() == '0') { return refuse(); }
	std::uint64_t value = 0;
	for (char c : name) {
		if (c < '0' || c > '9') { return refuse(); }
		auto digit = static_cast<std::uint64_t>(c - '0');
		if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) { return refuse(); }
		value = value * 10 + digit;
	}
	return std::string(name);
}

}  // namespace

std::string_view name(Role role) noexcept {
	switch (role) {
		case Role::server: return "server";
		case Role::peer: return "peer";
		case Role::client: return "client";
	}
	return "unknown";
}

Role parse_role(std::string_view text) {
	if (text == "server") { return Role::server; }
	if (text == "peer") { return Role::peer; }
	if (text == "client") { return Role::client; }
	throw Refusal(Reason::usage, "the role " + quoted(text) + " is not one of server, peer, or client");
}

std::string trust_domain(std::string_view cluster) {
	std::string out = lowered(cluster);
	if (out.empty() || out.size() > trust_domain_max_bytes || !all_spiffe(out)) {
		throw Refusal(Reason::identity_cluster, "the cluster name " + quoted(cluster) +
			" is not accepted; a cluster name is 1 to 255 of the letters a-z (any case), digits, '.', '-', and '_', "
			"since it is the SPIFFE trust domain, lowercased");
	}
	return out;
}

std::string identity_name(Consumer consumer, std::string_view name) {
	switch (consumer) {
		case Consumer::xapiand: return node_name(name);
		case Consumer::detent: return voter_id(name);
		case Consumer::unset: break;
	}
	throw Refusal(Reason::usage, "no consumer: give --consumer xapiand or detent");
}

std::string identity(std::string_view trust_domain, Consumer consumer, Role role, std::string_view name) {
	if (trust_domain.empty() || trust_domain.size() > trust_domain_max_bytes || !all_spiffe(trust_domain)) {
		throw Refusal(Reason::identity_cluster, "the trust domain " + quoted(trust_domain) + " is not a lowercased cluster name");
	}
	std::string segment = identity_name(consumer, name);
	std::string out = "spiffe://";
	out += trust_domain;
	out += '/';
	out += pki::name(consumer);
	out += role == Role::client ? "/client/" : "/node/";
	out += segment;
	return out;
}

}  // namespace pki
