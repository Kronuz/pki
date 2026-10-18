// T13's identity vectors (D5, SR11, PKI-R25), each refusal beside an accept.
#include <string>

#include "fixture.h"
#include "pki/identity.h"

using fixture::contains;
using pki::Consumer;
using pki::Reason;
using pki::Role;

int main() {
	// The trust domain is the cluster lowercased; Xapiand's default cluster is Xapiand.
	CHECK(pki::trust_domain("Xapiand") == "xapiand");
	CHECK(pki::trust_domain("prod.EU-west_1") == "prod.eu-west_1");
	CHECK(pki::trust_domain(std::string(255, 'C')) == std::string(255, 'c'));
	CHECK_REFUSED(Reason::identity_cluster, pki::trust_domain(std::string(256, 'c')));
	CHECK_REFUSED(Reason::identity_cluster, pki::trust_domain(""));
	CHECK(contains(CHECK_REFUSED(Reason::identity_cluster, pki::trust_domain("my cluster")), "1 to 255 of the letters"));
	CHECK(pki::trust_domain("my-cluster") == "my-cluster");
	for (const char* bad : {"a/b", "a%41", "a:1", "a@b", "caf\xc3\xa9"}) {
		CHECK_REFUSED(Reason::identity_cluster, pki::trust_domain(bad));
	}

	// Xapiand names, lowercased per byte; the role picks the path.
	std::string domain = pki::trust_domain("Xapiand");
	CHECK(pki::identity(domain, Consumer::xapiand, Role::server, "Gryzhak") == "spiffe://xapiand/xapiand/node/gryzhak");
	CHECK(pki::identity(domain, Consumer::xapiand, Role::peer, "Gryzhak") == "spiffe://xapiand/xapiand/node/gryzhak");
	CHECK(pki::identity(domain, Consumer::xapiand, Role::client, "Gryzhak") == "spiffe://xapiand/xapiand/client/gryzhak");
	CHECK(pki::identity(domain, Consumer::xapiand, Role::server, "n1.a-b_c") == "spiffe://xapiand/xapiand/node/n1.a-b_c");
	CHECK(pki::identity_name(Consumer::xapiand, "...") == "...");
	CHECK(pki::identity_name(Consumer::xapiand, std::string(511, 'N')) == std::string(511, 'n'));
	for (std::string bad : {std::string(), std::string("."), std::string(".."), std::string("a/b"), std::string("n%31"),
			std::string("node 1"), std::string("caf\xc3\xa9"), std::string("\x80"), std::string(512, 'n'), std::string("a\0b", 3)}) {
		CHECK(contains(CHECK_REFUSED(Reason::identity_name, pki::identity_name(Consumer::xapiand, bad)), "1 to 511"));
	}

	// A refusal quotes the name, so neither a NUL nor a terminal escape reaches the message.
	auto message = CHECK_REFUSED(Reason::identity_name, pki::identity_name(Consumer::xapiand, std::string("a\0\x1b[2Jb\"", 8)));
	CHECK(contains(message, "\"a\\x00\\x1b[2Jb\\x22\""));
	CHECK(pki::quoted("caf\xc3\xa9") == "\"caf\\xc3\\xa9\"");

	// Detent's voter ids, in decimal.
	CHECK(pki::identity(domain, Consumer::detent, Role::peer, "1") == "spiffe://xapiand/detent/node/1");
	CHECK(pki::identity_name(Consumer::detent, "18446744073709551615") == "18446744073709551615");
	for (const char* bad : {"0", "", "01", "-1", "+1", "1a", "18446744073709551616", "99999999999999999999"}) {
		CHECK(contains(CHECK_REFUSED(Reason::identity_name, pki::identity_name(Consumer::detent, bad)), "voter id"));
	}
	CHECK_REFUSED(Reason::usage, pki::identity_name(Consumer::unset, "n1"));

	// The longest identity: 791 bytes, under SPIFFE's 2,048.
	auto longest = pki::identity(std::string(255, 'd'), Consumer::xapiand, Role::client, std::string(511, 'n'));
	CHECK(longest.size() == 791);
	CHECK_REFUSED(Reason::identity_cluster, pki::identity("Xapiand", Consumer::xapiand, Role::server, "n1"));

	// A verifier compares bytes: neither an encoding nor a case variant of node1 matches.
	auto expected = pki::identity(domain, Consumer::xapiand, Role::server, "node1");
	CHECK(pki::same_identity(expected, "spiffe://xapiand/xapiand/node/node1"));
	CHECK(!pki::same_identity(expected, "spiffe://xapiand/xapiand/node/%6Eode1"));
	CHECK(!pki::same_identity(expected, "spiffe://xapiand/xapiand/node/NODE1"));
	CHECK(!pki::same_identity(expected, "spiffe://XAPIAND/xapiand/node/node1"));
	CHECK(!pki::same_identity(expected, "spiffe://xapiand/xapiand/client/node1"));
	CHECK(!pki::same_identity(expected, "spiffe://xapiand/xapiand/node/node1/"));

	CHECK(pki::parse_role("peer") == Role::peer);
	CHECK_REFUSED(Reason::usage, pki::parse_role("Peer"));
	return fixture::finish("pki_identity");
}
