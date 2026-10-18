#include "fixture.h"

#include <grp.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace fixture {

int failures = 0;
int checks = 0;

void report(bool ok, const char* expression, const char* file, int line) {
	++checks;
	if (!ok) {
		++failures;
		std::cerr << file << ":" << line << ": FAILED: " << expression << "\n";
	}
}

int finish(const char* suite) {
	if (failures != 0) {
		std::cerr << suite << ": " << failures << " of " << checks << " checks failed\n";
		return 1;
	}
	std::cout << suite << ": all " << checks << " checks passed\n";
	return 0;
}

std::string refused(pki::Reason reason, const std::function<void()>& body, const char* file, int line) {
	try {
		body();
	} catch (const pki::Refusal& refusal) {
		bool ok = refusal.reason() == reason;
		report(ok, "refused with the expected reason", file, line);
		if (!ok) {
			std::cerr << "  expected " << pki::name(reason) << ", got " << pki::name(refusal.reason()) << ": " << refusal.what() << "\n";
		}
		return refusal.what();
	} catch (const std::exception& error) {
		report(false, "refused, not another exception", file, line);
		std::cerr << "  " << error.what() << "\n";
		return {};
	}
	report(false, "refused", file, line);
	std::cerr << "  expected a refusal (" << pki::name(reason) << "), got none\n";
	return {};
}

void accepted(const std::function<void()>& body, const char* what, const char* file, int line) {
	try {
		body();
		report(true, what, file, line);
	} catch (const std::exception& error) {
		report(false, what, file, line);
		std::cerr << "  threw: " << error.what() << "\n";
	}
}

bool contains(std::string_view haystack, std::string_view needle) { return haystack.find(needle) != std::string_view::npos; }

std::string scratch(const std::string& name) {
	auto path = std::filesystem::current_path() / ("pki-test-" + name);
	// A failed run can leave a directory at mode 0000 behind.
	shell("chmod -R u+rwx '" + path.string() + "' 2>/dev/null");
	std::filesystem::remove_all(path);
	std::filesystem::create_directories(path);
	::chmod(path.c_str(), 0700);
	return path.string();
}

void write_file(const std::string& path, std::string_view bytes, mode_t mode) {
	::unlink(path.c_str());
	{
		std::ofstream out(path, std::ios::binary);
		out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
	}
	::chmod(path.c_str(), mode);
}

std::string read_file(const std::string& path) {
	std::ifstream in(path, std::ios::binary);
	std::stringstream buffer;
	buffer << in.rdbuf();
	return buffer.str();
}

gid_t other_group() {
	gid_t groups[256];
	int count = ::getgroups(256, groups);
	for (int i = 0; i < count; ++i) {
		if (groups[i] != ::getegid()) { return groups[i]; }
	}
	return static_cast<gid_t>(-1);
}

int shell(const std::string& command, std::string* output) {
	FILE* pipe = ::popen(command.c_str(), "r");
	if (pipe == nullptr) { return -1; }
	char buffer[4096];
	std::size_t n;
	while ((n = std::fread(buffer, 1, sizeof buffer, pipe)) > 0) {
		if (output != nullptr) { output->append(buffer, n); }
	}
	int status = ::pclose(pipe);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

std::string openssl() { return std::string("'") + PKI_TEST_OPENSSL + "'"; }

pki::Key key_of(const char* type) {
	std::string_view t = type;
	EVP_PKEY* key = nullptr;
	if (t == "P-256" || t == "P-384" || t == "P-521") {
		key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", type);
	} else if (t.starts_with("RSA-")) {
		key = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<std::size_t>(std::stoul(std::string(t.substr(4)))));
	} else if (t == "ED25519") {
		key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
	}
	if (key == nullptr) {
		ERR_print_errors_fp(stderr);
		std::abort();
	}
	return pki::Key(key);
}

namespace {

void add_extension(X509* certificate, X509* issuer, int nid, const char* value) {
	X509V3_CTX context;
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
	X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
	if (extension == nullptr || X509_add_ext(certificate, extension, -1) != 1) {
		ERR_print_errors_fp(stderr);
		std::abort();
	}
	X509_EXTENSION_free(extension);
}

pki::Certificate base(EVP_PKEY* key, std::int64_t not_before, std::int64_t not_after, std::uint64_t serial) {
	pki::Certificate certificate(X509_new());
	X509_set_version(certificate.get(), 2);
	ASN1_INTEGER_set_uint64(X509_get_serialNumber(certificate.get()), serial);
	ASN1_TIME_set(X509_getm_notBefore(certificate.get()), static_cast<time_t>(not_before));
	ASN1_TIME_set(X509_getm_notAfter(certificate.get()), static_cast<time_t>(not_after));
	X509_set_pubkey(certificate.get(), key);
	return certificate;
}

}  // namespace

pki::Certificate make_ca(EVP_PKEY* key, std::int64_t not_before, std::int64_t not_after) {
	auto certificate = base(key, not_before, not_after, 1);
	X509_NAME* name = X509_NAME_new();
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("fixture CA"), -1, -1, 0);
	X509_set_subject_name(certificate.get(), name);
	X509_set_issuer_name(certificate.get(), name);
	X509_NAME_free(name);
	add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
	add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	add_extension(certificate.get(), certificate.get(), NID_subject_key_identifier, "hash");
	X509_sign(certificate.get(), key, EVP_sha256());
	return certificate;
}

pki::Certificate make_leaf(X509* ca, EVP_PKEY* ca_key, EVP_PKEY* key, std::int64_t not_before, std::int64_t not_after,
	std::uint64_t serial) {
	auto certificate = base(key, not_before, not_after, serial);
	X509_set_issuer_name(certificate.get(), X509_get_subject_name(ca));
	add_extension(certificate.get(), ca, NID_subject_alt_name, "critical,URI:spiffe://fixture/xapiand/node/n1,DNS:localhost,IP:127.0.0.1");
	add_extension(certificate.get(), ca, NID_basic_constraints, "critical,CA:FALSE");
	add_extension(certificate.get(), ca, NID_key_usage, "critical,digitalSignature");
	add_extension(certificate.get(), ca, NID_ext_key_usage, "serverAuth");
	add_extension(certificate.get(), ca, NID_subject_key_identifier, "hash");
	add_extension(certificate.get(), ca, NID_authority_key_identifier, "keyid:always");
	X509_sign(certificate.get(), ca_key, EVP_sha256());
	return certificate;
}

std::string pem_of(const X509* certificate) {
	pki::Bio bio(BIO_new(BIO_s_mem()));
	PEM_write_bio_X509(bio.get(), certificate);
	char* data = nullptr;
	long length = BIO_get_mem_data(bio.get(), &data);
	return std::string(data, static_cast<std::size_t>(length));
}

std::string pem_of_public_key(const EVP_PKEY* key) {
	pki::Bio bio(BIO_new(BIO_s_mem()));
	PEM_write_bio_PUBKEY(bio.get(), key);
	char* data = nullptr;
	long length = BIO_get_mem_data(bio.get(), &data);
	return std::string(data, static_cast<std::size_t>(length));
}

}  // namespace fixture
