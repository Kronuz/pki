// D4: key types, the CA key's PKCS#8 under scrypt N = 2^14, r = 8, p = 1, read back by pki
// through OSSL_STORE and by the openssl CLI (T8's key cases).
#include <iostream>
#include <string>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "fixture.h"
#include "pki/directory.h"
#include "pki/key.h"

using fixture::contains;
using pki::Reason;

namespace {

pki::Secret secret_of(std::string_view text) {
	pki::Secret s(text.size());
	s.append(text.data(), text.size());
	return s;
}

void key_types() {
	auto generated = pki::generate_key();
	CHECK(pki::check_key_type(generated.get(), false) == pki::KeyKind::p256);
	CHECK(pki::describe_key(generated.get()) == "P-256");
	CHECK(pki::check_key_type(fixture::key_of("P-384").get(), false) == pki::KeyKind::p384);

	auto p521 = fixture::key_of("P-521");
	CHECK(contains(CHECK_REFUSED(Reason::key_type, pki::check_key_type(p521.get(), true)), "P-521"));
	CHECK_REFUSED(Reason::key_type, pki::check_key_type(fixture::key_of("ED25519").get(), true));

	auto rsa2048 = fixture::key_of("RSA-2048");
	CHECK(contains(CHECK_REFUSED(Reason::key_type, pki::check_key_type(rsa2048.get(), false)), "--allow-rsa"));
	CHECK(pki::check_key_type(rsa2048.get(), true) == pki::KeyKind::rsa);
	CHECK(pki::describe_key(rsa2048.get()) == "RSA 2048");
	auto rsa1024 = fixture::key_of("RSA-1024");
	CHECK(contains(CHECK_REFUSED(Reason::key_type, pki::check_key_type(rsa1024.get(), true)), "1024"));
	CHECK(pki::check_key_type(fixture::key_of("RSA-4096").get(), true) == pki::KeyKind::rsa);
}

// The encrypted PEM's algorithm: PBES2, scrypt with D4's parameters, AES-256-CBC.
int nid_and_sequence(const X509_ALGOR* algorithm, const ASN1_STRING** sequence) {
	const ASN1_OBJECT* oid = nullptr;
	const void* parameter = nullptr;
	int type = 0;
	X509_ALGOR_get0(&oid, &type, &parameter, algorithm);
	*sequence = type == V_ASN1_SEQUENCE ? static_cast<const ASN1_STRING*>(parameter) : nullptr;
	return OBJ_obj2nid(oid);
}

void encryption_parameters(const pki::Secret& pem) {
	pki::Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
	X509_SIG* sealed = PEM_read_bio_PKCS8(bio.get(), nullptr, nullptr, nullptr);
	CHECK(sealed != nullptr);
	if (sealed == nullptr) { return; }
	const X509_ALGOR* algorithm = nullptr;
	X509_SIG_get0(sealed, &algorithm, nullptr);
	const ASN1_STRING* sequence = nullptr;
	CHECK(nid_and_sequence(algorithm, &sequence) == NID_pbes2);
	auto* pbe2 = sequence ? static_cast<PBE2PARAM*>(ASN1_item_unpack(sequence, ASN1_ITEM_rptr(PBE2PARAM))) : nullptr;
	CHECK(pbe2 != nullptr);
	if (pbe2 != nullptr) {
		const ASN1_STRING* ignored = nullptr;
		CHECK(nid_and_sequence(pbe2->encryption, &ignored) == NID_aes_256_cbc);
		const ASN1_STRING* kdf = nullptr;
		CHECK(nid_and_sequence(pbe2->keyfunc, &kdf) == NID_id_scrypt);
		auto* scrypt = kdf ? static_cast<SCRYPT_PARAMS*>(ASN1_item_unpack(kdf, ASN1_ITEM_rptr(SCRYPT_PARAMS))) : nullptr;
		CHECK(scrypt != nullptr);
		if (scrypt != nullptr) {
			std::uint64_t n = 0, r = 0, p = 0;
			ASN1_INTEGER_get_uint64(&n, scrypt->costParameter);
			ASN1_INTEGER_get_uint64(&r, scrypt->blockSize);
			ASN1_INTEGER_get_uint64(&p, scrypt->parallelizationParameter);
			CHECK(n == 16384);
			CHECK(r == 8);
			CHECK(p == 1);
			CHECK(ASN1_STRING_length(scrypt->salt) == 16);
			SCRYPT_PARAMS_free(scrypt);
		}
		PBE2PARAM_free(pbe2);
	}
	X509_SIG_free(sealed);
}

void encrypted_keys() {
	auto key = pki::generate_key();
	auto passphrase = secret_of("correct horse battery staple");
	auto pem = pki::encrypt_private_key(key.get(), passphrase);
	CHECK(pem.view().starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
	CHECK(!contains(pem.view(), "BEGIN PRIVATE KEY"));
	encryption_parameters(pem);

	auto loaded = pki::load_private_key(pem, &passphrase, "ca.pem");
	CHECK(EVP_PKEY_eq(loaded.get(), key.get()) == 1);

	auto wrong = secret_of("correct horse battery stapler");
	CHECK(contains(CHECK_REFUSED(Reason::passphrase_wrong, pki::load_private_key(pem, &wrong, "ca.pem")), "does not open ca.pem"));
	CHECK(contains(CHECK_REFUSED(Reason::passphrase_wrong, pki::load_private_key(pem, nullptr, "ca.pem")), "no passphrase"));

	auto plain = pki::plain_private_key(key.get());
	CHECK(plain.view().starts_with("-----BEGIN PRIVATE KEY-----\n"));
	CHECK(EVP_PKEY_eq(pki::load_private_key(plain, nullptr, "node.key").get(), key.get()) == 1);
	CHECK(EVP_PKEY_eq(pki::load_private_key(plain, &passphrase, "node.key").get(), key.get()) == 1);

	CHECK_REFUSED(Reason::key_unreadable, pki::load_private_key(secret_of("not a key\n"), nullptr, "junk.pem"));
	auto certificate_only = secret_of(fixture::pem_of(fixture::make_ca(key.get(), 0, 1).get()));
	CHECK_REFUSED(Reason::key_unreadable, pki::load_private_key(certificate_only, nullptr, "ca.crt"));
	CHECK_REFUSED(Reason::passphrase_invalid, pki::encrypt_private_key(key.get(), secret_of("")));

	// The longest passphrase OpenSSL's readers take round-trips.
	auto longest = secret_of(std::string(1023, 'q'));
	auto sealed = pki::encrypt_private_key(key.get(), longest);
	CHECK(EVP_PKEY_eq(pki::load_private_key(sealed, &longest, "ca.pem").get(), key.get()) == 1);
}

// `openssl pkcs8` reads the CA key, so recovery needs no pki binary (D4).
void openssl_reads_it(const std::string& base) {
	auto key = pki::generate_key();
	std::string out;
	fixture::shell(fixture::openssl() + " version", &out);
	std::cout << "openssl CLI: " << out;

	for (std::size_t length : {std::size_t{28}, std::size_t{1023}}) {
		auto passphrase = secret_of(std::string(length, 'w'));
		auto pem = pki::encrypt_private_key(key.get(), passphrase);
		std::string key_file = base + "/ca-key.pem";
		std::string pass_file = base + "/ca-passphrase";
		std::string decrypted = base + "/ca-key-plain.pem";
		fixture::write_file(key_file, pem.view(), 0600);
		fixture::write_file(pass_file, std::string(passphrase.view()) + "\n", 0600);
		::unlink(decrypted.c_str());
		CHECK(fixture::shell(fixture::openssl() + " pkcs8 -in '" + key_file + "' -passin 'file:" + pass_file + "' -out '" + decrypted + "'") == 0);
		std::string public_pem;
		CHECK(fixture::shell(fixture::openssl() + " pkey -in '" + decrypted + "' -pubout", &public_pem) == 0);
		CHECK(public_pem == fixture::pem_of_public_key(key.get()));
		fixture::write_file(pass_file, std::string(length, 'x') + "\n", 0600);
		CHECK(fixture::shell(fixture::openssl() + " pkcs8 -in '" + key_file + "' -passin 'file:" + pass_file + "' -out /dev/null 2>/dev/null") != 0);
	}
}

// The key file through the authority directory's checks, then OSSL_STORE (D3 with D4).
void through_the_directory(const std::string& base) {
	std::string dir = base + "/authority";
	pki::make_directory(dir);
	auto authority = pki::Directory::open(dir);
	auto key = pki::generate_key();
	auto passphrase = secret_of("correct horse battery staple");
	auto pem = pki::encrypt_private_key(key.get(), passphrase);
	authority.create("key-1.pem", pem.bytes(), 0600);
	auto read = authority.read("key-1.pem", private_file::Policy::secret, pki::key_file_max_bytes);
	CHECK(EVP_PKEY_eq(pki::load_private_key(read, &passphrase, dir + "/key-1.pem").get(), key.get()) == 1);
}

void derivation() {
	double seconds = pki::derivation_seconds();
	std::cout << "one scrypt derivation (N = 2^14, r = 8, p = 1): " << seconds << " s\n";
	CHECK(seconds > 0);
}

}  // namespace

int main() {
	std::string base = fixture::scratch("key");
	key_types();
	encrypted_keys();
	openssl_reads_it(base);
	through_the_directory(base);
	derivation();
	return fixture::finish("pki_key");
}
