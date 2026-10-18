#include "pki/key.h"

#include <chrono>
#include <cstring>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>

#include "pki/refusal.h"

namespace pki {

namespace {

// The NID of an EC key's curve, or NID_undef.
int curve_nid(const EVP_PKEY* key) {
	char name[80];
	std::size_t length = 0;
	if (EVP_PKEY_get_group_name(key, name, sizeof name, &length) != 1) { return NID_undef; }
	int nid = OBJ_sn2nid(name);
	if (nid == NID_undef) { nid = EC_curve_nist2nid(name); }
	return nid;
}

Secret drain(BIO* bio) {
	char* data = nullptr;
	long length = BIO_get_mem_data(bio, &data);
	if (length <= 0 || data == nullptr) { crypto_failure("cannot encode the key"); }
	Secret secret(static_cast<std::size_t>(length));
	secret.append(data, static_cast<std::size_t>(length));
	return secret;
}

struct PassphraseData {
	const Secret* passphrase;
	bool asked;
};

int passphrase_callback(char* buffer, int size, int /*rwflag*/, void* user) {
	auto* data = static_cast<PassphraseData*>(user);
	data->asked = true;
	if (data->passphrase == nullptr || size < 0 || data->passphrase->size() > static_cast<std::size_t>(size)) { return -1; }
	std::memcpy(buffer, data->passphrase->data(), data->passphrase->size());
	return static_cast<int>(data->passphrase->size());
}

}  // namespace

KeyKind check_key_type(const EVP_PKEY* key, bool allow_rsa) {
	if (EVP_PKEY_is_a(key, "EC")) {
		int nid = curve_nid(key);
		if (nid == NID_X9_62_prime256v1) { return KeyKind::p256; }
		if (nid == NID_secp384r1) { return KeyKind::p384; }
		throw Refusal(Reason::key_type, "a " + describe_key(key) + " key is not accepted; pki takes P-256 or P-384, or RSA with --allow-rsa");
	}
	if (EVP_PKEY_is_a(key, "RSA")) {
		int bits = EVP_PKEY_get_bits(key);
		if (!allow_rsa) {
			throw Refusal(Reason::key_type, "an RSA key needs --allow-rsa; an RSA leaf gives no forward secrecy on a context without strict");
		}
		if (bits < 2048 || bits > 4096) {
			throw Refusal(Reason::key_type, "an RSA key of " + std::to_string(bits) + " bits is not accepted; RSA takes 2048 to 4096 bits");
		}
		return KeyKind::rsa;
	}
	throw Refusal(Reason::key_type, "a " + describe_key(key) + " key is not accepted; pki takes P-256 or P-384, or RSA with --allow-rsa");
}

std::string describe_key(const EVP_PKEY* key) {
	if (EVP_PKEY_is_a(key, "EC")) {
		int nid = curve_nid(key);
		if (nid == NID_X9_62_prime256v1) { return "P-256"; }
		if (nid == NID_secp384r1) { return "P-384"; }
		if (nid == NID_secp521r1) { return "P-521"; }
		const char* name = nid == NID_undef ? nullptr : OBJ_nid2sn(nid);
		return std::string("EC ") + (name ? name : "unknown curve");
	}
	if (EVP_PKEY_is_a(key, "RSA")) { return "RSA " + std::to_string(EVP_PKEY_get_bits(key)); }
	const char* name = EVP_PKEY_get0_type_name(key);
	return name ? name : "unknown";
}

Key generate_key() {
	Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
	if (!key) { crypto_failure("cannot generate a P-256 key"); }
	return key;
}

Secret encrypt_private_key(const EVP_PKEY* key, const Secret& passphrase) {
	check_passphrase(passphrase);
	std::unique_ptr<PKCS8_PRIV_KEY_INFO, OpenSSLDeleter<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free>> info(EVP_PKEY2PKCS8(key));
	if (!info) { crypto_failure("cannot encode the key as PKCS#8"); }
	unsigned char salt[16];
	if (RAND_bytes(salt, sizeof salt) != 1) { crypto_failure("cannot draw a salt"); }
	X509_ALGOR* pbe = PKCS5_pbe2_set_scrypt(EVP_aes_256_cbc(), salt, sizeof salt, nullptr, scrypt_n, scrypt_r, scrypt_p);
	if (pbe == nullptr) { crypto_failure("cannot set scrypt's parameters"); }
	std::unique_ptr<X509_SIG, OpenSSLDeleter<X509_SIG, X509_SIG_free>> sealed(
		PKCS8_set0_pbe(passphrase.chars(), static_cast<int>(passphrase.size()), info.get(), pbe));
	if (!sealed) {
		X509_ALGOR_free(pbe);
		crypto_failure("cannot encrypt the key");
	}
	Bio bio(BIO_new(BIO_s_mem()));
	if (!bio || PEM_write_bio_PKCS8(bio.get(), sealed.get()) != 1) { crypto_failure("cannot write the encrypted key"); }
	return drain(bio.get());
}

Secret plain_private_key(const EVP_PKEY* key) {
	Bio bio(BIO_new(BIO_s_secmem()));
	if (!bio || PEM_write_bio_PKCS8PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
		crypto_failure("cannot write the key");
	}
	return drain(bio.get());
}

Key load_private_key(const Secret& pem, const Secret* passphrase, const std::string& shown) {
	ERR_clear_error();
	Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
	std::unique_ptr<UI_METHOD, OpenSSLDeleter<UI_METHOD, UI_destroy_method>> ui(UI_UTIL_wrap_read_pem_callback(passphrase_callback, 0));
	if (!bio || !ui) { crypto_failure("cannot read " + shown); }
	PassphraseData data{passphrase, false};
	OSSL_STORE_CTX* store = OSSL_STORE_attach(bio.get(), "file", nullptr, nullptr, ui.get(), &data, nullptr, nullptr, nullptr);
	if (store == nullptr) { crypto_failure("cannot read " + shown); }
	OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY);
	Key key;
	// A PEM file holds few objects; the bound keeps a misbehaving loader from spinning.
	for (int objects = 0; !key && objects < 64 && !OSSL_STORE_eof(store); ++objects) {
		OSSL_STORE_INFO* info = OSSL_STORE_load(store);
		if (info == nullptr) {
			if (OSSL_STORE_error(store)) { break; }
			continue;
		}
		if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) { key.reset(OSSL_STORE_INFO_get1_PKEY(info)); }
		OSSL_STORE_INFO_free(info);
	}
	OSSL_STORE_close(store);
	ERR_clear_error();
	if (!key) {
		if (data.asked && passphrase != nullptr) {
			throw Refusal(Reason::passphrase_wrong, "the passphrase does not open " + shown);
		}
		if (data.asked) {
			throw Refusal(Reason::passphrase_wrong, shown + " is encrypted, and no passphrase was given");
		}
		throw Refusal(Reason::key_unreadable, "no private key in " + shown);
	}
	return key;
}

double derivation_seconds() {
	static const char probe[] = "pki derivation probe";
	unsigned char salt[16]{};
	unsigned char out[32];
	auto start = std::chrono::steady_clock::now();
	if (EVP_PBE_scrypt(probe, sizeof probe - 1, salt, sizeof salt, scrypt_n, scrypt_r, scrypt_p, 0, out, sizeof out) != 1) {
		crypto_failure("cannot run scrypt");
	}
	std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - start;
	return elapsed.count();
}

}  // namespace pki
