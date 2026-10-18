#include "pki/pem.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string_view>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "io.hh"
#include "pki/refusal.h"

namespace pki {

namespace {

struct PemBlock {
	char* name = nullptr;
	char* header = nullptr;
	unsigned char* data = nullptr;
	long length = 0;
	~PemBlock() {
		OPENSSL_free(name);
		OPENSSL_free(header);
		OPENSSL_clear_free(data, length > 0 ? static_cast<std::size_t>(length) : 0);
	}
};

bool is_private_key(std::string_view name) {
	return name == "PRIVATE KEY" || name == "ENCRYPTED PRIVATE KEY" || name.ends_with(" PRIVATE KEY");
}

}  // namespace

std::vector<PublicObject> read_public_objects(const std::string& path) {
	int fd = io::RetryAfterSignal(::open, path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) { throw Refusal(Reason::file_open, "cannot open " + path + ": " + std::strerror(errno)); }
	struct stat st{};
	if (io::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		::close(fd);
		throw Refusal(Reason::file_not_regular, path + " is not a regular file");
	}
	Bio bio(BIO_new_fd(fd, BIO_CLOSE));
	if (!bio) {
		::close(fd);
		crypto_failure("cannot read " + path);
	}
	ERR_clear_error();
	std::vector<PublicObject> objects;
	for (int index = 1;; ++index) {
		PemBlock block;
		if (PEM_read_bio(bio.get(), &block.name, &block.header, &block.data, &block.length) != 1) {
			unsigned long error = ERR_peek_last_error();
			if (ERR_GET_LIB(error) == ERR_LIB_PEM && ERR_GET_REASON(error) == PEM_R_NO_START_LINE) {
				ERR_clear_error();
				break;
			}
			ERR_clear_error();
			throw Refusal(Reason::pem, "PEM object " + std::to_string(index) + " of " + path + " is damaged");
		}
		std::string_view name = block.name;
		if (is_private_key(name)) {
			throw Refusal(Reason::pem, path + " holds a private key; give the certificate, the request, or the public key");
		}
		if (block.length <= 0 || static_cast<std::size_t>(block.length) > pem_object_max_bytes) {
			throw Refusal(Reason::pem, "PEM object " + std::to_string(index) + " of " + path + " is over 64 KiB, reactor::tls's certificate-list cap");
		}
		const unsigned char* cursor = block.data;
		const unsigned char* end = block.data + block.length;
		PublicObject object{};
		if (name == "CERTIFICATE") {
			object.kind = PublicObject::Kind::certificate;
			object.certificate.reset(d2i_X509(nullptr, &cursor, block.length));
			if (!object.certificate) { cursor = nullptr; }
		} else if (name == "CERTIFICATE REQUEST" || name == "NEW CERTIFICATE REQUEST") {
			object.kind = PublicObject::Kind::request;
			object.request.reset(d2i_X509_REQ(nullptr, &cursor, block.length));
			if (object.request) {
				object.key.reset(X509_REQ_get_pubkey(object.request.get()));
				if (!object.key) { cursor = nullptr; }
			} else {
				cursor = nullptr;
			}
		} else if (name == "PUBLIC KEY") {
			object.kind = PublicObject::Kind::public_key;
			object.key.reset(d2i_PUBKEY(nullptr, &cursor, block.length));
			if (!object.key) { cursor = nullptr; }
		} else {
			continue;
		}
		if (cursor != end) {
			ERR_clear_error();
			throw Refusal(Reason::pem, "PEM object " + std::to_string(index) + " of " + path + " (" + std::string(name) + ") does not decode");
		}
		objects.push_back(std::move(object));
	}
	if (objects.empty()) {
		throw Refusal(Reason::pem, path + " holds no certificate, request, or public key");
	}
	return objects;
}

std::vector<Certificate> read_certificates(const std::string& path) {
	std::vector<Certificate> certificates;
	for (auto& object : read_public_objects(path)) {
		if (object.kind == PublicObject::Kind::certificate) { certificates.push_back(std::move(object.certificate)); }
	}
	if (certificates.empty()) { throw Refusal(Reason::pem, path + " holds no certificate"); }
	return certificates;
}

}  // namespace pki
