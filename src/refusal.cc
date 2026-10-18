#include "pki/refusal.h"

#include <openssl/err.h>

namespace pki {

std::string_view name(Reason reason) noexcept {
	switch (reason) {
		case Reason::usage: return "usage";
		case Reason::io: return "io";
		case Reason::file_open: return "file-open";
		case Reason::file_symlink: return "file-symlink";
		case Reason::file_not_regular: return "file-not-regular";
		case Reason::file_links: return "file-links";
		case Reason::file_owner: return "file-owner";
		case Reason::file_mode: return "file-mode";
		case Reason::file_group: return "file-group";
		case Reason::file_too_large: return "file-too-large";
		case Reason::file_exists: return "file-exists";
		case Reason::dir_symlink: return "dir-symlink";
		case Reason::dir_not_directory: return "dir-not-directory";
		case Reason::dir_owner: return "dir-owner";
		case Reason::dir_mode: return "dir-mode";
		case Reason::dir_filesystem: return "dir-filesystem";
		case Reason::dir_xapiand_root: return "dir-xapiand-root";
		case Reason::passphrase_inside: return "passphrase-inside";
		case Reason::passphrase_short: return "passphrase-short";
		case Reason::passphrase_long: return "passphrase-long";
		case Reason::passphrase_invalid: return "passphrase-invalid";
		case Reason::passphrase_mismatch: return "passphrase-mismatch";
		case Reason::passphrase_wrong: return "passphrase-wrong";
		case Reason::key_type: return "key-type";
		case Reason::key_unreadable: return "key-unreadable";
		case Reason::pem: return "pem";
		case Reason::duration: return "duration";
		case Reason::crypto: return "crypto";
	}
	return "unknown";
}

void crypto_failure(const std::string& what) {
	std::string message = what;
	char buffer[256];
	while (unsigned long error = ERR_get_error()) {
		ERR_error_string_n(error, buffer, sizeof buffer);
		message += message == what ? ": " : "; ";
		message += buffer;
	}
	throw Refusal(Reason::crypto, message);
}

}  // namespace pki
