// pki::Refusal: every check that stops a command throws one, naming its reason.
#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace pki {

enum class Reason {
	usage,               // a command line pki does not take
	io,                  // a system call failed
	file_open,           // a file could not be opened
	file_symlink,        // a file pki reads is a symlink
	file_not_regular,    // not a regular file
	file_links,          // more than one hard link
	file_owner,          // owned by another user
	file_mode,           // a mode bit outside the policy's
	file_group,          // group-readable with a group other than the caller's own
	file_too_large,      // over the cap for its kind
	file_exists,         // an output that already exists
	dir_symlink,         // the authority directory is a symlink
	dir_not_directory,   // the authority directory is not a directory
	dir_owner,           // owned by another user
	dir_mode,            // not mode 0700
	dir_filesystem,      // not a local POSIX filesystem
	dir_xapiand_root,    // at or under a Xapiand data root
	passphrase_inside,   // a passphrase file inside the authority directory
	passphrase_short,    // under 12 characters
	passphrase_long,     // over what OpenSSL's readers take
	passphrase_invalid,  // empty, or holds a NUL
	passphrase_mismatch, // the two entries differ
	passphrase_wrong,    // it does not open the key
	key_type,            // a key type or size D4 does not accept
	key_unreadable,      // no private key in the file
	pem,                 // no PEM object pki reads, or a damaged one
	duration,            // a duration pki does not parse
	identity_cluster,    // a cluster name outside the trust domain's alphabet
	identity_name,       // a node name or voter id outside D5's rules
	crypto,              // an OpenSSL call failed
};

// The reason's stable name, as tests and scripts match it.
std::string_view name(Reason reason) noexcept;

class Refusal : public std::runtime_error {
public:
	Refusal(Reason reason, const std::string& message) : std::runtime_error(message), reason_(reason) {}
	Reason reason() const noexcept { return reason_; }

private:
	Reason reason_;
};

// TEXT in double quotes for a message, every byte outside printable ASCII as \xHH, so a
// refusal never carries a NUL or a terminal escape.
std::string quoted(std::string_view text);

// Throws Reason::crypto with OpenSSL's queued errors appended, and clears the queue.
[[noreturn]] void crypto_failure(const std::string& what);

}  // namespace pki
