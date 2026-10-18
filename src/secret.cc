#include "pki/secret.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <cstring>

#include <openssl/crypto.h>

#include "io.hh"
#include "pki/directory.h"
#include "pki/refusal.h"

namespace pki {

Secret::Secret(std::size_t capacity) : data_(new unsigned char[capacity ? capacity : 1]()), capacity_(capacity) {
	locked_ = ::mlock(data_.get(), capacity_ ? capacity_ : 1) == 0;
}

Secret::~Secret() { release(); }

Secret::Secret(Secret&& other) noexcept
	: data_(std::move(other.data_)), capacity_(other.capacity_), size_(other.size_), locked_(other.locked_) {
	other.capacity_ = other.size_ = 0;
	other.locked_ = false;
}

Secret& Secret::operator=(Secret&& other) noexcept {
	if (this != &other) {
		release();
		data_ = std::move(other.data_);
		capacity_ = other.capacity_;
		size_ = other.size_;
		locked_ = other.locked_;
		other.capacity_ = other.size_ = 0;
		other.locked_ = false;
	}
	return *this;
}

void Secret::release() noexcept {
	if (data_) {
		OPENSSL_cleanse(data_.get(), capacity_ ? capacity_ : 1);
		if (locked_) { ::munlock(data_.get(), capacity_ ? capacity_ : 1); }
		data_.reset();
	}
	capacity_ = size_ = 0;
	locked_ = false;
}

void Secret::resize(std::size_t size) {
	if (size > capacity_) { throw std::length_error("pki::Secret over its capacity"); }
	if (size < size_) { OPENSSL_cleanse(data_.get() + size, size_ - size); }
	size_ = size;
}

void Secret::append(const void* bytes, std::size_t size) {
	if (size > capacity_ - size_) { throw std::length_error("pki::Secret over its capacity"); }
	std::memcpy(data_.get() + size_, bytes, size);
	size_ += size;
}

void harden_process() noexcept {
	struct rlimit none{0, 0};
	::setrlimit(RLIMIT_CORE, &none);
#ifdef __linux__
	::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

void check_passphrase(const Secret& passphrase) {
	if (passphrase.size() == 0) {
		throw Refusal(Reason::passphrase_invalid, "the passphrase is empty");
	}
	if (std::memchr(passphrase.data(), '\0', passphrase.size()) != nullptr) {
		throw Refusal(Reason::passphrase_invalid, "the passphrase holds a NUL byte");
	}
	if (passphrase.size() > passphrase_max_bytes) {
		throw Refusal(Reason::passphrase_long, "the passphrase is over 1023 bytes, the most `openssl pkcs8` reads");
	}
}

void check_new_passphrase(const Secret& passphrase) {
	check_passphrase(passphrase);
	std::size_t characters = 0;
	for (unsigned char c : passphrase.bytes()) {
		if ((c & 0xC0) != 0x80) { ++characters; }
	}
	if (characters < passphrase_min_characters) {
		throw Refusal(Reason::passphrase_short, "the passphrase has " + std::to_string(characters) +
			" characters; it needs at least 12, since it carries the CA key's strength");
	}
}

namespace {

void drop_line_end(Secret& secret) {
	auto view = secret.view();
	if (view.ends_with("\r\n")) {
		secret.resize(secret.size() - 2);
	} else if (view.ends_with('\n')) {
		secret.resize(secret.size() - 1);
	}
}

}  // namespace

Secret read_passphrase_file(const std::string& path, const Directory* authority) {
	if (authority != nullptr && authority->contains(path)) {
		throw Refusal(Reason::passphrase_inside, "the passphrase file " + path + " is inside the authority directory " +
			authority->path() + "; keep it apart from the key it opens");
	}
	// Room for the largest passphrase, its line end, and one byte to detect a longer one.
	Secret secret(0);
	try {
		secret = read_private_file(path, private_file::Policy::secret, passphrase_max_bytes + 3);
	} catch (const Refusal& refusal) {
		if (refusal.reason() != Reason::file_too_large) { throw; }
		secret = Secret(passphrase_max_bytes + 3);
		secret.resize(secret.capacity());
	}
	if (secret.size() == secret.capacity()) {
		throw Refusal(Reason::passphrase_long, "the passphrase file " + path + " is over 1023 bytes, the most `openssl pkcs8` reads");
	}
	drop_line_end(secret);
	check_passphrase(secret);
	return secret;
}

namespace {

class Terminal {
public:
	Terminal() {
		fd_ = io::RetryAfterSignal(::open, "/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
		if (fd_ < 0) {
			throw Refusal(Reason::usage, "no terminal to read the passphrase from; pass --passphrase-file");
		}
		if (::tcgetattr(fd_, &saved_) == 0) {
			struct termios quiet = saved_;
			quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
			quiet.c_lflag |= ECHONL;
			restore_ = ::tcsetattr(fd_, TCSAFLUSH, &quiet) == 0;
		}
	}
	~Terminal() {
		if (restore_) { ::tcsetattr(fd_, TCSAFLUSH, &saved_); }
		::close(fd_);
	}
	Terminal(const Terminal&) = delete;
	Terminal& operator=(const Terminal&) = delete;

	Secret line(std::string_view prompt) {
		io::write(fd_, prompt.data(), prompt.size());
		Secret secret(passphrase_max_bytes + 3);
		unsigned char c;
		while (true) {
			ssize_t n = io::RetryAfterSignal(::read, fd_, static_cast<void*>(&c), std::size_t{1});
			if (n <= 0 || c == '\n') { break; }
			if (secret.size() == secret.capacity()) {
				throw Refusal(Reason::passphrase_long, "the passphrase is over 1023 bytes, the most `openssl pkcs8` reads");
			}
			secret.append(&c, 1);
		}
		OPENSSL_cleanse(&c, sizeof c);
		if (secret.view().ends_with('\r')) { secret.resize(secret.size() - 1); }
		return secret;
	}

private:
	int fd_ = -1;
	struct termios saved_{};
	bool restore_ = false;
};

}  // namespace

Secret read_passphrase_terminal(std::string_view prompt, bool confirm) {
	Terminal terminal;
	Secret first = terminal.line(prompt);
	check_passphrase(first);
	if (confirm) {
		Secret second = terminal.line("Again: ");
		if (first.size() != second.size() || CRYPTO_memcmp(first.data(), second.data(), first.size()) != 0) {
			throw Refusal(Reason::passphrase_mismatch, "the two passphrases differ");
		}
	}
	return first;
}

}  // namespace pki
