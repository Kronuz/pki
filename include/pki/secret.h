// Secrets in memory: a fixed buffer, locked where the host allows and wiped on release;
// the process hardening every command applies; and passphrase intake (D3, D4, SR5).
#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace pki {

class Directory;

class Secret {
public:
	explicit Secret(std::size_t capacity);
	~Secret();
	Secret(Secret&& other) noexcept;
	Secret& operator=(Secret&& other) noexcept;
	Secret(const Secret&) = delete;
	Secret& operator=(const Secret&) = delete;

	unsigned char* data() noexcept { return data_.get(); }
	const unsigned char* data() const noexcept { return data_.get(); }
	const char* chars() const noexcept { return reinterpret_cast<const char*>(data_.get()); }
	std::size_t size() const noexcept { return size_; }
	std::size_t capacity() const noexcept { return capacity_; }
	bool locked() const noexcept { return locked_; }
	std::string_view view() const noexcept { return {chars(), size_}; }
	std::span<const unsigned char> bytes() const noexcept { return {data_.get(), size_}; }

	void resize(std::size_t size);  // within capacity; wipes what it drops
	void append(const void* bytes, std::size_t size);

private:
	void release() noexcept;

	std::unique_ptr<unsigned char[]> data_;
	std::size_t capacity_ = 0;
	std::size_t size_ = 0;
	bool locked_ = false;
};

// No core dumps (RLIMIT_CORE 0) and, on Linux, not dumpable. Every command calls it first.
void harden_process() noexcept;

// D4: a passphrase of at least 12 characters (UTF-8 code points), and at most 1,023
// bytes, the most OpenSSL's PEM callback buffer (PEM_BUFSIZE) and `openssl pkcs8
// -passin file:` (APP_PASS_LEN) take, so recovery needs no pki binary.
inline constexpr std::size_t passphrase_min_characters = 12;
inline constexpr std::size_t passphrase_max_bytes = 1023;

// Refuses an empty passphrase, one holding a NUL, or one over the byte cap.
void check_passphrase(const Secret& passphrase);
// check_passphrase, and the 12-character minimum, for a new passphrase.
void check_new_passphrase(const Secret& passphrase);

// Reads a --passphrase-file: checked under the secret policy (0600, SR14), refused inside
// AUTHORITY (SR5), and one trailing LF or CRLF dropped.
Secret read_passphrase_file(const std::string& path, const Directory* authority);

// Reads a passphrase from the controlling terminal with echo off; CONFIRM asks twice.
Secret read_passphrase_terminal(std::string_view prompt, bool confirm);

}  // namespace pki
