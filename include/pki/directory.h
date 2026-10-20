// The authority directory's checks (D3; SR7, PKI-R12, PKI-R22): DIR is opened once and
// every file is reached through openat on it; files are written exclusively, at their
// mode whatever the umask, and synced with io::full_fsync, the directory after the file.
#pragma once

#include <sys/types.h>

#include <cstddef>
#include <span>
#include <string>
#include <utility>

#include "pki/private_file.h"
#include "pki/secret.h"

namespace pki {

class Directory {
public:
	// Opens PATH with O_DIRECTORY | O_NOFOLLOW and refuses it unless it is a directory the
	// caller owns, at mode 0700, on a local POSIX filesystem.
	static Directory open(const std::string& path);

	Directory(Directory&& other) noexcept;
	Directory& operator=(Directory&& other) noexcept;
	Directory(const Directory&) = delete;
	Directory& operator=(const Directory&) = delete;
	~Directory();

	int fd() const noexcept { return fd_; }
	const std::string& path() const noexcept { return path_; }

	// Whether PATH, resolved, is this directory or lies under it.
	bool contains(const std::string& path) const;

	// Reads NAME whole, at most CAP bytes, after the private-file check under POLICY.
	Secret read(const char* name, private_file::Policy policy, std::size_t cap) const;

	// Creates NAME with O_CREAT | O_EXCL | O_NOFOLLOW, sets MODE whatever the umask, writes
	// BYTES, and syncs the file, then the directory entry. Never replaces a file.
	void create(const char* name, std::span<const unsigned char> bytes, mode_t mode) const;

private:
	Directory(int fd, std::string path, dev_t dev, ino_t ino) : fd_(fd), path_(std::move(path)), dev_(dev), ino_(ino) {}

	int fd_ = -1;
	std::string path_;
	dev_t dev_ = 0;
	ino_t ino_ = 0;
};

// Creates PATH at mode 0700 whatever the umask; refuses one that exists.
void make_directory(const std::string& path);

// Refuses FD's filesystem unless it is local and keeps POSIX modes: MNT_LOCAL on macOS and
// FreeBSD, with FAT and exFAT refused; an allowlist of types on Linux. PATH names it.
void check_local_filesystem(int fd, const std::string& path);

// Refuses PATH when it, or any directory above it, holds `.xapiand/node`, Xapiand's
// data-root marker, so no node backup carries the authority (D3's placement).
void check_outside_xapiand_root(const std::string& path);

// Reads a file outside DIR (a node key, a passphrase file) whole, at most CAP bytes,
// after the private-file check under POLICY.
Secret read_private_file(const std::string& path, private_file::Policy policy, std::size_t cap);

// The private-file check's fault as a refusal naming PATH.
[[noreturn]] void refuse_file(const std::string& path, const private_file::Status& status, private_file::Policy policy);

}  // namespace pki
