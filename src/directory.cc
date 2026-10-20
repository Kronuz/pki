#include "pki/directory.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/vfs.h>
#else
#include <sys/mount.h>
#endif

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "io.hh"
#include "pki/refusal.h"

namespace pki {

namespace {

std::string octal(mode_t mode) {
	char buffer[8];
	std::snprintf(buffer, sizeof buffer, "%04o", static_cast<unsigned>(mode & 07777));
	return buffer;
}

std::string error_text(int error) { return std::strerror(error); }

void close_fd(int fd) noexcept {
	if (fd >= 0) { ::close(fd); }
}

// Reads FD whole into a Secret of CAP bytes; refuses a longer file.
Secret read_whole(int fd, std::size_t cap, const std::string& path) {
	Secret secret(cap);
	while (secret.size() < cap) {
		ssize_t n = io::read(fd, secret.data() + secret.size(), cap - secret.size());
		if (n < 0) {
			int error = errno;
			close_fd(fd);
			throw Refusal(Reason::io, "cannot read " + path + ": " + error_text(error));
		}
		if (n == 0) { break; }
		secret.resize(secret.size() + static_cast<std::size_t>(n));
	}
	if (secret.size() == cap) {
		unsigned char extra;
		ssize_t n = io::read(fd, &extra, 1);
		if (n > 0) {
			close_fd(fd);
			throw Refusal(Reason::file_too_large, path + " is over " + std::to_string(cap) + " bytes");
		}
	}
	close_fd(fd);
	return secret;
}

// The directory PATH resolves to, or the nearest existing directory above it.
std::string resolve_existing(const std::string& path) {
	std::string current = path.empty() ? std::string(".") : path;
	while (true) {
		char resolved[PATH_MAX];
		if (::realpath(current.c_str(), resolved) != nullptr) { return resolved; }
		auto slash = current.find_last_of('/');
		if (slash == std::string::npos) {
			current = ".";
		} else if (slash == 0) {
			current = "/";
		} else {
			current.resize(slash);
		}
	}
}

std::string parent_of(const std::string& path) {
	auto slash = path.find_last_of('/');
	if (slash == std::string::npos || slash == 0) { return "/"; }
	return path.substr(0, slash);
}

}  // namespace

void refuse_file(const std::string& path, const private_file::Status& status, private_file::Policy policy) {
	using private_file::Fault;
	using private_file::Policy;
	switch (status.fault) {
		case Fault::none:
			break;
		case Fault::open:
			throw Refusal(Reason::file_open, "cannot open " + path + ": " + error_text(status.error));
		case Fault::symlink:
			throw Refusal(Reason::file_symlink, path + " is a symlink; pki reads a key file only directly");
		case Fault::not_regular:
			throw Refusal(Reason::file_not_regular, path + " is not a regular file");
		case Fault::links:
			throw Refusal(Reason::file_links, path + " has more than one link");
		case Fault::owner:
			throw Refusal(Reason::file_owner, path + " is owned by another user");
		case Fault::mode: {
			const char* rule = policy == Policy::secret ? "a CA key or passphrase file must have no mode bit outside 0600"
				: policy == Policy::key ? "a key file must have no mode bit outside 0640"
				: "the file must not be group- or world-writable";
			throw Refusal(Reason::file_mode, path + " has mode " + octal(status.mode) + "; " + rule);
		}
		case Fault::group:
			throw Refusal(Reason::file_group, path + " has mode " + octal(status.mode) +
				" with a group other than the caller's own; group read is allowed only for the caller's own group");
	}
	throw Refusal(Reason::io, "refuse_file called without a fault for " + path);
}

Directory Directory::open(const std::string& path) {
	int fd = io::RetryAfterSignal(::open, path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		int error = errno;
		struct stat st{};
		if (::lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
			throw Refusal(Reason::dir_symlink, "the authority directory " + path + " is a symlink; name the directory itself");
		}
		if (error == ENOTDIR) {
			throw Refusal(Reason::dir_not_directory, path + " is not a directory");
		}
		throw Refusal(Reason::file_open, "cannot open the authority directory " + path + ": " + error_text(error));
	}
	struct stat st{};
	if (io::fstat(fd, &st) != 0) {
		int error = errno;
		close_fd(fd);
		throw Refusal(Reason::io, "cannot stat " + path + ": " + error_text(error));
	}
	if (!S_ISDIR(st.st_mode)) {
		close_fd(fd);
		throw Refusal(Reason::dir_not_directory, path + " is not a directory");
	}
	if (st.st_uid != ::geteuid()) {
		close_fd(fd);
		throw Refusal(Reason::dir_owner, "the authority directory " + path + " is owned by another user; whoever writes it owns the authority");
	}
	if ((st.st_mode & 07777) != 0700) {
		close_fd(fd);
		throw Refusal(Reason::dir_mode, "the authority directory " + path + " has mode " + octal(st.st_mode) + "; it must be 0700");
	}
	try {
		check_local_filesystem(fd, path);
	} catch (...) {
		close_fd(fd);
		throw;
	}
	return Directory(fd, path, st.st_dev, st.st_ino);
}

Directory::Directory(Directory&& other) noexcept
	: fd_(other.fd_), path_(std::move(other.path_)), dev_(other.dev_), ino_(other.ino_) {
	other.fd_ = -1;
}

Directory& Directory::operator=(Directory&& other) noexcept {
	if (this != &other) {
		close_fd(fd_);
		fd_ = other.fd_;
		path_ = std::move(other.path_);
		dev_ = other.dev_;
		ino_ = other.ino_;
		other.fd_ = -1;
	}
	return *this;
}

Directory::~Directory() { close_fd(fd_); }

bool Directory::contains(const std::string& path) const {
	std::string current = resolve_existing(path);
	while (true) {
		struct stat st{};
		if (::stat(current.c_str(), &st) == 0 && st.st_dev == dev_ && st.st_ino == ino_) { return true; }
		if (current == "/") { return false; }
		current = parent_of(current);
	}
}

Secret Directory::read(const char* name, private_file::Policy policy, std::size_t cap) const {
	private_file::Status status;
	int fd = private_file::open(fd_, name, policy, status);
	std::string shown = path_ + "/" + name;
	if (fd < 0) { refuse_file(shown, status, policy); }
	return read_whole(fd, cap, shown);
}

#ifdef PKI_TEST_HOOKS
namespace testing {
// Runs before each sync create issues; a nonzero return (errno set) is that sync's failure.
int (*sync_hook)(int fd) = nullptr;
}  // namespace testing
#endif

namespace {

int sync_fd(int fd) {
#ifdef PKI_TEST_HOOKS
	if (testing::sync_hook != nullptr && testing::sync_hook(fd) != 0) { return -1; }
#endif
	return io::full_fsync(fd);
}

}  // namespace

void Directory::create(const char* name, std::span<const unsigned char> bytes, mode_t mode) const {
	std::string shown = path_ + "/" + name;
	int fd = io::RetryAfterSignal(::openat, fd_, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		int error = errno;
		if (error == EEXIST) {
			throw Refusal(Reason::file_exists, shown + " exists; pki never writes over a file");
		}
		throw Refusal(Reason::io, "cannot create " + shown + ": " + error_text(error));
	}
	auto fail = [&](const char* what) {
		int error = errno;
		close_fd(fd);
		::unlinkat(fd_, name, 0);
		throw Refusal(Reason::io, std::string("cannot ") + what + " " + shown + ": " + error_text(error));
	};
	if (io::RetryAfterSignal(::fchmod, fd, mode) != 0) { fail("set the mode of"); }
	if (!bytes.empty() && io::write(fd, bytes.data(), bytes.size()) != static_cast<ssize_t>(bytes.size())) { fail("write"); }
	if (sync_fd(fd) != 0) { fail("sync"); }
	close_fd(fd);
	// The new entry is durable only once the directory is: a full sync of its descriptor.
	if (sync_fd(fd_) != 0) {
		int error = errno;
		::unlinkat(fd_, name, 0);
		throw Refusal(Reason::io, "cannot sync the directory of " + shown + ": " + error_text(error));
	}
}

void make_directory(const std::string& path) {
	// The umask can only clear bits; 077 keeps 0700 whole, and the commands are single-threaded.
	mode_t saved = ::umask(077);
	int made = io::RetryAfterSignal(::mkdir, path.c_str(), static_cast<mode_t>(0700));
	int error = errno;
	::umask(saved);
	if (made != 0) {
		if (error == EEXIST) {
			throw Refusal(Reason::file_exists, path + " exists; pki makes a new directory");
		}
		throw Refusal(Reason::io, "cannot make " + path + ": " + error_text(error));
	}
	int fd = io::RetryAfterSignal(::open, path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 || io::RetryAfterSignal(::fchmod, fd, static_cast<mode_t>(0700)) != 0) {
		int error = errno;
		close_fd(fd);
		throw Refusal(Reason::io, "cannot set the mode of " + path + ": " + error_text(error));
	}
	close_fd(fd);
}

namespace {

#if defined(__linux__)
struct FilesystemType {
	std::uint32_t magic;
	const char* name;
	bool allowed;
};

// Local filesystems that keep POSIX modes are allowed; the rest are named when refused.
constexpr FilesystemType linux_filesystems[] = {
	{0xEF53, "ext2/ext3/ext4", true},
	{0x58465342, "xfs", true},
	{0x9123683E, "btrfs", true},
	{0x2FC12FC1, "zfs", true},
	{0xF2F52010, "f2fs", true},
	{0x01021994, "tmpfs", false},
	{0x858458F6, "ramfs", false},
	{0x6969, "nfs", false},
	{0x65735546, "fuse", false},
	{0x794C7630, "overlayfs", false},
	{0xFF534D42, "cifs", false},
	{0xFE534D42, "smb2", false},
	{0x517B, "smb", false},
	{0x01021997, "9p", false},
	{0x00C36400, "ceph", false},
	{0x4D44, "vfat", false},
	{0x2011BAB0, "exfat", false},
	{0x5346544E, "ntfs", false},
	{0xF15F, "ecryptfs", false},
};
#endif

}  // namespace

void check_local_filesystem(int fd, const std::string& path) {
	struct statfs sfs{};
	if (::fstatfs(fd, &sfs) != 0) {
		throw Refusal(Reason::io, "cannot read the filesystem of " + path + ": " + error_text(errno));
	}
#if defined(__linux__)
	auto magic = static_cast<std::uint32_t>(sfs.f_type);
	for (const auto& type : linux_filesystems) {
		if (type.magic == magic) {
			if (type.allowed) { return; }
			throw Refusal(Reason::dir_filesystem, path + " is on " + type.name +
				"; the authority needs a local filesystem with POSIX modes (ext4, xfs, btrfs, zfs, or f2fs)");
		}
	}
	char hex[16];
	std::snprintf(hex, sizeof hex, "0x%X", static_cast<unsigned>(magic));
	throw Refusal(Reason::dir_filesystem, path + " is on a filesystem of type " + hex +
		"; the authority needs a local filesystem with POSIX modes (ext4, xfs, btrfs, zfs, or f2fs)");
#else
	std::string type = sfs.f_fstypename;
	if (!(sfs.f_flags & MNT_LOCAL)) {
		throw Refusal(Reason::dir_filesystem, path + " is on " + type +
			", which is not local; flock is not reliable across network clients");
	}
	if (type == "msdos" || type == "msdosfs" || type == "exfat") {
		throw Refusal(Reason::dir_filesystem, path + " is on " + type + ", which keeps no POSIX modes");
	}
#endif
}

void check_outside_xapiand_root(const std::string& path) {
	std::string current = resolve_existing(path);
	while (true) {
		std::string marker = (current == "/" ? std::string() : current) + "/.xapiand/node";
		struct stat st{};
		if (::lstat(marker.c_str(), &st) == 0) {
			throw Refusal(Reason::dir_xapiand_root, path + " is under the Xapiand data root " + current +
				"; every backup of that node would carry the authority");
		}
		if (current == "/") { return; }
		current = parent_of(current);
	}
}

Secret read_private_file(const std::string& path, private_file::Policy policy, std::size_t cap) {
	private_file::Status status;
	int fd = private_file::open(AT_FDCWD, path.c_str(), policy, status);
	if (fd < 0) { refuse_file(path, status, policy); }
	return read_whole(fd, cap, path);
}

}  // namespace pki
