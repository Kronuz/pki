// The private-file check, written once (SYS-15): a regular file, not a symlink, with one
// link, owned by the caller, under a mode policy. Dependency-free POSIX, so it can move.
#pragma once

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace private_file {

enum class Policy {
	secret,     // CA keys and passphrase files: no bit outside 0600 (SR14)
	key,        // node keys: no bit outside 0640, group read only for the caller's own group (SYS-13)
	integrity,  // completion's journal rule: no group or world write
};

enum class Fault { none, open, symlink, not_regular, links, owner, mode, group };

struct Status {
	Fault fault = Fault::none;
	int error = 0;    // errno, for Fault::open
	mode_t mode = 0;  // the file's permission bits
	explicit operator bool() const noexcept { return fault == Fault::none; }
};

inline Status check(const struct stat& st, Policy policy) noexcept {
	Status status;
	status.mode = st.st_mode & 07777;
	if (S_ISLNK(st.st_mode)) { status.fault = Fault::symlink; return status; }
	if (!S_ISREG(st.st_mode)) { status.fault = Fault::not_regular; return status; }
	if (st.st_nlink != 1) { status.fault = Fault::links; return status; }
	if (st.st_uid != ::geteuid()) { status.fault = Fault::owner; return status; }
	switch (policy) {
		case Policy::secret:
			if (status.mode & ~mode_t{0600}) { status.fault = Fault::mode; }
			break;
		case Policy::key:
			if (status.mode & ~mode_t{0640}) {
				status.fault = Fault::mode;
			} else if ((status.mode & 0040) && st.st_gid != ::getegid()) {
				status.fault = Fault::group;
			}
			break;
		case Policy::integrity:
			if (status.mode & 0022) { status.fault = Fault::mode; }
			break;
	}
	return status;
}

// Opens NAME under DIRFD (AT_FDCWD for a path) read-only, never through a final symlink
// and never blocking on a FIFO, and checks it. Returns the descriptor, or -1 with STATUS.
inline int open(int dirfd, const char* name, Policy policy, Status& status) noexcept {
	int fd;
	do {
		fd = ::openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
	} while (fd < 0 && errno == EINTR);
	struct stat st{};
	if (fd < 0) {
		int error = errno;
		// O_NOFOLLOW fails with ELOOP on Linux and macOS, EMLINK on FreeBSD.
		if ((error == ELOOP || error == EMLINK) && ::fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode)) {
			status = Status{Fault::symlink, error, static_cast<mode_t>(st.st_mode & 07777)};
		} else {
			status = Status{Fault::open, error, 0};
		}
		return -1;
	}
	if (::fstat(fd, &st) != 0) {
		status = Status{Fault::open, errno, 0};
		::close(fd);
		return -1;
	}
	status = check(st, policy);
	if (!status) {
		::close(fd);
		return -1;
	}
	int flags = ::fcntl(fd, F_GETFL);
	if (flags >= 0) { ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK); }
	return fd;
}

}  // namespace private_file
