// D3's checks: the private-file policies (SYS-13, SR14), the authority directory (SR7),
// the filesystem (PKI-R22), placement, passphrase files (SR5), and modes under any umask
// (T4's file cases, T8's mode cases).
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "fixture.h"
#include "pki/directory.h"
#include "pki/secret.h"

using fixture::contains;
using pki::Reason;
using private_file::Policy;

namespace {

mode_t mode_of(const std::string& path) {
	struct stat st{};
	::lstat(path.c_str(), &st);
	return st.st_mode & 07777;
}

void read_as(const std::string& path, Policy policy) { pki::read_private_file(path, policy, 4096); }

void policies(const std::string& dir) {
	std::string file = dir + "/key.pem";

	// secret: CA keys and passphrase files, 0600 only (SR14).
	fixture::write_file(file, "k", 0600);
	CHECK_ACCEPTED(read_as(file, Policy::secret));
	fixture::write_file(file, "k", 0400);
	CHECK_ACCEPTED(read_as(file, Policy::secret));
	fixture::write_file(file, "k", 0640);
	CHECK(contains(CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::secret)), "0640"));
	fixture::write_file(file, "k", 0644);
	CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::secret));
	fixture::write_file(file, "k", 0660);
	CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::secret));

	// key: node keys, 0640 only with the caller's own group (SYS-13). BSDs give a new file
	// its directory's group, so the own-group cases set the effective group first.
	fixture::write_file(file, "k", 0640);
	CHECK(::chown(file.c_str(), static_cast<uid_t>(-1), ::getegid()) == 0);
	CHECK_ACCEPTED(read_as(file, Policy::key));
	fixture::write_file(file, "k", 0440);
	CHECK(::chown(file.c_str(), static_cast<uid_t>(-1), ::getegid()) == 0);
	CHECK_ACCEPTED(read_as(file, Policy::key));
	fixture::write_file(file, "k", 0600);
	CHECK_ACCEPTED(read_as(file, Policy::key));
	fixture::write_file(file, "k", 0644);
	CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::key));
	fixture::write_file(file, "k", 0660);
	CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::key));
	fixture::write_file(file, "k", 04600);
	CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::key));
	if (gid_t other = fixture::other_group(); other != static_cast<gid_t>(-1)) {
		fixture::write_file(file, "k", 0600);
		CHECK(::chown(file.c_str(), static_cast<uid_t>(-1), other) == 0);
		CHECK_ACCEPTED(read_as(file, Policy::key));  // no group bit: the group does not matter
		::chmod(file.c_str(), 0640);
		CHECK_REFUSED(Reason::file_group, read_as(file, Policy::key));
		CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::secret));
		::chmod(file.c_str(), 0440);
		CHECK_REFUSED(Reason::file_group, read_as(file, Policy::key));
	} else {
		std::cout << "skipped: the group cases need a supplementary group\n";
	}

	// integrity: completion's journal rule.
	fixture::write_file(file, "k", 0644);
	CHECK_ACCEPTED(read_as(file, Policy::integrity));
	fixture::write_file(file, "k", 0664);
	CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::integrity));
	fixture::write_file(file, "k", 0602);
	CHECK_REFUSED(Reason::file_mode, read_as(file, Policy::integrity));

	// A symlink, beside its target.
	fixture::write_file(file, "k", 0600);
	std::string link = dir + "/link.pem";
	::unlink(link.c_str());
	CHECK(::symlink(file.c_str(), link.c_str()) == 0);
	CHECK_ACCEPTED(read_as(file, Policy::secret));
	CHECK_REFUSED(Reason::file_symlink, read_as(link, Policy::secret));
	CHECK_REFUSED(Reason::file_symlink, read_as(link, Policy::key));

	// Two links, then one.
	std::string hard = dir + "/hard.pem";
	::unlink(hard.c_str());
	CHECK(::link(file.c_str(), hard.c_str()) == 0);
	CHECK_REFUSED(Reason::file_links, read_as(file, Policy::secret));
	::unlink(hard.c_str());
	CHECK_ACCEPTED(read_as(file, Policy::secret));

	// A FIFO is refused without blocking; so is a directory.
	std::string fifo = dir + "/fifo.pem";
	::unlink(fifo.c_str());
	CHECK(::mkfifo(fifo.c_str(), 0600) == 0);
	CHECK_REFUSED(Reason::file_not_regular, read_as(fifo, Policy::secret));
	CHECK_REFUSED(Reason::file_not_regular, read_as(dir, Policy::secret));
	CHECK_REFUSED(Reason::file_open, read_as(dir + "/missing.pem", Policy::secret));

	// The cap.
	fixture::write_file(file, std::string(4097, 'k'), 0600);
	CHECK_REFUSED(Reason::file_too_large, read_as(file, Policy::secret));
	fixture::write_file(file, std::string(4096, 'k'), 0600);
	CHECK_ACCEPTED(read_as(file, Policy::secret));
}

void authority_directory(const std::string& base) {
	std::string dir = base + "/authority";
	pki::make_directory(dir);
	CHECK(mode_of(dir) == 0700);
	CHECK_ACCEPTED(pki::Directory::open(dir));
	CHECK_REFUSED(Reason::file_exists, pki::make_directory(dir));

	::chmod(dir.c_str(), 0750);
	CHECK(contains(CHECK_REFUSED(Reason::dir_mode, pki::Directory::open(dir)), "0750"));
	::chmod(dir.c_str(), 0770);
	CHECK_REFUSED(Reason::dir_mode, pki::Directory::open(dir));
	::chmod(dir.c_str(), 0500);
	CHECK_REFUSED(Reason::dir_mode, pki::Directory::open(dir));
	::chmod(dir.c_str(), 0700);
	CHECK_ACCEPTED(pki::Directory::open(dir));

	std::string link = base + "/authority-link";
	::unlink(link.c_str());
	CHECK(::symlink(dir.c_str(), link.c_str()) == 0);
	CHECK_REFUSED(Reason::dir_symlink, pki::Directory::open(link));
	std::string file = base + "/not-a-directory";
	fixture::write_file(file, "", 0600);
	CHECK_REFUSED(Reason::dir_not_directory, pki::Directory::open(file));
	CHECK_REFUSED(Reason::file_open, pki::Directory::open(base + "/missing"));

	// Files through openat on the directory.
	auto authority = pki::Directory::open(dir);
	fixture::write_file(dir + "/key.pem", "k", 0600);
	CHECK(authority.read("key.pem", Policy::secret, 16).view() == "k");
	::chmod((dir + "/key.pem").c_str(), 0640);
	CHECK_REFUSED(Reason::file_mode, authority.read("key.pem", Policy::secret, 16));
	::unlink((dir + "/inner-link").c_str());
	CHECK(::symlink("key.pem", (dir + "/inner-link").c_str()) == 0);
	CHECK_REFUSED(Reason::file_symlink, authority.read("inner-link", Policy::secret, 16));
}

void filesystem(const std::string& base) {
	int fd = ::open(base.c_str(), O_RDONLY | O_DIRECTORY);
	CHECK_ACCEPTED(pki::check_local_filesystem(fd, base));
	::close(fd);
#ifdef __linux__
	fd = ::open("/dev/shm", O_RDONLY | O_DIRECTORY);
	if (fd >= 0) {
		CHECK(contains(CHECK_REFUSED(Reason::dir_filesystem, pki::check_local_filesystem(fd, "/dev/shm")), "tmpfs"));
		::close(fd);
	}
	fd = ::open("/proc", O_RDONLY | O_DIRECTORY);
	if (fd >= 0) {
		CHECK(contains(CHECK_REFUSED(Reason::dir_filesystem, pki::check_local_filesystem(fd, "/proc")), "0x9FA0"));
		::close(fd);
	}
#endif
}

void placement(const std::string& base) {
	std::string root = base + "/data";
	::mkdir(root.c_str(), 0700);
	::mkdir((root + "/.xapiand").c_str(), 0700);
	fixture::write_file(root + "/.xapiand/node", "node1", 0600);
	CHECK(contains(CHECK_REFUSED(Reason::dir_xapiand_root, pki::check_outside_xapiand_root(root + "/authority")), root));
	CHECK_REFUSED(Reason::dir_xapiand_root, pki::check_outside_xapiand_root(root));
	CHECK_REFUSED(Reason::dir_xapiand_root, pki::check_outside_xapiand_root(root + "/a/b/c/authority"));
	std::string beside = base + "/data2";
	::mkdir(beside.c_str(), 0700);
	CHECK_ACCEPTED(pki::check_outside_xapiand_root(beside + "/authority"));
	CHECK_ACCEPTED(pki::check_outside_xapiand_root(beside));
}

void passphrase_files(const std::string& base) {
	std::string dir = base + "/authority2";
	pki::make_directory(dir);
	auto authority = pki::Directory::open(dir);

	std::string inside = dir + "/passphrase";
	fixture::write_file(inside, "correct horse battery\n", 0600);
	CHECK_REFUSED(Reason::passphrase_inside, pki::read_passphrase_file(inside, &authority));
	::mkdir((dir + "/sub").c_str(), 0700);
	fixture::write_file(dir + "/sub/passphrase", "correct horse battery\n", 0600);
	CHECK_REFUSED(Reason::passphrase_inside, pki::read_passphrase_file(dir + "/sub/passphrase", &authority));
	std::string outside = base + "/passphrase";
	fixture::write_file(outside, "correct horse battery\n", 0600);
	CHECK(pki::read_passphrase_file(outside, &authority).view() == "correct horse battery");
	std::string sneaky = base + "/sneaky";
	::unlink(sneaky.c_str());
	CHECK(::symlink(inside.c_str(), sneaky.c_str()) == 0);
	CHECK_REFUSED(Reason::passphrase_inside, pki::read_passphrase_file(sneaky, &authority));

	fixture::write_file(outside, "correct horse battery\r\n", 0600);
	CHECK(pki::read_passphrase_file(outside, nullptr).view() == "correct horse battery");
	fixture::write_file(outside, "correct horse battery", 0600);
	CHECK(pki::read_passphrase_file(outside, nullptr).view() == "correct horse battery");
	fixture::write_file(outside, "correct horse battery\n", 0640);
	CHECK_REFUSED(Reason::file_mode, pki::read_passphrase_file(outside, nullptr));
	fixture::write_file(outside, "\n", 0600);
	CHECK_REFUSED(Reason::passphrase_invalid, pki::read_passphrase_file(outside, nullptr));
	fixture::write_file(outside, std::string("correct\0horse battery", 21), 0600);
	CHECK_REFUSED(Reason::passphrase_invalid, pki::read_passphrase_file(outside, nullptr));
	fixture::write_file(outside, std::string(1023, 'p') + "\r\n", 0600);
	CHECK(pki::read_passphrase_file(outside, nullptr).size() == 1023);
	fixture::write_file(outside, std::string(1024, 'p') + "\n", 0600);
	CHECK_REFUSED(Reason::passphrase_long, pki::read_passphrase_file(outside, nullptr));
	fixture::write_file(outside, std::string(4000, 'p'), 0600);
	CHECK_REFUSED(Reason::passphrase_long, pki::read_passphrase_file(outside, nullptr));
}

void passphrase_strength() {
	auto secret = [](std::string_view text) {
		pki::Secret s(text.size());
		s.append(text.data(), text.size());
		return s;
	};
	CHECK(contains(CHECK_REFUSED(Reason::passphrase_short, pki::check_new_passphrase(secret("elevenchars"))), "11 characters"));
	CHECK_ACCEPTED(pki::check_new_passphrase(secret("twelve chars")));
	std::string enye;
	for (int i = 0; i < 11; ++i) { enye += "\xc3\xb1"; }  // 22 bytes, 11 characters
	CHECK_REFUSED(Reason::passphrase_short, pki::check_new_passphrase(secret(enye)));
	enye += "\xc3\xb1";
	CHECK_ACCEPTED(pki::check_new_passphrase(secret(enye)));
	CHECK_REFUSED(Reason::passphrase_invalid, pki::check_passphrase(secret("")));
}

void modes_under_umask(const std::string& base) {
	for (mode_t mask : {mode_t{0}, mode_t{077}, mode_t{0777}}) {
		mode_t saved = ::umask(mask);
		std::string dir = base + "/umask-" + std::to_string(mask);
		pki::make_directory(dir);
		CHECK(mode_of(dir) == 0700);
		auto authority = pki::Directory::open(dir);
		const unsigned char bytes[] = "certificate";
		authority.create("cert.pem", bytes, 0644);
		authority.create("key.pem", bytes, 0600);
		CHECK(mode_of(dir + "/cert.pem") == 0644);
		CHECK(mode_of(dir + "/key.pem") == 0600);
		CHECK(fixture::read_file(dir + "/cert.pem") == std::string("certificate", sizeof bytes));
		CHECK_REFUSED(Reason::file_exists, authority.create("cert.pem", bytes, 0644));
		CHECK(::symlink("elsewhere", (dir + "/planted").c_str()) == 0);
		CHECK_REFUSED(Reason::file_exists, authority.create("planted", bytes, 0600));
		::umask(saved);
	}
}

void secret_buffer() {
	pki::Secret s(8);
	s.append("abcdefgh", 8);
	CHECK(s.view() == "abcdefgh");
	s.resize(3);
	CHECK(s.view() == "abc");
	CHECK(s.data()[3] == 0);  // what resize drops is wiped
	bool threw = false;
	try {
		s.append("123456", 6);
	} catch (const std::length_error&) {
		threw = true;
	}
	CHECK(threw);
}

// T4's owner cases need root: CI runs this binary under sudo too.
void owner_cases(const std::string& base) {
	if (::geteuid() != 0) {
		std::cout << "skipped: the owner cases run as root (CI runs them under sudo)\n";
		return;
	}
	struct passwd* nobody = ::getpwnam("nobody");
	CHECK(nobody != nullptr);
	if (nobody == nullptr) { return; }
	std::string file = base + "/owned.pem";
	fixture::write_file(file, "k", 0600);
	CHECK_ACCEPTED(read_as(file, Policy::secret));
	CHECK(::chown(file.c_str(), nobody->pw_uid, static_cast<gid_t>(-1)) == 0);
	CHECK_REFUSED(Reason::file_owner, read_as(file, Policy::secret));
	CHECK_REFUSED(Reason::file_owner, read_as(file, Policy::key));
	std::string dir = base + "/owned-authority";
	pki::make_directory(dir);
	CHECK_ACCEPTED(pki::Directory::open(dir));
	CHECK(::chown(dir.c_str(), nobody->pw_uid, static_cast<gid_t>(-1)) == 0);
	CHECK_REFUSED(Reason::dir_owner, pki::Directory::open(dir));
}

}  // namespace

int main() {
	std::string base = fixture::scratch("files");
	policies(base);
	authority_directory(base);
	filesystem(base);
	placement(base);
	passphrase_files(base);
	passphrase_strength();
	modes_under_umask(base);
	secret_buffer();
	owner_cases(base);
	return fixture::finish("pki_files");
}
