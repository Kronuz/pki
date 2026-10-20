# AGENTS.md

Working notes for whoever changes this repository next. Read `ARCHITECTURE.md` for how
it fits together and `README.md` for what it does. pki is crypto and secrets code: every
change lands after a code review and a security review.

## Repo map

```
include/pki/pki.h            pki::run (the command entry point), Consumer, exit statuses
include/pki/refusal.h        pki::Refusal and its Reason; every check throws one
include/pki/private_file.h   The private-file check: dependency-free POSIX, three policies
include/pki/directory.h      The authority directory: open once, openat, create, filesystem, placement
include/pki/secret.h         Secret buffers, process hardening, passphrase intake
include/pki/key.h            Key types, generation, PKCS#8 under scrypt, OSSL_STORE loading
include/pki/fingerprint.h    SPKI and DER SHA-256 digests
include/pki/identity.h       SPIFFE identities: trust domain, node name or voter id, role path
include/pki/expiry.h         Validity, standing, durations, the clock
include/pki/pem.h            Public PEM files: certificates, requests, public keys
include/pki/openssl.h        unique_ptr handles for OpenSSL objects
src/*.cc                     One per header above (command.cc for pki.h)
examples/kronuz_pki.cc       kronuz-pki: the driver and example
test/fixture.{h,cc}          CHECK macros, scratch directories, fixture CAs and leaves, the openssl CLI
test/*_test.cc               files, key, fingerprint, expiry, identity, command
cmake/no_test_hooks.cmake    Fails if the release driver names a test hook
```

## Build and test

```sh
cmake -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"   # the prefix only on macOS
cmake --build build && ctest --test-dir build --output-on-failure
sudo build/pki_files_test                                         # the owner cases, as root
```

Under a host hold (`quiet check`), build at `nice -n 19` with at most 4 jobs, or not at
all under a strict one; CI validates every push. The tests make their scratch directories
under the build tree (`pki-test-*`), which must be on a local filesystem pki accepts: a
Linux build tree on tmpfs fails `pki_files`.

## Invariants

- **No secret before the checks, and none in argv, the environment, or output.** A
  passphrase is read only after every check on the request and the directory, from the
  terminal or a `secret`-policy file. Nothing prints a passphrase or key bytes.
- **Every file inside `DIR` through `openat` on the one descriptor `Directory::open`
  checked.** Never reopen by path.
- **Check the descriptor, not the path.** `private_file::open` opens, then `fstat`s what it
  opened; never `stat` then `open`.
- **pki never writes over a file.** Outputs and keys are `O_CREAT | O_EXCL | O_NOFOLLOW`,
  their mode set with `fchmod` whatever the umask, synced with `io::full_fsync`, then the directory
  likewise, before `create` returns.
- **CA keys and passphrase files are 0600-only** (`Policy::secret`); 0640 with the
  caller's own group is for node keys alone (`Policy::key`).
- **The SPKI digest is over `i2d_X509_PUBKEY`'s DER.** Never `X509_pubkey_digest`.
- **Limits name their mechanism:** the passphrase's 1,023 bytes (OpenSSL's PEM callback
  buffer and `openssl pkcs8`'s), a key file's 16 KiB (the largest accepted key several
  times over), a PEM object's 64 KiB (reactor::tls's certificate-list cap), a duration's
  9999-12-31 (the latest X.509 time).
- **An identity has one byte form.** Lowercase per byte (`chars::tolower`), refuse what
  falls outside the alphabet, never percent-encode, and compare bytes. The lowercasing
  is Xapiand's rule (its node names compare case-blind); do not "correct" the alphabet
  toward SPIFFE's mixed-case paths, which would give one node two identities.
- **Refusals quote what they repeat** (`pki::quoted`): no NUL or terminal escape reaches
  a message.
- **Test hooks never reach a release build.** `PKI_TEST_NOW` is read only under
  `PKI_TEST_HOOKS`, which only `pki_testing` defines.

## Traps

- **macOS's `/usr/bin/openssl` is LibreSSL.** It cannot read scrypt-encrypted PKCS#8, and
  its certificates fail OpenSSL 3's strict checks. CMake finds the `openssl` beside the
  linked library for the tests.
- **`O_NOFOLLOW` on a symlink fails with `ELOOP` on Linux and macOS, `EMLINK` on FreeBSD.**
  `private_file::open` confirms a symlink with `fstatat(AT_SYMLINK_NOFOLLOW)` either way.
- **`io::open` changes an empty file's mode to its `mode` argument** (default 0644). pki
  never calls it to read; it uses `io::RetryAfterSignal(::openat, ...)`.
- **OpenSSL 4 is more const.** `X509_get_X509_PUBKEY` and `X509_get_subject_name` return
  const pointers; keep code that builds against both 3.0 and 4.0, which CI checks.
- **OpenSSL 3.0 is the floor.** Ubuntu 24.04 and FreeBSD 14 ship 3.0; an API newer than 3.0
  breaks those jobs.
- **`make_directory` sets the umask to 077 around `mkdir`.** The umask is process-wide; the
  commands are single-threaded.
