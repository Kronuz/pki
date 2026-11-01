# pki

Part of [Kronuz C++ Libraries](https://github.com/Kronuz/cpp-libraries), a collection of small, reusable C++ libraries.

[![CI](https://github.com/Kronuz/pki/actions/workflows/ci.yml/badge.svg)](https://github.com/Kronuz/pki/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)

Offline certificate-authority toolkit for C++20 over OpenSSL 3: keys, SPIFFE identities, fingerprints, and expiry checks.
A consumer's binary calls one command entry point, `pki::run`, and the library
runs the checks an operator would otherwise skip: who owns the authority's
directory, what mode its keys have, which filesystem it sits on, and when each
certificate runs out. Reach for it to keep a cluster's TLS keys on an operator's
host, for consumers such as Xapiand's HTTPS API and Detent's mutual-TLS peers.

## ✨ Highlights

- **Fingerprints.** The SHA-256 of a certificate's SubjectPublicKeyInfo DER (the
  SPKI pin) and of its DER (a certificate pin), as 64 lowercase hex digits.
- **Expiry checks.** A certificate is expiring past five sixths of its life, or
  within a span you give; `check` exits 1 when one is, for a cron job on each
  node.
- **Keys.** ECDSA P-256 generation; P-384 accepted, and RSA of 2,048 to 4,096
  bits only when asked for. CA keys are PKCS#8 under scrypt (N = 2^14, r = 8,
  p = 1) and AES-256-CBC, which `openssl pkcs8` from OpenSSL 3 and 4 reads back,
  so recovery needs no pki binary.
- **A guarded authority directory.** Opened once and reached through `openat`;
  owned by the caller at 0700, on a local filesystem with POSIX modes, never
  under a Xapiand data root. Key and passphrase files are regular, singly
  linked, the caller's, and private.
- **Identities.** SPIFFE IDs, `spiffe://<cluster>/<consumer>/<node | client>/<name>`,
  with one byte form: the cluster and a node name lowercased per byte and held
  to SPIFFE's alphabet, a voter id in canonical decimal, and nothing
  percent-encoded.
- **Secrets.** No core dumps; passphrases from the terminal or a checked file,
  never argv or the environment; locked and wiped buffers.
- **Refusals that name their reason.** Exit status 0 is ok, 1 a check found
  something, and 2 a refusal, with one line on stderr naming the reason.

## 🚀 Quick start

```cpp
#include "pki/pki.h"

// my-pki fingerprint node1.pem
//   certificate 1
//   spki-sha256 <64 hex digits>
//   der-sha256 <64 hex digits>
// my-pki check node1.pem --within 30d
//   certificate 1 valid not-before 2026-10-17T11:00:00Z not-after 2027-10-17T12:00:00Z (365 days left)
// my-pki fingerprint node1.key
//   my-pki: refused (pem): node1.key holds a private key; give the certificate, the request, or the public key
int main(int argc, char** argv) {
	return pki::run(pki::Consumer::xapiand, argc, argv);  // 0 ok, 1 found something, 2 refused
}
```

A consumer fixes its own `pki::Consumer` and passes its `pki` subcommand's
arguments. [`examples/kronuz_pki.cc`](examples/kronuz_pki.cc) builds
`kronuz-pki`, the driver, which takes `--consumer` instead and is never packaged.

## 📦 Installation

Requires a C++20 compiler, CMake 3.16 or newer, and OpenSSL 3.0 or newer
(LibreSSL is not OpenSSL 3; on macOS use Homebrew's `openssl@3` or `openssl@4`);
it fetches [io](https://github.com/Kronuz/io) and
[char-classify](https://github.com/Kronuz/char-classify). CI builds and tests it on
Linux (x86_64 with GCC and Clang, arm64) against OpenSSL 3.0, on macOS (arm64,
x86_64) against Homebrew's OpenSSL 3 and, on arm64, OpenSSL 4, and on FreeBSD
against its base OpenSSL 3.0, plus ASan with UBSan, TSan, and the owner cases run
as root.

```cmake
include(FetchContent)
FetchContent_Declare(pki
  GIT_REPOSITORY https://github.com/Kronuz/pki.git
  GIT_TAG        8cc2db66e97953f2de03a0880d0d37f237493809)  # or main for the tip
FetchContent_MakeAvailable(pki)

target_link_libraries(my_app PRIVATE pki::pki)
```

```cpp
#include "pki/pki.h"
```

`pki::pki` brings `OpenSSL::Crypto` and `io::io`. A consumer that compiles
`io.cc` into its own objects sets `PKI_LINK_IO=OFF`.

## 🎯 When to use it

Use it to fingerprint a cluster's certificates, check their expiry from a cron
job, and generate and store the authority's keys under checks that refuse an
unsafe directory or file.

Not for:

- **Issuing certificates.** pki has no signing, index, rotation or backup; see
  [docs/ROADMAP.md](docs/ROADMAP.md).
- **LibreSSL or OpenSSL 1.1.** CMake asks for OpenSSL 3.0 or newer, and keys
  load through OpenSSL 3's `OSSL_STORE`.

## 📚 Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): the layers, the checks, keys,
  fingerprints and expiry, identities, and the seams.
- [docs/ROADMAP.md](docs/ROADMAP.md): the remaining steps.
- [AGENTS.md](AGENTS.md): the file map, the invariants, and the traps.
- [Kronuz C++ Libraries](https://github.com/Kronuz/cpp-libraries/blob/main/AGENTS.md#pki): the catalog entry.

## 🛠️ Building and testing

```sh
cmake -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"  # the prefix only on macOS
cmake --build build
ctest --test-dir build
sudo build/pki_files_test  # the owner cases, as root
```

The tests make their scratch directories under the build tree, which must be on a
local filesystem pki accepts: a Linux build tree on tmpfs fails `pki_files`.
`./build/kronuz-pki help` lists the commands.

## 🤝 Contributing

Issues and pull requests are welcome. Read [AGENTS.md](AGENTS.md) and the
catalog's [rules of engagement](https://github.com/Kronuz/cpp-libraries/blob/main/AGENTS.md#rules-of-engagement)
first; CI must pass on every platform.

## 📄 License

MIT, Copyright (c) 2026 Germán Méndez Bravo. See [LICENSE](LICENSE).
