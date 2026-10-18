# pki

[![CI](https://github.com/Kronuz/pki/actions/workflows/ci.yml/badge.svg)](https://github.com/Kronuz/pki/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)

An offline certificate authority for a cluster's TLS, as a C++20 library over OpenSSL 3
and a command entry point each consumer's binary calls (`xapiand pki ...`). One
authority per cluster, one certificate profile, and the checks an operator would
otherwise skip: who owns the authority's directory, what mode its keys have, which
filesystem it sits on, and when each certificate runs out.

It serves [Xapiand](https://github.com/Kronuz/Xapiand)'s HTTPS API and Detent's
mutual-TLS peers, both through [reactor](https://github.com/Kronuz/reactor)'s TLS roles,
which verify certificates and make none.

## Status

Step 1 of 5 of the design. In this repository today:

- **Fingerprints:** the SHA-256 of a certificate's SubjectPublicKeyInfo DER (the SPKI pin)
  and of its DER (a certificate pin), as 64 lowercase hex digits.
- **Expiry checks:** a certificate is expiring past five sixths of its life, or within a
  span you give; `check` exits 1 when one is, for a cron job on each node.
- **Keys:** ECDSA P-256 generation; P-384 accepted, and RSA 2,048 to 4,096 bits only when
  asked for; CA keys as PKCS#8 under scrypt (N = 2^14, r = 8, p = 1) and AES-256-CBC, which
  `openssl pkcs8` from OpenSSL 3 and 4 reads back, so recovery needs no pki binary.
- **The authority directory's checks:** opened once and reached through `openat`; owned by
  the caller at 0700, on a local filesystem with POSIX modes, never under a Xapiand data
  root; key and passphrase files regular, singly linked, the caller's, and private.
- **Secrets:** no core dumps, passphrases from the terminal or a checked file (never argv
  or the environment), locked and wiped buffers.

Still to come, in order: the index, the certificate profile, and signing; rotation,
backup, and recovery; Xapiand's `xapiand pki`; Detent's adoption.

## 🚀 Usage

```console
$ kronuz-pki fingerprint node1.pem
certificate 1
spki-sha256 4f0c...e1
der-sha256 9a21...7b
$ kronuz-pki check node1.pem --within 30d
certificate 1 valid not-before 2026-10-17T11:00:00Z not-after 2027-10-17T12:00:00Z (365 days left)
$ echo $?
0
```

Exit status: 0 ok, 1 a check found something, 2 refused. A refusal names its reason:

```console
$ kronuz-pki fingerprint node1.key
kronuz-pki: refused (pem): node1.key holds a private key; give the certificate, the request, or the public key
```

`kronuz-pki` is the library's driver and example; it is never packaged. A consumer calls
the same entry point with its own consumer fixed:

```cpp
#include "pki/pki.h"

int pki_command(int argc, char** argv) {  // argv[0] is "pki"
	return pki::run(pki::Consumer::xapiand, argc, argv);
}
```

## 📦 Building

Requires a C++20 compiler, CMake 3.16 or newer, and OpenSSL 3.0 or newer (LibreSSL is not
OpenSSL 3; on macOS use Homebrew's `openssl@3` or `openssl@4`).

```sh
cmake -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"  # the prefix only on macOS
cmake --build build && ctest --test-dir build
```

As a dependency:

```cmake
include(FetchContent)
FetchContent_Declare(pki GIT_REPOSITORY https://github.com/Kronuz/pki.git GIT_TAG main)
FetchContent_MakeAvailable(pki)
target_link_libraries(my_app PRIVATE pki::pki)
```

`pki::pki` brings `OpenSSL::Crypto` and [io](https://github.com/Kronuz/io). A consumer
that compiles `io.cc` into its own objects sets `PKI_LINK_IO=OFF`.

CI builds and tests it on Linux (x86_64 with GCC and Clang, arm64) against OpenSSL 3.0,
on macOS (arm64, x86_64) against Homebrew's OpenSSL 3 and 4, and on FreeBSD against its
base OpenSSL 3.0, plus ASan with UBSan, TSan, and the owner cases run as root.

Performance is not a concern here beyond scrypt's deliberate cost, about 0.06 to 0.1 s a
derivation, so there is no benchmark.

## 📚 More

- [ARCHITECTURE.md](ARCHITECTURE.md): the modules, the checks, and the seams.
- [AGENTS.md](AGENTS.md): the file map, the invariants, and the traps.

## License

MIT. See [LICENSE](LICENSE).
