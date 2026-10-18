# Architecture

pki is an offline certificate authority: the authority's key lives on an operator's
host, never on a serving node, and every certificate is issued from a request the node
made, so a node's key never travels. This file describes how the library is put
together; the decisions it implements (D1 to D14) and their gate rows (T1 to T14) are
in Xapiand's PKI design, `docs/design/pki.md`, with its architect and security reviews.

## Layers

```
  consumer binary (xapiand pki ...)      kronuz-pki (driver, never packaged)
                 \                          /
                  pki::run(consumer, argv)          src/command.cc
                  /        |          \
        fingerprint.h   expiry.h    pem.h            what commands compute and read
                  \        |          /
        key.h (OpenSSL 3: keys, PKCS#8, OSSL_STORE)
        directory.h, secret.h (the authority directory, files, secrets)
        private_file.h (dependency-free POSIX check)  +  io (EINTR-safe calls, full_fsync)
```

Each command runs in its own process: the serving process never runs issuance code.
`run()` first calls `harden_process()` (no core dumps; on Linux, not dumpable), then
parses the command, and turns every `pki::Refusal` into exit status 2 and one line on
stderr naming the reason (`refused (file-mode): ...`). A check that finds something, such
as `check` on an expiring certificate, exits 1.

## The checks

**Private files** (`private_file.h`). One check, written once, with the policy as a
parameter: a regular file, not a symlink, with one link, owned by the effective user,
and then

| Policy | For | Mode |
|---|---|---|
| `secret` | CA keys, passphrase files | no bit outside 0600 |
| `key` | node keys | no bit outside 0640; group read only when the group is the caller's effective group |
| `integrity` | journal-style files | no group or world write |

The file is opened with `O_NOFOLLOW | O_NONBLOCK` (a FIFO never blocks the open), then
checked with `fstat` on the descriptor, so what is checked is what is read. The header
uses nothing but POSIX, so it can move to a shared home.

**The authority directory** (`directory.h`). `Directory::open` opens `DIR` once with
`O_DIRECTORY | O_NOFOLLOW` and refuses it unless `fstat` shows a directory the caller
owns at exactly 0700, on a local filesystem that keeps POSIX modes: `MNT_LOCAL` on macOS
and FreeBSD, with FAT and exFAT refused; on Linux an allowlist (ext2/3/4, xfs, btrfs, zfs,
f2fs), and a refusal that names any other type, tmpfs and FUSE included. Every file
inside is reached through `openat` on that descriptor. `create` writes a file with
`O_CREAT | O_EXCL | O_NOFOLLOW`, sets its mode with `fchmod` whatever the umask, and
syncs it with `io::full_fsync` (`F_FULLFSYNC` on macOS), so a planted name or symlink is
never followed and nothing is written over.

`check_outside_xapiand_root` refuses a path at or under a directory holding
`.xapiand/node`, so no node's backup carries an authority. `Directory::contains` compares
device and inode up the resolved path, which is how a passphrase file inside `DIR` is
refused even through a symlink.

**Secrets** (`secret.h`). A `Secret` is a fixed-capacity buffer, `mlock`ed where the host
allows, wiped with `OPENSSL_cleanse` when it shrinks or dies, and never reallocated, so no
stale copy is left behind. Passphrases come from `/dev/tty` with echo off or from a
`--passphrase-file` under the `secret` policy, never from argv or the environment. A new
passphrase needs 12 characters (code points); every passphrase is at most 1,023 bytes,
the most OpenSSL's PEM callback buffer and `openssl pkcs8 -passin file:` take.

## Keys

`generate_key` makes ECDSA P-256 keys. `check_key_type` accepts P-256 and P-384, and RSA
of 2,048 to 4,096 bits only under `--allow-rsa`, since an RSA leaf gives no forward
secrecy on a context without `strict`. CA keys are PKCS#8, PBES2 with AES-256-CBC under
scrypt N = 2^14, r = 8, p = 1 (16 MiB): the most OpenSSL's reader takes under its
32 MiB default limit. `load_private_key` reads a key through `OSSL_STORE_attach` over the
bytes the directory check read, so the check and the read see one file, and a later
format can name a `pkcs11:` key without changing callers.

## Fingerprints and expiry

`spki_sha256` hashes `i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x))`, the SubjectPublicKeyInfo
DER; `X509_pubkey_digest` hashes only the key's bits and gives another value, so the two
are never mixed. `der_sha256` hashes the certificate's DER. A same-key renewal keeps the
first and changes the second.

`standing` reads notBefore and notAfter as seconds and calls a certificate expired from
notAfter on (OpenSSL 3.6 refuses there and 4.0 accepts, so pki takes the stricter), and
expiring past five sixths of its life (61 days before the end of a 365-day leaf) or within
a span the caller gives. Durations are a count and a unit (`30d`), capped at
9999-12-31T23:59:59Z, the latest time X.509 encodes.

## Seams

- `PKI_LINK_IO` (ON): link `io::io`. A consumer that compiles `io.cc` into its own objects
  with its own trace and fault seams turns it off, so its binary holds one copy of io.
- `PKI_TEST_HOOKS`: defined only for `pki_testing`, the variant the tests link. It alone
  reads `PKI_TEST_NOW` (the clock); the `pki_release_has_no_test_hooks` test fails if the
  release driver carries a hook's name.
- The consumer: fixed by the calling binary; `kronuz-pki` takes `--consumer`.
