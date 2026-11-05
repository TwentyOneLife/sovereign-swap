# Verifying a release

Every release carries `SHA256SUMS` and a detached signature `SHA256SUMS.asc` from the TwentyOne.Life
release key, published in this repository at `keys/twentyonelife-release.asc`.

```sh
# import the key into a throwaway keyring, the way a stranger would
export GNUPGHOME="$(mktemp -d)"
gpg --import keys/twentyonelife-release.asc

# the signature must be good, then the hashes must match
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

A good signature means the checksums are the ones we signed; the hash check means the file you
downloaded is the one we built. The StartOS relay package builds the relay from source at a pinned
tag rather than downloading this binary, so its chain from source to running relay needs no separate
binary verification.
