#!/bin/sh
# Downloads the two node releases the regtest suite runs against and refuses them unless both
# checks pass: the tarball hash equals the pin below, and SHA256SUMS carries a valid signature from
# a key in keys/ with the expected fingerprint.
#
# Usage: scripts/fetch-nodes.sh <dir>     prints CORE_DIR=... and KNOTS_DIR=... for the test script.
set -eu
DEST=$1
REPO=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$DEST"

CORE_VERSION=31.1
CORE_URL=https://bitcoincore.org/bin/bitcoin-core-$CORE_VERSION
CORE_TAR=bitcoin-$CORE_VERSION-x86_64-linux-gnu.tar.gz
CORE_SHA=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e
CORE_SIGNERS="152812300785C96444D3334D17565732E08E5E41 E777299FC265DD04793070EB944D35F9AC3DB76A"

KNOTS_VERSION=29.4.3.knots20260508
KNOTS_URL=https://github.com/bitcoinknots/bitcoin/releases/download/v$KNOTS_VERSION
KNOTS_TAR=bitcoin-$KNOTS_VERSION-x86_64-linux-gnu.tar.gz
KNOTS_SHA=4c67f1139b668fc3b98e339dd16112c636b2c0f42c2294b98fb92d1d27943e24
KNOTS_SIGNERS="1A3E761F19D2CC7785C5502EA291A2C45D0C504A"

# GitHub's release CDN answers 504 now and then; gh fetches the same asset through the API.
get() { # url file
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$2" "$1" && return
    case $1 in
    https://github.com/*/releases/download/*)
        command -v gh >/dev/null || return 1
        path=${1#https://github.com/}
        gh release download "$(echo "$path" | cut -d/ -f5)" --repo "$(echo "$path" | cut -d/ -f1-2)" \
            --pattern "$(basename "$1")" --output "$2" --clobber
        ;;
    *) return 1 ;;
    esac
}

fetch() { # name url tarball sha keyfile signers
    dir=$DEST/$1
    mkdir -p "$dir"
    for f in "$3" SHA256SUMS SHA256SUMS.asc; do
        [ -f "$dir/$f" ] || get "$2/$f" "$dir/$f"
    done
    echo "$4  $dir/$3" | sha256sum -c --quiet
    grep -q "^$4  $3\$" "$dir/SHA256SUMS"
    gnupg=$(mktemp -d)
    gpg --homedir "$gnupg" --quiet --import "$REPO/keys/$5" 2>/dev/null
    status=$(gpg --homedir "$gnupg" --status-fd 1 --verify "$dir/SHA256SUMS.asc" "$dir/SHA256SUMS" 2>/dev/null || true)
    rm -rf "$gnupg"
    for signer in $6; do
        echo "$status" | grep -qE "^\[GNUPG:\] VALIDSIG .* $signer\$" || { echo "no valid signature by $signer on $1" >&2; exit 1; }
    done
    tar -xzf "$dir/$3" -C "$dir"
}

fetch core "$CORE_URL" "$CORE_TAR" "$CORE_SHA" core-builders.asc "$CORE_SIGNERS"
fetch knots "$KNOTS_URL" "$KNOTS_TAR" "$KNOTS_SHA" knots-luke-dashjr.asc "$KNOTS_SIGNERS"
echo "CORE_DIR=$DEST/core/bitcoin-$CORE_VERSION"
echo "KNOTS_DIR=$DEST/knots/bitcoin-$KNOTS_VERSION"
