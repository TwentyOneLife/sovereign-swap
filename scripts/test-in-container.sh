#!/bin/sh
# Builds the pinned image, then runs format check, clippy and the test suite in it.
# CORE_DIR and KNOTS_DIR point at unpacked, verified release directories (each with bin/bitcoind):
# Bitcoin Core and Bitcoin Knots BLAKE2b. Without them only the unit tests run.
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=sovereign-swap-build
docker build -q -t "$IMAGE" "$REPO" >/dev/null
MOUNTS=""
if [ -n "${CORE_DIR:-}" ] && [ -n "${KNOTS_DIR:-}" ]; then
    MOUNTS="-v $CORE_DIR:/core:ro -v $KNOTS_DIR:/knots:ro -e BTC_BITCOIND=/core/bin/bitcoind -e XBTC_BITCOIND=/knots/bin/bitcoind"
fi
# shellcheck disable=SC2086
exec docker run --rm -v "$REPO":/src -w /src $MOUNTS \
    -v sovereign-swap-cargo:/usr/local/cargo/registry -v sovereign-swap-target:/target \
    -e CARGO_TARGET_DIR=/target -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    "$IMAGE" sh -c 'cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked "$@"; rc=$?; chown "$HOST_UID:$HOST_GID" Cargo.lock; exit $rc' sh "$@"
