# Development build and test image. Base pinned by digest: rust:1-slim-bookworm, rustc 1.99.1.
# clippy and rustfmt are fetched unpinned at image build; a release build vendors and pins its inputs.
FROM rust@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07
RUN rustup component add clippy rustfmt
# Fulcrum (the regtest Electrum server for the E1 ChainBackend test) links libbz2 at runtime; the
# slim base image does not ship it.
RUN apt-get update && apt-get install -y --no-install-recommends libbz2-1.0 \
    && rm -rf /var/lib/apt/lists/*
