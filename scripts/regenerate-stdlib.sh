#!/usr/bin/env bash
# The committed stdlib blobs are canonically built in this container, at
# the path it mounts. Toolchains emit the same code in a different
# function order per host OS, and cargo salts each crate's symbol hashes
# with the absolute path it builds from, so the bytes are reproducible
# only here — one operating system and one directory own them together.
# Runs the regenerate example in that environment and writes the blobs
# back into the working tree; review and commit the result.
#
# `--check` compares instead of writing and fails naming what diverged,
# which is how CI judges the committed bytes: in the environment that
# makes them, because no other one can.
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm \
    --platform linux/amd64 \
    --volume "$PWD:/work" \
    --volume hyperscale-vm-regen-rustup:/usr/local/rustup \
    --volume hyperscale-vm-regen-cargo:/usr/local/cargo \
    --volume hyperscale-vm-regen-target:/work/target \
    --workdir /work \
    rust:1.96.0 \
    bash -euc '
        channel="$(sed -n "s/^channel = \"\(.*\)\"$/\1/p" guests/rust-toolchain.toml)"
        rustup toolchain install "$channel" \
            --component rust-src --target wasm32-unknown-unknown
        cargo run --release --example regenerate_stdlib -p hyperscale-vm-harness -- "$@"
    ' _ "$@"
