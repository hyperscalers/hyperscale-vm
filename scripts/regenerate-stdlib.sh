#!/usr/bin/env bash
# The committed stdlib blobs are canonically Linux-built: toolchains
# emit the same code in different function order per host OS, so one
# platform owns the bytes — the same x86-64 Linux CI verifies them on.
# Runs the regenerate example in that environment and writes the blobs
# back into the working tree; review and commit the result.
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
        rustup toolchain install nightly-2026-06-08 \
            --component rust-src --target wasm32-unknown-unknown
        cargo run --release --example regenerate_stdlib -p hyperscale-vm-harness
    '
