//! Differential harness: runs seeded corpora under the blessed engine (every
//! backend the feature matrix admits) and the reference interpreter, comparing
//! outcomes byte-identically — return values, host access logs, trap kind.
//!
//! Also home of the profile rejection corpus and guest fixtures (hand-written
//! WAT compiled at test time, plus one realistic Rust guest). Dev-only: never
//! a dependency of `vm-runtime` or `vm-ref`.
