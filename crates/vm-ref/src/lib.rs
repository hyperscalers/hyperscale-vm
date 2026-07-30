//! Reference interpreter of the deterministic profile.
//!
//! A slow, obviously-correct implementation of exactly the subset the profile
//! validator admits — the executable spec, differentially tested against the
//! blessed engine. Execution semantics, canonical-ABI lift/lower, and the fuel
//! schedule are implemented independently of wasmtime; sharing is permitted
//! only at the decode layer.
