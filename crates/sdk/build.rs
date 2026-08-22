//! Names the one question the vocabulary branches on.
//!
//! A body is read on one target and run on another, and which of those a
//! given compilation is doing takes both halves of an answer: the `guest`
//! feature says this crate belongs to a package that publishes a
//! component, and the target says this is the build that produces it. A
//! package's own host build reads its declaration, and so does every
//! consumer that never publishes anything — including one that is itself
//! compiled to wasm, which is why the target alone cannot answer.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(component)");

    let publishes = std::env::var_os("CARGO_FEATURE_GUEST").is_some();
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    if publishes && wasm {
        println!("cargo::rustc-cfg=component");
    }
}
