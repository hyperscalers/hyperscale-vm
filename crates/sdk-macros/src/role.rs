//! What the crate being expanded is, and so which halves it gets.
//!
//! A package's text yields two readings: the declaration routing consumes
//! and the calls a client composes, which any consumer may need, and the
//! component the package publishes, which only the crate that publishes
//! it can build. Both come out of one walk — that is what keeps them
//! agreeing — but a crate that publishes nothing has no use for the
//! second and no kernel to bind it against.
//!
//! Which of the two is being compiled is not a property of the target. A
//! consumer that only ever reads a declaration may itself be compiled to
//! wasm, and a package's own host build reads its declaration too. So the
//! crate says which it is, by the SDK feature it names, and the target
//! narrows a publishing crate to the build that emits the artifact.

use proc_macro2::TokenStream;
use quote::quote;

/// Which readings of a package's text this expansion emits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A crate that reads packages. The declaration and the call surface
    /// stand on every target, and no component is emitted.
    Reader,
    /// A crate that publishes this package. Both halves are emitted, and
    /// the target picks between them: the artifact build gets the
    /// component, and every other build of the same crate — its tests
    /// above all — reads the declaration like any other consumer.
    Publisher,
}

impl Role {
    /// The gate the declaration and the call surface are emitted under.
    pub fn reading(self) -> TokenStream {
        match self {
            Self::Reader => quote!(),
            Self::Publisher => quote!(#[cfg(not(target_arch = "wasm32"))]),
        }
    }

    /// Whether the executing half is emitted at all.
    pub fn publishes(self) -> bool {
        self == Self::Publisher
    }
}
