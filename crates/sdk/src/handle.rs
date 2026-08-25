//! The materialized handle a body's accessors call through.
//!
//! Carried on both targets, because both have something to call: a guest
//! build resolves it to the kernel import, and a host build to the
//! session behind the same operation. What it names is a position in a
//! table the kernel owns, and needs nothing from either side to say so.

/// A materialized handle: the site the walk bound, and the element of
/// it this access names.
///
/// The mode is not here, because it is not the guest's to carry: what a
/// body may do through a handle is the capability's answer, held by the
/// kernel at every operation. Nor is the width: a plain access is a site
/// of one element, so nothing about holding one differs between it and
/// a `for-each` expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    /// The site's position in the session's site table.
    pub site: u32,
    /// Which element of it this access names.
    pub element: u32,
}

impl Handle {
    /// The handle for `element` of `site`.
    #[must_use]
    pub const fn at(site: u32, element: u32) -> Self {
        Self { site, element }
    }
}
