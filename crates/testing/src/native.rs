//! The packages' own bodies behind a chain, with no engine under them.
//!
//! What a body does, at the speed of a function call and with a
//! backtrace when it goes wrong. What it does *not* prove is anything a
//! network would charge for or refuse over: there is no fuel here, no
//! canonical-ABI copy accounting, and no profile validator. So this lane
//! answers whether a contract is right and never whether it is
//! admissible — which is why the one that answers the second question
//! runs the same tests.

use std::collections::BTreeMap;

use hyperscale_vm_effects::PackageHash;
use hyperscale_vm_kernel::{
    GuestArg, GuestBackend, GuestCall, InvokeResult, Invoked, KernelSession,
};
use hyperscale_vm_types::AbortReason;

/// One package's native dispatch, at the session it is called with.
///
/// The generic the macro emits, instantiated: a package crate names no
/// kernel, and the type it would have had to name is fixed here instead.
pub type Dispatch = fn(&str, KernelSession, &[GuestArg<'_>]) -> (KernelSession, Invoked);

/// The published packages' bodies, by the content address a call names
/// them at.
#[derive(Default)]
pub struct Native {
    packages: BTreeMap<PackageHash, Dispatch>,
}

impl Native {
    /// Take a package's dispatch under the address its code publishes at.
    pub fn seed(&mut self, package: PackageHash, dispatch: Dispatch) {
        self.packages.insert(package, dispatch);
    }
}

impl GuestBackend for Native {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let Some(dispatch) = self.packages.get(&call.package) else {
            return InvokeResult {
                session,
                fuel: 0,
                result: Invoked::Aborted(AbortReason::CodeUnavailable),
                exhausted: false,
            };
        };
        let (session, result) = dispatch(call.export, session, call.args);
        InvokeResult {
            session,
            // Nothing metered it. Reported as nothing spent rather than
            // as a figure nobody could act on: a receipt from this lane
            // is not one a consensus reader ever sees, and a plausible
            // number would be the harder thing to notice.
            fuel: 0,
            result,
            exhausted: false,
        }
    }
}
