//! The non-fungible guest: instances as holdings entries. `mint` writes
//! one instance's data cell and issues it, `deposit` files an arriving
//! edge's instances, `withdraw` takes named ones out — trapping on one
//! not held — and `burn` destroys them under the same grant that made
//! them.
//!
//! Hand-authored against the boundary itself, with no SDK: the imports
//! at the kernel's own types, the id register collected by hand, and the
//! reply made where the export ends.

#[link(wasm_import_module = "hyperscale:kernel/abi")]
unsafe extern "C" {
    fn arg(index: u32, ptr: u32);
    fn reply(ptr: u32, count: u32);
}

#[link(wasm_import_module = "hyperscale:kernel/state")]
unsafe extern "C" {
    #[link_name = "site-set"]
    fn site_set(site: u32, element: u32, ptr: u32, len: u32);
    #[link_name = "mint-instances"]
    fn mint_instances(grant: u32, ids: u32, count: u32) -> u32;
    #[link_name = "site-instance-put"]
    fn site_instance_put(site: u32, element: u32, funds: u32, ptr: u32, len: u32);
    #[link_name = "site-instance-take"]
    fn site_instance_take(site: u32, element: u32, ids: u32, count: u32) -> u32;
    fn burn(funds: u32);
}

/// A pointer as the boundary carries it.
fn at<T>(ptr: *const T) -> u32 {
    ptr as usize as u32
}

/// Replies with `edges`, in declared output order.
fn replied(edges: &[u32]) {
    unsafe { reply(at(edges.as_ptr()), edges.len() as u32) };
}

/// Mint one instance: write its data cell and produce the instance
/// under this method's own issuance grant.
#[unsafe(export_name = "mint")]
pub extern "C" fn mint(data: u32, id: u64) {
    let bytes = id.to_le_bytes();
    unsafe { site_set(data, 0, at(bytes.as_ptr()), bytes.len() as u32) };
    // The one issuance this method declares, so index zero — the
    // hand-authored twin of what the lowering computes for a body that
    // writes the mark instead.
    let ids = [id];
    let funds = unsafe { mint_instances(0, at(ids.as_ptr()), 1) };
    replied(&[funds]);
}

/// File the arriving instances as holdings entries.
#[unsafe(export_name = "deposit")]
pub extern "C" fn deposit(holdings: u32, funds: u32) {
    let value = [1u8];
    unsafe { site_instance_put(holdings, 0, funds, at(value.as_ptr()), 1) };
    replied(&[]);
}

/// Take the named instances out of the holdings interval, trapping on
/// one not held. The ids wait in the register at parameter one, eight
/// bytes each.
#[unsafe(export_name = "withdraw")]
pub extern "C" fn withdraw(holdings: u32, ids_len: u32) {
    let mut ids = vec![0u64; (ids_len / 8) as usize];
    unsafe { arg(1, at(ids.as_mut_ptr())) };
    let funds = unsafe { site_instance_take(holdings, 0, at(ids.as_ptr()), ids.len() as u32) };
    replied(&[funds]);
}

/// Destroy the instances the edge carries; they stop existing.
#[unsafe(export_name = "burn")]
pub extern "C" fn burn_instances(funds: u32) {
    unsafe { burn(funds) };
    replied(&[]);
}

/// Nothing but its own gate: opens for whoever presents the identity
/// the configured badge resource names.
#[unsafe(export_name = "operate")]
pub extern "C" fn operate() {
    // The gate is the kernel's; a body would have nothing to say.
    replied(&[]);
}

/// The same, at instance resolution: opens for whoever presents the
/// one instance the configured resource and id name.
#[unsafe(export_name = "operate-instance")]
pub extern "C" fn operate_instance() {
    // Likewise: what differs is which claim the gate names, which is
    // the declaration's business and never this body's.
    replied(&[]);
}

/// The same over an admin set: opens for whoever presents two of the
/// three configured instances.
#[unsafe(export_name = "operate-quorum")]
pub extern "C" fn operate_quorum() {
    // Likewise again: a threshold is a shape the declaration holds, so
    // counting the presentations is the kernel's and not this body's
    // either.
    replied(&[]);
}
