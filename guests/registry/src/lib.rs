//! The registry guest: bindings in an unordered collection. `bind` writes
//! the entry at its hashed order, `check` traps on a missing or
//! mismatched binding, and `drain` removes the declared tail's entries.
//!
//! Hand-authored against the boundary itself, with no SDK: the imports
//! at the kernel's own types, the byte registers collected by hand, and
//! the reply made where the export ends.

#[link(wasm_import_module = "hyperscale:kernel/abi")]
unsafe extern "C" {
    fn arg(index: u32, ptr: u32);
    fn take(ptr: u32);
    fn reply(ptr: u32, count: u32);
}

#[link(wasm_import_module = "hyperscale:kernel/state")]
unsafe extern "C" {
    #[link_name = "site-count"]
    fn site_count(site: u32, element: u32) -> u32;
    #[link_name = "site-entry"]
    fn site_entry(site: u32, element: u32, index: u32) -> u32;
    #[link_name = "site-insert"]
    fn site_insert(site: u32, element: u32, order: u32, ptr: u32, len: u32);
    #[link_name = "site-remove"]
    fn site_remove(site: u32, element: u32, index: u32);
}

/// A pointer as the boundary carries it.
fn at<T>(ptr: *const T) -> u32 {
    ptr as usize as u32
}

/// The bytes waiting in input register `index`, `len` of them.
fn collected(index: u32, len: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; len as usize];
    unsafe { arg(index, at(bytes.as_mut_ptr())) };
    bytes
}

/// Replies with no edges: every export here produces none.
fn replied() {
    unsafe { reply(0, 0) };
}

/// The order an entry cell names, as the sixteen bytes the boundary
/// carries an amount as. The binding hands this guest the kernel's own
/// cell, so an off-width one never arrives and reads zero.
fn order_of(cell: &[u8]) -> [u8; 16] {
    cell.try_into().unwrap_or([0; 16])
}

/// Set the binding — the width-one interval at the name's hashed order
/// — to `value`. The order arrives derived, because the hash is
/// admission's to compute, never the guest's.
#[unsafe(export_name = "bind")]
pub extern "C" fn bind(entry: u32, order_len: u32, value_len: u32) {
    let order = order_of(&collected(1, order_len));
    let value = collected(2, value_len);
    unsafe {
        site_insert(
            entry,
            0,
            at(order.as_ptr()),
            at(value.as_ptr()),
            value.len() as u32,
        );
    }
    replied();
}

/// Trap unless the binding holds exactly `expected`.
#[unsafe(export_name = "check")]
pub extern "C" fn check(entry: u32, expected_len: u32) {
    let expected = collected(1, expected_len);
    assert!(unsafe { site_count(entry, 0) } == 1, "unbound name");
    let len = unsafe { site_entry(entry, 0, 0) };
    let mut held = vec![0u8; len as usize];
    unsafe { take(at(held.as_mut_ptr())) };
    assert!(held == expected, "mismatched binding");
    replied();
}

/// Remove every entry the declared tail shows, bounded by its cap.
#[unsafe(export_name = "drain")]
pub extern "C" fn drain(tail: u32) {
    while unsafe { site_count(tail, 0) } > 0 {
        unsafe { site_remove(tail, 0, 0) };
    }
    replied();
}
