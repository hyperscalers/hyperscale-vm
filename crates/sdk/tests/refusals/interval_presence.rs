use hyperscale_vm_sdk::{Blueprint, ParamType, SlotId, Sym, Trace, U128, sym::lit_u64};

fn main() {
    let _ = Blueprint::builder()
        .method("sweep", &[ParamType::U128], |t: &mut Trace| {
            let owner = t.self_addr();
            let cursor: Sym<U128> = t.arg(0);
            // A presence requirement is about the leaf a write lands on,
            // and an interval has none: whether it holds anything says
            // nothing about the entries a write chooses at execution. So
            // neither requirement is offered on one, and reaching for
            // either is a type error rather than a published method
            // whose condition judges something else.
            t.sweep(&owner, SlotId(16), &cursor, &lit_u64(4)).create();
            t.range(&owner, SlotId(16), &[], &cursor, &cursor, &lit_u64(4))
                .existing();
        })
        .build();
}
