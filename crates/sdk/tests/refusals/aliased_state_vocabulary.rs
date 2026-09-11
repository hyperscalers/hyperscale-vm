use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    // The state field kinds are read off a type's last path segment, so
    // aliasing `Vault` to `Cell` would lower `held` as a plain cell the
    // alias only spells.
    use hyperscale_vm_sdk::state::Vault as Cell;

    #[state]
    struct Contract {
        held: Cell,
    }

    impl Contract {
        pub fn touch(&mut self) {}
    }
}

fn main() {}
