use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{AuthBase, AuthCell, Cell, RoleTable};

    #[state]
    struct Contract {
        held: Cell<Option<AuthCell>>,
    }

    impl Contract {
        // One cell, required absent and required present. No committed
        // state satisfies both, so the call could never be feasible.
        pub fn both(&mut self, roles: RoleTable, delay_ms: u64) {
            let _ = self.held.existing();
            self.held.create(AuthCell::new(AuthBase {
                recovery_delay_ms: delay_ms,
                roles,
            }));
        }
    }
}

fn main() {}
