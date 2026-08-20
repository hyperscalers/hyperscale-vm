use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{AuthBase, AuthCell, Cell, Quantity, RoleTable, clock_ms};

    #[roles]
    enum Roles {
        Admin,
    }

    #[state]
    struct Contract {
        roles: Cell<Option<AuthCell>>,
        flag: Cell<Quantity>,
    }

    impl Contract {
        #[requires(roles[Admin])]
        pub fn rotate(&mut self, table: RoleTable, value: Quantity) {
            let stored = self.roles.existing();
            let current = stored.governing(clock_ms()).clone();
            self.roles.set(Some(AuthCell::new(AuthBase {
                recovery_delay_ms: current.recovery_delay_ms,
                roles: table,
            })));
            self.flag.set(value);
        }
    }
}

fn main() {}
