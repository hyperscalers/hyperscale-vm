use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{AuthCell, Cell};

    #[roles]
    enum Roles {
        Admin,
    }

    #[state]
    struct Contract {
        roles: Cell<Option<AuthCell>>,
    }

    impl Contract {
        pub fn peek(&mut self) {
            let _ = self.roles.get();
        }
    }
}

fn main() {}
