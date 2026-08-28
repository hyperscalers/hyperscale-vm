use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Instances;

    #[resource(non_fungible, grants(mint = self))]
    struct Ticket {
        holder: u64,
    }

    #[config]
    struct Settings {
        mark: Address,
    }

    #[state]
    struct Contract {
        #[holds(config.mark)]
        stock: Instances,
    }

    impl Contract {
        pub fn stow(&mut self, id: u64, holder: u64) {
            self.stock.whole().file(Ticket::mint(id, Ticket { holder }));
        }
    }
}

fn main() {}
