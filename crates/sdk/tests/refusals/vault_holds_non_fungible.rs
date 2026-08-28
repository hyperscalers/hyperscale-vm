use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Vault;

    #[resource(non_fungible, grants(mint = self))]
    struct Ticket {
        holder: u64,
    }

    #[state]
    struct Contract {
        #[holds(issued(Ticket))]
        bank: Vault,
    }
}

fn main() {}
