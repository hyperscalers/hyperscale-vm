use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;

    #[config]
    struct Settings {
        x: ResourceAddr,
        y: ResourceAddr,
    }

    #[error]
    enum Error {
        SelfPaired,
    }

    #[state]
    struct Contract {}

    impl Contract {
        // A refusing bring-up ends in `Ok(())`: the supply is filed after
        // it by the declaration, so the tail is not the body's to shape.
        pub fn instantiate(&mut self) -> Result<(), Error> {
            let settings = self.config();
            if settings.x == settings.y {
                Err(Error::SelfPaired)
            } else {
                Ok(())
            }
        }
    }
}

fn main() {}
