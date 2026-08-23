//! One test text, run on every engine the crate was built with.
//!
//! A [`Chain`] says nothing about which engine is under it, so a test
//! written against one holds for both — and running only one is what the
//! testing crate's own module doc argues against. What stopped it being
//! the default was the spelling: naming the second lane took a second
//! test, and a second test is a thing an author can forget to write.
//!
//! So the chain arrives as a parameter and the lanes are emitted. The
//! blessed lane goes through the testing crate's `wasm_lane!`, which is
//! a `cfg` gate over whatever it is handed: whether that lane exists is
//! a fact about how *that* crate was built, and a `cfg` emitted here
//! would ask the test's own crate instead.
//!
//! [`Chain`]: https://docs.rs/hyperscale-vm-testing

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::spanned::Spanned as _;

/// Expand one test into a body and a lane per engine.
///
/// # Errors
///
/// For a body that takes anything but the chain it runs on, and for one
/// that is `async` — there is no lane that awaits.
pub fn expand(mut item: syn::ItemFn) -> syn::Result<TokenStream2> {
    if let Some(token) = item.sig.asyncness {
        return Err(syn::Error::new(
            token.span(),
            "a lane runs a body to completion, so there is nothing here to await",
        ));
    }
    if item.sig.inputs.len() != 1 {
        return Err(syn::Error::new(
            item.sig.inputs.span(),
            "a lane test takes exactly one parameter: the chain it is handed",
        ));
    }

    let name = item.sig.ident.clone();
    let body = format_ident!("{name}_body");
    let native = format_ident!("{name}_native");
    let blessed = format_ident!("{name}_wasm");
    let output = item.sig.output.clone();
    // The body keeps everything the author wrote — attributes, visibility,
    // the parameter's own type — and loses only its name, which the lanes
    // take over.
    item.sig.ident = body.clone();

    Ok(quote! {
        #item

        #[test]
        fn #native() #output {
            #body(::hyperscale_vm_testing::Chain::native())
        }

        ::hyperscale_vm_testing::wasm_lane! {
            #[test]
            fn #blessed() #output {
                #body(::hyperscale_vm_testing::Chain::wasm())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::expand;

    /// What the expansion says about a body it cannot run on a lane.
    fn refusal(body: syn::ItemFn) -> String {
        expand(body)
            .expect_err("a body no lane can run")
            .to_string()
    }

    #[test]
    fn a_body_that_is_handed_no_chain_is_refused() {
        assert!(
            refusal(syn::parse_quote! { fn takes_nothing() {} }).contains("exactly one parameter"),
        );
    }

    #[test]
    fn a_body_that_wants_more_than_the_chain_is_refused() {
        assert!(
            refusal(syn::parse_quote! { fn takes_two(chain: Chain, seed: u64) {} })
                .contains("exactly one parameter"),
        );
    }

    #[test]
    fn an_async_body_is_refused_because_no_lane_awaits() {
        assert!(refusal(syn::parse_quote! { async fn awaits(chain: Chain) {} }).contains("await"));
    }

    #[test]
    fn a_lane_is_named_for_the_engine_under_it() {
        let expanded = expand(syn::parse_quote! { fn a_swap_pays(chain: Chain) {} })
            .expect("a body one lane can run")
            .to_string();
        // The body keeps the text and loses only the name; each lane is a
        // test of its own, so a divergence names the engine.
        assert!(expanded.contains("a_swap_pays_body"), "{expanded}");
        assert!(expanded.contains("a_swap_pays_native"), "{expanded}");
        assert!(expanded.contains("a_swap_pays_wasm"), "{expanded}");
        assert!(expanded.contains("Chain :: native"), "{expanded}");
        assert!(expanded.contains("Chain :: wasm"), "{expanded}");
    }
}
