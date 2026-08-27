//! One test text, run on every engine the crate was built with.
//!
//! A [`Chain`] says nothing about which engine is under it, so a test
//! written against one holds for both — and running only one is what the
//! testing crate's own module doc argues against. What stopped it being
//! the default was the spelling: naming the second lane took a second
//! test, and a second test is a thing an author can forget to write.
//!
//! So the chain arrives as a parameter and both lanes are emitted, each
//! a test of its own — the bodies at the speed of a function call, and
//! the artifact a network would run. A failure then names the engine
//! that failed rather than the pair.
//!
//! [`Chain`]: https://docs.rs/hyperscale-vm-testing

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::spanned::Spanned as _;

/// Which lanes a test runs on.
#[derive(Debug)]
pub enum Lanes {
    /// Every engine the crate was built with — the default.
    Both,
    /// The bodies alone, stated: what a test of an inline or fixture
    /// module says, so a lane never drops silently.
    Native,
}

/// Read the attribute's lane selection.
///
/// # Errors
///
/// For anything but nothing or `native` — the wasm lane alone would
/// hold the artifact against no reading of what the author meant.
pub fn lanes(attr: &TokenStream2) -> syn::Result<Lanes> {
    if attr.is_empty() {
        return Ok(Lanes::Both);
    }
    let selected: syn::Ident = syn::parse2(attr.clone())?;
    if selected == "native" {
        return Ok(Lanes::Native);
    }
    Err(syn::Error::new(
        selected.span(),
        "the one explicit lane is `native` — both lanes are the default, and the wasm \
         lane alone would hold the artifact against no reading of what the author meant",
    ))
}

/// Expand one test into a body and a lane per engine.
///
/// # Errors
///
/// For a body that takes anything but the chain it runs on, and for one
/// that is `async` — there is no lane that awaits.
pub fn expand(lanes: &Lanes, mut item: syn::ItemFn) -> syn::Result<TokenStream2> {
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

    let wasm = match lanes {
        Lanes::Both => quote! {
            #[test]
            fn #blessed() #output {
                let mut chain = ::hyperscale_vm_testing::Chain::wasm();
                #body(&mut chain)
            }
        },
        Lanes::Native => quote!(),
    };
    Ok(quote! {
        #item

        #[test]
        fn #native() #output {
            let mut chain = ::hyperscale_vm_testing::Chain::native();
            #body(&mut chain)
        }

        #wasm
    })
}

#[cfg(test)]
mod tests {
    use super::{Lanes, expand, lanes};

    /// What the expansion says about a body it cannot run on a lane.
    fn refusal(body: syn::ItemFn) -> String {
        expand(&Lanes::Both, body)
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
        let expanded = expand(
            &Lanes::Both,
            syn::parse_quote! { fn a_swap_pays(chain: &mut Chain) {} },
        )
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

    #[test]
    fn the_explicit_native_form_emits_one_lane() {
        let selected = lanes(&quote::quote!(native)).expect("the one explicit lane");
        let expanded = expand(
            &selected,
            syn::parse_quote! { fn deeds_recall(chain: &mut Chain) {} },
        )
        .expect("a body the native lane runs")
        .to_string();
        assert!(expanded.contains("deeds_recall_native"), "{expanded}");
        assert!(!expanded.contains("deeds_recall_wasm"), "{expanded}");
    }

    #[test]
    fn a_lane_selection_that_is_not_native_is_refused() {
        assert!(
            lanes(&quote::quote!(wasm))
                .expect_err("the wasm lane cannot stand alone")
                .to_string()
                .contains("`native`"),
        );
    }
}
