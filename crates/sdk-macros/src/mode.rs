//! The handle-mode vocabulary, stated once.
//!
//! A declared site's mode decides four coupled facts: the WIT resource
//! its handle crosses as, the Rust type wit-bindgen derives from that
//! name, the kernel `CellKind` the native dispatch constructs, and the
//! SDK `Handle` variant the guest binds. Each backend reads its fact off
//! this enum, so a mode added here is exhaustively matched everywhere —
//! where four string maps would each accept the new name silently and
//! two of them would default it differently.

use proc_macro2::{Span, TokenStream};
use quote::quote;

/// Which kernel resource a declared site's handle arrives as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleMode {
    /// `read-cell`.
    ReadCell,
    /// `write-cell`.
    WriteCell,
    /// `amount-cell`.
    AmountCell,
    /// `amount-read`.
    AmountRead,
    /// `delta-cell`.
    DeltaCell,
    /// `reserve-cell`.
    ReserveCell,
    /// `range-read`.
    RangeRead,
    /// `range-write`.
    RangeWrite,
    /// `instance-range`.
    InstanceRange,
}

impl HandleMode {
    /// The WIT resource name, as the world declares it.
    #[must_use]
    pub const fn world_name(self) -> &'static str {
        match self {
            Self::ReadCell => "read-cell",
            Self::WriteCell => "write-cell",
            Self::AmountCell => "amount-cell",
            Self::AmountRead => "amount-read",
            Self::DeltaCell => "delta-cell",
            Self::ReserveCell => "reserve-cell",
            Self::RangeRead => "range-read",
            Self::RangeWrite => "range-write",
            Self::InstanceRange => "instance-range",
        }
    }

    /// The Rust type wit-bindgen derives from the WIT name.
    #[must_use]
    pub fn guest_type(self) -> syn::Ident {
        let name = match self {
            Self::ReadCell => "ReadCell",
            Self::WriteCell => "WriteCell",
            Self::AmountCell => "AmountCell",
            Self::AmountRead => "AmountRead",
            Self::DeltaCell => "DeltaCell",
            Self::ReserveCell => "ReserveCell",
            Self::RangeRead => "RangeRead",
            Self::RangeWrite => "RangeWrite",
            Self::InstanceRange => "InstanceRange",
        };
        syn::Ident::new(name, Span::call_site())
    }

    /// The kernel `CellKind` variant the native dispatch constructs.
    #[must_use]
    pub fn cell_kind(self) -> TokenStream {
        match self {
            Self::ReadCell => quote!(Read),
            Self::WriteCell => quote!(Write),
            Self::AmountCell => quote!(Amount),
            Self::AmountRead => quote!(AmountRead),
            Self::DeltaCell => quote!(Delta),
            Self::ReserveCell => quote!(Reserve),
            Self::RangeRead => quote!(RangeRead),
            Self::RangeWrite => quote!(RangeWrite),
            Self::InstanceRange => quote!(InstanceRange),
        }
    }

    /// The SDK `Handle` variant a borrowed resource arrives as.
    #[must_use]
    pub fn handle_variant(self) -> TokenStream {
        match self {
            Self::ReadCell => quote!(Read),
            Self::WriteCell => quote!(Write),
            Self::AmountCell => quote!(Amount),
            Self::AmountRead => quote!(AmountRead),
            Self::DeltaCell => quote!(Delta),
            Self::ReserveCell => quote!(Reserve),
            Self::RangeRead => quote!(RangeRead),
            Self::RangeWrite => quote!(RangeWrite),
            Self::InstanceRange => quote!(InstanceRange),
        }
    }
}
