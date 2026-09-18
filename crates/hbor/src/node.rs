//! A type's shape as a static tree, and the bounds folded off it.
//!
//! A [`ShapeNode`] holds its children by `&'static` reference, which is
//! the form a `const` can state and a generic impl can compose: `Option<T>`
//! names `T`'s own node, and a struct names one per field. A type that
//! reaches itself would make its constant name itself, and rustc refuses
//! that as a cycle on the impl — so a tree a type can state is acyclic by
//! construction, and the folds below need no budget to terminate.
//!
//! Three folds read three figures off one tree, in `const` so a type's
//! bound is a constant beside its shape rather than a second derivation:
//! the most and the fewest bytes a value can occupy, and the levels its
//! encoding nests. Each mirrors what the encoder charges — a composite
//! spends one level on its children, a run one on its elements, an
//! `Option` one on its payload, and a name none at all.

use crate::varint;

/// A type, as a static tree.
///
/// The vocabulary is what the encoding admits and nothing beside it, and
/// every run carries the cap its type states: a shape this describes has
/// a widest value, and [`max_encoded_len`] answers for every node.
#[derive(Debug, PartialEq, Eq)]
pub enum ShapeNode {
    /// One byte, `0` or `1`.
    Bool,
    /// An unsigned 8-bit integer. Every integer is little-endian at its
    /// own width and carries no length.
    U8,
    /// An unsigned 16-bit integer.
    U16,
    /// An unsigned 32-bit integer.
    U32,
    /// An unsigned 64-bit integer.
    U64,
    /// An unsigned 128-bit integer.
    U128,
    /// A signed 8-bit integer.
    I8,
    /// A signed 16-bit integer.
    I16,
    /// A signed 32-bit integer.
    I32,
    /// A signed 64-bit integer.
    I64,
    /// A signed 128-bit integer.
    I128,
    /// A length then at most `cap` bytes of UTF-8.
    ///
    /// The cap is bytes, not characters: it bounds the encoding, and
    /// UTF-8 is what the encoding carries.
    Text {
        /// The most bytes the text may occupy after its length.
        cap: usize,
    },
    /// Exactly this many bytes, with no length field of its own.
    ByteArray(usize),
    /// A length then at most `cap` elements.
    Seq {
        /// The most elements a value may hold.
        cap: usize,
        /// What each element is.
        element: &'static Self,
    },
    /// A length then at most `cap` elements, strictly ascending.
    Set {
        /// The most elements a value may hold.
        cap: usize,
        /// What each element is.
        element: &'static Self,
    },
    /// A length then at most `cap` key-value pairs, keys strictly
    /// ascending.
    Map {
        /// The most pairs a value may hold.
        cap: usize,
        /// The key's shape.
        key: &'static Self,
        /// The value's shape.
        value: &'static Self,
    },
    /// `0`, or `1` followed by the payload.
    Option(&'static Self),
    /// Its elements in order, with nothing between them. Also what a
    /// tuple struct, a tuple variant, and a unit are.
    Tuple(&'static [&'static Self]),
    /// Its fields in declaration order, each under the name that turns a
    /// decoded position into a fact.
    Struct(&'static [(&'static str, &'static Self)]),
    /// A one-byte discriminant then that variant's content: each
    /// variant's name, the byte the wire carries, and what follows it.
    Enum(&'static [(&'static str, u8, &'static Self)]),
    /// A declared type's name over its definition.
    ///
    /// Not a layer on the wire — the folds pass straight through — and
    /// what a consumer names the type by, so an address survives the
    /// encoding that erases it.
    Named {
        /// The name the type publishes under.
        name: &'static str,
        /// What the name stands for.
        shape: &'static Self,
    },
}

/// A type with a bound on its encoding, read off its shape.
///
/// What sizes a stack buffer an event encodes into, a leaf's width in a
/// package's declaration, and the decoder cap a record is read under —
/// each a constant beside the type rather than a figure written by hand.
pub trait HborBound {
    /// The most bytes this type's encoding can occupy.
    ///
    /// A bound rather than a width, because `Option<T>` is one byte or
    /// one more than `T` — so a type holding one has no single length,
    /// and what a caller can size a buffer from is the larger.
    const MAX_ENCODED_LEN: usize;
    /// The most levels this type's encoding nests, which is the decoder
    /// cap that admits exactly its values.
    const MAX_DEPTH: usize;
}

/// The most bytes any value of `node` can occupy.
///
/// Saturating: a hand-written node may claim widths that add past what an
/// address space holds, and a wrapped sum would understate them.
///
/// # Panics
///
/// On a run over an element that occupies no bytes, whose length is a
/// count no input pays for. A `const` context turns this into a compile
/// error on the type, which is where the codec refuses the same thing.
#[must_use]
pub const fn max_encoded_len(node: &ShapeNode) -> usize {
    match node {
        ShapeNode::Bool | ShapeNode::U8 | ShapeNode::I8 => 1,
        ShapeNode::U16 | ShapeNode::I16 => 2,
        ShapeNode::U32 | ShapeNode::I32 => 4,
        ShapeNode::U64 | ShapeNode::I64 => 8,
        ShapeNode::U128 | ShapeNode::I128 => 16,
        ShapeNode::Text { cap } => varint::encoded_len(*cap).saturating_add(*cap),
        ShapeNode::ByteArray(width) => *width,
        ShapeNode::Seq { cap, element } | ShapeNode::Set { cap, element } => {
            refuse_zero_width(min_encoded_len(element));
            varint::encoded_len(*cap).saturating_add(cap.saturating_mul(max_encoded_len(element)))
        }
        ShapeNode::Map { cap, key, value } => {
            refuse_zero_width(min_encoded_len(key).saturating_add(min_encoded_len(value)));
            let pair = max_encoded_len(key).saturating_add(max_encoded_len(value));
            varint::encoded_len(*cap).saturating_add(cap.saturating_mul(pair))
        }
        ShapeNode::Option(held) => max_encoded_len(held).saturating_add(1),
        ShapeNode::Tuple(elements) => {
            let mut sum = 0usize;
            let mut i = 0;
            while i < elements.len() {
                sum = sum.saturating_add(max_encoded_len(elements[i]));
                i += 1;
            }
            sum
        }
        ShapeNode::Struct(fields) => {
            let mut sum = 0usize;
            let mut i = 0;
            while i < fields.len() {
                sum = sum.saturating_add(max_encoded_len(fields[i].1));
                i += 1;
            }
            sum
        }
        // The discriminant, then the widest variant's content.
        ShapeNode::Enum(variants) => {
            let mut widest = 0usize;
            let mut i = 0;
            while i < variants.len() {
                let most = max_encoded_len(variants[i].2);
                if most > widest {
                    widest = most;
                }
                i += 1;
            }
            widest.saturating_add(1)
        }
        ShapeNode::Named { shape, .. } => max_encoded_len(shape),
    }
}

/// The fewest bytes any value of `node` can occupy.
///
/// What bounds a claimed length against the bytes that remain, on the
/// same terms [`HborWidth::MIN_ENCODED_LEN`](crate::HborWidth) states for
/// a type: a fixed-width leaf is its width, and anything behind a length
/// is the one byte an empty length takes.
#[must_use]
pub const fn min_encoded_len(node: &ShapeNode) -> usize {
    match node {
        // The one-byte scalars, and the one byte an empty length or an
        // absent payload takes.
        ShapeNode::Bool
        | ShapeNode::U8
        | ShapeNode::I8
        | ShapeNode::Text { .. }
        | ShapeNode::Seq { .. }
        | ShapeNode::Set { .. }
        | ShapeNode::Map { .. }
        | ShapeNode::Option(_) => 1,
        ShapeNode::U16 | ShapeNode::I16 => 2,
        ShapeNode::U32 | ShapeNode::I32 => 4,
        ShapeNode::U64 | ShapeNode::I64 => 8,
        ShapeNode::U128 | ShapeNode::I128 => 16,
        ShapeNode::ByteArray(width) => *width,
        ShapeNode::Tuple(elements) => {
            let mut sum = 0usize;
            let mut i = 0;
            while i < elements.len() {
                sum = sum.saturating_add(min_encoded_len(elements[i]));
                i += 1;
            }
            sum
        }
        ShapeNode::Struct(fields) => {
            let mut sum = 0usize;
            let mut i = 0;
            while i < fields.len() {
                sum = sum.saturating_add(min_encoded_len(fields[i].1));
                i += 1;
            }
            sum
        }
        // The discriminant, then the lightest variant's content; an enum
        // with no variants is its discriminant alone.
        ShapeNode::Enum(variants) => {
            let mut lightest = usize::MAX;
            let mut i = 0;
            while i < variants.len() {
                let least = min_encoded_len(variants[i].2);
                if least < lightest {
                    lightest = least;
                }
                i += 1;
            }
            if variants.is_empty() {
                1
            } else {
                lightest.saturating_add(1)
            }
        }
        ShapeNode::Named { shape, .. } => min_encoded_len(shape),
    }
}

/// The levels a value of `node` nests, as the encoder charges them.
///
/// A composite spends one level on its children where it has any, a run
/// one on its elements, and an `Option` one on its payload; a leaf and a
/// name spend none. A decoder whose cap is this figure admits every value
/// of the type and nothing deeper.
#[must_use]
pub const fn max_depth(node: &ShapeNode) -> usize {
    match node {
        ShapeNode::Bool
        | ShapeNode::U8
        | ShapeNode::U16
        | ShapeNode::U32
        | ShapeNode::U64
        | ShapeNode::U128
        | ShapeNode::I8
        | ShapeNode::I16
        | ShapeNode::I32
        | ShapeNode::I64
        | ShapeNode::I128
        | ShapeNode::Text { .. }
        | ShapeNode::ByteArray(_) => 0,
        ShapeNode::Seq { element, .. } | ShapeNode::Set { element, .. } => max_depth(element) + 1,
        ShapeNode::Map { key, value, .. } => {
            let key = max_depth(key);
            let value = max_depth(value);
            if key > value { key + 1 } else { value + 1 }
        }
        ShapeNode::Option(held) => max_depth(held) + 1,
        ShapeNode::Tuple(elements) => {
            if elements.is_empty() {
                return 0;
            }
            let mut deepest = 0usize;
            let mut i = 0;
            while i < elements.len() {
                let depth = max_depth(elements[i]);
                if depth > deepest {
                    deepest = depth;
                }
                i += 1;
            }
            deepest + 1
        }
        ShapeNode::Struct(fields) => {
            if fields.is_empty() {
                return 0;
            }
            let mut deepest = 0usize;
            let mut i = 0;
            while i < fields.len() {
                let depth = max_depth(fields[i].1);
                if depth > deepest {
                    deepest = depth;
                }
                i += 1;
            }
            deepest + 1
        }
        // The discriminant is a byte the enum writes itself; every level
        // below it belongs to the variant's own content.
        ShapeNode::Enum(variants) => {
            let mut deepest = 0usize;
            let mut i = 0;
            while i < variants.len() {
                let depth = max_depth(variants[i].2);
                if depth > deepest {
                    deepest = depth;
                }
                i += 1;
            }
            deepest
        }
        ShapeNode::Named { shape, .. } => max_depth(shape),
    }
}

const fn refuse_zero_width(least: usize) {
    assert!(
        least > 0,
        "a run over an element that carries no bytes is a count nothing pays for"
    );
}
