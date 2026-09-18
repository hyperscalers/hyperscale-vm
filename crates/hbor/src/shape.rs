//! Describing a type to a consumer that does not have it.
//!
//! The encoding is schema-external: bytes carry content and nothing else,
//! so a decoder without the type decodes nothing. A shape is that type
//! written down — enough to walk a payload and name what was read, and
//! no more. It says how to decode, never how to render.
//!
//! Shapes compose the way the codec composes. [`HborShape`] is derived
//! beside [`HborEncode`](crate::HborEncode) and states a struct's node
//! from its fields' own, so the two cannot describe different bytes.
//! Nothing on the codec path reads one.
//!
//! # Two forms
//!
//! What Rust states is a static tree: a type's [`ShapeNode`], holding its
//! children by `'static` reference, which is the form a `const` can carry
//! and a generic impl can compose. What a consumer decodes is a
//! [`ShapeTable`]: one flat array of [`TypeShape`] nodes, each naming its
//! children by index, built from the trees at publish. A child sits at a
//! lower index than every node that names it, so a table is acyclic by
//! the same fact that makes a tree finite, and one pass over it in index
//! order measures every node off children already measured. A subtree
//! two types share is written once.
//!
//! A name is an annotation on a node — [`TypeShape::Named`] — and not a
//! layer on the wire: the folds pass straight through it, and it is what
//! a consumer finds a type by. A `transparent` wrapper is a name the
//! wire drops, so it carries none and describes as its inner type. A
//! type whose *name* is what a consumer needs states its node by hand.

use std::collections::BTreeSet;
use std::fmt;

use crate::decode::Decoder;
use crate::encode::{Encoder, Sink};
use crate::error::{DecodeError, EncodeError};
use crate::name::{MalformedName, Name};
use crate::node::{ShapeNode, max_depth, max_encoded_len};
use crate::{
    DEFAULT_MAX_DEPTH, Hbor, HborBound, HborDecode, HborEncode, HborWidth, bounded, varint,
};

/// The levels of a shape's own tree that a reader of one walks.
///
/// [`DEFAULT_MAX_DEPTH`] bounds the levels a *value* nests, and that is
/// not what bounds a walk over the shape: a name and a discriminant are
/// nodes the encoding spends no level on, so a shape stands taller than
/// its values nest. Between two levels a decoder follows there is at
/// most one of each, so a shape a decoder follows stands at most three
/// times as tall, and one more for the name over its root.
const MAX_SHAPE_HEIGHT: usize = 3 * DEFAULT_MAX_DEPTH + 1;

/// A node's place in a [`ShapeTable`]: its index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(crate = crate, transparent)]
pub struct NodeId(pub u32);

impl NodeId {
    fn at(index: usize) -> Self {
        Self(u32::try_from(index).expect("a table shorter than u32"))
    }

    const fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// One node of a published shape, as a consumer without the type must
/// read it.
///
/// The vocabulary is what the encoding admits and nothing beside it, and
/// every run carries the cap its type states: there is no form here that
/// no value can be written in, and none whose widest value is unknown.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(crate = crate)]
pub enum TypeShape {
    /// One byte, `0` or `1`.
    #[hbor(discriminant = 0)]
    Bool,
    /// An unsigned 8-bit integer. Every integer is little-endian at its
    /// own width and carries no length.
    #[hbor(discriminant = 1)]
    U8,
    /// An unsigned 16-bit integer.
    #[hbor(discriminant = 2)]
    U16,
    /// An unsigned 32-bit integer.
    #[hbor(discriminant = 3)]
    U32,
    /// An unsigned 64-bit integer.
    #[hbor(discriminant = 4)]
    U64,
    /// An unsigned 128-bit integer.
    #[hbor(discriminant = 5)]
    U128,
    /// A signed 8-bit integer.
    #[hbor(discriminant = 6)]
    I8,
    /// A signed 16-bit integer.
    #[hbor(discriminant = 7)]
    I16,
    /// A signed 32-bit integer.
    #[hbor(discriminant = 8)]
    I32,
    /// A signed 64-bit integer.
    #[hbor(discriminant = 9)]
    I64,
    /// A signed 128-bit integer.
    #[hbor(discriminant = 10)]
    I128,
    /// A length then at most `cap` bytes of UTF-8.
    ///
    /// Separate from a byte sequence because the validity is a decoding
    /// fact: bytes that are not UTF-8 are not a value of this shape. The
    /// cap is bytes, not characters: it bounds the encoding.
    #[hbor(discriminant = 11)]
    Text {
        /// The most bytes the text may occupy after its length.
        cap: u32,
    },
    /// Exactly this many bytes, with no length field of its own.
    #[hbor(discriminant = 12)]
    ByteArray(u32),
    /// A length then at most `cap` elements.
    #[hbor(discriminant = 13)]
    Seq {
        /// The most elements a value may hold.
        cap: u32,
        /// What each element is.
        element: NodeId,
    },
    /// A length then at most `cap` elements, strictly ascending.
    #[hbor(discriminant = 14)]
    Set {
        /// The most elements a value may hold.
        cap: u32,
        /// What each element is.
        element: NodeId,
    },
    /// A length then at most `cap` key-value pairs, keys strictly
    /// ascending.
    #[hbor(discriminant = 15)]
    Map {
        /// The most pairs a value may hold.
        cap: u32,
        /// The key's shape.
        key: NodeId,
        /// The value's shape.
        value: NodeId,
    },
    /// `0`, or `1` followed by the payload.
    #[hbor(discriminant = 16)]
    Option(NodeId),
    /// Its elements in order, with nothing between them. Also what a
    /// tuple struct, a tuple variant, and a unit are.
    #[hbor(discriminant = 17)]
    Tuple(Vec<NodeId>),
    /// Its fields in declaration order. The names are the whole reason a
    /// decoded position becomes a fact.
    #[hbor(discriminant = 18)]
    Struct(Vec<ShapeField>),
    /// A one-byte discriminant then that variant's content.
    #[hbor(discriminant = 19)]
    Enum(Vec<ShapeVariant>),
    /// A declared type's name over its definition.
    ///
    /// Not a layer on the wire, and what a consumer finds the type by:
    /// an address survives the encoding that erases it because its
    /// thirty-two bytes sit under this.
    #[hbor(discriminant = 20)]
    Named {
        /// The name the type publishes under.
        name: Name,
        /// What the name stands for.
        shape: NodeId,
    },
}

/// One named field of a struct.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(crate = crate)]
pub struct ShapeField {
    /// The field's name, as its author spelled it.
    pub name: Name,
    /// What the field holds.
    pub shape: NodeId,
}

/// One variant of an enum.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(crate = crate)]
pub struct ShapeVariant {
    /// The variant's name, as its author spelled it.
    pub name: Name,
    /// The byte the wire carries. Stated rather than positional, because
    /// a variant may pin its own and the position would then be a second
    /// answer.
    pub discriminant: u8,
    /// What follows the discriminant: a [`TypeShape::Struct`] for named
    /// fields, a [`TypeShape::Tuple`] otherwise — empty for a unit.
    pub content: NodeId,
}

/// Why a node cannot join a table.
///
/// Every one of these is refused where a node is added — at publish, and
/// at decode node by node — so a [`ShapeTable`] that exists is one every
/// consumer can walk.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShapeFault {
    /// A reference to a node the table does not hold before this one.
    ///
    /// A child sits below every node that names it, which is what makes
    /// a table acyclic: a reference upward or outward is refused here,
    /// and nothing afterwards can meet a cycle.
    #[error("shape references node {0}, which the table does not hold before it")]
    Unresolved(NodeId),
    /// A node repeating one the table already holds.
    ///
    /// A subtree is written once, so a decoded table that spells one
    /// twice is not the table its publisher built.
    #[error("node {0} repeats an earlier node")]
    Duplicate(NodeId),
    /// A shape nesting past the levels a decoder follows.
    ///
    /// A shape deeper than the decoder's cap describes values no decoder
    /// admits, and is refused for that reason and no other.
    #[error("shape nests past the {DEFAULT_MAX_DEPTH} levels a decoder follows")]
    TooDeep,
    /// A shape standing taller than a reader of one walks.
    ///
    /// A name and a discriminant are levels of the tree that the encoding
    /// spends nothing on, so a shape can stand taller than the values it
    /// describes nest — and what walks a shape recurses over the tree
    /// rather than over the encoding. Refused so a shape a consumer
    /// holds is one a consumer can read.
    #[error("shape stands past the {MAX_SHAPE_HEIGHT} levels a reader of one walks")]
    TooTall,
    /// A sequence, set, or map over an element that occupies no bytes.
    ///
    /// A length is then a count no input pays for, so a claimed one
    /// cannot be bounded by the bytes that remain. The codec refuses the
    /// same thing at compile time, where a `Vec<()>` is unwritable.
    #[error("a run over an element that carries no bytes is a count nothing pays for")]
    ZeroWidth,
    /// Two fields of one struct, or two variants of one enum, under one
    /// name.
    ///
    /// The name is what turns a decoded position into a fact, so a name
    /// covering two of them is two answers to the question a consumer
    /// asks. A declaration cannot spell this — Rust names a type's
    /// members once each — so nothing a derive writes is refused here.
    #[error("{0:?} names two members of one type, so keying by it has two answers")]
    AmbiguousName(String),
    /// Two variants of one enum on one discriminant.
    ///
    /// The byte is what selects a variant, so the second is a name no
    /// payload ever reaches. The codec refuses the same collision where
    /// a variant is declared; a shape is data, so the refusal moves to
    /// where it is read.
    #[error("discriminant {0} selects two variants, so one of them is unreachable")]
    AmbiguousDiscriminant(u8),
    /// Two types under one name.
    ///
    /// A consumer finds a type by its name, so a second definition under
    /// it would leave the lookup with two answers. Two of a package's own
    /// types cannot reach one name, because a name is the identifier that
    /// declared it.
    #[error("{0:?} names two types, so finding one by it has two answers")]
    NameTaken(String),
    /// A name no identifier could have spelled.
    ///
    /// A tree states its names as `&'static str`, so a hand-written impl
    /// can write one the macro would have refused.
    #[error("{name:?}: {source}")]
    Malformed {
        /// The string that is not a name.
        name: String,
        /// What is wrong with it.
        #[source]
        source: MalformedName,
    },
}

impl ShapeFault {
    /// The fault as the decoder reports it, where a table is read.
    const fn reason(&self) -> &'static str {
        match self {
            Self::Unresolved(_) => "shape references a node the table does not hold before it",
            Self::Duplicate(_) => "shape table repeats a node",
            Self::TooDeep => "shape nests past the levels a decoder follows",
            Self::TooTall => "shape stands past the levels a reader of one walks",
            Self::ZeroWidth => "shape runs over an element that carries no bytes",
            Self::AmbiguousName(_) => "shape names two members of one type alike",
            Self::AmbiguousDiscriminant(_) => "shape selects two variants by one discriminant",
            Self::NameTaken(_) => "shape table names two types alike",
            Self::Malformed { .. } => "shape names a type as no identifier could",
        }
    }
}

/// Every name in one composite its own.
///
/// # Errors
///
/// [`ShapeFault::AmbiguousName`] for the first name seen twice.
fn distinct<'s>(names: impl Iterator<Item = &'s str>) -> Result<(), ShapeFault> {
    let mut seen = BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(ShapeFault::AmbiguousName(name.to_owned()));
        }
    }
    Ok(())
}

/// What one node measures: the levels a value of it nests, the levels
/// the node itself stands, and the fewest and the most bytes one value
/// can occupy.
///
/// Every sum is saturating: a shape is data, so it may claim widths that
/// add past what an address space holds, and a wrapped sum would
/// understate what a run costs and let a claimed length past the bytes
/// that must pay for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Measure {
    /// The levels a value of the node nests, as the encoder charges
    /// them. A name costs none: it is not on the wire.
    depth: usize,
    /// The levels the node itself stands over its leaves, which is what
    /// a walk over the shape recurses through. Every node costs one,
    /// the ones the encoding spends nothing on included.
    height: usize,
    /// The fewest bytes any value of the node occupies.
    least: usize,
    /// The most bytes any value of the node occupies.
    most: usize,
}

impl Measure {
    /// A scalar: no levels under it, and its own width.
    const fn leaf(width: usize) -> Self {
        Self {
            depth: 0,
            height: 1,
            least: width,
            most: width,
        }
    }

    /// A run of at most `cap` elements each measuring `element`: a length
    /// then the elements, one byte at its shortest, and one level down.
    const fn run(cap: u32, element: Self) -> Result<Self, ShapeFault> {
        if element.least == 0 {
            return Err(ShapeFault::ZeroWidth);
        }
        let cap = cap as usize;
        Ok(Self {
            depth: element.depth + 1,
            height: element.height + 1,
            least: 1,
            most: varint::encoded_len(cap).saturating_add(cap.saturating_mul(element.most)),
        })
    }

    /// A composite's children, walked one level down: their widths sum,
    /// and the decoder's level is spent only where there is a child to
    /// spend it on.
    fn under(children: impl Iterator<Item = Self>) -> Self {
        let mut deepest = None::<usize>;
        let mut tallest = 0usize;
        let mut least = 0usize;
        let mut most = 0usize;
        for child in children {
            deepest = Some(deepest.map_or(child.depth, |seen| seen.max(child.depth)));
            tallest = tallest.max(child.height);
            least = least.saturating_add(child.least);
            most = most.saturating_add(child.most);
        }
        Self {
            depth: deepest.map_or(0, |depth| depth + 1),
            height: tallest + 1,
            least,
            most,
        }
    }
}

/// A package's shapes, as a consumer decodes them: one flat array of
/// nodes, every child below the node that names it.
///
/// Built by adding nodes — from a type's static tree through
/// [`declare`](Self::declare), or one at a time through
/// [`push`](Self::push) — and each is measured as it joins, off children
/// already measured, so every width, every depth and every fault is
/// settled before the node exists. A table decoded off the wire goes
/// through the same door node by node. So there is no table a consumer
/// cannot walk, and what [`most`](Self::most), [`least`](Self::least)
/// and [`depth`](Self::depth) answer is a field read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShapeTable {
    nodes: Vec<TypeShape>,
    measures: Vec<Measure>,
}

impl ShapeTable {
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            measures: Vec::new(),
        }
    }

    /// The table holding `T`'s tree and nothing else, with the node
    /// `T` describes as.
    ///
    /// # Panics
    ///
    /// On a tree the decoder could not follow, which a derived type
    /// cannot state.
    #[must_use]
    pub fn of<T: HborShape>() -> (Self, NodeId) {
        let mut table = Self::new();
        let root = table
            .declare(T::NODE)
            .expect("a type's own tree is one a decoder follows");
        (table, root)
    }

    /// Whether the table holds no node.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// How many nodes the table holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Every node, in index order.
    pub fn nodes(&self) -> impl Iterator<Item = (NodeId, &TypeShape)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (NodeId::at(index), node))
    }

    /// The node at `id`, where the table holds one.
    #[must_use]
    pub fn get(&self, id: NodeId) -> Option<&TypeShape> {
        self.nodes.get(id.index())
    }

    /// The node at `id`.
    ///
    /// # Panics
    ///
    /// On an id the table does not hold. Every id a table hands out is
    /// its own; one carried in from elsewhere goes through
    /// [`get`](Self::get) first.
    fn node(&self, id: NodeId) -> &TypeShape {
        self.get(id)
            .unwrap_or_else(|| panic!("node {id} is not in this table"))
    }

    fn measure_of(&self, id: NodeId) -> Measure {
        self.measures
            .get(id.index())
            .copied()
            .unwrap_or_else(|| panic!("node {id} is not in this table"))
    }

    /// The most bytes any value of `id` can occupy.
    ///
    /// What sizes a leaf's width from its type alone.
    ///
    /// # Panics
    ///
    /// On an id the table does not hold.
    #[must_use]
    pub fn most(&self, id: NodeId) -> usize {
        self.measure_of(id).most
    }

    /// The fewest bytes any value of `id` can occupy.
    ///
    /// What bounds a claimed length against the bytes that remain, on
    /// the same terms [`HborWidth::MIN_ENCODED_LEN`] states for a type.
    ///
    /// # Panics
    ///
    /// On an id the table does not hold.
    #[must_use]
    pub fn least(&self, id: NodeId) -> usize {
        self.measure_of(id).least
    }

    /// The levels a value of `id` nests, which is the decoder cap that
    /// admits exactly its values.
    ///
    /// # Panics
    ///
    /// On an id the table does not hold.
    #[must_use]
    pub fn depth(&self, id: NodeId) -> usize {
        self.measure_of(id).depth
    }

    /// The type published under `name`, where the table holds one.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<NodeId> {
        self.names()
            .find_map(|(held, id)| (held == name).then_some(id))
    }

    /// Every published type, by name, in index order.
    pub fn names(&self) -> impl Iterator<Item = (&Name, NodeId)> {
        self.nodes().filter_map(|(id, node)| match node {
            TypeShape::Named { name, .. } => Some((name, id)),
            _ => None,
        })
    }

    /// The child a reference names, where the table holds it below the
    /// node being added.
    fn held(&self, id: NodeId) -> Result<Measure, ShapeFault> {
        self.measures
            .get(id.index())
            .copied()
            .ok_or(ShapeFault::Unresolved(id))
    }

    /// What `node` would measure, off the children the table holds.
    fn measure(&self, node: &TypeShape) -> Result<Measure, ShapeFault> {
        Ok(match node {
            TypeShape::Bool | TypeShape::U8 | TypeShape::I8 => Measure::leaf(1),
            TypeShape::U16 | TypeShape::I16 => Measure::leaf(2),
            TypeShape::U32 | TypeShape::I32 => Measure::leaf(4),
            TypeShape::U64 | TypeShape::I64 => Measure::leaf(8),
            TypeShape::U128 | TypeShape::I128 => Measure::leaf(16),
            TypeShape::Text { cap } => {
                let cap = *cap as usize;
                Measure {
                    depth: 0,
                    height: 1,
                    least: 1,
                    most: varint::encoded_len(cap).saturating_add(cap),
                }
            }
            TypeShape::ByteArray(width) => Measure::leaf(*width as usize),
            TypeShape::Seq { cap, element } | TypeShape::Set { cap, element } => {
                Measure::run(*cap, self.held(*element)?)?
            }
            TypeShape::Map { cap, key, value } => {
                let key = self.held(*key)?;
                let value = self.held(*value)?;
                let pair = Measure {
                    depth: key.depth.max(value.depth),
                    height: key.height.max(value.height),
                    least: key.least.saturating_add(value.least),
                    most: key.most.saturating_add(value.most),
                };
                Measure::run(*cap, pair)?
            }
            // The discriminant byte, with `None` carrying nothing beside
            // it.
            TypeShape::Option(held) => {
                let held = self.held(*held)?;
                Measure {
                    depth: held.depth + 1,
                    height: held.height + 1,
                    least: 1,
                    most: held.most.saturating_add(1),
                }
            }
            TypeShape::Tuple(elements) => {
                let mut children = Vec::with_capacity(elements.len());
                for element in elements {
                    children.push(self.held(*element)?);
                }
                Measure::under(children.into_iter())
            }
            TypeShape::Struct(fields) => {
                distinct(fields.iter().map(|field| field.name.as_str()))?;
                let mut children = Vec::with_capacity(fields.len());
                for field in fields {
                    children.push(self.held(field.shape)?);
                }
                Measure::under(children.into_iter())
            }
            // The discriminant is a byte the enum writes itself; every
            // level below it belongs to the variant's own content, and
            // the lightest variant is what no encoding is shorter than.
            TypeShape::Enum(variants) => {
                distinct(variants.iter().map(|variant| variant.name.as_str()))?;
                let mut selected = BTreeSet::new();
                let mut deepest = 0usize;
                let mut tallest = 0usize;
                let mut lightest = None::<usize>;
                let mut widest = 0usize;
                for variant in variants {
                    if !selected.insert(variant.discriminant) {
                        return Err(ShapeFault::AmbiguousDiscriminant(variant.discriminant));
                    }
                    let content = self.held(variant.content)?;
                    deepest = deepest.max(content.depth);
                    tallest = tallest.max(content.height);
                    lightest = Some(lightest.map_or(content.least, |seen| seen.min(content.least)));
                    widest = widest.max(content.most);
                }
                Measure {
                    depth: deepest,
                    height: tallest + 1,
                    least: lightest.unwrap_or(0).saturating_add(1),
                    most: widest.saturating_add(1),
                }
            }
            // A name is not a level on the wire, so it measures as what
            // it names — but it is a level of the tree, which is what a
            // reader of the shape walks.
            TypeShape::Named { name, shape } => {
                if self.named(name).is_some() {
                    return Err(ShapeFault::NameTaken(name.to_string()));
                }
                let held = self.held(*shape)?;
                Measure {
                    height: held.height + 1,
                    ..held
                }
            }
        })
    }

    /// Add `node`, or find it where the table already holds it.
    ///
    /// Measured as it joins, off children the table holds — so every
    /// reference resolves downward, no run is over an element carrying
    /// no bytes, no name covers two members and no discriminant two
    /// variants, nothing nests past what a decoder follows, and nothing
    /// stands past what a reader of a shape walks. A node equal to one
    /// already held is that node, found rather than added: a subtree is
    /// written once.
    ///
    /// # Errors
    ///
    /// [`ShapeFault`] for a node the table cannot hold.
    pub fn push(&mut self, node: TypeShape) -> Result<NodeId, ShapeFault> {
        if let Some(index) = self.nodes.iter().position(|held| *held == node) {
            return Ok(NodeId::at(index));
        }
        let measure = self.measure(&node)?;
        if measure.depth > DEFAULT_MAX_DEPTH {
            return Err(ShapeFault::TooDeep);
        }
        if measure.height > MAX_SHAPE_HEIGHT {
            return Err(ShapeFault::TooTall);
        }
        let id = NodeId::at(self.nodes.len());
        self.nodes.push(node);
        self.measures.push(measure);
        Ok(id)
    }

    /// Add a type's static tree, and answer the node it describes as.
    ///
    /// Children first, so every node is added once its children are
    /// held; a subtree the table already holds — a type reached from two
    /// places, or a name reached twice — is found rather than written
    /// again.
    ///
    /// # Errors
    ///
    /// [`ShapeFault`], as [`push`](Self::push).
    ///
    /// # Panics
    ///
    /// On a cap or a width past what the wire carries, which no type
    /// the codec admits states.
    pub fn declare(&mut self, node: &ShapeNode) -> Result<NodeId, ShapeFault> {
        let wide = |width: usize| u32::try_from(width).expect("a width the wire carries");
        let named = |text: &'static str| {
            Name::new(text.to_owned()).map_err(|source| ShapeFault::Malformed {
                name: text.to_owned(),
                source,
            })
        };
        let lowered = match node {
            ShapeNode::Bool => TypeShape::Bool,
            ShapeNode::U8 => TypeShape::U8,
            ShapeNode::U16 => TypeShape::U16,
            ShapeNode::U32 => TypeShape::U32,
            ShapeNode::U64 => TypeShape::U64,
            ShapeNode::U128 => TypeShape::U128,
            ShapeNode::I8 => TypeShape::I8,
            ShapeNode::I16 => TypeShape::I16,
            ShapeNode::I32 => TypeShape::I32,
            ShapeNode::I64 => TypeShape::I64,
            ShapeNode::I128 => TypeShape::I128,
            ShapeNode::Text { cap } => TypeShape::Text { cap: wide(*cap) },
            ShapeNode::ByteArray(width) => TypeShape::ByteArray(wide(*width)),
            ShapeNode::Seq { cap, element } => TypeShape::Seq {
                cap: wide(*cap),
                element: self.declare(element)?,
            },
            ShapeNode::Set { cap, element } => TypeShape::Set {
                cap: wide(*cap),
                element: self.declare(element)?,
            },
            ShapeNode::Map { cap, key, value } => TypeShape::Map {
                cap: wide(*cap),
                key: self.declare(key)?,
                value: self.declare(value)?,
            },
            ShapeNode::Option(held) => TypeShape::Option(self.declare(held)?),
            ShapeNode::Tuple(elements) => {
                let mut ids = Vec::with_capacity(elements.len());
                for element in *elements {
                    ids.push(self.declare(element)?);
                }
                TypeShape::Tuple(ids)
            }
            ShapeNode::Struct(fields) => {
                let mut declared = Vec::with_capacity(fields.len());
                for (name, shape) in *fields {
                    declared.push(ShapeField {
                        name: named(name)?,
                        shape: self.declare(shape)?,
                    });
                }
                TypeShape::Struct(declared)
            }
            ShapeNode::Enum(variants) => {
                let mut declared = Vec::with_capacity(variants.len());
                for (name, discriminant, content) in *variants {
                    declared.push(ShapeVariant {
                        name: named(name)?,
                        discriminant: *discriminant,
                        content: self.declare(content)?,
                    });
                }
                TypeShape::Enum(declared)
            }
            ShapeNode::Named { name, shape } => {
                let declared = named(name)?;
                let shape = self.declare(shape)?;
                // The name reached a second time is the same type reached
                // a second way, and the same node.
                if let Some(id) = self.named(name) {
                    if self.node(id)
                        == &(TypeShape::Named {
                            name: declared,
                            shape,
                        })
                    {
                        return Ok(id);
                    }
                    return Err(ShapeFault::NameTaken((*name).to_owned()));
                }
                TypeShape::Named {
                    name: declared,
                    shape,
                }
            }
        };
        self.push(lowered)
    }

    /// Whether the node at `id` describes the same values `node` does.
    ///
    /// What holds a package's definition of a protocol name to the
    /// protocol's own: the two are compared shape for shape, name for
    /// name, cap for cap.
    ///
    /// # Panics
    ///
    /// On an id the table does not hold.
    #[must_use]
    pub fn matches(&self, id: NodeId, node: &ShapeNode) -> bool {
        let same_cap = |cap: u32, stated: usize| cap as usize == stated;
        match (self.node(id), node) {
            (TypeShape::Bool, ShapeNode::Bool)
            | (TypeShape::U8, ShapeNode::U8)
            | (TypeShape::U16, ShapeNode::U16)
            | (TypeShape::U32, ShapeNode::U32)
            | (TypeShape::U64, ShapeNode::U64)
            | (TypeShape::U128, ShapeNode::U128)
            | (TypeShape::I8, ShapeNode::I8)
            | (TypeShape::I16, ShapeNode::I16)
            | (TypeShape::I32, ShapeNode::I32)
            | (TypeShape::I64, ShapeNode::I64)
            | (TypeShape::I128, ShapeNode::I128) => true,
            (TypeShape::Text { cap }, ShapeNode::Text { cap: stated }) => same_cap(*cap, *stated),
            (TypeShape::ByteArray(width), ShapeNode::ByteArray(stated)) => {
                same_cap(*width, *stated)
            }
            (
                TypeShape::Seq { cap, element },
                ShapeNode::Seq {
                    cap: stated,
                    element: held,
                },
            )
            | (
                TypeShape::Set { cap, element },
                ShapeNode::Set {
                    cap: stated,
                    element: held,
                },
            ) => same_cap(*cap, *stated) && self.matches(*element, held),
            (
                TypeShape::Map { cap, key, value },
                ShapeNode::Map {
                    cap: stated,
                    key: held_key,
                    value: held_value,
                },
            ) => {
                same_cap(*cap, *stated)
                    && self.matches(*key, held_key)
                    && self.matches(*value, held_value)
            }
            (TypeShape::Option(held), ShapeNode::Option(stated)) => self.matches(*held, stated),
            (TypeShape::Tuple(elements), ShapeNode::Tuple(stated)) => {
                elements.len() == stated.len()
                    && elements
                        .iter()
                        .zip(*stated)
                        .all(|(element, held)| self.matches(*element, held))
            }
            (TypeShape::Struct(fields), ShapeNode::Struct(stated)) => {
                fields.len() == stated.len()
                    && fields.iter().zip(*stated).all(|(field, (name, held))| {
                        field.name == *name && self.matches(field.shape, held)
                    })
            }
            (TypeShape::Enum(variants), ShapeNode::Enum(stated)) => {
                variants.len() == stated.len()
                    && variants.iter().zip(*stated).all(
                        |(variant, (name, discriminant, content))| {
                            variant.name == *name
                                && variant.discriminant == *discriminant
                                && self.matches(variant.content, content)
                        },
                    )
            }
            (
                TypeShape::Named { name, shape },
                ShapeNode::Named {
                    name: stated,
                    shape: held,
                },
            ) => name == stated && self.matches(*shape, held),
            _ => false,
        }
    }

    /// Read one complete value of the node at `root` from `bytes`.
    ///
    /// What a consumer holding a package's metadata and a payload does
    /// with the two. The bytes must be exactly one value: anything left
    /// over is a payload the shape does not describe.
    ///
    /// Checked is everything the shape can know — every width, every
    /// length minimal, under its cap and payable by the bytes that
    /// remain, text valid UTF-8, every discriminant declared, no byte
    /// unaccounted for, and no member of a set or key of a map encoded
    /// twice: under canonicity one value has one encoding, so two members
    /// with the same bytes are one member, which the type-erased reader
    /// can see without knowing the type. Not checked is the ascent of
    /// those keys: that order is the element type's own, and a shape
    /// carries structure rather than a comparison. A reader rejecting on
    /// a guess at it would refuse payloads the chain accepted.
    ///
    /// So `read` is not a canonicity gate, where the codec is: two byte
    /// strings differing only in the order of a set's or a map's members
    /// both read here, to values that keep the wire's order and so
    /// compare unequal. A caller that needs one byte string per value —
    /// because it hashes the bytes, or trusts what it read to re-encode
    /// identically — must hold that itself, or read only bytes the codec
    /// already wrote. The package-metadata readers that read state leaves
    /// do the latter: a leaf is bytes the encoder wrote canonically. An
    /// event payload is not — it is guest bytes the kernel bounds in
    /// length but does not canonicalize — so a reader that hashes or
    /// re-encodes one canonicalizes it first.
    ///
    /// Nesting is bounded by the table: every node joined it measured,
    /// and none stands past the levels a reader of a shape walks, so
    /// this recurses as far as the shape stands and no further however
    /// many elements a value holds. The levels a *value* nests are the
    /// smaller figure and not the one that bounds this — a name and a
    /// discriminant are levels here that the encoding spends nothing
    /// on.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for bytes the node does not describe.
    ///
    /// # Panics
    ///
    /// On an id the table does not hold.
    pub fn read(&self, root: NodeId, bytes: &[u8]) -> Result<ShapeValue, DecodeError> {
        let mut decoder = Decoder::new(bytes, DEFAULT_MAX_DEPTH);
        let value = self.read_from(root, &mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    /// Read one value of the node at `id`, leaving whatever follows it
    /// for the caller.
    fn read_from(&self, id: NodeId, decoder: &mut Decoder<'_>) -> Result<ShapeValue, DecodeError> {
        // Every width the encoding fixes, read as the little-endian run
        // it is.
        macro_rules! fixed {
            ($ty:ty, $variant:ident) => {{
                let bytes = decoder.read_array::<{ ::core::mem::size_of::<$ty>() }>()?;
                Ok(ShapeValue::$variant(<$ty>::from_le_bytes(bytes)))
            }};
        }
        match self.node(id) {
            TypeShape::Bool => match decoder.read_u8()? {
                0 => Ok(ShapeValue::Bool(false)),
                1 => Ok(ShapeValue::Bool(true)),
                other => Err(DecodeError::InvalidBool(other)),
            },
            TypeShape::U8 => fixed!(u8, U8),
            TypeShape::U16 => fixed!(u16, U16),
            TypeShape::U32 => fixed!(u32, U32),
            TypeShape::U64 => fixed!(u64, U64),
            TypeShape::U128 => fixed!(u128, U128),
            TypeShape::I8 => fixed!(i8, I8),
            TypeShape::I16 => fixed!(i16, I16),
            TypeShape::I32 => fixed!(i32, I32),
            TypeShape::I64 => fixed!(i64, I64),
            TypeShape::I128 => fixed!(i128, I128),
            TypeShape::Text { cap } => {
                bounded::decode_bounded_string(decoder, *cap as usize).map(ShapeValue::Text)
            }
            TypeShape::ByteArray(width) => Ok(ShapeValue::ByteArray(
                decoder.read_slice(*width as usize)?.to_vec(),
            )),
            TypeShape::Seq { cap, element } => self
                .read_run(decoder, *element, *cap, false)
                .map(ShapeValue::Seq),
            TypeShape::Set { cap, element } => self
                .read_run(decoder, *element, *cap, true)
                .map(ShapeValue::Set),
            TypeShape::Map { cap, key, value } => self.read_map(decoder, *key, *value, *cap),
            TypeShape::Option(held) => match decoder.read_u8()? {
                0 => Ok(ShapeValue::Option(None)),
                1 => self
                    .read_from(*held, decoder)
                    .map(|read| ShapeValue::Option(Some(Box::new(read)))),
                other => Err(DecodeError::InvalidDiscriminant(other)),
            },
            TypeShape::Tuple(elements) => {
                let mut read = Vec::with_capacity(elements.len());
                for element in elements {
                    read.push(self.read_from(*element, decoder)?);
                }
                Ok(ShapeValue::Tuple(read))
            }
            TypeShape::Struct(fields) => {
                let mut read = Vec::with_capacity(fields.len());
                for field in fields {
                    let value = self.read_from(field.shape, decoder)?;
                    read.push((field.name.clone(), value));
                }
                Ok(ShapeValue::Struct(read))
            }
            TypeShape::Enum(variants) => {
                let discriminant = decoder.read_u8()?;
                let variant = variants
                    .iter()
                    .find(|variant| variant.discriminant == discriminant)
                    .ok_or(DecodeError::InvalidDiscriminant(discriminant))?;
                Ok(ShapeValue::Variant {
                    name: variant.name.clone(),
                    discriminant,
                    content: Box::new(self.read_from(variant.content, decoder)?),
                })
            }
            TypeShape::Named { shape, .. } => self.read_from(*shape, decoder),
        }
    }

    /// A run of at most `cap` elements; `distinct` refuses one encoded
    /// twice.
    fn read_run(
        &self,
        decoder: &mut Decoder<'_>,
        element: NodeId,
        cap: u32,
        distinct: bool,
    ) -> Result<Vec<ShapeValue>, DecodeError> {
        let len = run_length(decoder, self.least(element), cap)?;
        let mut read = Vec::with_capacity(decoder.reserve_hint::<ShapeValue>(len));
        let mut spans = Vec::new();
        for _ in 0..len {
            let start = decoder.position();
            read.push(self.read_from(element, decoder)?);
            if distinct {
                spans.push(decoder.consumed(start));
            }
        }
        refuse_duplicates(spans)?;
        Ok(read)
    }

    /// The pairs of a map, at most `cap` of them and no key encoded
    /// twice.
    fn read_map(
        &self,
        decoder: &mut Decoder<'_>,
        key: NodeId,
        value: NodeId,
        cap: u32,
    ) -> Result<ShapeValue, DecodeError> {
        let pair = self.least(key).saturating_add(self.least(value));
        let len = run_length(decoder, pair, cap)?;
        let mut pairs = Vec::with_capacity(decoder.reserve_hint::<(ShapeValue, ShapeValue)>(len));
        let mut spans = Vec::with_capacity(pairs.capacity());
        for _ in 0..len {
            let start = decoder.position();
            let read = self.read_from(key, decoder)?;
            spans.push(decoder.consumed(start));
            pairs.push((read, self.read_from(value, decoder)?));
        }
        refuse_duplicates(spans)?;
        Ok(ShapeValue::Map(pairs))
    }
}

/// How many elements a run claims, bounded by what the bytes could pay
/// for and by the cap the node states.
///
/// The element's own minimum is what makes the first bound real, and the
/// cap is the type's own: a claimed length is refused on either before
/// anything is allocated for it.
fn run_length(decoder: &mut Decoder<'_>, least: usize, cap: u32) -> Result<usize, DecodeError> {
    bounded::check(decoder.read_len(least)?, cap as usize)
}

impl HborWidth for ShapeTable {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborEncode for ShapeTable {
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), EncodeError> {
        self.nodes.encode(encoder)
    }
}

/// Read node by node through the same door a published table was built
/// through, so a table that decodes is one every consumer can walk — and
/// the one its publisher built, down to each subtree written once.
impl HborDecode for ShapeTable {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let nodes: Vec<TypeShape> = decoder.nested()?;
        let mut table = Self::new();
        for (index, node) in nodes.into_iter().enumerate() {
            let expected = NodeId::at(index);
            let id = table
                .push(node)
                .map_err(|fault| DecodeError::FailedValidation(fault.reason()))?;
            if id != expected {
                return Err(DecodeError::FailedValidation(
                    ShapeFault::Duplicate(expected).reason(),
                ));
            }
        }
        Ok(table)
    }
}

/// A value read against a shape: what a consumer holding the bytes and
/// the [`ShapeTable`] gets back.
///
/// One variant per form the vocabulary admits, so a reader walks the
/// value the way it would have walked the shape. Field and variant names
/// ride along, because the name is what turns a decoded position into a
/// fact and re-reading the shape to recover it is a second walk over the
/// same ground.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShapeValue {
    /// A boolean.
    Bool(bool),
    /// An unsigned 8-bit integer.
    U8(u8),
    /// An unsigned 16-bit integer.
    U16(u16),
    /// An unsigned 32-bit integer.
    U32(u32),
    /// An unsigned 64-bit integer.
    U64(u64),
    /// An unsigned 128-bit integer.
    U128(u128),
    /// A signed 8-bit integer.
    I8(i8),
    /// A signed 16-bit integer.
    I16(i16),
    /// A signed 32-bit integer.
    I32(i32),
    /// A signed 64-bit integer.
    I64(i64),
    /// A signed 128-bit integer.
    I128(i128),
    /// Text.
    Text(String),
    /// A fixed-width run of bytes.
    ByteArray(Vec<u8>),
    /// A sequence's elements, in order.
    Seq(Vec<Self>),
    /// A set's elements, in the order they were written.
    Set(Vec<Self>),
    /// A map's pairs, in the order they were written.
    Map(Vec<(Self, Self)>),
    /// An optional payload.
    Option(Option<Box<Self>>),
    /// A tuple's elements. Also what a tuple struct and a unit read as.
    Tuple(Vec<Self>),
    /// A struct's fields, named and in declaration order.
    Struct(Vec<(Name, Self)>),
    /// The variant the discriminant selected, and what followed it.
    Variant {
        /// The variant's name.
        name: Name,
        /// The byte the wire carried.
        discriminant: u8,
        /// What followed it: a struct or a tuple.
        content: Box<Self>,
    },
}

/// Refuse a set or map that encodes one member twice.
///
/// Byte equality is the oracle: the encoding is canonical, so equal
/// members have equal bytes and unequal members do not, whatever their
/// type. Sorted by bytes rather than by the type's own order, which the
/// reader does not know and does not need for this.
fn refuse_duplicates(mut spans: Vec<&[u8]>) -> Result<(), DecodeError> {
    spans.sort_unstable();
    if spans.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DecodeError::UnsortedKeys);
    }
    Ok(())
}

/// A type that can describe itself to a consumer that does not have it.
///
/// Derived rather than written, so a shape and an encoding are one
/// derivation from one declaration. Nothing should ever author one by
/// hand except where the name is the point — the address family — and
/// there the hand impl is what carries the name the wire drops.
///
/// A type that reaches itself has no node: its constant would name
/// itself, which rustc refuses as a cycle on the impl. Such a type still
/// derives the codec; it has no finite widest value, so it has no shape
/// and no [`HborBound`].
pub trait HborShape {
    /// This type's shape: a node whose children are other types' nodes.
    const NODE: &'static ShapeNode;
}

/// Every shaped type states a bound, folded off its node: a shape
/// without one would be a leaf nothing can price.
impl<T: HborShape> HborBound for T {
    const MAX_ENCODED_LEN: usize = max_encoded_len(T::NODE);
    const MAX_DEPTH: usize = max_depth(T::NODE);
}

macro_rules! primitive {
    ($($ty:ty => $shape:ident),+ $(,)?) => {
        $(impl HborShape for $ty {
            const NODE: &'static ShapeNode = &ShapeNode::$shape;
        })+
    };
}

primitive! {
    bool => Bool,
    u8 => U8, u16 => U16, u32 => U32, u64 => U64, u128 => U128,
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
}

impl HborShape for () {
    const NODE: &'static ShapeNode = &ShapeNode::Tuple(&[]);
}

impl<const N: usize> HborShape for [u8; N] {
    const NODE: &'static ShapeNode = &ShapeNode::ByteArray(N);
}

impl<T: HborShape> HborShape for Option<T> {
    const NODE: &'static ShapeNode = &ShapeNode::Option(T::NODE);
}

// A box and an arc are names for a place: they encode as their contents
// and charge no level, so they describe as their contents too.
impl<T: HborShape + ?Sized> HborShape for Box<T> {
    const NODE: &'static ShapeNode = T::NODE;
}

impl<T: HborShape + ?Sized> HborShape for std::sync::Arc<T> {
    const NODE: &'static ShapeNode = T::NODE;
}

macro_rules! tuple {
    ($($name:ident),+) => {
        impl<$($name: HborShape),+> HborShape for ($($name,)+) {
            const NODE: &'static ShapeNode = &ShapeNode::Tuple(&[$($name::NODE),+]);
        }
    };
}

tuple!(A, B);
tuple!(A, B, C);
tuple!(A, B, C, D);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::min_encoded_len;
    use crate::{assert_canonical_at_depth, from_slice_with_depth, to_vec, to_vec_with_depth};

    /// Every form the vocabulary admits, in one table, so a round-trip
    /// covers the whole of it rather than the forms a real type reaches.
    fn every_form() -> (ShapeTable, NodeId, NodeId) {
        let mut table = ShapeTable::new();
        let mut push = |node| table.push(node).expect("a form the table holds");
        let unit = push(TypeShape::Tuple(Vec::new()));
        let i8 = push(TypeShape::I8);
        let boolean = push(TypeShape::Bool);
        let pair = push(TypeShape::Tuple(vec![i8, boolean]));
        let text = push(TypeShape::Text { cap: 300 });
        let named_text = push(TypeShape::Struct(vec![ShapeField {
            name: Name::declared("text"),
            shape: text,
        }]));
        let leaf = push(TypeShape::Enum(vec![
            ShapeVariant {
                name: Name::declared("Nothing"),
                discriminant: 0,
                content: unit,
            },
            ShapeVariant {
                name: Name::declared("Pair"),
                discriminant: 7,
                content: pair,
            },
            ShapeVariant {
                name: Name::declared("Named"),
                discriminant: 9,
                content: named_text,
            },
        ]));
        let leaf = push(TypeShape::Named {
            name: Name::declared("leaf"),
            shape: leaf,
        });
        let widths = [
            TypeShape::U8,
            TypeShape::U16,
            TypeShape::U32,
            TypeShape::U64,
            TypeShape::U128,
            TypeShape::I16,
            TypeShape::I32,
            TypeShape::I64,
            TypeShape::I128,
        ]
        .into_iter()
        .map(&mut push)
        .collect();
        let widths = push(TypeShape::Tuple(widths));
        let fixed = push(TypeShape::ByteArray(32));
        let maybe = push(TypeShape::Option(leaf));
        let byte = push(TypeShape::U8);
        let many = push(TypeShape::Seq {
            cap: 4,
            element: byte,
        });
        let word = push(TypeShape::U64);
        let distinct = push(TypeShape::Set {
            cap: 2,
            element: word,
        });
        let by_key = push(TypeShape::Map {
            cap: 3,
            key: text,
            value: leaf,
        });
        let whole = push(TypeShape::Struct(vec![
            ShapeField {
                name: Name::declared("widths"),
                shape: widths,
            },
            ShapeField {
                name: Name::declared("fixed"),
                shape: fixed,
            },
            ShapeField {
                name: Name::declared("maybe"),
                shape: maybe,
            },
            ShapeField {
                name: Name::declared("many"),
                shape: many,
            },
            ShapeField {
                name: Name::declared("distinct"),
                shape: distinct,
            },
            ShapeField {
                name: Name::declared("by_key"),
                shape: by_key,
            },
        ]));
        let whole = push(TypeShape::Named {
            name: Name::declared("whole"),
            shape: whole,
        });
        (table, leaf, whole)
    }

    /// A shape's wire discriminants, pinned the way every other wire
    /// enum's are: the metadata section, and so every package hash and
    /// every instance address derived from one, folds these bytes.
    #[test]
    fn every_shape_keeps_its_wire_discriminant() {
        let leaf = NodeId(0);
        let forms = [
            (0, TypeShape::Bool),
            (1, TypeShape::U8),
            (2, TypeShape::U16),
            (3, TypeShape::U32),
            (4, TypeShape::U64),
            (5, TypeShape::U128),
            (6, TypeShape::I8),
            (7, TypeShape::I16),
            (8, TypeShape::I32),
            (9, TypeShape::I64),
            (10, TypeShape::I128),
            (11, TypeShape::Text { cap: 1 }),
            (12, TypeShape::ByteArray(1)),
            (
                13,
                TypeShape::Seq {
                    cap: 1,
                    element: leaf,
                },
            ),
            (
                14,
                TypeShape::Set {
                    cap: 1,
                    element: leaf,
                },
            ),
            (
                15,
                TypeShape::Map {
                    cap: 1,
                    key: leaf,
                    value: leaf,
                },
            ),
            (16, TypeShape::Option(leaf)),
            (17, TypeShape::Tuple(vec![])),
            (18, TypeShape::Struct(vec![])),
            (19, TypeShape::Enum(vec![])),
            (
                20,
                TypeShape::Named {
                    name: Name::declared("leaf"),
                    shape: leaf,
                },
            ),
        ];
        assert_eq!(forms.len(), 21, "one row per variant");
        for (byte, shape) in forms {
            assert_eq!(
                to_vec(&shape).expect("a shape encodes")[0],
                byte,
                "{shape:?} moved off wire byte {byte}"
            );
        }
    }

    /// A member encoded twice is one member: refused by byte equality,
    /// which canonicity makes a faithful oracle for a reader that knows
    /// no type. The order of members is the type's own and still not
    /// the reader's to judge.
    #[test]
    fn a_duplicate_member_is_refused_and_an_unsorted_one_is_not() {
        let mut table = ShapeTable::new();
        let byte = table.push(TypeShape::U8).unwrap();
        let set = table
            .push(TypeShape::Set {
                cap: 8,
                element: byte,
            })
            .unwrap();
        assert!(table.read(set, &[2, 5, 3]).is_ok());
        assert_eq!(table.read(set, &[2, 5, 5]), Err(DecodeError::UnsortedKeys));
        let map = table
            .push(TypeShape::Map {
                cap: 8,
                key: byte,
                value: byte,
            })
            .unwrap();
        assert!(table.read(map, &[2, 5, 0, 3, 0]).is_ok());
        assert_eq!(
            table.read(map, &[2, 5, 0, 5, 1]),
            Err(DecodeError::UnsortedKeys)
        );
        // A sequence is a sequence: repeats are what it holds.
        let seq = table
            .push(TypeShape::Seq {
                cap: 8,
                element: byte,
            })
            .unwrap();
        assert!(table.read(seq, &[2, 5, 5]).is_ok());
    }

    /// A claimed length past the node's cap is refused before anything
    /// is allocated for it, whatever the bytes could pay for.
    #[test]
    fn a_run_past_its_cap_is_refused() {
        let mut table = ShapeTable::new();
        let byte = table.push(TypeShape::U8).unwrap();
        let seq = table
            .push(TypeShape::Seq {
                cap: 2,
                element: byte,
            })
            .unwrap();
        assert!(table.read(seq, &[2, 5, 5]).is_ok());
        assert_eq!(
            table.read(seq, &[3, 5, 5, 5]),
            Err(DecodeError::BoundExceeded { max: 2, actual: 3 })
        );
        let text = table.push(TypeShape::Text { cap: 2 }).unwrap();
        assert!(table.read(text, b"\x02ab").is_ok());
        assert_eq!(
            table.read(text, b"\x03abc"),
            Err(DecodeError::BoundExceeded { max: 2, actual: 3 })
        );
    }

    #[test]
    fn every_form_round_trips_canonically() {
        let (table, _, _) = every_form();
        let bytes = to_vec_with_depth(&table, 8).expect("encodes");
        let read: ShapeTable = from_slice_with_depth(&bytes, 8).expect("decodes");
        assert_eq!(read, table);
        assert_canonical_at_depth(&table, 8);
    }

    #[test]
    fn depth_counts_the_levels_a_decoder_spends() {
        let (table, leaf, whole) = every_form();
        // A variant's content is a struct or a tuple, and the level goes
        // to its fields; the discriminant is a byte the enum writes.
        assert_eq!(table.depth(leaf), 1);
        // The map's own level, the name its value holds, and that
        // leaf's own — the deepest field is what the record costs.
        assert_eq!(table.depth(whole), 3);
    }

    #[test]
    fn an_empty_composite_still_spends_its_level() {
        let mut table = ShapeTable::new();
        let unit = table.push(TypeShape::Tuple(Vec::new())).unwrap();
        assert_eq!(table.depth(unit), 0);
        let byte = table.push(TypeShape::U8).unwrap();
        let bytes = table
            .push(TypeShape::Seq {
                cap: 1,
                element: byte,
            })
            .unwrap();
        assert_eq!(table.depth(bytes), 1);
    }

    /// A name is what turns a decoded position into a fact, so one name
    /// over two members is two answers to one question — and a byte that
    /// selects two variants leaves one of them unreachable.
    ///
    /// Neither is a shape a declaration can spell: Rust names a type's
    /// members once each, and the codec refuses a discriminant collision
    /// where the variant is written. A shape is data, so the refusals
    /// move to where it joins a table.
    #[test]
    fn one_name_over_two_members_is_a_fault() {
        let mut table = ShapeTable::new();
        let byte = table.push(TypeShape::U8).unwrap();
        let field = |name: &str| ShapeField {
            name: Name::declared(name),
            shape: byte,
        };
        assert_eq!(
            table.push(TypeShape::Struct(vec![field("amount"), field("amount")])),
            Err(ShapeFault::AmbiguousName("amount".into()))
        );
        assert!(
            table
                .push(TypeShape::Struct(vec![field("amount"), field("fee")]))
                .is_ok()
        );

        let unit = table.push(TypeShape::Tuple(Vec::new())).unwrap();
        let variant = |name: &str, discriminant| ShapeVariant {
            name: Name::declared(name),
            discriminant,
            content: unit,
        };
        assert_eq!(
            table.push(TypeShape::Enum(vec![
                variant("left", 0),
                variant("left", 1)
            ])),
            Err(ShapeFault::AmbiguousName("left".into()))
        );
        assert_eq!(
            table.push(TypeShape::Enum(vec![
                variant("left", 0),
                variant("right", 0)
            ])),
            Err(ShapeFault::AmbiguousDiscriminant(0))
        );
        assert!(
            table
                .push(TypeShape::Enum(vec![
                    variant("left", 0),
                    variant("right", 7)
                ]))
                .is_ok()
        );
    }

    /// A reference resolves downward or not at all: to a node the table
    /// does not hold, or to the node being added, is the same refusal.
    #[test]
    fn a_reference_to_nothing_is_a_fault() {
        let mut table = ShapeTable::new();
        assert_eq!(
            table.push(TypeShape::Option(NodeId(0))),
            Err(ShapeFault::Unresolved(NodeId(0)))
        );
        let byte = table.push(TypeShape::U8).unwrap();
        assert_eq!(
            table.push(TypeShape::Option(NodeId(7))),
            Err(ShapeFault::Unresolved(NodeId(7)))
        );
        assert!(table.push(TypeShape::Option(byte)).is_ok());
    }

    /// Two types cannot share a name, because a consumer finds one by it.
    #[test]
    fn two_types_under_one_name_is_a_fault() {
        let mut table = ShapeTable::new();
        let byte = table.push(TypeShape::U8).unwrap();
        let word = table.push(TypeShape::U64).unwrap();
        let named = |shape| TypeShape::Named {
            name: Name::declared("thing"),
            shape,
        };
        let first = table.push(named(byte)).unwrap();
        // The same type reached a second way is the same node.
        assert_eq!(table.push(named(byte)), Ok(first));
        assert_eq!(
            table.push(named(word)),
            Err(ShapeFault::NameTaken("thing".into()))
        );
        assert_eq!(table.named("thing"), Some(first));
    }

    /// A shape deeper than a decoder follows describes values no decoder
    /// admits.
    #[test]
    fn a_shape_past_the_decoders_cap_is_a_fault() {
        let mut table = ShapeTable::new();
        let mut held = table.push(TypeShape::U8).unwrap();
        for _ in 0..DEFAULT_MAX_DEPTH {
            held = table.push(TypeShape::Option(held)).unwrap();
        }
        assert_eq!(table.depth(held), DEFAULT_MAX_DEPTH);
        assert_eq!(
            table.push(TypeShape::Option(held)),
            Err(ShapeFault::TooDeep)
        );
    }

    /// A table that decodes is the one its publisher built: a node that
    /// reaches upward, or repeats an earlier one, is refused as the bytes
    /// are read.
    #[test]
    fn a_decoded_table_passes_through_the_same_door() {
        let upward = vec![TypeShape::Option(NodeId(1)), TypeShape::U8];
        let bytes = to_vec(&upward).unwrap();
        assert!(matches!(
            from_slice_with_depth::<ShapeTable>(&bytes, 8),
            Err(DecodeError::FailedValidation(_))
        ));
        let repeated = vec![TypeShape::U8, TypeShape::U8];
        let bytes = to_vec(&repeated).unwrap();
        assert!(matches!(
            from_slice_with_depth::<ShapeTable>(&bytes, 8),
            Err(DecodeError::FailedValidation(_))
        ));
        let ordered = vec![TypeShape::U8, TypeShape::Option(NodeId(0))];
        let bytes = to_vec(&ordered).unwrap();
        let table = from_slice_with_depth::<ShapeTable>(&bytes, 8).unwrap();
        assert_eq!(table.most(NodeId(1)), 2);
    }

    /// A tree declared into a table measures what its folds state, node
    /// for node, and a subtree reached twice is written once.
    #[test]
    fn a_declared_tree_measures_as_its_folds_and_shares_its_subtrees() {
        const ELEMENT: &ShapeNode = &ShapeNode::Named {
            name: "Element",
            shape: &ShapeNode::Struct(&[("a", &ShapeNode::U8), ("b", &ShapeNode::U64)]),
        };
        const ROOT: &ShapeNode = &ShapeNode::Named {
            name: "Root",
            shape: &ShapeNode::Struct(&[
                ("one", ELEMENT),
                ("two", &ShapeNode::Option(ELEMENT)),
                (
                    "many",
                    &ShapeNode::Seq {
                        cap: 3,
                        element: ELEMENT,
                    },
                ),
            ]),
        };
        let mut table = ShapeTable::new();
        let root = table.declare(ROOT).unwrap();
        assert_eq!(table.most(root), max_encoded_len(ROOT));
        assert_eq!(table.least(root), min_encoded_len(ROOT));
        assert_eq!(table.depth(root), max_depth(ROOT));
        let element = table.named("Element").unwrap();
        assert_eq!(table.most(element), max_encoded_len(ELEMENT));
        // u8, u64, the struct, its name, the option, the sequence, the
        // root's struct and its name: eight nodes for three mentions.
        assert_eq!(table.len(), 8);
        assert!(table.matches(root, ROOT));
        assert!(!table.matches(element, ROOT));
    }
}
