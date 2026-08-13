//! The text projection: a graph, read back as the surface syntax.
//!
//! The signed form is the graph; the text is a view of it, in the
//! SSA-style let-binding shape — imperative to read, dataflow in
//! denotation. Each node is one statement in node order, each output edge
//! one binding, and every consumer names the binding it takes. Nothing is
//! recovered or inferred: a producer precedes its consumers in the graph
//! already, so the reading order is the graph's own.
//!
//! Metadata buys two things and no more. It gives a node's output arity
//! from the signature rather than from counting who consumed what, and it
//! evaluates each output's declared type, so a binding can be shown
//! carrying the resource it will carry. It does **not** give parameter
//! names: a signature declares kinds and counts and nothing else, so
//! arguments render positionally whatever metadata is on hand. A target
//! that does not resolve degrades to exactly that and keeps rendering.
//!
//! Names come from the caller. There is no register of symbols in this
//! system — an address is a hash — so `pool` and `usdc` can only be what
//! somebody already calls them. A wallet passes the names it shows its
//! user; anything unnamed renders as the address itself, in bech32m for
//! the network the caller is reading on, which is why the network word is
//! an input here for the reason it is in [`preflight`](crate::preflight).
//!
//! An address written as an argument carries an `@`, because that position
//! admits a binding too and a reader signing a transfer has to tell the
//! resource from a bucket of it. A target and a type each sit somewhere
//! only one of the two can be, so neither is marked.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use hyperscale_vm_effects::{
    Address, Constraint, EdgeContent, EdgeRef, GraphArg, Hasher, InstanceRegistry, ManifestGraph,
    MetadataCache, ResourceRef, SubstateKey, TextError, Value,
};

use crate::typed::{output_resources, unknown};

/// What a reader already calls the addresses a graph names.
///
/// Empty is a complete answer — every address then renders as itself — so
/// a caller holding no symbols passes [`Names::none`] and loses only
/// brevity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names(BTreeMap<Address, String>);

impl Names {
    /// A table naming nothing.
    #[must_use]
    pub const fn none() -> Self {
        Self(BTreeMap::new())
    }

    /// Name `address` `name` wherever the projection would print it.
    #[must_use]
    pub fn with(mut self, address: impl Into<Address>, name: impl Into<String>) -> Self {
        self.0.insert(address.into(), name.into());
        self
    }

    /// What this table calls `address`, if anything.
    #[must_use]
    pub fn get(&self, address: impl Into<Address>) -> Option<&str> {
        self.0.get(&address.into()).map(String::as_str)
    }
}

impl<A: Into<Address>, S: Into<String>> FromIterator<(A, S)> for Names {
    fn from_iter<I: IntoIterator<Item = (A, S)>>(names: I) -> Self {
        Self(
            names
                .into_iter()
                .map(|(address, name)| (address.into(), name.into()))
                .collect(),
        )
    }
}

/// Render `graph` as the surface syntax, for `network`.
///
/// The metadata is consulted where it resolves and skipped where it does
/// not, so a caller holding an empty cache still gets targets, methods and
/// positional arguments.
///
/// # Errors
///
/// [`TextError`] if `network` is a word no address can be named under.
pub fn render(
    graph: &ManifestGraph,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
    network: &str,
    names: &Names,
) -> Result<String, TextError> {
    let mut printer = Printer {
        network,
        names,
        text: BTreeMap::new(),
        bindings: BTreeMap::new(),
        taken: BTreeMap::new(),
    };
    // Resolved before the walk, because a binding's name is read at its
    // definition and its constraints are written at its use.
    let types = edge_types(graph, cache, instances, hasher);

    let mut out = String::new();
    for (index, node) in graph.nodes.iter().enumerate() {
        let producer = u32::try_from(index).unwrap_or(u32::MAX);
        let outputs = types.get(&producer).map_or(0, Vec::len);
        let mut bindings = Vec::with_capacity(outputs);
        for slot in 0..outputs {
            let slot = u32::try_from(slot).unwrap_or(u32::MAX);
            let edge = EdgeRef {
                producer,
                output: slot,
            };
            let resource = types[&producer][usize::try_from(slot).unwrap_or(0)];
            bindings.push(printer.bind(edge, resource)?);
        }
        if !bindings.is_empty() {
            out.push_str("let ");
            out.push_str(&bindings.join(", "));
            out.push_str(" = ");
        }
        let target = printer.address(node.target.address())?;
        let mut args = Vec::with_capacity(node.args.len());
        for arg in &node.args {
            args.push(printer.arg(arg)?);
        }
        let _ = writeln!(out, "{target}.{}({});", node.method, args.join(", "));
    }
    Ok(out)
}

/// Carries the reader's vocabulary and the names already handed out.
struct Printer<'a> {
    network: &'a str,
    names: &'a Names,
    /// Addresses already rendered, so one address costs one encoding
    /// however often a graph names it.
    text: BTreeMap<Address, String>,
    /// The name and shown type of each bound edge.
    bindings: BTreeMap<EdgeRef, (String, Option<ResourceRef>)>,
    /// How many bindings have taken each base name.
    taken: BTreeMap<String, u32>,
}

impl Printer<'_> {
    /// An address as the reader knows it, or as itself.
    fn address(&mut self, address: Address) -> Result<String, TextError> {
        if let Some(name) = self.names.get(address) {
            return Ok(name.to_owned());
        }
        if let Some(text) = self.text.get(&address) {
            return Ok(text.clone());
        }
        let text = address.to_text(self.network)?;
        self.text.insert(address, text.clone());
        Ok(text)
    }

    /// Name one output edge and answer its binding, typed where the type
    /// is not already what the name says.
    fn bind(&mut self, edge: EdgeRef, resource: Option<ResourceRef>) -> Result<String, TextError> {
        // A binding is named after what it carries, which is the closest
        // this system has to a name for a value: an edge is not addressed,
        // so nothing else about it could be looked up.
        let base = resource
            .and_then(|resource| self.names.get(resource.address()))
            .map_or_else(|| "v".to_owned(), str::to_owned);
        let count = self.taken.entry(base.clone()).or_insert(0);
        *count += 1;
        let name = if *count == 1 && base != "v" {
            base
        } else {
            format!("{base}{count}")
        };
        self.bindings.insert(edge, (name.clone(), resource));
        // Naming a binding after its resource already says what it
        // carries; annotating it again would be the same word twice.
        let annotate = match resource {
            Some(resource) if self.names.get(resource.address()).is_none() => {
                Some(self.address(resource.address())?)
            }
            _ => None,
        };
        Ok(match annotate {
            Some(shown) => format!("{name}: {shown}"),
            None => name,
        })
    }

    /// One bound argument.
    fn arg(&mut self, arg: &GraphArg) -> Result<String, TextError> {
        match arg {
            GraphArg::Literal(value) => self.value(value),
            GraphArg::Param(position) => Ok(format!("${position}")),
            GraphArg::Edge { edge, constraints } => {
                let (name, shown) = self
                    .bindings
                    .get(edge)
                    .cloned()
                    .unwrap_or_else(|| (format!("v{}_{}", edge.producer, edge.output), None));
                let mut written = Vec::new();
                for constraint in constraints {
                    match constraint {
                        // The type is on the binding already unless the
                        // consumer asserted a different one, which only an
                        // untyped author can have written.
                        Constraint::ResourceIs(resource) => {
                            if shown != Some(*resource) {
                                let text = self.address(resource.address())?;
                                written.push(format!("is {text}"));
                            }
                        }
                        Constraint::MinAmount(amount) => written.push(format!(">= {amount}")),
                        Constraint::MaxAmount(amount) => written.push(format!("<= {amount}")),
                    }
                }
                Ok(if written.is_empty() {
                    name
                } else {
                    format!("{name}{{{}}}", written.join(", "))
                })
            }
        }
    }

    /// One literal.
    ///
    /// An address is written `@name`, because an argument position admits
    /// both an address and a binding and a reader has to tell a resource
    /// from a bucket of it. Nowhere else needs the mark: a target sits
    /// before its method, and a type sits after a colon.
    fn value(&mut self, value: &Value) -> Result<String, TextError> {
        Ok(match value {
            Value::U64(number) => number.to_string(),
            Value::U128(number) => number.to_string(),
            Value::Bytes(bytes) => format!("0x{}", hex(bytes)),
            Value::Address(address) => format!("@{}", self.address(*address)?),
            Value::Key(key) => self.key(key)?,
            // Never a manifest literal — a bucket arrives as an edge — so
            // this is only reachable through the escape hatch that lets a
            // caller write any value.
            Value::Bucket { resource, .. } => format!("bucket(@{})", self.address(*resource)?),
            Value::Tuple(fields) => {
                let mut written = Vec::with_capacity(fields.len());
                for field in fields {
                    written.push(self.value(field)?);
                }
                format!("({})", written.join(", "))
            }
            Value::List(items) => {
                let mut written = Vec::with_capacity(items.len());
                for item in items {
                    written.push(self.value(item)?);
                }
                format!("[{}]", written.join(", "))
            }
        })
    }

    /// One substate key: the owner it sits under, and the slot within it.
    fn key(&mut self, key: &SubstateKey) -> Result<String, TextError> {
        let owner = self.address(key.owner)?;
        Ok(format!("{owner}/0x{}", hex(&key.local.0)))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// What each node's outputs carry, by producer, evaluated forward: a
/// node's inputs are literals and edges earlier nodes typed, which is the
/// same walk admission makes and the same order the graph already fixes.
///
/// A node whose target or method does not resolve contributes the outputs
/// its consumers name, so a graph rendered against an empty cache still
/// binds every edge somebody takes.
fn edge_types(
    graph: &ManifestGraph,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
) -> BTreeMap<u32, Vec<Option<ResourceRef>>> {
    let consumed = consumed_slots(graph);
    let mut types: BTreeMap<u32, Vec<Option<ResourceRef>>> = BTreeMap::new();
    for (index, node) in graph.nodes.iter().enumerate() {
        let producer = u32::try_from(index).unwrap_or(u32::MAX);
        let declared = instances
            .get(node.target)
            .and_then(|meta| Some((meta, cache.get(meta.package)?)))
            .and_then(|(meta, package)| Some((meta, package.methods.get(&node.method)?)));
        let Some((meta, signature)) = declared else {
            let slots = consumed.get(&producer).copied().unwrap_or(0);
            types.insert(producer, vec![None; usize::try_from(slots).unwrap_or(0)]);
            continue;
        };
        let mut known = Vec::with_capacity(node.args.len());
        let mut values = Vec::with_capacity(node.args.len());
        for arg in &node.args {
            let value = match arg {
                GraphArg::Literal(value) => Some(value.clone()),
                GraphArg::Edge { edge, .. } => types
                    .get(&edge.producer)
                    .and_then(|slots| slots.get(usize::try_from(edge.output).unwrap_or(usize::MAX)))
                    .copied()
                    .flatten()
                    .map(|resource| Value::Bucket {
                        resource: resource.address(),
                        content: EdgeContent::Fungible,
                    }),
                GraphArg::Param(_) => None,
            };
            known.push(value.is_some());
            values.push(value.unwrap_or_else(unknown));
        }
        types.insert(
            producer,
            output_resources(
                signature,
                node.target,
                &meta.config,
                &values,
                &known,
                producer,
                hasher,
            ),
        );
    }
    types
}

/// How many output slots each producer's consumers name — the arity a
/// graph reveals on its own, for a target no metadata resolves.
fn consumed_slots(graph: &ManifestGraph) -> BTreeMap<u32, u32> {
    let mut slots = BTreeMap::new();
    for node in &graph.nodes {
        for arg in &node.args {
            if let GraphArg::Edge { edge, .. } = arg {
                let seen = slots.entry(edge.producer).or_insert(0);
                *seen = (*seen).max(edge.output.saturating_add(1));
            }
        }
    }
    slots
}
