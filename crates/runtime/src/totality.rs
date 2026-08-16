//! Deploy-time totality checking.
//!
//! A method marked total promises its callers that it cannot come back
//! with a refusal or a fault. Two things could break that promise here
//! and the vocabulary sees only one of them: a gate turns callers away
//! before the body runs, which a signature's accessibility states, and a
//! trap leaves the type system entirely and states nothing anywhere.
//! This module answers the second — a scan of a function body for the
//! operators that can fault, so the verdict is read off the code rather
//! than taken from the package that would benefit from it.
//!
//! There is no third. WIT has `result<t, e>`, and no world in this
//! protocol uses it: every export returns a value or nothing, and a
//! method declines by trapping. So the error arm a signature could carry
//! is not a signal that distinguishes anything here, and the scan is not
//! half the answer but nearly all of it.
//!
//! The scan is a membership test, not an analysis. Proving an arbitrary
//! body cannot fault is undecidable, and approximating it well is a
//! research problem; deciding whether a body stays inside a vocabulary
//! that has no faulting member is a walk over its operators. What that
//! costs is expressiveness — a body that could never fault in practice is
//! refused for using an instruction that could in principle — and what it
//! buys is that a granted mark means something checkable.
//!
//! Refusal is cheap on purpose. A method that fails this check is not
//! broken and its package still deploys: it classifies as
//! [`Infallible`](hyperscale_vm_effects::Totality::Infallible) at best, so
//! what it loses is the decomposition an outbound leg would have had.
//! That asymmetry is what lets the check ship while it is still
//! conservative.
//!
//! ## Linear memory is taken as safe, and that is a judgment
//!
//! Every load and store can fault on an out-of-bounds address, so a scan
//! that treated them as trap-capable would refuse every body that touches
//! memory, which is every body. The check instead relies on the
//! toolchain: safe Rust compiled to wasm accesses only memory its own
//! allocator manages, and the bounds checks it emits fault through
//! `unreachable` rather than through the access itself. So the
//! `unreachable` ban below is what covers indexing, and a raw
//! out-of-bounds store could only come from unsafe code the profile does
//! not otherwise restrict.
//!
//! This is the check's weakest link and it is deliberate. It is sound for
//! the stdlib, which is the code the mark is granted to today, and it
//! wants revisiting before an untrusted package can earn one.
//!
//! ## The canonical ABI's glue is excluded, and that is the second
//!
//! Measured against the account guest, every export but the two that read
//! and return nothing fails on `unreachable` — and the failure is never in
//! the authored body. It is in the allocator the ABI calls to move a
//! `list<u8>` across the boundary, which panics on allocation failure, and
//! which every export that carries a value therefore reaches. Checking it
//! would deny the mark to every method in the language, forever, for a
//! reason no author can act on.
//!
//! So the closure of the ABI's support functions is excluded from the
//! walk, on the same footing as the imports: allocation failure is a
//! resource bound the boundary discharges, exactly as fuel exhaustion is,
//! and a leg whose memory is pre-sized cannot reach it.
//!
//! **Which functions those are is read from the component's own wiring,
//! never from their names.** A `cabi_` prefix is something an author
//! chooses, so excluding by prefix would let a package export its
//! panicking helper under that name and have the scan look away — a hole
//! anyone reading this file could walk through. What a `canon lift`
//! designates is a role rather than a name: the runtime calls that
//! function to allocate for every value crossing the boundary. A package
//! can still point the role at a body of its own, and then that body has
//! to serve as the allocator, which leaves it holding the gap the honest
//! allocator already has instead of opening a new one.
//!
//! What the exclusion costs is still real: a body that panics *through*
//! the glue is not caught, and a helper the allocator and an authored
//! method both call is set aside on the allocator's account. Closing that
//! means a panic-free allocator rather than a cleverer scan.

use std::collections::BTreeSet;

use wasmparser::{
    CanonicalFunction, CanonicalOption, ComponentAlias, ExternalKind, FunctionBody, Operator,
    Parser, Payload, TypeRef,
};

/// Why a body cannot carry the total mark.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TotalityError {
    /// The body can reach `unreachable`, which is where every Rust panic
    /// lands: a failed bounds check, an unwrap on nothing, an overflow
    /// the build checks for. Its absence is the single strongest thing
    /// the scan learns, because the compiler emitting no panic path is
    /// the compiler having proven there is none.
    #[error("the body can reach `unreachable`")]
    Unreachable,
    /// An integer division or remainder whose divisor is not a non-zero
    /// literal. Division by zero faults, and only a constant divisor
    /// rules it out where the scan can see.
    #[error("integer division by a value the scan cannot prove non-zero")]
    DivisionByUnprovenDivisor,
    /// An indirect call, which faults on a null table slot or a mismatched
    /// signature. It also hides the callee, so the transitive body the
    /// mark speaks for would not be knowable.
    #[error("an indirect call, whose callee is neither known nor guaranteed to exist")]
    IndirectCall,
    /// A loop, whose trip count the scan cannot bound and therefore whose
    /// fuel it cannot bound either. Totality includes not exhausting the
    /// fuel the transaction pre-charged, which needs a static ceiling.
    #[error("a loop, whose fuel cost has no static bound")]
    UnboundedLoop,
    /// No core module in the artifact exports the named method.
    #[error("no core module exports {0:?}")]
    NoSuchExport(String),
    /// The body could not be decoded.
    #[error("undecodable body: {0}")]
    Undecodable(String),
}

/// Whether `body` stays inside the vocabulary that has no faulting member.
///
/// The divisor rule is a peephole: an integer division is admitted when
/// the operator immediately before it pushed a non-zero constant, which is
/// the shape a division by a fixed denominator compiles to. Anything else
/// — a divisor read from memory, computed, or passed in — is refused,
/// since the scan has no way to know it is non-zero.
///
/// # Errors
///
/// The first [`TotalityError`] the walk reaches. The scan stops there:
/// one faulting operator is enough to deny the mark, and reporting the
/// rest would not change the verdict.
pub fn check_body(body: &FunctionBody<'_>) -> Result<(), TotalityError> {
    let reader = body
        .get_operators_reader()
        .map_err(|e| TotalityError::Undecodable(e.to_string()))?;

    let mut previous: Option<Operator<'_>> = None;
    for op in reader {
        let op = op.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
        match op {
            Operator::Unreachable => return Err(TotalityError::Unreachable),
            Operator::CallIndirect { .. } => return Err(TotalityError::IndirectCall),
            Operator::Loop { .. } => return Err(TotalityError::UnboundedLoop),
            Operator::I32DivS
            | Operator::I32DivU
            | Operator::I32RemS
            | Operator::I32RemU
            | Operator::I64DivS
            | Operator::I64DivU
            | Operator::I64RemS
            | Operator::I64RemU
                if !divisor_is_non_zero(previous.as_ref()) =>
            {
                return Err(TotalityError::DivisionByUnprovenDivisor);
            }
            _ => {}
        }
        previous = Some(op);
    }
    Ok(())
}

/// Whether every function reachable from `entry` stays inside the
/// vocabulary, walking the module's own call graph.
///
/// The mark speaks for a transitive body, not for one function: a method
/// whose own operators are harmless but which calls something that panics
/// can still panic. So the check follows every direct call from the entry
/// and refuses if any body it reaches does.
///
/// **A call to an import is admitted, and that is the kernel's promise
/// rather than the scan's finding.** Host calls are how a body reaches
/// the kernel at all, and they can refuse — but a total leg runs with
/// every handle already materialized from its declared effect set, so the
/// gate that would refuse has been discharged before the body starts.
/// The scan cannot see that and does not try to; it records here that the
/// guarantee comes from the boundary, so a change to how handles are
/// materialized is a change to what this check means.
///
/// `entry` indexes the module's whole function space — imports first,
/// then defined functions — the same space [`Operator::Call`] uses.
///
/// # Errors
///
/// The first [`TotalityError`] any reachable body yields, or
/// [`TotalityError::Undecodable`] if the module does not parse.
pub fn check_reachable(module: &[u8], entry: u32) -> Result<(), TotalityError> {
    let designated = abi_support_exports(module)?;
    let parsed = Module::parse(module)?;
    let shim = parsed.shim_closure(&designated)?;
    parsed.walk(entry, &shim)
}

/// Whether the method a package exports as `method` can carry the mark.
///
/// Takes the artifact as deployed. A component under this profile wraps
/// exactly one core module, and wit-bindgen names that module's exports
/// after the WIT functions they implement, so the method's name is the
/// core export's name and no canonical-ABI indirection has to be
/// unwound to find it.
///
/// # Errors
///
/// [`TotalityError::NoSuchExport`] if no core module exports `method`,
/// or whatever the walk from it yields.
pub fn check_method(artifact: &[u8], method: &str) -> Result<(), TotalityError> {
    let designated = abi_support_exports(artifact)?;
    for module in core_modules(artifact)? {
        let parsed = Module::parse(module)?;
        let Some(entry) = parsed.export_named(method) else {
            continue;
        };
        let shim = parsed.shim_closure(&designated)?;
        return parsed.walk(entry, &shim);
    }
    Err(TotalityError::NoSuchExport(method.to_string()))
}

/// The core modules an artifact carries: the ones nested inside a
/// component, or the artifact itself when it is already a core module.
fn core_modules(artifact: &[u8]) -> Result<Vec<&[u8]>, TotalityError> {
    let mut nested = Vec::new();
    for payload in Parser::new(0).parse_all(artifact) {
        if let Payload::ModuleSection {
            unchecked_range, ..
        } = payload.map_err(|e| TotalityError::Undecodable(e.to_string()))?
        {
            let bytes = artifact
                .get(unchecked_range)
                .ok_or_else(|| TotalityError::Undecodable("module range out of bounds".into()))?;
            nested.push(bytes);
        }
    }
    if nested.is_empty() {
        nested.push(artifact);
    }
    Ok(nested)
}

/// The core exports the component itself designates as canonical-ABI
/// support: whatever its `canon lift`s name as their realloc and their
/// post-return.
///
/// Read from the component's own wiring rather than from a naming
/// convention, and that is the whole point. A prefix is something an
/// author picks, so excluding everything called `cabi_*` lets a package
/// export its panicking helper under that name and have the scan look
/// away. What a lift designates is not a name but a role: the runtime
/// calls this function to allocate, on every value that crosses the
/// boundary. A package can still point that role at a body of its own —
/// but then that body must actually serve as the allocator, which leaves
/// it with the same gap the honest allocator already has rather than a
/// new one.
///
/// Empty for a bare core module, which has no canonical section and
/// therefore no glue to set aside.
fn abi_support_exports(artifact: &[u8]) -> Result<BTreeSet<String>, TotalityError> {
    // The component's core function index space, in payload order: an
    // alias of a core export contributes its name, and every canonical
    // function except a lift contributes an entry that is not an alias.
    // A lift produces a component function and so contributes nothing.
    let mut core_functions: Vec<Option<String>> = Vec::new();
    let mut designated: BTreeSet<u32> = BTreeSet::new();

    for payload in Parser::new(0).parse_all(artifact) {
        match payload.map_err(|e| TotalityError::Undecodable(e.to_string()))? {
            Payload::ComponentAliasSection(reader) => {
                for alias in reader {
                    let alias = alias.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
                    if let ComponentAlias::CoreInstanceExport { kind, name, .. } = alias
                        && kind == ExternalKind::Func
                    {
                        core_functions.push(Some(name.to_owned()));
                    }
                }
            }
            Payload::ComponentCanonicalSection(reader) => {
                for function in reader {
                    let function =
                        function.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
                    let CanonicalFunction::Lift { options, .. } = function else {
                        core_functions.push(None);
                        continue;
                    };
                    for option in &options {
                        match option {
                            CanonicalOption::Realloc(index)
                            | CanonicalOption::PostReturn(index) => {
                                designated.insert(*index);
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(designated
        .into_iter()
        .filter_map(|index| core_functions.get(index as usize).cloned().flatten())
        .collect())
}

/// A core module's function space, indexed the way calls index it.
struct Module<'a> {
    /// Imports occupy the low indices and have no body here.
    imported_functions: u32,
    bodies: Vec<FunctionBody<'a>>,
    /// Exported function indices by name, for finding the shim's roots.
    exports: Vec<(&'a str, u32)>,
}

impl<'a> Module<'a> {
    fn parse(module: &'a [u8]) -> Result<Self, TotalityError> {
        let mut parsed = Self {
            imported_functions: 0,
            bodies: Vec::new(),
            exports: Vec::new(),
        };
        for payload in Parser::new(0).parse_all(module) {
            match payload.map_err(|e| TotalityError::Undecodable(e.to_string()))? {
                Payload::ImportSection(reader) => {
                    // Grouped in the compact encoding, so flatten before
                    // counting: what shifts the defined functions' indices
                    // is the number of imports, not of groups.
                    for import in reader.into_imports() {
                        let import =
                            import.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
                        if matches!(import.ty, TypeRef::Func(_)) {
                            parsed.imported_functions += 1;
                        }
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export =
                            export.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
                        if matches!(export.kind, ExternalKind::Func) {
                            parsed.exports.push((export.name, export.index));
                        }
                    }
                }
                Payload::CodeSectionEntry(body) => parsed.bodies.push(body),
                _ => {}
            }
        }
        Ok(parsed)
    }

    /// Defined function `i` sits at `imports + i`; anything below that is
    /// an import, which has no body here to walk into.
    fn body_of(&self, index: u32) -> Option<&FunctionBody<'a>> {
        index
            .checked_sub(self.imported_functions)
            .and_then(|defined| self.bodies.get(defined as usize))
    }

    fn callees(&self, index: u32) -> Result<Vec<u32>, TotalityError> {
        let Some(body) = self.body_of(index) else {
            return Ok(Vec::new());
        };
        let reader = body
            .get_operators_reader()
            .map_err(|e| TotalityError::Undecodable(e.to_string()))?;
        let mut out = Vec::new();
        for op in reader {
            let op = op.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
            if let Operator::Call { function_index } = op {
                out.push(function_index);
            }
        }
        Ok(out)
    }

    fn export_named(&self, name: &str) -> Option<u32> {
        self.exports
            .iter()
            .find(|(export, _)| *export == name)
            .map(|(_, index)| *index)
    }

    /// Everything the designated ABI support reaches.
    fn shim_closure(&self, designated: &BTreeSet<String>) -> Result<BTreeSet<u32>, TotalityError> {
        let frontier: Vec<u32> = self
            .exports
            .iter()
            .filter(|(name, _)| designated.contains(*name))
            .map(|(_, index)| *index)
            .collect();
        self.reachable(frontier, &BTreeSet::new())
    }

    /// Indices reachable from `frontier`, not descending into `excluded`.
    fn reachable(
        &self,
        mut frontier: Vec<u32>,
        excluded: &BTreeSet<u32>,
    ) -> Result<BTreeSet<u32>, TotalityError> {
        let mut seen = BTreeSet::new();
        while let Some(index) = frontier.pop() {
            if excluded.contains(&index) || !seen.insert(index) {
                continue;
            }
            frontier.extend(self.callees(index)?);
        }
        Ok(seen)
    }

    /// Check every body reachable from `entry` that is not shim.
    fn walk(&self, entry: u32, shim: &BTreeSet<u32>) -> Result<(), TotalityError> {
        for index in self.reachable(vec![entry], shim)? {
            if let Some(body) = self.body_of(index) {
                check_body(body)?;
            }
        }
        Ok(())
    }
}

/// Whether the operator that pushed the divisor proves it non-zero.
const fn divisor_is_non_zero(previous: Option<&Operator<'_>>) -> bool {
    match previous {
        Some(Operator::I32Const { value }) => *value != 0,
        Some(Operator::I64Const { value }) => *value != 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use wat::parse_str;

    use super::*;

    /// Compile one function body to a core module and check it.
    fn check(body: &str) -> Result<(), TotalityError> {
        let wat = format!("(module (func $f {body}))");
        let bytes = parse_str(&wat).expect("valid wat");
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::CodeSectionEntry(body) = payload.expect("parses") {
                return check_body(&body);
            }
        }
        panic!("a module with a function has a code section");
    }

    #[test]
    fn arithmetic_that_cannot_fault_passes() {
        assert_eq!(check("i32.const 2 i32.const 3 i32.add drop"), Ok(()));
    }

    /// The one that matters: every Rust panic lands here, so its absence
    /// is what the whole check leans on.
    #[test]
    fn unreachable_is_refused() {
        assert_eq!(check("unreachable"), Err(TotalityError::Unreachable));
    }

    /// A constant divisor is provably non-zero and a computed one is not,
    /// which is the whole of the peephole.
    #[test]
    fn division_is_refused_unless_the_divisor_is_a_non_zero_literal() {
        assert_eq!(check("i32.const 6 i32.const 3 i32.div_s drop"), Ok(()));
        assert_eq!(
            check("i32.const 6 i32.const 0 i32.div_s drop"),
            Err(TotalityError::DivisionByUnprovenDivisor),
        );
        assert_eq!(
            check("i32.const 6 local.get 0 i32.div_s drop"),
            Err(TotalityError::DivisionByUnprovenDivisor),
        );
    }

    #[test]
    fn a_loop_is_refused_for_having_no_fuel_ceiling() {
        assert_eq!(check("loop end"), Err(TotalityError::UnboundedLoop),);
    }

    /// A branch is not a loop: forward control flow terminates, so it
    /// carries a static fuel bound and stays admissible.
    #[test]
    fn forward_branching_is_admitted() {
        assert_eq!(check("block br 0 end"), Ok(()));
        assert_eq!(check("i32.const 1 if else end"), Ok(()));
    }

    /// Two functions, the second reached from the first by a direct call.
    fn caller_and_callee(callee_body: &str) -> Vec<u8> {
        parse_str(format!(
            "(module (func $entry call $callee) (func $callee {callee_body}))"
        ))
        .expect("valid wat")
    }

    /// The mark speaks for the transitive body: a caller whose own
    /// operators are harmless still cannot be total when what it calls
    /// can panic.
    #[test]
    fn a_callee_that_can_fault_denies_its_caller() {
        assert_eq!(check_reachable(&caller_and_callee("nop"), 0), Ok(()));
        assert_eq!(
            check_reachable(&caller_and_callee("unreachable"), 0),
            Err(TotalityError::Unreachable),
        );
    }

    /// Reachability is the whole of it: a faulting function nobody calls
    /// says nothing about the entry, which is what lets one package hold
    /// both a total method and a fallible one.
    #[test]
    fn an_unreached_faulting_function_is_not_the_entrys_problem() {
        let module =
            parse_str("(module (func $entry nop) (func $orphan unreachable))").expect("valid wat");
        assert_eq!(check_reachable(&module, 0), Ok(()));
        assert_eq!(
            check_reachable(&module, 1),
            Err(TotalityError::Unreachable),
            "the orphan is refused on its own account, just not the entry's",
        );
    }

    /// Recursion terminates the walk rather than hanging it. The cycle is
    /// refused for its loop-free-but-unbounded fuel elsewhere; what this
    /// pins is that the visit set closes.
    #[test]
    fn a_call_cycle_terminates_the_walk() {
        let module = parse_str("(module (func $a call 1) (func $b call 0))").expect("valid wat");
        assert_eq!(check_reachable(&module, 0), Ok(()));
    }

    /// A bare core module designates nothing, so nothing is set aside:
    /// with no component around it there is no `canon lift` to name a
    /// realloc, and a faulting callee is the entry's problem however it
    /// is named.
    #[test]
    fn a_name_alone_sets_nothing_aside() {
        for export in ["helper", "cabi_realloc"] {
            let module = parse_str(format!(
                r#"(module
                     (func $entry call $helper)
                     (func $helper unreachable)
                     (export "deposit" (func $entry))
                     (export "{export}" (func $helper)))"#
            ))
            .expect("valid wat");
            assert_eq!(
                check_reachable(&module, 0),
                Err(TotalityError::Unreachable),
                "exporting the faulting body as {export:?} must not excuse it",
            );
        }
    }

    /// An imported function has no body to walk into, and a call to one
    /// is admitted on the kernel's precondition discharge rather than on
    /// anything the scan established.
    #[test]
    fn a_call_into_an_import_is_admitted() {
        let module = parse_str(r#"(module (import "k" "f" (func)) (func $entry call 0))"#)
            .expect("valid wat");
        // The import occupies index 0, so the defined entry is index 1 —
        // the shift the walk has to get right to find any body at all.
        assert_eq!(check_reachable(&module, 1), Ok(()));
    }
}
