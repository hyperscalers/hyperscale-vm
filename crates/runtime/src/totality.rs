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
//! There is no third the scan must find. A method that can decline says
//! so in its own signature — the `result<_, u32>` error arm is the
//! declared refusal channel, and the gate reads a totality claim against
//! it — so declining is a fact the vocabulary already states. What no
//! signature states is trapping, and that is the whole of what the scan
//! answers.
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
//! `Totality::Infallible` at best, so
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
//! ## The register collectors are excluded, and that is the second
//!
//! Measured against the account guest, every export but the two that read
//! and return nothing fails on `unreachable` — and the failure is never in
//! the authored body. It is in the allocation that makes room for a
//! register's bytes, which panics on allocation failure, and which every
//! export that collects a value therefore reaches. Checking it would deny
//! the mark to every method in the language, forever, for a reason no
//! author can act on.
//!
//! So the closure of the collectors is excluded from the walk, on the
//! same footing as the imports: allocation failure is a resource bound
//! the boundary discharges, exactly as fuel exhaustion is, and a leg
//! whose memory is pre-sized cannot reach it.
//!
//! **Which functions those are is read from the module's own calls,
//! never from their names.** A collector is a function that calls the
//! boundary's `take` or `arg`, which is a role rather than a name: an
//! export named after a collector sets nothing aside, and a helper that
//! collects is set aside whatever it is called. The entry itself is never
//! a collector, so a body that collects by hand is scanned whole.
//!
//! The same holds for the body the scan starts from. A method's export
//! names the core function that runs under it, and the scan starts there
//! rather than at any function that shares the name.
//!
//! What the exclusion costs is still real: a body that panics *through*
//! a collector is not caught, and a helper a collector and an authored
//! method both call is set aside on the collector's account. Closing
//! that means a panic-free collector rather than a cleverer scan.

use std::collections::BTreeSet;

use wasmparser::{
    BinaryReaderError, ExternalKind, FunctionBody, Operator, Parser, Payload, TypeRef,
};

use crate::profile;

/// The kernel imports a total body may call, each with the
/// invariant that discharges its refusals before the body starts.
///
/// The list is an allowlist on purpose: a host call outside it is
/// refused, so a new kernel import stays outside the mark's reach until
/// someone writes down why it cannot refuse on a total leg. What every
/// entry leans on first is materialization — a handle the body holds
/// names a cell its declared effect set materialized, so existence and
/// mode are settled before the first instruction runs — and the
/// per-entry comments carry what each operation needs past that.
const DISCHARGED: &[(&str, &str)] = &[
    // A get reads the cell its handle names; materialization is the
    // whole of what it needs.
    ("state", "site-get"),
    // A set stores the bytes it is handed with no judgment at the call;
    // what a receipt may carry is judged at its own boundary.
    ("state", "site-set"),
    // A clear ends a leaf the handle already holds exclusively; there
    // is nothing to judge that materialization did not.
    ("state", "site-clear"),
    // A denominated cell holds an amount: value enters one only through
    // movements, so the read cannot meet bytes — a cell that did would
    // be a defect in state, not a refusal the call can reach.
    ("state", "site-balance"),
    // What an edge carries is the edge's own fact.
    ("state", "bucket-amount"),
    // A credit of conserved value: the cell's denomination was judged at
    // admission against what the edge carries, and supply linearity
    // bounds any balance plus any bucket at the accumulator's width — a
    // sum past it would need value no mint ever created. Refused at the
    // call for an exclusive hold and at the fold for a movement, and
    // neither refusal is one this leg can reach.
    ("state", "site-put"),
    // A count takes no index, so there is no bound to fall outside; the
    // coverage question is answered from the same page and its probe.
    ("state", "site-count"),
    ("state", "site-covered"),
    // Total on every input; the arithmetic that refuses a divisor or a
    // width stays out, because those are runtime values no declaration
    // speaks about.
    ("math", "geometric-mean"),
    // Environment reads with no failure mode at all.
    ("env", "clock"),
    ("crypto", "hash"),
    // The one admission that rests on the mark's envelope rather than on
    // a kernel discharge: the caps — type, count, payload — can refuse
    // in general. The mark is granted to protocol code only (the gate
    // refuses a published totality claim outright), and the protocol's
    // total bodies emit fixed-width payloads from loop-free code, so the
    // count is bounded by call sites and a decomposed leg's session
    // starts at zero events. Nothing here proves that; the grant's
    // review does.
    ("events", "emit"),
];

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
    /// The module exports no such method.
    #[error("no exported method {0:?}")]
    NoSuchExport(String),
    /// A call to a host function that can fault for a reason no
    /// declaration discharges.
    #[error("a call to `{0}`, whose refusal no declared effect set discharges")]
    FaultingHostCall(String),
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
/// **A host call is admitted only where a declaration discharges its
/// refusals, and a bare entry gives that judgment nothing to work
/// with.** Which imports a method may lean on is the method's own
/// gate's question, so here every import call is refused: what is not
/// judged cannot be discharged. The per-function verdicts live in
/// [`DISCHARGED`] and are applied by [`check_method`].
///
/// `entry` indexes the module's whole function space — imports first,
/// then defined functions — the same space [`Operator::Call`] uses.
///
/// Nothing is set aside either: the collector exclusion belongs to
/// [`check_method`] on the same grounds as the import verdicts.
///
/// # Errors
///
/// The first [`TotalityError`] any reachable body yields, or
/// [`TotalityError::Undecodable`] if the module does not parse.
pub fn check_reachable(module: &[u8], entry: u32) -> Result<(), TotalityError> {
    let parsed = Module::parse(module)?;
    let undischarged = (0..u32::try_from(parsed.imports.len()).unwrap_or(u32::MAX)).collect();
    parsed.walk(entry, &BTreeSet::new(), &undischarged)
}

/// Whether the method the module exports as `method` can carry the mark.
///
/// The body is the export itself, resolved by name in the one module,
/// and every import is a kernel function: discharged where the
/// declaration settles its refusals before the body runs, undischarged
/// otherwise.
///
/// What is set aside is the register collects. A function that collects
/// a register — one whose body calls the boundary's `take` or `arg` —
/// makes room for bytes the kernel already holds, and the allocation
/// that makes room is the boundary's work: linear memory is taken as
/// safe, so the collector and everything it reaches are outside the
/// scan. The
/// entry itself is never a collector; a body that collects registers by
/// hand is scanned whole.
///
/// # Errors
///
/// [`TotalityError::NoSuchExport`] if the module exports no such
/// method, or whatever the walk from its body yields.
pub fn check_method(module: &[u8], method: &str) -> Result<(), TotalityError> {
    let parsed = Module::parse(module)?;
    let entry = parsed
        .export_named(method)
        .ok_or_else(|| TotalityError::NoSuchExport(method.to_string()))?;
    let undischarged = parsed
        .imports
        .iter()
        .enumerate()
        .filter(|(_, (module, name))| !discharged_import(module, name))
        .filter_map(|(index, _)| u32::try_from(index).ok())
        .collect();
    let collects: BTreeSet<u32> = parsed
        .imports
        .iter()
        .enumerate()
        .filter(|(_, (module, name))| {
            module.strip_prefix(profile::KERNEL_IMPORT_PREFIX) == Some("abi")
                && matches!(name.as_str(), "take" | "arg")
        })
        .filter_map(|(index, _)| u32::try_from(index).ok())
        .collect();
    let imported = u32::try_from(parsed.imports.len()).unwrap_or(u32::MAX);
    let mut collectors = Vec::new();
    for index in imported..imported.saturating_add(u32::try_from(parsed.bodies.len()).unwrap_or(0))
    {
        if index != entry
            && parsed
                .callees(index)?
                .iter()
                .any(|callee| collects.contains(callee))
        {
            collectors.push(index);
        }
    }
    let support = parsed.reachable(collectors, &BTreeSet::from([entry]))?;
    parsed.walk(entry, &support, &undischarged)
}

/// Whether a kernel import's refusals are discharged before a total body
/// runs.
fn discharged_import(module: &str, name: &str) -> bool {
    let Some(interface) = module.strip_prefix(profile::KERNEL_IMPORT_PREFIX) else {
        return false;
    };
    interface == "abi"
        || DISCHARGED.contains(&(interface, name))
        || (interface == "state" && name == "bucket-drop")
}

/// A module's function space, indexed the way calls index it.
struct Module<'a> {
    /// Imported functions, as `(module, name)`, in index order: function
    /// `i` of this list is function index `i`, and imports occupy the low
    /// indices with no body here.
    imports: Vec<(String, String)>,
    bodies: Vec<FunctionBody<'a>>,
    /// Exported function indices by name.
    exports: Vec<(&'a str, u32)>,
}

impl<'a> Module<'a> {
    fn parse(module: &'a [u8]) -> Result<Self, TotalityError> {
        let mut parsed = Self {
            imports: Vec::new(),
            bodies: Vec::new(),
            exports: Vec::new(),
        };
        let fail = |e: BinaryReaderError| TotalityError::Undecodable(e.to_string());
        for payload in Parser::new(0).parse_all(module) {
            match payload.map_err(fail)? {
                Payload::ImportSection(reader) => {
                    // Grouped in the compact encoding, so flatten before
                    // counting: what shifts the defined functions' indices
                    // is the number of imports, not of groups.
                    for import in reader.into_imports() {
                        let import = import.map_err(fail)?;
                        if let TypeRef::Func(_) | TypeRef::FuncExact(_) = import.ty {
                            parsed
                                .imports
                                .push((import.module.to_owned(), import.name.to_owned()));
                        }
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(fail)?;
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
            .checked_sub(u32::try_from(self.imports.len()).ok()?)
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

    /// Check every body reachable from `entry` that is not support, and
    /// refuse where the reachable set calls an import nothing discharges.
    fn walk(
        &self,
        entry: u32,
        support: &BTreeSet<u32>,
        undischarged: &BTreeSet<u32>,
    ) -> Result<(), TotalityError> {
        let reached = self.reachable(vec![entry], support)?;
        if let Some(called) = reached.iter().find(|index| undischarged.contains(index)) {
            let named = usize::try_from(*called)
                .ok()
                .and_then(|index| self.imports.get(index))
                .map_or_else(
                    || called.to_string(),
                    |(module, name)| format!("{module}/{name}"),
                );
            return Err(TotalityError::FaultingHostCall(named));
        }
        for index in reached {
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

    /// Compile one function body to a module and check it.
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

    /// A name sets nothing aside: a faulting callee is the entry's problem
    /// however it is exported.
    #[test]
    fn a_name_alone_sets_nothing_aside() {
        for export in ["helper", "allocate", "take"] {
            let module = parse_str(format!(
                r#"(module
                     (func $entry call $helper)
                     (func $helper unreachable)
                     (export "deposit" (func $entry))
                     (export "{export}" (func $helper)))"#
            ))
            .expect("valid wat");
            assert_eq!(
                check_method(&module, "deposit"),
                Err(TotalityError::Unreachable),
                "exporting the faulting body as {export:?} must not excuse it",
            );
        }
    }

    /// A function that collects a register is the boundary's support:
    /// its allocation, and whatever it reaches, is set aside. The entry
    /// itself never is — a body that collects by hand is scanned whole.
    #[test]
    fn a_collector_is_set_aside_and_the_entry_is_not() {
        let collector = parse_str(
            r#"(module
                 (import "hyperscale:kernel/abi" "take" (func $take (param i32)))
                 (func $entry call $collect)
                 (func $collect call $alloc (i32.const 0) call $take)
                 (func $alloc unreachable)
                 (export "deposit" (func $entry)))"#,
        )
        .expect("valid wat");
        assert_eq!(check_method(&collector, "deposit"), Ok(()));

        let by_hand = parse_str(
            r#"(module
                 (import "hyperscale:kernel/abi" "take" (func $take (param i32)))
                 (func $entry call $alloc (i32.const 0) call $take)
                 (func $alloc unreachable)
                 (export "deposit" (func $entry)))"#,
        )
        .expect("valid wat");
        assert_eq!(
            check_method(&by_hand, "deposit"),
            Err(TotalityError::Unreachable),
            "an entry that collects its own registers is not support",
        );
    }

    /// A method the module does not export has no body to judge.
    #[test]
    fn a_method_the_module_does_not_export_is_refused() {
        let module = parse_str(r#"(module (func $f nop) (export "withdraw" (func $f)))"#)
            .expect("valid wat");
        assert_eq!(
            check_method(&module, "deposit"),
            Err(TotalityError::NoSuchExport("deposit".to_string())),
        );
    }

    /// A bare module's import call is refused through the reachable walk:
    /// with nothing naming which host function it reaches, nothing can
    /// discharge it.
    #[test]
    fn a_bare_modules_import_call_is_refused() {
        let module = parse_str(
            r#"(module (import "hyperscale:kernel/env" "clock" (func)) (func $entry call 0))"#,
        )
        .expect("valid wat");
        // The import occupies index 0, so the defined entry is index 1 —
        // the shift the walk has to get right to find any body at all.
        assert_eq!(
            check_reachable(&module, 1),
            Err(TotalityError::FaultingHostCall(
                "hyperscale:kernel/env/clock".to_string()
            )),
        );
        // And one nobody calls is not the entry's problem: the verdict is
        // about the reachable set, not the import section.
        let unreached =
            parse_str(r#"(module (import "k" "f" (func)) (func $entry nop))"#).expect("valid wat");
        assert_eq!(check_reachable(&unreached, 1), Ok(()));
    }

    /// A module importing `math` under `module`, with `deposit` calling
    /// the import `name` names and nothing else.
    fn math_caller(module: &str, name: &str) -> Vec<u8> {
        let call = if name == "mul-div" {
            "(call $md (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 0) (i32.const 96))"
        } else {
            "(call $gm (i32.const 0) (i32.const 32) (i32.const 64))"
        };
        parse_str(format!(
            r#"(module
                 (import "{module}" "mul-div" (func $md (param i32 i32 i32 i32 i32)))
                 (import "{module}" "geometric-mean" (func $gm (param i32 i32 i32)))
                 (func $run {call})
                 (export "deposit" (func $run)))"#
        ))
        .expect("valid wat")
    }

    /// The blanket admission of host calls rests on a total leg running
    /// with its handles already materialized, so the gate that would
    /// refuse is discharged before the body starts. Nothing discharges a
    /// zero divisor, so the arithmetic that can meet one is refused.
    #[test]
    fn a_faulting_host_call_denies_the_mark() {
        assert_eq!(
            check_method(&math_caller("hyperscale:kernel/math", "mul-div"), "deposit"),
            Err(TotalityError::FaultingHostCall(
                "hyperscale:kernel/math/mul-div".to_string()
            )),
        );
    }

    /// And the one that cannot fault is admitted, which is the whole
    /// reason the rule names functions rather than the interface: a
    /// square root has no refusal to discharge.
    ///
    /// Both imports are named by the module, so what is set aside is the
    /// reachable set and not the import section.
    #[test]
    fn a_total_host_call_keeps_the_mark() {
        assert_eq!(
            check_method(
                &math_caller("hyperscale:kernel/math", "geometric-mean"),
                "deposit"
            ),
            Ok(()),
        );
    }

    /// The verdict reads the import's module and name, never a name the
    /// guest chose for its own function: an import spelled like a state
    /// accessor under a module the kernel does not define is refused.
    #[test]
    fn an_import_outside_the_kernel_is_refused_all_the_same() {
        assert_eq!(
            check_method(&math_caller("k", "geometric-mean"), "deposit"),
            Err(TotalityError::FaultingHostCall(
                "k/geometric-mean".to_string()
            )),
        );
    }

    /// A state operation that can refuse is outside the allowlist: what a
    /// take refuses — an insufficient balance — is a runtime value no
    /// declaration discharges, so a body that can meet it cannot be
    /// total.
    #[test]
    fn a_refusable_state_op_denies_the_mark() {
        let module = parse_str(
            r#"(module
                 (import "hyperscale:kernel/state" "bucket-take"
                   (func $take (param i32 i32) (result i32)))
                 (func $run (call $take (i32.const 0) (i32.const 16)) drop)
                 (export "deposit" (func $run)))"#,
        )
        .expect("valid wat");
        assert_eq!(
            check_method(&module, "deposit"),
            Err(TotalityError::FaultingHostCall(
                "hyperscale:kernel/state/bucket-take".to_string()
            )),
        );
    }
}
