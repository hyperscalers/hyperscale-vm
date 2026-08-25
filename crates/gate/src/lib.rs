//! The publish gate: what an artifact must satisfy to enter the chain as
//! a package.
//!
//! The whole verdict is a pure function of the bytes, which is what lets
//! it be reached anywhere the bytes are: at admission, where it refuses a
//! publish before a block carries it, and at build time, where it refuses
//! an artifact before anyone signs one. The gate lives here rather than
//! beside the chain so that those are the same call and not two
//! implementations that agree until they do not.
//!
//! A package is content-addressed over its whole artifact, so the
//! metadata inside the artifact is what makes a method's declared effects
//! and an index into its event table unable to drift from the code they
//! describe: change either and the address changes. The section walk and
//! its codec are the vocabulary's own; what this module adds is chain
//! policy — the byte budget on the section, the deterministic wasm
//! profile, and the judgement of each declared method against the export
//! that will receive its arguments.

pub use hyperscale_vm_effects::METADATA_SECTION;
use hyperscale_vm_effects::{
    AbiParam, Clause, MethodSignature, PackageMetadata, Totality,
    attach_metadata as attach_canonical, check_signature, metadata_section, seals, supports,
};
use hyperscale_vm_runtime::{
    ExportParam, ExportShape, check_method, classify_exports, validated_component,
};

pub use crate::section::{MAX_PACKAGE_METADATA_BYTES, decode_metadata, encode_metadata};

mod section;

/// Why an artifact is not admissible as a package.
///
/// One error rather than a taxonomy, because every clause is a pure
/// function of the bytes and the verdict is the same wherever it is
/// reached: the chain refuses the publish, and `cargo hyperscale` refuses
/// the build, off the same call. What differs between them is who is
/// listening, so what a caller needs is the sentence, not a variant to
/// branch on.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct GateError(pub String);

/// Attach `metadata` to a component artifact as its metadata section.
///
/// The result is the publishable artifact: same code, one section longer,
/// and a different content address.
///
/// # Errors
///
/// [`GateError`] if the artifact's section framing is malformed, if
/// it already declares a metadata section, or if the metadata is past a
/// bound the codec enforces — the chain's byte budget included, judged
/// here so nothing assembles an artifact admission would refuse on size.
pub fn attach_metadata(artifact: &[u8], metadata: &PackageMetadata) -> Result<Vec<u8>, GateError> {
    encode_metadata(metadata)?;
    attach_canonical(artifact, metadata).map_err(|error| GateError(error.to_string()))
}

/// The effect metadata a component artifact declares, if it declares any.
///
/// # Errors
///
/// [`GateError`] if the artifact's section framing is malformed, if
/// it declares the metadata section more than once, or if the section's
/// payload is oversized or not canonical metadata.
pub fn extract_metadata(artifact: &[u8]) -> Result<Option<PackageMetadata>, GateError> {
    metadata_section(artifact)
        .map_err(|error| GateError(error.to_string()))?
        .map(decode_metadata)
        .transpose()
}

/// The metadata a publish admits from an artifact, or why it does not.
///
/// Five things are checkable today, and they are checked: the artifact
/// clears the deterministic profile, it declares a metadata section at
/// all, the section decodes canonically and within the bounds the
/// vocabulary fixes, every method it describes is a function the
/// component actually exports, and each method's ABI binding agrees with
/// that export's own type — same arity, a capability handle where the
/// export takes a borrow of the resource the clause's mode implies, a
/// bucket's amount where it takes bytes. Whether a signature
/// over-approximates the code it describes is a compiler's judgement,
/// and this is not one — an under-declaration is harmless because the
/// capability gate never materialises a handle the declaration did not
/// ask for, so a wrong signature costs its author a trap rather than
/// costing anyone else safety. A binding that disagrees with the export
/// is different: the disagreement surfaces at invocation, through
/// whatever error channel each runtime happens to have, so it is refused
/// here where the verdict is one.
///
/// Every one of these is a pure function of the artifact's bytes, which
/// is what lets the whole verdict be reached at admission rather than
/// split across admission and execution. A publish that cannot be
/// admitted never enters a block, so nobody pays for it and nobody
/// stores it.
///
/// # Errors
///
/// [`GateError`] on an artifact outside the profile, an absent or
/// non-canonical metadata section, a declared method the component does
/// not export, an ABI binding the export's type cannot honour, or a
/// claim to totality, which only [`admit_protocol_package`] grants.
pub fn admit_package(artifact: &[u8]) -> Result<PackageMetadata, GateError> {
    admit(artifact, Provenance::Published)
}

/// Admit an artifact the protocol supplies rather than a publisher.
///
/// Identical to [`admit_package`] but for the totality mark, which a
/// publisher cannot claim and which this one reads against the code
/// rather than takes on faith. Genesis seeds the stdlib through here;
/// nothing reachable from a transaction does, so the distinction is a
/// fact about the caller rather than about the bytes — which is the only
/// place it can live, since an artifact claiming to be protocol code
/// looks exactly like one that is.
///
/// # Errors
///
/// As [`admit_package`], except that a claim to totality is checked
/// against the artifact instead of refused, and fails admission when the
/// code does not support it.
pub fn admit_protocol_package(artifact: &[u8]) -> Result<PackageMetadata, GateError> {
    admit(artifact, Provenance::Protocol)
}

/// Who supplied an artifact, which is what decides whether its claim to
/// totality is its own to make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// A publisher's, arriving through a transaction.
    Published,
    /// The protocol's own, seeded at genesis.
    Protocol,
}

fn admit(artifact: &[u8], provenance: Provenance) -> Result<PackageMetadata, GateError> {
    let types = validated_component(artifact)
        .map_err(|error| GateError(format!("artifact is outside the profile: {error}")))?;
    let metadata = extract_metadata(artifact)?
        .ok_or_else(|| GateError("artifact declares no effect metadata section".into()))?;
    let exports = classify_exports(artifact, &types)
        .map_err(|error| GateError(format!("artifact does not parse: {error}")))?;
    for (method, signature) in &metadata.methods {
        let Some(export) = exports.get(method.as_str()) else {
            return Err(GateError(format!(
                "metadata declares method {method:?}, which the component does not export"
            )));
        };
        // The composed signature check: the same judgment the metadata
        // cache runs at its door, asked here first so a refusal names the
        // artifact rather than a call.
        check_signature(signature)
            .map_err(|error| GateError(format!("method {method:?}: {error}")))?;
        check_abi_against_export(method, signature, &export.params)?;
        check_outputs_against_export(method, signature, export)?;
        judge_totality(artifact, method, signature, export, provenance)?;
    }
    judge_seal(&metadata, provenance)?;
    Ok(metadata)
}

/// Judge that a published package can bring its components up.
///
/// Admission fences every call on a component against the presence of
/// its configuration leaf, and the only thing that can write that leaf
/// is a method of the component's own package. A published package
/// declaring no such method has components that can never become actual
/// — every call to every one of them refused, for a reason no caller
/// could have read off the package. Refused here, where the answer is
/// the author's to give.
///
/// Only a publisher's. A principal has no creation to finish, so the
/// package serving them declares no seal and wants none; that package is
/// the protocol's, seeded at genesis, and no published package can take
/// its place.
fn judge_seal(metadata: &PackageMetadata, provenance: Provenance) -> Result<(), GateError> {
    if matches!(provenance, Provenance::Protocol) || metadata.methods.values().any(seals) {
        return Ok(());
    }
    Err(GateError(
        "the package declares no way to make a component of it actual: one method must \
         write the component's own configuration leaf, which is the cell every call to \
         it is judged against"
            .into(),
    ))
}

/// Judge what a method declares it hands back against what its export
/// hands back.
///
/// Every edge crosses as a bucket the kernel takes ownership of, so an
/// export's result carries one own per declared output; a method that
/// answers carries a byte list beside them. Both are functions of the
/// artifact, so a signature disagreeing with either describes a package
/// that is not the one being published.
fn check_outputs_against_export(
    method: &str,
    signature: &MethodSignature,
    export: &ExportShape,
) -> Result<(), GateError> {
    let declared = signature.outputs.len();
    if declared != export.edges {
        return Err(GateError(format!(
            "method {method:?}: the signature produces {declared} value edges, the export \
             hands back {}",
            export.edges
        )));
    }
    if signature.answers != export.answers {
        return Err(GateError(if export.answers {
            format!(
                "method {method:?}: the export hands back a value beside its edges, and \
                 the signature says it answers with nothing"
            )
        } else {
            format!(
                "method {method:?}: the signature says the method answers with a value, \
                 and the export hands back none"
            )
        }));
    }
    Ok(())
}

/// Judge a claim to totality: refused outright from a publisher, and read
/// against the code when the protocol makes it.
///
/// The mark says a caller can commit without waiting to hear back, so a
/// wrong one is not a lost optimisation but a torn settlement: an
/// outbound leg the core already committed against, failing. Two
/// different things follow from that, one per provenance.
///
/// **A publisher cannot claim it at all.** What stands behind the mark is
/// a scan with documented gaps — linear memory taken as safe, the ABI's
/// allocator set aside — and both are open in the direction an author who
/// wanted the mark would push. Provenance cannot be read off the bytes,
/// since an artifact claiming to be protocol code looks exactly like one
/// that is, so it rides the entry point rather than an allowlist. The
/// refusal costs a published package little: a venue's own code is core,
/// where no mark is wanted, and the legs around it are the account's
/// withdraw and deposit that the stdlib supplies.
///
/// **The protocol's own claim is checked here rather than trusted.** The
/// artifact is in hand and the scan is a pure function of it, so a mark
/// the code cannot support fails admission rather than waiting for a test
/// to notice — which is what makes the mark verified at deploy instead of
/// asserted at deploy and audited later.
fn judge_totality(
    artifact: &[u8],
    method: &str,
    signature: &MethodSignature,
    export: &ExportShape,
    provenance: Provenance,
) -> Result<(), GateError> {
    // The weakest state is the one the component type decides outright,
    // in both directions. A signature is `Fallible` exactly when its
    // export carries an error arm: claiming it without one describes a
    // refusal channel the code does not have, and omitting it with one
    // hides the channel from every reader that acts on the mark. Neither
    // is a conservative reading — the mark is a function of the artifact,
    // so there is one right answer and the gate holds authors to it.
    if export.declines != (signature.totality == Totality::Fallible) {
        return Err(GateError(if export.declines {
            format!(
                "method {method:?} declares {:?} over an export that carries an error arm",
                signature.totality
            )
        } else {
            format!("method {method:?} declares Fallible over an export that cannot decline")
        }));
    }
    if signature.totality != Totality::Total {
        return Ok(());
    }
    match provenance {
        Provenance::Published => Err(GateError(format!(
            "method {method:?} claims totality, which a published package cannot: \
             the mark is granted to protocol code seeded at genesis"
        ))),
        Provenance::Protocol => check_method(artifact, method).map_err(|error| {
            GateError(format!(
                "method {method:?} claims totality its artifact does not support: {error}"
            ))
        }),
    }
}

/// Judge a method's ABI binding against the export type that will
/// receive the arguments it builds.
///
/// `check_abi` has already judged the binding against the signature, so
/// clause and parameter indices resolve; what remains is whether the
/// compiled export can take what the binding builds.
fn check_abi_against_export(
    method: &str,
    signature: &MethodSignature,
    params: &[ExportParam],
) -> Result<(), GateError> {
    if signature.abi.len() != params.len() {
        return Err(GateError(format!(
            "method {method:?}: the binding builds {} arguments, the export takes {}",
            signature.abi.len(),
            params.len()
        )));
    }
    for (position, (binding, param)) in signature.abi.iter().zip(params).enumerate() {
        match binding {
            AbiParam::Handle { clause, site } => {
                if *param != ExportParam::Handle {
                    return Err(GateError(format!(
                        "method {method:?}: ABI parameter {position} is a capability \
                         handle, but the export takes {param:?}"
                    )));
                }
                // Whether the site the binding names materializes
                // anything at all. What it materializes is the
                // capability's own answer, held by the kernel at every
                // operation.
                let declared = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| signature.effects.get(index));
                let backed = match declared {
                    Some(Clause::ForEach { body, .. }) => usize::try_from(*site)
                        .ok()
                        .and_then(|at| body.get(at))
                        .is_some_and(supports),
                    Some(clause) => *site == 0 && supports(clause),
                    None => false,
                };
                if !backed {
                    return Err(GateError(format!(
                        "method {method:?}: ABI parameter {position} borrows site {site} of \
                         clause {clause}, which materializes none"
                    )));
                }
            }
            AbiParam::Bucket(_) => {
                if *param != ExportParam::Bucket {
                    return Err(GateError(format!(
                        "method {method:?}: ABI parameter {position} is a value edge, \
                         but the export takes {param:?}"
                    )));
                }
            }
            AbiParam::Guard(_) => {
                if *param != ExportParam::Flag {
                    return Err(GateError(format!(
                        "method {method:?}: ABI parameter {position} is a clause's guard \
                         verdict, but the export takes {param:?}"
                    )));
                }
            }
            AbiParam::Derived(_) => {
                if param.is_resource() {
                    return Err(GateError(format!(
                        "method {method:?}: ABI parameter {position} is a derived \
                         value, but the export takes {param:?}"
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{
        AbiParam, Clause, Expr, MethodSignature, PackageMetadata, RuleExpr, seal_clauses,
    };
    use hyperscale_vm_fixtures::{LOTTERY_COMPONENT, book, lottery};
    use hyperscale_vm_runtime::component_exports;
    use hyperscale_vm_stdlib::{account, account_artifact, staking_artifact};
    use wat::parse_str;

    use super::{admit_protocol_package, *};

    /// A component exporting one no-argument function per name.
    fn component_exporting(names: &[&str]) -> Vec<u8> {
        use std::fmt::Write as _;

        // Every published package brings its components up through a
        // seal of its own, so the fixture exports one beside whatever
        // the case under test names.
        let names: Vec<&str> = names.iter().copied().chain(["instantiate"]).collect();
        let mut source = String::from("(component\n  (core module $m\n");
        for index in 0..names.len() {
            let _ = writeln!(source, "    (func (export \"f{index}\"))");
        }
        source.push_str("  )\n  (core instance $i (instantiate $m))\n");
        for (index, name) in names.iter().enumerate() {
            let _ = writeln!(
                source,
                "  (func (export \"{name}\") (canon lift (core func $i \"f{index}\")))"
            );
        }
        source.push(')');
        parse_str(&source).expect("the component assembles")
    }

    /// Metadata declaring one empty signature per method name, beside
    /// the seal every published package needs to bring a component up.
    fn declaring(methods: &[&str]) -> PackageMetadata {
        let mut metadata = PackageMetadata::default();
        for method in methods {
            metadata
                .methods
                .insert((*method).into(), MethodSignature::default());
        }
        metadata.methods.insert("instantiate".into(), sealing());
        metadata
    }

    /// A signature carrying the seal every published package needs.
    fn sealing() -> MethodSignature {
        MethodSignature {
            effects: seal_clauses(),
            ..MethodSignature::default()
        }
    }

    /// A preamble followed by one non-custom section carrying `body`.
    fn with_section(id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = b"\0asm".to_vec();
        out.extend_from_slice(&[0x0d, 0x00, 0x01, 0x00]);
        out.push(id);
        out.push(u8::try_from(body.len()).expect("test sections stay under one length byte"));
        out.extend_from_slice(body);
        out
    }

    /// A binding a caller cannot resolve is refused where it is cheapest
    /// to refuse: the artifact's own bytes, before a block carries it.
    ///
    /// The predicate itself is the vocabulary's and is tested there. What
    /// this pins is that a publish consults it at all, and that its
    /// refusal names the method whose binding is wrong — a package
    /// declaring several is otherwise unactionable.
    #[test]
    fn an_unresolvable_abi_binding_refuses_at_publish() {
        let component = component_exporting(&["m"]);
        let mut metadata = declaring(&["m"]);
        metadata
            .methods
            .get_mut("m")
            .expect("declared")
            // The signature declares no effect clauses, so there is no
            // clause 0 for a handle to name.
            .abi = vec![AbiParam::Handle { clause: 0, site: 0 }];
        let artifact = attach_metadata(&component, &metadata).expect("attaches");

        let refused = admit_package(&artifact).expect_err("an unresolvable binding refuses");
        assert!(refused.0.contains("\"m\""), "{}", refused.0);

        // The same artifact with nothing bound admits, so the refusal is
        // the binding and not the shape.
        let sound = attach_metadata(&component, &declaring(&["m"])).expect("attaches");
        assert!(admit_package(&sound).is_ok());
    }

    #[test]
    fn an_artifact_declares_the_metadata_it_was_attached() {
        for metadata in [account::metadata(), book::metadata()] {
            let plain = with_section(1, b"code goes here");
            assert_eq!(extract_metadata(&plain).expect("walks"), None);

            let artifact = attach_metadata(&plain, &metadata).expect("attaches");
            assert_eq!(
                extract_metadata(&artifact).expect("walks"),
                Some(metadata.clone())
            );
            // The code is untouched and the artifact is a different one.
            assert!(artifact.starts_with(&plain));
            assert_ne!(artifact, plain);
        }
    }

    #[test]
    fn different_metadata_makes_a_different_artifact() {
        // What content addressing over the whole artifact buys: the
        // declared effects cannot drift from the code under one address.
        let plain = with_section(1, b"code");
        let one = attach_metadata(&plain, &account::metadata()).expect("attaches");
        let other = attach_metadata(&plain, &book::metadata()).expect("attaches");
        assert_ne!(one, other);
    }

    #[test]
    fn a_corrupt_payload_is_refused_rather_than_read() {
        let plain = with_section(1, b"code");
        let artifact = attach_metadata(&plain, &account::metadata()).expect("attaches");
        // Every byte the section's payload occupies: a change either
        // fails to decode or names different metadata, never silently
        // the same.
        for index in plain.len()..artifact.len() {
            let mut mutated = artifact.clone();
            mutated[index] ^= 0xFF;
            if let Ok(Some(metadata)) = extract_metadata(&mutated) {
                assert_ne!(metadata, account::metadata());
            }
        }
    }

    #[test]
    fn a_publish_admits_metadata_the_component_backs() {
        let component = component_exporting(&["deposit", "withdraw"]);
        let metadata = declaring(&["deposit", "withdraw"]);
        let artifact = attach_metadata(&component, &metadata).expect("attaches");
        assert_eq!(admit_package(&artifact).expect("admits"), metadata);

        // Declaring fewer methods than the component exports is fine:
        // an export nothing declares is an export nothing can call.
        let partial = attach_metadata(&component, &declaring(&["deposit"])).expect("attaches");
        assert!(admit_package(&partial).is_ok());
    }

    /// What a publish admits is what the package declared, down to who
    /// may call each method.
    ///
    /// The gate at admission reads this field and nothing else to decide
    /// whether a node needs its target's signature, so a codec that
    /// dropped it would not fail loudly — it would publish every method
    /// as public and leave the gate agreeing.
    #[test]
    fn a_publish_admits_the_accessibility_the_package_declares() {
        let component = component_exporting(&["deposit", "withdraw"]);
        let mut metadata = declaring(&["deposit", "withdraw"]);
        metadata
            .methods
            .get_mut("withdraw")
            .expect("declared")
            .effects
            .push(Clause::Requires {
                guard: None,
                rule: RuleExpr::claim(Expr::SelfAddr),
            });
        let artifact = attach_metadata(&component, &metadata).expect("attaches");

        let admitted = admit_package(&artifact).expect("admits");
        assert!(admitted.methods["withdraw"].requires_evidence());
        assert!(!admitted.methods["deposit"].requires_evidence());

        // And the two declarations are two artifacts: the field is
        // content-addressed with the code, so nothing can republish the
        // same address under a weaker claim.
        let public =
            attach_metadata(&component, &declaring(&["deposit", "withdraw"])).expect("attaches");
        assert_ne!(artifact, public);
    }

    /// A component whose one export declines: the refusal channel over a
    /// method producing nothing, which is the shape a `Fallible` mark is
    /// judged against.
    fn component_declining(name: &str) -> Vec<u8> {
        parse_str(&*format!(
            "(component\n  (core module $m\n    (memory (export \"mem\") 1 1)\n               (func (export \"f\") (result i32) i32.const 0)\n               (func (export \"seal\")))\n             (core instance $i (instantiate $m))\n             (func (export \"instantiate\") (canon lift (core func $i \"seal\")))\n             (func (export \"{name}\") (result (result (error u32)))\n               (canon lift (core func $i \"f\") (memory $i \"mem\"))))"
        ))
        .expect("the component assembles")
    }

    /// The totality mark is a function of the component type, and the
    /// gate holds it to that in both directions.
    ///
    /// Under-claiming is refused as firmly as over-claiming, which is
    /// what makes the mark canonical: a leg's decomposition reads it, and
    /// two artifacts with the same code could otherwise describe
    /// themselves differently and be judged differently.
    #[test]
    fn a_totality_mark_the_export_type_contradicts_refuses_at_publish() {
        let declining = component_declining("swap");
        let mut fallible = PackageMetadata::default();
        fallible.methods.insert("instantiate".into(), sealing());
        fallible.methods.insert(
            "swap".into(),
            MethodSignature {
                totality: Totality::Fallible,
                ..MethodSignature::default()
            },
        );
        assert!(
            admit_package(&attach_metadata(&declining, &fallible).expect("attaches")).is_ok(),
            "an error arm is what a Fallible mark describes"
        );

        // The same code, marked as if it could not decline.
        let understated = attach_metadata(&declining, &declaring(&["swap"])).expect("attaches");
        let error = admit_package(&understated).expect_err("the arm is in the type");
        assert!(
            error.to_string().contains("carries an error arm"),
            "{error}"
        );

        // And the converse: an arm-free export marked as declining.
        let overstated =
            attach_metadata(&component_exporting(&["swap"]), &fallible).expect("attaches");
        let error = admit_package(&overstated).expect_err("there is no arm to describe");
        assert!(error.to_string().contains("cannot decline"), "{error}");
    }

    #[test]
    fn a_publish_refuses_a_method_the_component_does_not_export() {
        let component = component_exporting(&["deposit"]);
        let artifact =
            attach_metadata(&component, &declaring(&["deposit", "withdraw"])).expect("attaches");
        let refused = admit_package(&artifact).expect_err("refuses");
        assert!(refused.0.contains("withdraw"), "{}", refused.0);

        // The name has to match exactly — a component export is looked
        // up by the name a manifest node writes.
        let renamed = attach_metadata(
            &component_exporting(&["deposit2"]),
            &declaring(&["deposit"]),
        )
        .expect("attaches");
        assert!(admit_package(&renamed).is_err());
    }

    /// A published package has to be able to bring a component up.
    ///
    /// Admission judges every call on a component against its
    /// configuration leaf, and only a method of the component's own
    /// package can write that leaf. A package declaring none has
    /// components nobody can ever call — refused here, where the author
    /// can still do something about it, rather than one call at a time
    /// for the life of the package.
    #[test]
    fn a_publish_refuses_a_package_that_can_seal_nothing() {
        let mut sealless = declaring(&["deposit"]);
        sealless.methods.remove("instantiate");
        let artifact =
            attach_metadata(&component_exporting(&["deposit"]), &sealless).expect("attaches");
        let refused = admit_package(&artifact).expect_err("its components could never be called");
        assert!(refused.0.contains("configuration leaf"), "{}", refused.0);

        // The same package, with the seal its components come up
        // through.
        let artifact =
            attach_metadata(&component_exporting(&["deposit"]), &declaring(&["deposit"]))
                .expect("attaches");
        assert!(admit_package(&artifact).is_ok());

        // The protocol's own account declares no seal and wants none: a
        // principal has no creation to finish, and the package serving
        // them is seeded at genesis rather than published.
        assert!(admit_protocol_package(account_artifact()).is_ok());
    }

    #[test]
    fn a_publish_refuses_an_artifact_that_declares_nothing() {
        // No signatures, no deploy: an artifact without the section is
        // refused rather than published with an empty table.
        let component = component_exporting(&["deposit"]);
        assert!(admit_package(&component).is_err());
        // And one whose section is not parseable as an artifact at all.
        assert!(admit_package(&with_section(1, b"code")).is_err());
    }

    #[test]
    fn only_the_outermost_components_exports_count() {
        // A nested component's exports are its own; nothing a manifest
        // names can reach them, so they cannot back a declaration.
        let inner = "(component (core module $m (func (export \"f\"))) \
             (core instance $i (instantiate $m)) \
             (func (export \"hidden\") (canon lift (core func $i \"f\"))))";
        let outer = parse_str(&*format!(
            "(component (core module $m (func (export \"f\"))) \
             (core instance $i (instantiate $m)) \
             (func (export \"shown\") (canon lift (core func $i \"f\"))) \
             {inner})"
        ))
        .expect("the component assembles");

        let exports = component_exports(&outer).expect("parses");
        assert_eq!(exports.keys().collect::<Vec<_>>(), vec!["shown"]);
        let artifact = attach_metadata(&outer, &declaring(&["hidden"])).expect("attaches");
        assert!(admit_package(&artifact).is_err());
    }

    /// The committed stdlib artifacts pass the same gate a runtime
    /// publish would: their authored metadata agrees with the export
    /// types their blobs compile to. Without this the stdlib's binding
    /// is judged by nothing — genesis seeds it into the cache directly.
    #[test]
    fn the_stdlib_artifacts_pass_the_publish_gate() {
        for (name, artifact) in [
            ("account", account_artifact()),
            ("staking", staking_artifact()),
        ] {
            admit_protocol_package(artifact)
                .unwrap_or_else(|error| panic!("{name}: the stdlib must admit: {}", error.0));
        }
    }

    /// The stdlib's own artifact is what a publisher would have to submit
    /// to claim totality, and submitting it is exactly what the gate
    /// refuses: the same bytes admit as protocol code and refuse as a
    /// publish, because provenance is the caller's and not the artifact's.
    #[test]
    fn a_published_package_cannot_claim_totality() {
        let artifact = account_artifact();
        assert!(
            admit_protocol_package(artifact).is_ok(),
            "the account declares a total method, or this proves nothing",
        );

        let error = admit_package(artifact).expect_err("a publish cannot carry the mark");
        assert!(
            error.0.contains("claims totality"),
            "refused for the wrong reason: {}",
            error.0,
        );
    }

    /// The protocol's own claim is read against its code. Marking a
    /// method the artifact cannot support fails admission, which is what
    /// makes the mark verified at deploy rather than asserted at deploy
    /// and audited somewhere else.
    #[test]
    fn a_protocol_claim_its_artifact_refuses_does_not_admit() {
        // The lottery's settlement is public, so it clears the gate rule
        // and reaches the artifact. Two things stand in front of the
        // code: a round settles once, so its declaration carries a
        // precondition and a total method admits every state; and the
        // export carries an error arm, since a settlement declines a page
        // it cannot prove covered the round. The declaration is read
        // first. The account does not serve as the example: every body it
        // has is a call or two, and the kernel does the work the loops
        // used to.
        let mut metadata = lottery::metadata();
        metadata
            .methods
            .get_mut("settle")
            .expect("the lottery settles a round")
            .totality = Totality::Total;
        let artifact = attach_metadata(LOTTERY_COMPONENT, &metadata).expect("attaches");

        let error = admit_protocol_package(&artifact)
            .expect_err("a mark the code cannot support is not admissible");
        assert!(
            error.0.contains("precondition"),
            "refused for the wrong reason: {}",
            error.0,
        );

        // Behind the declaration stands the refusal it masks on the
        // admission path: settling walks the entrants, and a walk has no
        // static fuel ceiling, so the artifact itself refuses the mark
        // whatever the metadata claims.
        let honest = attach_metadata(LOTTERY_COMPONENT, &lottery::metadata()).expect("attaches");
        check_method(&honest, "settle").expect_err("a walk has no static ceiling");
    }

    /// A component whose one export takes a `u64`, for bindings to
    /// disagree with.
    fn scalar_export() -> Vec<u8> {
        parse_str(
            r#"(component
                 (core module $m
                   (func (export "f") (param i64) (result i64) local.get 0)
                   (func (export "seal")))
                 (core instance $i (instantiate $m))
                 (func (export "instantiate") (canon lift (core func $i "seal")))
                 (func (export "m") (param "clock" u64) (result u64)
                   (canon lift (core func $i "f"))))"#,
        )
        .expect("the component assembles")
    }

    #[test]
    fn a_binding_the_export_type_cannot_honour_refuses_at_publish() {
        use hyperscale_vm_effects::{Clause, Expr, ModeExpr, TargetExpr, Value, package_slot};
        use hyperscale_vm_types::{Address, AddressClass};

        // A value cell is keyed by what it holds, so the two clauses
        // below that move value say so twice.
        let held = || {
            Expr::Literal(Value::Address(Address::new(
                [0xE1; 31],
                AddressClass::Resource,
            )))
        };

        // Arity: the binding builds nothing, the export takes one.
        let empty = declaring(&["m"]);
        let artifact = attach_metadata(&scalar_export(), &empty).expect("attaches");
        let refused = admit_package(&artifact).expect_err("arity must refuse");
        assert!(refused.0.contains("arguments"), "{}", refused.0);

        // A handle binding against a scalar parameter.
        let mut wrong_kind = declaring(&["m"]);
        {
            let signature = wrong_kind.methods.get_mut("m").expect("declared");
            signature.effects = vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: package_slot(0),
                    material: vec![],
                }),
                mode: ModeExpr::Write,
                denomination: None,
            }];
            signature.abi = vec![AbiParam::Handle { clause: 0, site: 0 }];
        }
        let artifact = attach_metadata(&scalar_export(), &wrong_kind).expect("attaches");
        let refused = admit_package(&artifact).expect_err("a handle needs a borrow");
        assert!(refused.0.contains("capability handle"), "{}", refused.0);

        // A handle binding on a site the declaration does not have.
        // Every capability crosses as one resource of one width, so what
        // is left to hold is whether the site it names is declared at
        // all — an empty loop declares none.
        let borrow_export = parse_str(
            r#"(component
                 (import "hyperscale:kernel/state" (instance $state
                   (export "site" (type $ac (sub resource)))))
                 (alias export $state "site" (type $access))
                 (core module $m
                   (func (export "f") (param i32) (result i64) i64.const 0)
                   (func (export "seal")))
                 (core instance $i (instantiate $m))
                 (func (export "instantiate") (canon lift (core func $i "seal")))
                 (func (export "m") (param "vault" (borrow $access)) (result u64)
                   (canon lift (core func $i "f"))))"#,
        )
        .expect("the component assembles");
        let mut unbacked = declaring(&["m"]);
        {
            let signature = unbacked.methods.get_mut("m").expect("declared");
            signature.effects = vec![Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![],
            }];
            signature.abi = vec![AbiParam::Handle { clause: 0, site: 0 }];
        }
        let artifact = attach_metadata(&borrow_export, &unbacked).expect("attaches");
        let refused = admit_package(&artifact).expect_err("an empty loop declares no site");
        assert!(refused.0.contains("not an access"), "{}", refused.0);

        // The same shape with the matching mode admits, so the refusals
        // above are the disagreement and not the shape.
        let mut sound = declaring(&["m"]);
        {
            let signature = sound.methods.get_mut("m").expect("declared");
            signature.effects = vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: package_slot(0),
                    material: vec![held()],
                }),
                mode: ModeExpr::Delta,
                denomination: Some(Box::new(held())),
            }];
            signature.abi = vec![AbiParam::Handle { clause: 0, site: 0 }];
        }
        let artifact = attach_metadata(&borrow_export, &sound).expect("attaches");
        assert!(admit_package(&artifact).is_ok());
    }
}
