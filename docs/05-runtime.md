# Runtime: the Component Model host and the deterministic profile

## 1. Why a standards-track ABI is safe here

Language-tied VMs (Move, Scrypto) exist because safety lives in the language. Here safety lives in the kernel gate and the effect metadata ([01-effects-and-routing.md](01-effects-and-routing.md)), neither of which trusts the guest: a contract from a hostile toolchain with wrong declarations earns deterministic aborts, never divergence. That makes a language-neutral ABI free of safety cost, so the WASM Component Model wins over a bespoke boundary. The specific alignments:

- **WIT is the signature substrate.** Effect metadata maps over exactly WIT's shape — component, function, typed args. WIT has no annotation mechanism, so metadata rides a **custom section** in the component binary, content-addressed with the package: one artifact, one hash, one cache entry. The section also carries deploy-verified function attributes — static gas bounds and totality marks — never self-asserted ones.
- **Capability imports are the enforcement gate.** A component touches only what its world imports; the kernel instantiates it with handles for the declared effect set and nothing else. "No handle exists" (INV-VM-1) is the Component Model's native discipline.
- **`own`/`borrow` handle semantics carry the boundary half of linearity.** A cell handle is lent for one call: it arrives `borrow`, and the capability it grants is whatever mode materialized it. Value in flight is the world's one owned resource — passed `own`, so crossing it is a transfer the canonical ABI performs, and the drop of one is delivered to the kernel rather than being a guest-side no-op. What the boundary cannot see, the kernel holds on its own account: neither engine's ABI is trusted for value conservation, because an ABI that let a body name one edge twice would otherwise be a mint ([03-objects-and-state.md](03-objects-and-state.md) §6).

## 2. The deterministic profile

A frozen subset of WASM, validated at deploy — a non-conforming module never enters state:

- No floats, no relaxed SIMD, no threads, no Component Model async, no exceptions, no GC, no typed function references.
- The subset is an **allowlist of proposals**, and exclusions are enforced there rather than in the operator walk wherever a proposal can be excluded whole — the walk sees function bodies, so it can reject an operator but not a type in a signature, and refusing at the feature set is exhaustive by construction. Only where a proposal is needed in part does the walk carry the exclusion (reference types stay on for the `call_indirect` encoding the Rust toolchain emits; bulk memory for `memory.copy`/`fill`).
- Fixed limits — linear memory, tables, call depth, module size, function count — all consensus constants that trap identically everywhere, plus **structural compile bounds** checked at deploy: function body size, basic blocks, parameters, types, per-function operand stack. Bytecode-to-native translation is a priced, deterministically bounded resource — deploy gas covers worst-case compilation within the limits, the bound values calibrated against compile-bomb corpora — and **no verdict anywhere depends on wall-clock compile time**: a timeout verdict is hardware-dependent and therefore a fork.
- Fuel metering covers every instruction **and** canonical-ABI lift/lower proportional to bytes moved; boundary copies are never free. It covers what a **collection scan lifts out of the store**, too — bytes that never cross the ABI, and so are invisible to the copy supplement that prices everything else. A declared interval's entry cap bounds one such page, and the charge is what bounds the number of them: a write drops the page it invalidates, so a body alternating a write with a read of the same interval materializes a fresh one each time, and the fee is what stops that being free. Gas units are *defined as* engine fuel plus supplements, never an instrumented reproduction of a foreign schedule. Size-linear ops charge per byte; the stack bound is static, computed at deploy — and it budgets **two** quantities, native stack bytes and frame count, because the deepest chain and the heaviest one need not be the same chain. The bound is computed over the component's **linked** graph, not per core module: an element segment in one module can populate the table another calls through, closing a call cycle at run time that no single module contains — the shape `wit-bindgen` actually emits.
- Pinned canonical ABI options (UTF-8 only) and specified handle-table allocation behavior.
- Deterministic compilation irrelevance: consensus outcomes are identical interpreted or compiled; compiled-module caches key on code hash and are pure acceleration.

How any of the above moves — the epoch-gated upgrade process and the determinism audit that gates it — is [../upgrades.md](../upgrades.md).

## 3. One blessed engine, one executable spec

**One blessed engine per protocol version** — wasmtime, version-pinned, embedded (`crates/runtime`). The rationale: it is the reference implementation of the exact specs the profile freezes; its security posture is best-in-class; its tiered backends execute one semantics, giving the differential harness intra-engine cross-check lanes; its fuel metering is instruction-deterministic within a version, which the pin absorbs; and it embeds Rust-native with no FFI in the consensus path. Engine upgrades are protocol upgrades through the host's epoch-gated governance channel. Three operational rules ride the pin: the blessed **backend** is pinned with the version (Cranelift; the other backends stay as differential lanes); compiled-module caches **pre-warm in the epoch before an engine bump** — the boundary is epoch-gated and known ahead, so the recompilation avalanche is scheduled away, and package immutability means no other invalidation event exists; and compilation runs on a **dedicated OS thread pool, never the shared dispatch pools** — nested work-stealing between the engine's internal parallel compilation and the host's pools is a known self-deadlock shape.

**The reference interpreter is the executable spec.** A slow, obviously-correct interpreter of the profile (`crates/ref`) lives beside the blessed engine and is differentially tested against it under seeded harnesses. Divergence between the two is a release blocker, whichever is wrong. It is independently written — never derived from the engine's own interpreter tier — because same-vendor implementations share bug correlations, and the interpreter's whole value is being an uncorrelated witness.

**Tiered language support.** Rust is the audited toolchain. Every other wit-bindgen target — C first among the candidates — is admitted per-toolchain once its emitted code and embedded runtime pass the determinism audit ([../upgrades.md](../upgrades.md)); a garbage collector or embedded JS engine inside a module is an unaudited determinism surface, not a policy preference.

## 4. The host surface

The contract world imports `hyperscale:kernel` and nothing else — no WASI, ever, in contract worlds:

- **State capabilities** per declared key and mode ([01-effects-and-routing.md](01-effects-and-routing.md) §6).
- **Environment**: the transaction clock and the per-transaction randomness draw ([04-execution-semantics.md](04-execution-semantics.md) §3) — and nothing that varies with schedule position.
- **Events**: blueprint-declared, WIT-typed application events emitted through the kernel world — size- and count-capped, carried success-only, homed on the emitting object's shard, priced as retention bytes. Events are consensus content: they merkle into the receipt root ([07-host-integration.md](07-host-integration.md) §5).
- **Crypto**: hashing, signature verification, and any future proof verification are host functions exclusively. Guest-side crypto is rejected at deploy where detectable and priced out where not — which keeps the hash-function seam and any future proof verifier in one swappable place, and lets fuel track hardware honestly.
- **Numerics**: one blessed fixed-point decimal type with canonical overflow-abort semantics, host-provided. Contract-local reimplementations of money math are a deploy lint.

## 5. Encodings

- **Call and escrow boundary values**: the canonical ABI.
- **Substates, wire types, hashed content**: HBOR (`crates/hbor`).
- **Instantiation-time generics** — non-fungible data types, typed KV stores, possibly defined in another package — encode as opaque payloads bound to a content-addressed schema reference, validated at admission.

**HBOR.** Self-describing encodings exist because schemas might be unavailable; here every schema is content-addressed and immutable, so that premise is gone while its costs remain. HBOR is **schema-external** — a `(schema_hash, payload)` envelope gives self-description on demand; **canonical at decode** — exactly one valid byte string per value, the decoder rejecting unsorted maps, non-minimal integers, and trailing bytes, making canonicity decoder construction rather than encoder discipline (INV-VM-13); **natively merkleized** — every type defines its chunking, so field-level proofs fall out of the encoding, composing with substate granularity; and **WIT-aligned** — one value model spanning persistence and calls, so there is no second encoding for depth and size caps to disagree with. Kept from its predecessor: fixed discriminants, versioned payloads, backwards-compat schema assertions, derive ergonomics, depth limits.

## 6. Authentication, authorization, and callers

Split at the admission/execution boundary:

- **Authentication** — signature validation — happens at admission against the **registered scheme set**, before any ordering or fee exposure. Deterministic, priced per scheme, never guest code. Keys and signatures are scheme-tagged everywhere — `(scheme_id, bytes)`, never bare bytes — and the registry extends additively through the epoch-gated governance channel, so post-quantum schemes join without an envelope change. Verification is priced per scheme and per byte — kilobyte signatures are a fee fact, not a hidden subsidy.
- **Authorization** — roles, badges — happens during execution as ordinary declared reads of badge state, resolved through the effect model like any other access. Evidence is uniform: signatures surface as **virtual badges** identified by `(scheme_id, pubkey)`, so every authorization is a badge-evidence edge in the manifest whether the evidence is a key, a held token, or a role. Hybrid classical+PQ signing is AND-composition in the rule language, no protocol mechanism needed. Role rules use a declarative require/AND/OR/threshold expression language, bound against evidence edges at admission where the edges are static, with deploy-time depth and branch caps. Runtime proof objects with clone/drop lifecycles do not exist.
- **Caller identity is synthesized evidence.** The kernel synthesizes a caller capability per static call edge — the calling package, component, outer object, or parent intent — so "only my package", "outer object only", and parent-verification rules are declarative edge requirements checked against the static call graph, with no ambient caller badge. This is how the stdlib's own invariants are expressed: a vault's lock methods admit only its resource manager.

Virtual principals derive their address from their key and are forever bound to that scheme; securified principals hold scheme-tagged key entries and rotate schemes — including to post-quantum — with no address change. Securify-then-rotate is the migration path.

## 7. Reentrancy

The per-transaction call graph is static — call targets are manifest-visible — and checked **acyclic at admission**. Reentrancy is deleted as a concept, not defended against; effect composition is a DAG fold, and the defensive idiom set built around reentrant calls does not carry over.

## 8. Validity-proof posture

Nothing ships, and the design keeps the door open at near-zero cost. The readiness disciplines are all already load-bearing for other reasons: the deterministic profile is the provable spec and the reference interpreter its semantic anchor (a circuit is a third implementation of the same profile, slotting into the differential harness); total static access pre-declares the entire state-access witness, which removes the dominant nondeterministic-RAM cost of proving general execution; host-side crypto is the precompile boundary; and no receipt format may assume re-execution as the only verification path. The trigger for going further is named: when networking costs cap the host's ability to add shards, so per-shard throughput must rise. Not before — while topology scales, splitting a shard is orders of magnitude cheaper than proving one, and proofs never lift the serial hot-object ceiling.
