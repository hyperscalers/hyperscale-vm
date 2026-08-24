# Manifests and intents: the typed dataflow DAG

The manifest is the artifact every other layer reads: `route()` folds over it, admission type-checks it, wallets render it, solvers compose it, and effect signatures bind to it. Its design goal is that each of those consumers gets a read-off, never a reconstruction.

## 1. Structure

A manifest is a directed acyclic graph:

- **Nodes** are method invocations, typed against the target's WIT signature ([05-runtime.md](05-runtime.md)). Arguments are literals, envelope inputs, or inbound edges.
- **Edges** are typed value flows — resource amounts, proofs, plain data — each with exactly one producer and one consumer. Buckets are edges; proofs are edges. There is no ambient auth zone: evidence flows explicitly to the nodes that need it, and every claim it carries was minted by a gate that read state ([06-authority.md](06-authority.md)).
- **Linearity is well-formedness.** Every output edge must be consumed; a node's remainder (change from a partial take, residue after a swap) is a typed **rest edge** that must be routed somewhere, usually back to the sender's account. "Nothing dangles" is a syntactic check, not an execution-time discovery. SDK sugar auto-routes rest edges so the ergonomic cost lands in tooling, not on users.
- **Transient values are edge types.** A value whose type restricts its consumers to designated methods must be consumed like any edge, so the hot-potato pattern — flash loans, single-use rights — needs zero runtime machinery: the repayment obligation is unparseable to violate.
- **Constraints are declarative edge annotations** — minimum and maximum amounts, resource types. This is the same constraint language as subintent bindings (§3): a slippage bound and an intent's "I accept ≥ 100 USDC" are one mechanism. The language stays enumerable and declarative — never a program — or admission-time checking erodes.
- **Sequencing is dataflow-only.** Execution order is the DAG's topological order; independent legs are visibly independent. Acyclicity is subsumed by the format: a manifest is acyclic or it does not parse.
- **Amounts are dynamic, types are static.** A swap-output edge's amount is runtime-determined; its resource type and constraints are not. Effects need types (which vaults), never amounts — the which-key/how-much split, carried into the format's type system.

**Fees are not in the manifest.** The fee payer, `max_fee`, and gas limit live in the envelope ([01-effects-and-routing.md](01-effects-and-routing.md) §8). There is no fee instruction of any kind.

## 2. What each consumer reads

- **`route()`**: a fold over nodes — evaluate each node's effect signature with its bound literals and inbound edge types, union the results. Order-independent by construction (INV-VM-ACCESS-5).
- **Admission**: type agreement between every node and its WIT signature plus effect metadata; well-formedness (single producer and consumer per edge, acyclicity, constraint syntax); envelope binding. The parser and graph type-checker are more surface than an instruction-list decoder — a one-time toll at the layer where correctness matters most, and the admission checks are the bounded-decode discipline applied one level up.
- **Wallets**: the manifest *is* the asset-flow diagram to display — sources, transformations, destinations, and the user's own constraints — with no simulation and no instruction-trace recovery. Value movement is manifest structure, not call side effects, which is what makes signing legible and blind-signing structurally impossible.
- **The surface syntax** is SSA-style let-binding form — `let usdc = pool.swap(xrd); account.deposit(usdc)` — imperative to read, dataflow in denotation. The graph is the canonical (hashed, signed) encoding; the text form is a projection.

## 3. Subintents

A transaction may be a tree of separately-signed intents: a parent composing child **subintents**, each with its own manifest, signers, and auth context, connected by typed yields. The primitive exists because static access evicts choice-making to signing time — solvers compose users' intents off-chain, and subintents bound their power to composition, never custody: a child's manifest and constraints are signed by its own party and can be bound, never altered.

- **Yield parameters are DSL inputs.** A child's effect signature is a function of its manifest arguments *and* its typed yield parameters; the composed envelope binds every yield concretely, so `route()` evaluates over the bound tree and stays total-static — any node derives the union effect set from the envelope alone. Signed constraints on the binding (minimum amounts, resource types) are validity conditions, checked at admission where static and at execution otherwise, failing into the abort taxonomy ([04-execution-semantics.md](04-execution-semantics.md) §4).
- **Once-only by nullifier.** Committing a subintent writes a kernel nullifier substate at a canonical address under its signer's account prefix; existence is spent. The address is computable, hence declarable; the signer's shard participates anyway; and two compositions racing one subintent contend on the nullifier key — exactly one commits, the other aborts deterministically. Expiry rides the subintent's own weighted-time validity window, the same horizon as transaction dedup. A signer cancels an outstanding subintent before its window expires by spending its nullifier directly — a signer-authorized write under their own prefix.
- **One fee payer: the composer.** Per-subintent payers would create circular commit-proof dependencies among multiple first-committing shards ([08-host-integration.md](08-host-integration.md) §2); subintents reimburse the composer in-band. Composer-paid fees plus deferred bonds compose into gasless onboarding ([03-objects-and-state.md](03-objects-and-state.md) §4).
- **Composition is graph gluing.** Structurally, a subintent is a sub-DAG and a yield is an edge crossing a signing boundary. Referential transparency is structural: no register state leaks between intents, so a solver adds edges *between* graphs and can never change the meaning of the edges *within* one — "bound, never altered" made literal.
- **Multi-yield intents encode as segments.** An intent that yields N times is N segment-nodes in the DAG — each segment the straight-line span between yields, with yield edges connecting segments across the signing boundary. "Child gives funds → parent swaps → child inspects the result" is a cycle between *intents* but a DAG over *segments*, so coroutine-shaped counterparty protocols stay expressible while the format stays acyclic. Parent verification is a caller-capability requirement on the segment edge ([05-runtime.md](05-runtime.md) §6), not an ambient assertion.

## 4. Lineage

The format keeps, deliberately: asset-orientation (value movement as structure); code-free composition (chaining components atomically with no deployed glue contract); transaction-level assertions, generalized to edge constraints; transaction-layer linearity, generalized to total edge consumption; explicit auth evidence and per-intent isolation. It rejects the ambient mutable worktop — an instruction register that makes meaning depend on encoding order and turns static analysis into abstract interpretation — along with untyped-until-runtime call boundaries and fee instructions in the payload. From Sui's programmable transaction blocks it takes explicit result references with no ambient store, and leaves the sequential command encoding and the absence of a constraint language.
