# Standard library and the upgrade rule

## 1. Two-tier packages

- **User packages are immutable, permanently.** No in-place upgrade path exists at any privilege level.
- **System packages** — the stdlib and protocol contracts — upgrade only through the epoch-gated, beacon-governed channel that upgrades the VM profile itself. A system-package upgrade is a protocol upgrade, coordinated and priced as one. Existing objects migrate without sweeps: versioned substates upgrade **lazily on first read** — a deterministic pure function, identical on every replica, reshape-safe because the record moves with its subtree — and blueprint minor-version dispatch keeps old objects on old semantics where a silent behavior change would be wrong. Eager whole-state migration sweeps are rejected: O(state) work with reshape-exposed progress tracking.

Immutability is structurally honest here, not aspirational: dynamic dispatch through state is inexpressible ([01-effects-and-routing.md](01-effects-and-routing.md) §1), so delegate-proxy patterns cannot reintroduce silent mutability. An "upgrade" can only mean publishing v2 at a new address and clients retargeting — explicit, user-visible, never a pointer flip under signed intents.

What immutability buys, compounding: effect metadata is eternal and content-addressed (the routing cache never invalidates, no version pinning at signing); verification results hold forever; and upgrade-key compromise — empirically the dominant real-world exploit class — leaves the threat model entirely.

**Rejected: compatible in-place upgrades.** Every "compatibility policy" is a mutability policy with extra steps; it reintroduces metadata invalidation, admin authority, and the audit question "which version executed". The demand it serves is met by the migration pattern below.

## 2. The blessed migration pattern

Shipped as stdlib idiom and SDK tooling, or the ecosystem invents a worse one:

1. **Publish v2** at a new address; v1 keeps running untouched.
2. **Holder-signed migration**: per-user transactions move the *user's own* positions from v1 components to v2. Migration authority is never an operator flipping state under everyone at once.
3. **Client retargeting**: wallets and frontends point at v2 — natural under manifest-visible call targets, since clients name their targets anyway.
4. **Recovery exits**: stdlib component templates carry an optional timelocked owner escape hatch, chosen at instantiation, for funds held by logic that later proves wedged. Kernel bailouts stay rejected ([00-overview.md](00-overview.md)).

The custody backstop that keeps immutable-app bugs survivable: assets live in system-tier vaults whose withdrawal semantics are verified once and shared by everything, so an application-logic bug is a logic failure, not an asset-primitive failure.

## 3. Co-location

Auth policy and fallback sinks live under the prefix of the object they serve. Free-standing satellite objects — a separate access controller for withdraw auth, a global locker for the deposit fallback — would grow a transfer's participant set by a shard per satellite, and under static declaration the fallback keys are declared whether or not the fallback triggers, so the extra shards would be paid on every transfer, not just failing ones. Two placements follow:

- **Account auth is an internal module.** The role structure and timed recovery live as owned substates under the account prefix; auth checks and recovery operations are same-shard, always. A generic badge-custodian component remains for admin custody of non-account objects — rare operations, never the transfer hot path.
- **The deposit fallback is the recipient's kernel claims area**: a kernel-guaranteed sink at `account_prefix | H(account, claims_role, resource)` that cannot refuse. Deposit rules govern only the main vault — deposit-or-claims is total for every account, independent of recipient state, and local to the recipient's shard. Consent is preserved economically rather than by placement: the sender bonds the bytes it lands and the recipient's sweep-delete collects the refund — dust pays its victim. A dApp wanting claim-style distribution builds a sender-side claim component as an ordinary contract; the stdlib blesses no global locker.

The rule generalizes: anything that "helps" an object on its hot path lives under that object's prefix, or it adds a shard to every use.

## 4. Inventory

Each entry ships with effect signatures derived from its own bodies ([01-effects-and-routing.md](01-effects-and-routing.md) §9), reshape-clean split/merge semantics where stateful, and a formal-verification obligation — verify the component once, every user inherits it:

| Component | Notes |
|---|---|
| **Fungible resource** | Linear amounts, `delta`/`reserve` native, per-shard supply accumulators (INV-VM-VALUE-2). Declarative role-gated behaviors — mint, burn, freeze, recall, deposit restriction — with lockable rules; freeze checks ride `locked` mode on cold config, free at scheduling. The highest-value verification target in the system. |
| **Non-fungible resource** | Structural ownership native; per-item leaves; the same behavior set. |
| **Principal (account / persona)** | One primitive, two configurations: an internal auth module — rule-DSL roles and timed recovery — with an optional asset surface. With vaults it is the **account**: virtual (key-derived, lazily instantiated), canonical vault addresses, deferred-bond onboarding and sponsored creation, the kernel claims area as deposit fallback, recovery-exit template host. Without vaults it is the **persona**: a login identity, virtual and free until securified for rotation and recovery; login verification is a client-proven read of its key configuration against an attested root — proof-carrying, no privileged gateway. Personal data stays wallet-side; wallets default to cheap per-context personas, securifying only the reputation-bearing ones. |
| **Badges and auth rules** | A badge is an ordinary resource, fungible or with one instance per holder, presented through a custodial method on the holder's own account; rules are thresholds over presented claims, declared by a package or stored by an account under one algebra ([06-authority.md](06-authority.md)). |
| **Metadata module** | Standardized name/icon/dApp claims on globals with two-way dApp verification — the wallet anti-phishing layer; a verified claim on an immutable package stays verified. |
| **Staking** | Emits its lifecycle facts as events, which the host's beacon witness channel consumes from its home shard; system-tier with register-grade rigor, since the fold it feeds is consensus. |
| **Restructuring idioms** | Commit/claim, pagination crank, argument-lifted router, and the allowance grant — a per-period reservation right in the account's auth module, owner-revocable, accumulator-backed (the recurring-authorization idiom). Plus the sequence-without-a-sequencer family: hash IDs where sequence is mere uniqueness, `(WT, tx_hash)` sort keys for batch-granular arrival order, sharded counters for dense sequences — an explicit counter substate is legal but lint-nudged as a self-imposed serialization point. Plus **saturating time arithmetic** — the blessed helpers for the transaction clock, monotone per payer chain and boundedly regressive across chains. |
| **Sharded aggregates** | Per-shard accumulator, owner-sharded registry, and the sharded-registry template — N sub-registries under distinct owners routed by key hash — the lint-suggested answers to singleton shapes ([03-objects-and-state.md](03-objects-and-state.md) §5). |

**The verification mechanism — deferred: spec blocks.** No spec-block machinery exists in the SDK yet; the design is that per-component obligations are discharged by SMT-backed proof over SDK **spec blocks** — abort conditions, postconditions, struct invariants — with one structural advantage: the effect signature *is* the frame condition, by construction. The expensive half of contract verification — proving a method touches only what it claims — is given by INV-VM-ACCESS-1/2 rather than inferred, so the discharge per method reduces to postconditions under a known frame. When built, stdlib components ship with specs and discharged proofs (the fungible resource's conservation and reservation soundness are the flagship targets); user packages get spec blocks as optional SDK machinery, and a package's verified-spec status is content-addressed with it — immutable, so provable once and surfaceable by wallets forever.

Stdlib verification obligations attach to the invariants they carry (INV-VM-VALUE-1 accumulators, INV-VM-VALUE-2 conservation) rather than minting new IDs per component; the register entry for each names the components that discharge it.

**Rejected: per-method developer royalties.** Redundant and harmful. Redundant because any component can charge in-band — its cut is explicit asset flow in the manifest DAG, more legible than a kernel royalty could ever be. Harmful because protocol royalties make composed transactions' fee surfaces unpredictable, thread a new payee through settlement and the abort taxonomy, and reward rent-seeking that immutable open packages undercut anyway — the royalty-free fork wins. Developers who want revenue charge visibly, in their own logic.
