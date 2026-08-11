# Objects and state: ownership, layout, and state economics

## 1. Structural ownership

An object's owner is part of its identity, not a value stored inside it:

- **An address says what it is and proves what it binds.** A global address is 31 bytes of domain-separated hash followed by a byte naming its class — principal, component, package, resource, or native. The body commits to the derivation that produced it: a principal's auth material and scheme, a component's package and creation-fixed configuration, a package's content, a resource's minter. A claimed binding is therefore checked by recomputing the derivation rather than by consulting state, and any shard verifies any target with no foreign reads. The tag trails rather than leads because the leading bytes are what the shard trie routes on: uniformly distributed hash output spreads every class across the prefix space, while a leading tag would herd each class onto one slice of it. An unassigned tag is not an address — zeroed memory fails closed, and a class added later is a protocol version change older parsers refuse rather than misread.
- **Leaf keys embed the owner.** Every substate's storage key is an owner address and a local half; the owner half is assigned by the kernel at object creation from the creating context's owner — never recovered by walking substate values for ownership references. Placement is a property of the name (INV-VM-4).
- **Canonical child addresses.** Role-bound internal objects have computed addresses: the vault for resource `R` under account `A` is `A_prefix | H(A, vault_role, R)`; a KV entry keyed by manifest argument `k` is `A_prefix | H(A, kv_role, collection, k)`. The owner is salted into the digest as well as prefixed onto the key. This is what makes level-1 access pure computation in the effect DSL.
- **Deterministic fresh IDs.** A new object's local ID hashes the signed envelope and the call site's position in the static call graph — no allocation counters, no state read to create, and no coordination between parallel executions ([04-execution-semantics.md](04-execution-semantics.md) §2).
- **Owned objects are not externally addressable.** No transaction can name a path to an internal object except through its owner — locality under the owner's prefix is unreachable to violate, not merely audited.
- **Re-parenting is an explicit `move`.** An object's owner changes only through a kernel-level move whose source and destination owners are both in the effect set; when the owners live on different shards, the move *is* a cross-shard transfer. Nothing re-parents implicitly.

Child keys are bounded within their owner: a canonical child key truncates its digest to the local half, a birthday bound whose domain the owner salt keeps per-owner — a ground collision reproduces under no other owner, so the search cannot amortize across accounts — and a collision cannot cross a prefix, so it cannot cross a shard.

## 2. Substate layout

Substate partitioning sets three costs with one knob: lock granularity (false sharing), provision bytes (every cross-shard byte rides a multiproof), and proof size. The layout rule:

- **Hot mutable scalars get dedicated leaves.** A balance, a counter, a price never shares a substate with configuration or metadata.
- **Cold configuration clusters.** Immutable-after-instantiation fields pack into one leaf.
- **Layout is declared, not emergent.** Blueprint field groups carry layout annotations checked by the compiler; the default — one leaf per field group, scalars split — is chosen so the unannotated case is the safe case.
- **Ordered collections are a kernel kind.** Beyond point-keyed entries, a field group can declare an ordered collection: entries keyed under a canonical order-prefixed interval space, accessed by declared ranges ([01-effects-and-routing.md](01-effects-and-routing.md) §5). Non-fungible vault contents are the canonical instance.
- **Instance configuration is locked at creation.** Creation-fixed parameters — a resource's divisibility and feature set, which optional substates an object has at all — are permanently locked substates recorded with the object: an input to `route()`, an unbounded-window locked read at execution, never a cross-shard participation.

Acceptance test for the rule: a fungible transfer's provision carries the two balance leaves and nothing else.

## 3. The storage bond

Committed byte growth triggers shard splits; splits demand committees; committee demand moves the host's stake price. Unpriced state is therefore an attack on the validator supply, not a disk nuisance. The mechanism is a per-byte **bond**:

- **Bond at write.** Every substate carries a bond, paid at creation at the fold-set per-byte rate and recorded with the substate — so bonds split and merge with the subtree by construction. No sweeps, no clocks, no expiry: accounting is O(write), never O(state). The liability is the bond's *time value*, not a payment stream.
- **Refund to the deleter.** Deleting a substate refunds its bond, minus a non-refundable **churn fraction**, into the deleting transaction's fee sphere. Deletion authority is already effect- and auth-gated, so refund-to-deleter cannot expropriate; it creates permissionless cleanup markets (the pagination-crank idiom), and deletion pressure is the counter-force that relieves split pressure. The churn fraction prices tree writes and checkpoint retention and caps refund-mining.
- **Bytes pay validators; bonds discipline owners.** Validator compensation is a reweighting of the host's fixed per-epoch emission by attested stored-byte totals ([07-host-integration.md](07-host-integration.md) §2). Compensation never keys on bond value, which dissolves the grandfathering problem when the per-byte rate later moves.
- **A zero balance is an absent cell.** An amount cell deletes when it reaches zero rather than storing zero bytes forever. A commutative cell has no other exit — a delta capability cannot remove — so draining is the only shrink it will ever have, and it is the commonest shrink event in the system. Two consequences carry: a drained cell reads as **empty** at the guest boundary, so every amount decoder accepts an empty cell; and the churn fraction is sized against a balance oscillating across zero, since delete-on-zero puts bond refunds inside ordinary arithmetic.
- **Bond capital is inert.** Bonds are excluded from the host's stake pricing and governance tallies. There is no staked storage fund and no second staking system.
- **The rate is fold-derived and attack-priced.** The per-byte rate scales as committee cost over split threshold: filling a shard to its split threshold locks capital on the order of the committee it conscripts. Every term is host consensus state, so pricing is deterministic on every replica, and it self-adjusts — state is cheap exactly when the network can afford growth.

Bond and debt accounting is conserved end to end: totals change only by creation, debt settlement, deletion refund, and reshape composition (INV-VM-7).

## 4. Onboarding: virtual accounts and deferred bonds

Bond-at-write must not make receiving assets the recipient's problem. Two mechanisms, both static under the effect model:

- **Virtual accounts.** Account addresses derive from keys; the shell instantiates lazily on first deposit. Canonical addresses make this fully static: a deposit to a fresh account declares the shell keys it creates, with no state read and no prior transaction by the recipient.
- **Deferred bond.** A first deposit may create the shell and vault carrying a recorded `bond_debt` at the standard rate instead of a paid bond. While indebted, an account accepts deposits up to a substate cap, each adding to the debt; **native-token inflows settle the debt before crediting the balance** — a kernel rule, deterministic, so the account bonds itself the first time it is funded. Once cleared, the account is ordinary.
- **The unbonded premium.** A deposit creating deferred-bond state pays a non-refundable premium sized so unbonded bytes cost at least the bonded time-value over the expected dormancy horizon — dust-bloat through unbonded accounts is strictly costlier than bonding, so no eviction or revival machinery is needed even for the never-funded case. Attested byte totals include unbonded bytes, so validator compensation is unaffected by bond status.
- **Sponsorship remains.** A sender — an app onboarding its users — may simply pay the bond outright at deposit.
- **Gasless onboarding composes.** A solver-composed subintent transaction is paid by its composer, so a brand-new user can sign an intent, receive assets into a virtual account under deferred bond debt, and transact without ever holding the native token. No protocol special-casing; the mechanisms compose.

## 5. No global singletons

Any protocol- or ecosystem-wide cell — a total supply counter, a global registry, a network config object — lands on one shard and becomes a permanent hot key no scheduling lever can fix:

- **Aggregates are per-shard accumulators.** Total supply is per-shard linear accounting (§6) composed at read time; registries are owner-sharded namespaces.
- **Reshape-clean composition.** Every stdlib accumulator type defines its split and merge semantics, and those commute with the tree operation: composing two children's accumulators yields exactly the parent's (INV-VM-5). A reshape scenario per stdlib type holds the line.
- **The compiler warns on singleton shapes.** A blueprint declaring a global-role object with write effects reachable from unbounded callers gets a deploy-time lint; the stdlib provides the sharded alternative for each common shape.
- **A single owner's prefix is the sharding atom.** Owner-prefixed keying means a shard boundary never cuts through one owner, so an unbounded collection under a single global owner is an un-splittable mass no reshape can ever relieve — the singleton rule extended from cells to owners. Deploy lint: an unbounded collection on a global single-owner component warns; the alternative is the sharded-registry template ([06-stdlib-and-upgrades.md](06-stdlib-and-upgrades.md)) — N sub-registries under distinct owners, routed by key hash, each name's home computable statically by any client.

## 6. Linearity and per-shard supply

Fungible value in the kernel is **linear**: amounts are split, merged, and moved, never duplicated or dropped. Each shard maintains, per resource, an accumulator of total supply held under its prefix, updated by mint, burn, and cross-shard movement. Accumulators are the reshape-clean kind: children's parts compose to the parent's exactly.

Conservation is then a global statement with local enforcement: for every resource, the per-shard accumulators sum to minted-minus-burned supply, and no execution path changes a shard's accumulator except mint, burn, or an attested cross-shard movement (INV-VM-6). A fabricated deposit would need an attested movement its source's own accumulator history cannot support — detectable at admission against state the receiving shard already tracks, with no separate conservation-audit protocol. The attestation is cheap because the kernel maintains the quantity natively.

## 7. Kernel accounting across reshape

Deferred bond debts are substates, so they move with the subtree under split and merge like any other state. A fee reservation is not: it is an accounting entry over the payer shard's own committed chain, with no on-chain existence to inherit ([07-host-integration.md](07-host-integration.md) §2). When the payer's shard terminates, the successor's chain begins at its seeded genesis — nothing is inherited, nothing sweeps, and a payer stranded by its shard's death is admitted again by the shard that replaces it, so release holds by construction.
