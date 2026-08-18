# Authority: proofs, rules, and the two verdicts

Authorization here is one comparison: a set of claims a call *presents* against a rule its target *names*. Both sides speak the same vocabulary, every claim in the presented set was minted by a gate that read state to verify it, and the whole graph of who authorizes what is fixed when the intent is signed.

A method's accessibility is package metadata, content-addressed with the code it describes and judged at publish, so no transaction can weaken it and no shard reads it differently. Nothing about it is inferred from who is calling, because nothing is: a method is named by a manifest node and there is no caller for a body to consult ([05-runtime.md](05-runtime.md) §6).

## 1. The proof currency

A claim is a `Presented` (`crates/effects`), and it has three cases because the system has three:

| Case | What it says |
|---|---|
| `Identity(address)` | An account or component acting as itself. |
| `Resource(address)` | A fungible badge the holder holds some of. |
| `Instance(address, id)` | One named instance of a non-fungible badge. |

The third case is the one that earns the type. Flattened to a bare address, a badge resource with a thousand instances issued to a thousand holders is one authority, because nothing downstream can tell the holders apart. With it, one badge resource with one non-fungible per admin — rotate by issuing, revoke by burning — is expressible, and it is the shape most real permission systems take.

An expression yields a claim by coercion from the value it already evaluates to, so naming one costs no new vocabulary: an address of class `Resource` is a badge, an address of any other class is something acting as itself, and a `(resource, id)` pair is an instance. The coercion is total and unambiguous because a resource can never be an acting identity — `CallTarget` refuses a resource, so the only gate minting a target's own address can only ever mint a component or a principal. Which case an expression yields is a property of the address, not of the site that evaluated it: a gate naming a configured resource slot wants the badge, and says so by naming it.

**Rejected: virtual badge resources.** A signature could be made to look like a held token by folding it into a non-fungible of a magic global resource, so that everything a rule judges is a badge. That buys uniformity at the price of a namespace of resources nothing issues, and of an address space where some resources are real and some are the kernel talking to itself. A signature and a held badge are already the same kind of value here by the time a rule judges them — both are `Presented` — so the uniformity arrives without the fiction.

## 2. Rules are thresholds over claims

A rule is `Require(claim)` or `CountOf { count, rules }`. One constructor covers "this key", "any of these three" and "two of these five": a count of one is disjunction, a count equal to the branch count is conjunction. Satisfaction is a walk comparing claims for equality.

The caps bound a rule before anything evaluates it, and they are enforced at decode — where a rule is written — rather than at evaluation. Depth is capped at four (a lone claim is one, a threshold one more than its deepest branch), branch width at sixteen, and degenerate thresholds are refused: a count of zero, which everyone satisfies, and a count past the branch count, which no one does. So `satisfied_by` walks a structure whose size is a constant of the vocabulary rather than of its input, and a stored rule always names somebody it admits and somebody it refuses.

The algebra is the same on both sides of the declared/stored split. A rule a package *declares* is a `RuleExpr` over expressions, evaluated at admission into a concrete `Rule`; a rule an account *stores* is a `Rule` already. An object whose admins are fixed at publish can say "two of these three" exactly as an account whose keys are stored can.

**Deferred: amount thresholds.** A rule asks which claims are present and nothing else — there is no "holds at least N of this badge". Turning the custody gate's `held > 0` into `held >= min` is a field and a comparison, so the cost is not the obstacle; the reason to wait is that an instantaneous balance gate is satisfiable by borrowing, which makes it a governance mechanism worth designing against a concrete case rather than a knob worth having early. `CustodyClaim::Fungible` is shaped to take a minimum later without moving anything else.

## 3. The five gates

A method's `Accessibility` (`crates/effects`) says whose authority naming it requires. Three derived facets — whether it requires evidence, whether it reads a rule, and whether it mints — are what the rest of the engine asks, so a sixth variant would be one place to think rather than nine.

| Accessibility | A caller presents | The gate reads | It mints |
|---|---|---|---|
| `Public` | nothing | nothing | nothing |
| `Guarded(RuleExpr)` | claims satisfying the declared rule | nothing | nothing |
| `Authorizing` | claims satisfying the target's stored primary | the target's rule cell | `Identity(target)` |
| `RoleGated(role)` | claims satisfying the target's stored rule for `role` | the target's rule cell | nothing |
| `Custodial(claim)` | claims satisfying the holder's stored primary | the holder's rule cell, and the badge | the badge |

**`Guarded` names an identity the target itself names** — its own address, or a slot of its creation-fixed configuration. `Require(SelfAddr)` is a method only the target may be made to perform; a configuration slot is how an object nobody owns admits somebody, since a pool's address derives from no key while a configured field can name a claim that does. Every leaf is checked against reading what the caller supplies: a caller who names the claim they must present can always present it, so such a rule reads as guarded and admits everyone.

**`Authorizing` is the only gate that mints an identity**, and it always mints the target's own. Letting it name anything else would be forgeable identity, since satisfying one's own stored rule is no feat. This is the account's `authorize`, and it is why authority another party holds is a call to *them* — a node of their own in the manifest, presenting their own evidence.

**`RoleGated` is the recovery surface.** It is judged like an authorizing gate but against the named role rather than the primary, and it mints nothing, so recovery authority opens recovery methods and nothing else. The governing role set is picked at the transaction clock, so a matured proposal judges without anything applying it.

**`Custodial` is holding as a way to mint a proof.** The holder's own stored primary judges the caller — the holder acts, nobody else presents its badges — with a possession read beside it. Which read is the claim's own business:

- `Fungible(badge)` reads the badge-keyed vault and requires a non-zero amount. It mints `Resource(badge)`.
- `Instance { badge, id }` reads the badge's holdings entry at that id. It mints both `Instance(badge, id)` and `Resource(badge)`, because a holder of an instance holds the badge: a rule naming the resource admits any holder, and one naming the instance admits its holder alone.

A resource is issued as one shape or the other, so the claim says which, and a resource used both ways takes a method per shape. Declaring both reads and admitting either would leave the declaration unable to say what the method is for. Both reads are keyed by *exactly* the expression the gate mints, which is what makes the thing held and the identity minted one resource.

The id is a manifest argument, and caller-named is not the hazard it sounds like: the refusal on caller-named authority is on the *requiring* side, where a caller naming whose authority is needed would name their own. Naming which instance you are presenting is the presenting side, and the gate reads state to confirm it.

**Rejected: per-package role tables.** Roles are an account concern — primary, recovery, confirmation — and a package declares no role namespace of its own. The cases that motivate one are already served: a fixed admin set is a declared rule over configuration slots, and a rotating one is instances of a single badge resource, issued and burned. Whether packages should ever get their own is open; nothing here forecloses it, and the numbering discipline any answer would inherit is settled.

## 4. Two verdicts, in two places

**Presence is a property of the signed form, answered at admission** (INV-VM-12). A call to a method requiring evidence presents something; a call to one requiring none presents nothing; the reverse of either is refused. No state is read, so the verdict is a pure function of signed content and is reached ahead of ordering and fee exposure — an envelope that presents nothing where something is required never enters a block and nobody pays for it.

Evidence is presented, never ambient. A node names what it hands its callee, from exactly two sources, both scoped to the node's own intent:

- **The intent's own signature**, carrying the signer's identity. It reaches only the gates that read a rule. A signature signs in; whether the key behind it still holds its account's authority is that account's stored rule to answer, and an identity a declaration names is not something a signature can stand in for.
- **An earlier node of the same intent**, carrying the claims that node's gate minted. Admission resolves the index against the intent's own node list and refuses one that is not earlier or whose method mints nothing. Nothing re-checks it later: if the producing node's gate refuses, that node aborts the transaction, so a consumer only ever runs in a world where the producer succeeded.

**Satisfaction is the target's own question, answered at execution, against the target** (INV-VM-15). A declared rule is a pure match over the presented set. A stored-rule gate reads the target's cell — declared by the method itself, so provisioned wherever the call runs — and hands the bytes to one verdict function, the same one the payer shard's fee-binding check uses. A custody gate adds its possession read. A cell that cannot be read fails closed; stored bytes that do not decode admit nobody.

Because every claim a gate can require is one the target itself names, no authority question is ever answered by reading state under a prefix the manifest did not name (INV-VM-16). A call presenting anything else aborts identically on every replica and its sender pays the ceiling they signed: both what the call presents and what the target requires are content the signer put their name to.

An account that never securified has no rule cell, and is governed by the identity its address derives — so for a virtual account the two halves coincide and the signer's own proof satisfies its own account directly. Securifying is a one-way door: the body refuses a second write, so the transition off the address-derived rule happens once.

**Rejected: an ambient auth zone.** Per-frame authority accumulating in a mutable container, with barriers deciding how far it propagates, is the alternative, and it fails in two ways that are not fixable from inside it: proofs leak to callees that were never meant to have them, and a proof passed as an argument carries a resource address the caller chose — which is why such a system needs a checked-proof ceremony before a body may read one, and why forgetting the ceremony is a live exploit class. Here a body reads no proof at all. Evidence is resolved by admission from what gates minted, the resolution is a property of the signed graph, and the two sources above are the whole of it.

Two consequences follow rather than being defended separately. **Authority is not delegable**: presenting a badge goes through a custodial method on the holder's own account, so the holder's stored rule judges every use of it. And **proofs have no lifecycle** — no clone, no drop, no runtime proof object. A proof is a manifest edge, so linearity is the graph's property ([02-manifests-and-intents.md](02-manifests-and-intents.md) §1) and the authority graph is fixed when the intent is signed: nothing becomes authorized by something discovered mid-execution.

## 5. Choosing: a badge, or a stored rule

Both mechanisms are here, and the choice is not a matter of taste — it is a question about the authority itself.

**A badge resource** is authority that moves. It is a token: it shows up in a wallet, it transfers, it can be issued to a new holder and burned from an old one without touching the object it governs, and a holder presents it through a custodial method on their own account. Reach for it when the authority is a *position* rather than a person — the pool's fee-setter, an operator seat, a membership — when the holder set changes over time, and when the change should be an ordinary transaction rather than a redeploy. One badge resource with one instance per holder is the default shape; the object's gate is a declared rule over that resource, or over particular instances of it if the seats differ.

**An account's stored rule** is authority that does not move. It is a configuration of an identity, not an object anybody holds: it survives key loss through the recovery roles, it cannot be accidentally transferred away with a bucket, and it is what the payer shard consults when it decides who may spend from that account. Reach for it when the authority *is* the identity — signing in, spending, rotating keys — and when the point is precisely that it stays put.

The two compose rather than compete: presenting a badge goes through a custodial method on the holder's account, so the badge's authority is always gated by the holder's stored rule underneath it. Losing the keys to an account loses the badges it holds, which is the intended coupling — and the reason a badge is the wrong home for authority whose recovery story matters.

Neither is the right answer for a fixed admin set known at publish. That is a `Guarded` rule over configuration slots, with no resource to issue and nothing to hold.
