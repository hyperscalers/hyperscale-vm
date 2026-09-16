# Authority: claims, rules, and where each is judged

Authorization here is one comparison: a set of claims a call *presents* against a rule its target *names*. Both sides speak the same vocabulary, every claim in the presented set was attested by something that read state to verify it, and the whole graph of who authorizes what is fixed when the intent is signed.

What a method requires is package metadata, content-addressed with the code it describes and judged at publish, so no transaction can weaken it and no shard reads it differently. Nothing about it is inferred from who is calling, because nothing is: a method is named by a manifest node and there is no caller for a body to consult ([05-runtime.md](05-runtime.md) §6).

## 1. What a proof carries

A claim is a `Claim` (`crates/effects`), and it is one shape rather than a taxonomy:

| Field | What it says |
|---|---|
| `subject` | The address the claim is about. |
| `instance` | Which instance of it, where the subject is a non-fungible badge and the claim is about one instance rather than any. |

What a subject *is* — an account acting as itself, a badge somebody holds — is its address class's answer, read where a site needs it rather than decided at construction. A claim that fixed the kind when it was built made one address mean different things depending on which site built it.

**Everything an author names is a badge.** Two kinds — one somebody holds, one nobody does:

| Badge | Named as | Attested by | Held by |
|---|---|---|---|
| A held badge: a resource, or one instance of it | `Claim(resource)`, `Claim::of_instance` | a custodial method on the holder's own account, judged by possession | the vault |
| An account's virtual badge | `Claim(principal)` — the account's own address | the signature of an intent acting as that account, judged by the account's shard | nobody |
| A component's virtual badge | `Claim(component)` | the component's own proving gate, the venue pattern | nobody; the code is the identity |

A virtual badge is minted by nothing and costs a manifest no node. An account's is the case that carries the system: a rule anywhere naming Alice is satisfied by an intent Alice's account signed, and the shard that keeps her `auth` cell is what says the keys behind that signature are still hers. So rotation is followed rather than tracked — a rule written years earlier names the account, and the account's own cell decides what opens it today.

A config slot holding a principal address is a badge address like any other, and a rule stored in a cell is a mutable rule *over* badges rather than a third kind of authority.

The instance field is what earns the type. Flattened to a bare address, a badge resource with a thousand instances issued to a thousand holders is one authority, because nothing downstream can tell the holders apart. With it, one badge resource with one non-fungible per admin — rotate by issuing, revoke by burning — is expressible, and it is the shape most real permission systems take.

Equality is the whole of judgment: two claims are the same claim exactly when they name the same subject and the same instance of it. So satisfaction is a walk comparing claims, and nothing about it depends on what a site meant.

A claim is never caller-supplied. Every one is attested — by a gate that read state, or by the shard that keeps the account's own cell — and resolved at admission from what the target's own declaration names, so widening what a proof says widens nothing about who may say it.

**Rejected: virtual badge resources.** A signature could be made to look like a *held* token by folding it into a non-fungible of a magic global resource, so that everything a rule judges is something somebody holds. That buys uniformity at the price of a namespace of resources nothing issues, and of an address space where some resources are real and some are the kernel talking to itself. A signature and a held badge are already the same kind of value here by the time a rule judges them — both are a `Claim` — so the uniformity arrives without the fiction.

**Rejected: the key as the badge.** The signature could present the raw key instead, nameable by any package. Sound, and smaller in the kernel — but a rule naming a key breaks the moment its holder rotates, where one naming the account's own badge does not. The rule's author would be choosing, without knowing it, between "whoever this account is" and "whoever holds this key today"; naming the account makes the first the only reading, and leaves the second to the one cell that means it.

## 2. One rule tree, three leaves

A rule is `Require(leaf)` or `CountOf { count, rules }`. One constructor covers "this account", "any of these three" and "two of these five": a count of one is disjunction, a count equal to the branch count is conjunction.

The tree is generic in its leaf, and the leaf is what the three sides differ in:

| Instantiation | Leaf | Who holds it |
|---|---|---|
| `RuleExpr` | `RuleLeaf` — expressions over a method's own inputs | a package's declaration, judged at publish |
| `StoredRule` | a claim, already resolved | an account's cell, judged where the cell lives |
| the evaluated form | `JudgedLeaf` — the three above resolved, plus `Signed`: the one leaf judged against keys | admission, after evaluating the declaration |

One tree serves all three, so an object whose admins are fixed at publish can say "two of these three" exactly as an account whose keys are stored can, and a caps walk written once holds every side to the same shape.

A declared leaf is one of exactly three things:

- **`Claim(expr)`** — a claim the caller must present, evaluated over the method's own inputs into the claim compared for equality.
- **`Stored { cell }`** — the rule stored at this cell, judged where the cell lives. The one leaf that reaches mutable authority, and the type is what bounds the reach: a stored rule holds no `Stored` leaf, so a declared rule reads a stored one exactly one level deep and no chain of cell reads is expressible.
- **`Presence { target, expect }`** — the leaf this target names is there, or is not. The one leaf answered from the store rather than from what a caller presented, which is what decides *where* a rule holding it is judged: a rule of these alone states a feasibility fact and is answered before any body runs; one mixing them with a claim is judged at the call.

The caps bound a rule before anything evaluates it, and they are enforced where a rule is *written* rather than at evaluation. Depth is capped at four (a lone leaf is one, a threshold one more than its deepest branch), branch width at sixteen, leaves at sixty-four, and a count past the branches it is over is refused. So satisfaction walks a structure whose size is a constant of the vocabulary rather than of its input.

**The threshold over no branches is how this algebra spells its constants.** A count of zero over nothing admits everyone; a count of one over nothing admits nobody. Both are storable and each has exactly one spelling — `always()` and `never()` — so the judge computes both from `met >= count` without an arm of its own. A constant standing *beside* real branches is refused, because everyone-may beside anything is everyone-may and no-one-may beside it is the rest of the threshold: each meaning keeps one spelling however deep it sits. `never()`'s encoding is a public constant, which is what lets a resource say a movement is forbidden rather than merely ungranted.

Where "written" is depends on which side wrote it. A stored rule is bytes, so its decoder is the gate, and bytes past the caps are refused as they arrive. A declared rule is source, so its author is told on the line: depth and width and count are properties of the shape alone, which the macro reads off the same constants the decoder does — a gate nobody could meet never reaches the decoder that would have refused it.

**Deferred: amount thresholds.** A rule asks which claims are present and nothing else — there is no "holds at least N of this badge". The custody gate's possession read is a presence question, and turning it into a minimum is a field and a comparison, so the cost is not the obstacle; the reason to wait is that an instantaneous balance gate is satisfiable by borrowing, which makes it a governance mechanism worth designing against a concrete case rather than a knob worth having early.

## 3. What a method requires, and what it mints

At the engine's level there are no gate *kinds*. A signature declares clauses, and two of them are about authority: a `Requires` clause carrying a rule, and a `Mints` clause naming a claim the method hands to later nodes. Everything else is the same effect vocabulary every other clause is written in, which is what puts a gate's own reads in the declaration that provisions them.

The five shapes an author writes are the SDK's spelling of that, not a fifth thing the kernel knows:

| Authored as | A caller presents | The gate reads | It mints |
|---|---|---|---|
| nothing | nothing | nothing | nothing |
| `#[requires(<rule>)]` | claims satisfying the declared rule | whatever the rule's leaves name | nothing |
| `#[proves(self)]` | nothing; the body decides | nothing | the component's own claim |
| `#[requires(governs(<field>))]` | claims satisfying the rule stored at that field | that field's cell | nothing |
| `#[proves(badge[id])]` | the holder's own claim | the badge-keyed vault, or the holdings entry at the id | the badge, and the instance |

**A declared rule names an identity the target itself names** — its own address, or a slot of its creation-fixed configuration. `Claim(SelfAddr)` is a method only the target may be made to perform; a configuration slot is how an object nobody owns admits somebody, since a pool's address derives from no key while a configured field can name a claim that does. Every leaf is checked against reading what the caller supplies: a caller who names the claim they must present can always present it, so such a rule admits everyone and is refused at publish.

**`#[proves(self)]` is a component vouching for its own code.** A component's address derives from no key, nothing can store a rule in its `auth` cell, and no signature yields a claim on it — so the one party that can speak for a component is the component, and what decides is its own body, which may decline. The venue pattern is this: a method that checks whatever it likes and mints the venue's claim when satisfied.

An account has no such method, and a `#[proves(self)]` on a blueprint serving principals does not compile. Its virtual badge is attested by its own shard (§5), so a body that also vouched would be a second opinion that could disagree with the first — and the account was the one case where the stored rule made "satisfying one's own rule" look like a feat rather than a restatement. The refusal lands at authoring rather than at publish because the publish gate cannot see the seat: which package serves principals is the protocol's own, fixed at genesis, so there is no publisher for a gate to turn away.

**`governs(<field>)` is the recovery surface.** It is judged like a declared gate but against the rule stored at the named cell, and it mints nothing, so recovery authority opens recovery methods and nothing else. While nothing is stored there, the identity that address itself derives governs — which is what makes a key-derived address govern itself before it has any state.

**A custody gate is holding as a way to mint a proof.** The holder names itself — the holder acts, nobody else presents its badges — with a possession read beside it, and the read is keyed by *exactly* the expression the gate mints, which is what makes the thing held and the identity minted one resource. The holder's own claim is the whole of the authority half: it is answered by the signature of the intent acting as them, whose keys their shard already judged, so reading their stored rule again here would reach the same verdict at the cost of a cell every participant provisions. A fungible badge reads the badge-keyed vault; a non-fungible one reads the holdings entry at the named id and mints both the instance and the badge, because a holder of an instance holds the badge: a rule naming the resource admits any holder, and one naming the instance admits its holder alone.

The id is a manifest argument, and caller-named is not the hazard it sounds like: the refusal on caller-named authority is on the *requiring* side, where a caller naming whose authority is needed would name their own. Naming which instance you are presenting is the presenting side, and the gate reads state to confirm it.

**Rejected: per-package role tables.** A package declares no role namespace of its own, and the concept was removed rather than left half-built. The cases that motivate one are already served: a fixed admin set is a declared rule over configuration slots, and a rotating one is instances of a single badge resource, issued and burned. An account's own three rules — primary, recovery, confirmation — are three cells rather than a table with a vocabulary of its own, so each gate reads the one it needs.

## 4. What a resource's own entries demand

The rules above are what a *method* requires. Separately, a resource's issuer seals entries into the resource itself, and those bind every movement of it wherever it happens — including in packages that know nothing about the resource.

There are six behaviours an entry can govern (`GrantedBehaviour`): **mint**, **burn**, **withdraw**, **deposit**, **halt**, and **recall**. An entry is a rule like any other, and the entry set is folded into the resource's address, so a resource that grants differently is a different resource and immutability is the derivation rather than a promise.

**Absence withholds.** A resource granting no entry for a behaviour is one nobody may perform it on, which is every resource until its issuer says otherwise. That is what makes omission inexpressible: a package cannot forget to gate a movement, because the requirement comes from the resource rather than from the package moving it.

Every one of those requirements goes through one door at admission. What separates the behaviours is only *where the entry is found* — a declaration derives one for an issuance, a presented record carries the others — and from there it is one question asked several times: does the entry decode, does the frame's own claim already satisfy it, and what is left for the caller to answer. Asking it in one place is what keeps the answer one answer: a composer predicts this to know what to present, so a site that subtracted where another did not would emit a graph admission refuses.

**A frame speaks for itself.** An entry the executing instance's own claim already satisfies is not appended at all, which reproduces the issuer's own authority exactly and costs the ordinary case nothing.

**`recall` is reaching a holding under a prefix that is not the reacher's**, and it is the one behaviour whose whole point is crossing an ownership boundary. Four things make it safe, all shape rather than review: the owner is not the reaching instance, the target is keyed first by the resource whose entry admits the reach, the cell is the one the behaviour is about — a halt entry says who may raise a holder's flag, not who may write anything at all under their prefix — and a reached holding is only taken from. The last matters because a reaching access earns no movement entry and no halt fence: a recall that could credit would deposit past the resource's own deposit entry and past a halt on the holder, and one that only read would see a balance the entry never opened.

**The class byte is what makes a record's absence detectable.** A resource whose sealed rules restrict a movement anyone could otherwise make carries `AddressClass::Restricted`; one that does not stays plain. A reader holding only the address therefore knows whether it must have the rules in hand before letting a movement through, and a restricted resource moved with no record presented is refused for being withheld rather than judged as if it granted nothing.

## 5. Three judgments, in three places

**Presence is a property of the signed form, answered at admission** (INV-VM-AUTH-1). A call to a method requiring evidence presents something; a call to one requiring none presents nothing; the reverse of either is refused. No state is read, so the verdict is a pure function of signed content and is reached ahead of ordering and fee exposure — an envelope that presents nothing where something is required never enters a block and nobody pays for it.

Evidence is presented, never ambient. A node names what it hands its callee, from exactly three sources, the first two scoped to the node's own intent:

- **The intent's own signature**, resolving to the claim on the account that intent acts as. That is the account's virtual badge, and it answers any rule naming that account — its own methods and any other party's alike, since a rule naming Alice means the account rather than a key. It rides every gated call, because it costs the graph nothing and is the claim a rule the composer cannot read is most likely to want.
- **An earlier node of the same intent**, carrying the claims that node's gate minted. Admission resolves the index against the intent's own node list and refuses one that is not earlier or whose method mints nothing. Nothing re-checks it later: if the producing node's gate refuses, that node aborts the transaction, so a consumer only ever runs in a world where the producer succeeded.
- **A socket the intent declared and the composition filled**, which is the only way a claim crosses a signing boundary. The declaring intent names the *claim* it is asking for, never whose node supplies it, so what its signer undertook means one thing however it was later carried; the composition binds it to a node's mint or to a grant of the account its own intent acts as. A grant is the composition lending its own authority downward: nothing proves it and no node carries it, so the socket it fills waits on nothing.

**The sign-in is the account's shard's, and it lands between the two** (INV-VM-AUTH-6). A signature resolving to a claim on an account is signed content, so admission alone cannot tell whether the keys behind it still open that account. Admission therefore injects, per intent, a read of the account's `auth` cell and one condition: the rule stored there admits the attesting keys, or the cell is unwritten and those keys are the address's own. The condition is judged at materialization by the shard that keeps the cell, before any body of that transaction runs — the same stage and the same cell as the fee reservation, through one verdict function so the two cannot read it differently.

That cell is the one place in the system judged against *keys*. Every other stored rule names principal addresses and is judged against the accounts a call speaks for; `Claim(bob)` in Alice's `auth` is Bob's key, and `Claim(bob)` in Alice's `recovery` is Bob's account. Same vocabulary, two judges, and the cell decides which — which is also why key-based delegation through an `auth` cell is one level deep and never a chain, and why a key its owner retired at their own account still opens another account whose cell names it.

**Satisfaction is the target's own question, answered at execution, against the target** (INV-VM-AUTH-2). A declared rule is a pure match over the presented set. A `governs` gate reads the target's cell — declared by the method itself, so provisioned wherever the call runs — and hands the bytes to the same verdict function. A custody gate adds its possession read. A cell that cannot be read fails closed; stored bytes that do not decode admit nobody.

A rule the judge it reached cannot answer is refused rather than waved through: the judge that cannot answer a question is not the one to decide it was satisfied.

Because every claim a gate can require is one the target itself names, no authority question is ever answered by reading state under a prefix the manifest did not name (INV-VM-ACCESS-4). A call presenting anything else aborts identically on every replica and its sender pays the ceiling they signed: both what the call presents and what the target requires are content the signer put their name to.

An account that never securified has no rule cell, and the sign-in admits exactly the key its address derives. Securifying is a one-way door, and the declaration is what makes it one: the write requires the cell absent, so a second securify is refused by the shard holding it before any body runs ([01-effects-and-routing.md](01-effects-and-routing.md) §2). The transition off the address-derived rule happens once, and a caller can see that it will from the signature alone. The rule that lands in that cell names principal claims and nothing else, held to it by the parameter's own kind — a leaf naming a resource is one no attesting set could ever meet, so accepting it would store a rule that leaves the account unopenable.

**Rejected: an ambient auth zone.** Per-frame authority accumulating in a mutable container, with barriers deciding how far it propagates, is the alternative, and it fails in two ways that are not fixable from inside it: proofs leak to callees that were never meant to have them, and a proof passed as an argument carries a resource address the caller chose — which is why such a system needs a checked-proof ceremony before a body may read one, and why forgetting the ceremony is a live exploit class. Here a body reads no proof at all. Evidence is resolved by admission from what gates minted and what the composition wired, the resolution is a property of the signed graph, and the three sources above are the whole of it.

Two consequences follow rather than being defended separately. **A held badge is not delegable**: presenting one goes through a custodial method on the holder's own account, so it is the holder's intent, and their shard's sign-in, that stands behind every use of it. And **proofs have no lifecycle** — no clone, no drop, no runtime proof object. A proof is a manifest edge, so linearity is the graph's property ([02-manifests-and-intents.md](02-manifests-and-intents.md) §1) and the authority graph is fixed when the intent is signed: nothing becomes authorized by something discovered mid-execution.

## 6. Choosing: held, or virtual

Every authority an author names is a badge (§1), so the choice is not between mechanisms — it is whether the badge is something somebody holds.

**A held badge** is authority that moves. It is a resource: it shows up in a wallet, it transfers, it can be issued to a new holder and burned from an old one without touching the object it governs, and a holder presents it through a custodial method on their own account. Reach for it when the authority is a *position* rather than a person — the pool's fee-setter, an operator seat, a membership — when the holder set changes over time, and when the change should be an ordinary transaction rather than a redeploy. One badge resource with one instance per holder is the default shape; the object's gate is a declared rule over that resource, or over particular instances of it if the seats differ.

**An account's virtual badge** is authority that does not move. Nobody holds it and nothing issues it: it is the account's own address, attested by the account's own shard. It survives key loss through the recovery surface, it cannot be accidentally transferred away with a bucket, and it follows every rotation its holder makes — a rule written years earlier keeps naming the account rather than whatever key opened it that day. Reach for it when the authority *is* the identity — spending, writing, rotating keys — and when the point is precisely that it stays put.

**A stored rule is neither**; it is a *mutable rule over* badges. An account's three cells hold one each: what governs it, what may replace that, and what may enact a replacement early. A component keeps its own under `governs(<field>)`. The rule is the thing that changes; the badges it names are the vocabulary it changes between.

The two badge kinds compose rather than compete: presenting a held badge goes through a custodial method on the holder's account, so the holder's virtual badge — and the sign-in behind it — stands under every use of it. Losing the keys to an account loses the badges it holds, which is the intended coupling, and the reason a held badge is the wrong home for authority whose recovery story matters.

Neither is the right answer for a fixed admin set known at publish. That is a declared rule over configuration slots, with no resource to issue and nothing to hold.

And neither is the right answer for what a *resource* forbids. An issuer that wants a movement gated everywhere seals an entry into the resource (§4); a package's own gate cannot reach movements in packages that have never heard of it.
