# Smash — Discovery, Coverage, and Known-Issue Design Note

Status: design reasoning (companion to SPEC-SMASH-001 v0.3, not a replacement).
Scope: how Smash moves beyond "regression coverage of known invariants" toward
finding the unanticipated — and how known-vulnerability catalogs fit without
overclaiming.

## 1. Two modes, and the honest limit

Smash does two distinct jobs, and they must never be conflated in a report:

- **Regression testing** — a known invariant is encoded, and Smash checks it
  still holds. Catches the day someone breaks something already understood.
- **Discovery** — finding a failure that was *not* anticipated.

The MVP is deliberately the first kind. Per the spec: a fixed technique catalog
is regression coverage; it does **not** establish resistance to novel attacks,
and reports must say so (a green dashboard is never "this app is secure").

**The epistemic floor:** a black-box tester can only find an effect it can
*observe*. A vulnerability that produces no observable signal in the
instrumented environment is invisible to Smash. So "find what we can't see" is
bounded — it means *maximize the observable surface, then test the shape of
correct behavior rather than a list of known bugs*. The canary fixture, write
receipt, state snapshot, and completion barrier exist to widen what can be seen.
Smash's real job: **turn unknown-unknowns into observable divergences from a
stated invariant.**

## 2. Three mechanisms that find the unanticipated

None require knowing the target's internals.

1. **Differential oracles** (`OracleKind::Differential`, already in core). Fire a
   probe and a benign control through the same path; compare. A divergence you
   never predicted surfaces on its own — no need to specify the bug in advance.
2. **Metamorphic properties** (§13.D). Relationships that must hold across input
   *transformations*: lowering a session's permission must never enable more
   effects; argument reordering must not change authorization; equivalent
   encodings must get equivalent decisions. A violation is a bug nobody wrote a
   test for.
3. **Model-assisted research mode** (§13.G, deferred). A sandboxed component that
   *generates* candidate probes. The path from catalog to search. See §4.

## 3. The canonicalization-divergence fighter (worked example)

Storm Gate's `canonical_json` documents its own attack surface: duplicate-key
collapse ("the gate can hash one key while the harness executes another"), the
`$serde_json::private::Number` magic-map, the v1→v2 numeric cutover. Its own
comment: *"a canonicalization collision is an approval-bypass primitive."* That
is a class of unseen vulnerability handed to us with a map.

This forces a split that applies generally:

- **Reference canonicalizer** — job is to *agree* byte-for-byte with the target,
  so a probe correlates to a real effect (calibrating the instrument). This one
  mirrors the target's implementation (serde_json, recursive key sort,
  duplicate-key rejection, v2 numeric rules). It is `smash-engine`'s `canonical`
  module, pinned by vectors lifted from the target's own source.
- **Divergence fighter** — job is to *disagree*: generate adversarial inputs over
  the documented bypass primitives and check whether the value the gate *hashes*
  matches the value the backend *executes*. This must be **independent** of the
  target's implementation, or it can only ever agree with it.

General rule: **mirroring an implementation can only confirm what that
implementation already does.** Discovery needs an independent oracle of correct
behavior, not a copy of the target.

## 4. Model-assisted exploratory testing (§13.G)

The architecture's rule: **the model is a player, never the referee.**

- **Generator / strategist — yes.** A model proposes *what to try*: novel
  candidate probes, mutations, sequences, encodings. Good at surfacing what a
  fixed catalog won't.
- **Oracle / judge — no, firm line.** Verdicts stay deterministic and replayable
  offline with a pinned oracle (`smash-oracle`, model-free). A model must never
  establish a verdict; that would make findings non-replayable and gameable. The
  model can hunt; it cannot score.

**Why it is containable — the cage already exists.** A model in the decider slot
inherits every type-level constraint for free: it can only produce an inert
`Call`; the only path to the wire is `Capability::authorize` +
`check_dispatchable`, so it cannot widen scope, raise the ceiling, forge a token,
or exceed budget. Everything fires in a disposable canary fixture within the
authorized origin set. `CorrelationKey` ties any effect to the exact execution.
The model's creativity is bounded by the types, not by trusting the model.

**The admission stage is the real work.** Model output does not become a probe
directly. It passes admission (§13.F), which assigns bounded parameters, an
effect classification, fixture requirements, an execution budget, and an
evidence/oracle contract. Candidates are restricted to a **supported declarative
probe format** executed by approved implementations — never arbitrary executable
code, whose effects no automated check can bound.

Consequences:
- **Provenance / pinning.** Store the exact generated artifact; offline
  verification replays it, never regenerates it. A finding reproducible only by
  re-asking a model is not a finding.
- **Candidate ≠ finding.** A model-generated probe without a validated oracle is
  an *exploratory observation*. Promotion into the regression catalog requires a
  human to turn it into an invariant + a seeded failing fixture.
- **Separate trust domain.** Generative output is adversarial *content* existing
  inside the system — exactly what the manifest wall keeps out of decider
  context. The generator is sandboxed and quarantined, outside the
  decider-containment guarantee, with its own threat model. Adding it is an
  explicit architecture revision, not a quiet grant of payload-authoring power to
  the existing decider.

## 5. Known-issue catalogs (OWASP, CVE)

A catalog is not a test — it is either a coverage map or a candidate source.

- **OWASP (esp. the LLM Top 10) → a coverage taxonomy.** It enumerates *classes
  of enforcement failure* (prompt injection, excessive agency, insecure output
  handling), which maps onto Smash's fighter structure. Load it as the
  **categories of the coverage matrix** (§13.A): each class is covered / partial
  / unsupported, backed by admitted fighters. Makes the report honest about
  scope. Classic web OWASP (SQLi, XSS) mostly does not map to a tool-call
  gateway — import what fits the target class; do not pad with "N/A".
- **CVEs / advisories → candidate source, not an auto-suite.** Smash is a
  behavioral black-box prober, not a version scanner. "Does dependency X v1.2
  have CVE-Y" is a software-composition question for `cargo audit` / OSV / Trivy
  — a different tool to **integrate / point to**, not rebuild. A CVE in another
  gateway becomes a *candidate technique* ("does mine have the analogue?") that
  enters the same admission funnel as a model-generated candidate: invariant +
  oracle + seeded fixture before it is a fighter. CVE/advisory feeds and the
  generator converge on one pipeline.

Two constraints:
- **Pin the catalog version.** Editions and feeds change. A run records the exact
  snapshot tested against ("OWASP LLM Top 10 2025 + CVE snapshot 2026-10-22"),
  same discipline as pinning oracle/schema versions. No live mid-run queries —
  they break replay.
- **Catalog data is untrusted content.** A fetched feed rides behind the manifest
  wall: it becomes a typed candidate handle, never free text that could steer the
  harness or a model via a poisoned "advisory".

## 6. Safe discovery of the unknown — the safety case and the capability ladder

The unanticipated attack is the one that hurts a developer who has never heard of
it, so "find what we can't see" (§1) is the point of Smash, not a stretch goal.
The question is not *whether* to run discovery but *how to run it safely*. The
answer rests on two safety axes, kept deliberately separate, both already built
into the workspace — and a reframe of what the search looks for.

### 6.1 Two safety axes

- **Containment — safety of execution.** A discovery probe may be novel and
  aggressive, but its *effect* is fenced regardless of what it does: it fires only
  in a disposable canary (or an explicitly authorized staging environment), under
  the capability gate, through the controlled transport, within a run-level
  dispatch ceiling, and **never** against a production environment (L2 is a hard
  exclusion). An unresolved mutating effect raises the quiescence barrier — no
  further mutating dispatch until quiescence or isolation is proven, else the run
  aborts. So "we don't know what this probe does" is survivable: the worst case is
  bounded, reversible, and inside the fence. (See `staging-and-containment.md` and
  `autonomous-loop.md` §3.)
- **Honesty — safety of inference.** A discovered divergence is a *candidate
  observation*, never an auto-promoted finding and never an auto-fix. The oracle
  asymmetry holds: an invariant violation is a **KILL**; a non-violation is
  **Inconclusive**, never a **Pass**. A clean discovery run means "no divergence
  observed along this trajectory," not "secure." Promotion to a catalog finding
  requires a human to ratify the invariant and seed a failing fixture. So novelty
  cannot manufacture a false verdict, and a discovery run can never quietly bless
  a target as safe.

These are independent of *how novel* the probe is. Safety does not come from
preventing novelty; it comes from **fencing novelty's effects (containment) and
refusing to let novelty score itself (honesty).**

### 6.2 The reframe that makes it work

A catalog of attacks can only test attacks someone already wrote down — useless
against the unknown. Discovery inverts the search: instead of enumerating
*attacks*, state an **invariant from the threat model** — what must always be true
regardless of input — and search for any input that **violates** it. The developer
does not need to know the attack; they need to know the invariant. The
counterexample *is* the new attack, learned from the violation.

This is why metamorphic relations (§2.2) are the heart of safe discovery:
"equivalent encodings must get equal decisions", "lowering permission must never
enable more effects", "external (Tier-3) content cannot learn or forge its own
session delimiter" (fighter #2). The invariant comes from the threat model, not
the gate's source — so a violation can genuinely surprise its author. A mutator
generates the paired or varied inputs; the relation is the oracle; a break is a
finding no one pre-specified. The developer's knowledge requirement moves from
"every attack" (unbounded, and the dangerous ones are the ones they lack) to
"what must hold" (bounded, and what they actually understand about their system).

### 6.3 The capability ladder (honest about reach)

- **Tier A — model-free discovery (safe, near-term, build now).** Human-authored
  threat-model invariants, expressed as differential + metamorphic relations, ×
  a reviewed mutator library × seeded, coverage-guided search, all inside the
  containment envelope. Finds new *instances* within understood mechanism classes,
  and — through metamorphic relations — genuine violations the invariant's author
  did not anticipate. No model inside Smash; the oracle stays deterministic and
  replayable. This is fighter #2's shape and the phase-2 generator's job
  (`generator-model-free.md`), and it is what we build next.
- **Tier B — model-assisted mechanism discovery (gated frontier, §13.G).** A
  quarantined model proposes *new mechanisms* a human never templated. This is the
  only path to genuinely novel *mechanism* classes, and it is the most dangerous
  to build, so it carries the strictest gate (§4): the model is a player never the
  referee, its output is an inert declarative candidate that must clear admission,
  candidate ≠ finding, and the generator is a separate trust domain with its own
  threat model. Approached only after Tier A is proven out and the §13.G threat
  model is ratified — never as a quiet escalation of Tier A.

### 6.4 The honest boundary

Tier A finds **instances, not mechanisms**: a mutator sweeps the neighbourhood of
an invariant a human stated and surfaces violations within it. It cannot invent an
invariant nobody wrote — that is Tier B, or human authorship. This is the same
limit as the mutator library (a mutator generalizes a *known transformation class*
into a reusable search axis; it does not discover a new class). What makes *both*
tiers safe is identical and independent of their reach: containment bounds the
effect, and candidate ≠ finding plus the oracle asymmetry bound the claim. The
honest promise is therefore strong but exact: **Smash can safely search for, and
surface as reproducible candidate evidence, violations of any invariant a human
can state — including violations produced by attacks the developer had never heard
of — while never letting that search escape its fence or mint its own verdict.**

## 7. The invariant across all of it

Model, catalog, generator, differential, metamorphic — every one of these is a
*source of plays*. The service remains the arena; the oracle remains the
deterministic referee. **Candidate ≠ finding**: nothing becomes a verified
security finding without a validated oracle and a seeded failing fixture, and
nothing reaches the wire without clearing the capability gate in a disposable
fixture. That is what lets Smash expand *coverage* arbitrarily while keeping
*trust* and *replayability* exactly where they are today.
