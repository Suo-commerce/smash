# Smash — Admission funnel completion spec (the three missing §4 stages)

Status: **SPEC / DRAFT** (Smash-side). Completes the distributed §4 admission funnel.
Reconciled against `build/admission-gap-audit-2026-10-28.md`, `specs/generator-boundary.md`
(§4 the 8-stage pipeline, §3.1 instances-not-mechanisms), `design/discovery-and-coverage.md`
(§3 reference-vs-divergence, §6 containment + the canary receipt), `specs/staging-and-containment.md`,
and `specs/autonomous-loop.md` (§3 quiescence barrier). Date: 2026-10-28.

## 0. What this is, and the one constraint

The gap audit found admission **~70% built and distributed** — the capability gate
(core), the registry contract cross-check (engine), and region/oracle admission (loop)
are done and tested. **Three stages have no home:** parameter bounds (2), dedup-merge
(7), and the runtime **fixture/receipt** layer (5). This spec defines them.

The one constraint, non-negotiable (gap-audit P2): every stage here **precedes and
reuses** the existing capability gate and the one oracle `differential::judge`. None of
them adds a second gate or a second verdict rule. Admission is a deterministic
pre-stage that hands an admitted candidate to machinery that already exists.

These are framework capabilities. A target pack *implements* small detectors (as it
already implements the `Gate` adapter); it never implements admission.

## 1. Stage 2 — parameter bounds

**Decision (proposed): bounds live on the TEMPLATE, not the candidate** — the mirror of
severity (findings decision 4). An untrusted generator fills typed param slots; the
reviewed template declares their bounds. A candidate cannot widen its own bounds.

- A **`ParamSpec`** per slot, declared when the human admits the template and versioned
  with it: `Int{min,max}`, `Str{max_len, charset}`, `Bool`, `List{max_len, elem: Box<ParamSpec>}`,
  `Map{keys: BTreeMap<String, ParamSpec>}`, `Enum{choices}`.
- **Admission check:** every candidate param resolves to a declared slot and is within
  bounds; out-of-range → **reject, no silent clamp** → `AdmissionDenial::ParamOutOfBounds`
  → a `RejectedAtAdmission` coverage row. An unknown or missing slot is also a reject.
- **Home (proposed):** the `ParamSpec` set attaches to the engine `Technique`
  (trusted-base template data, next to the oracle/prereqs the registry already carries).
  The loop's `admit_candidate` gains the bounds check — which means `CandidateProposal`
  must carry the candidate's params (today it carries only `{key, intended_region}`), or
  admission takes the full `Candidate`.
- **Defense in depth:** the generator *reads* the bounds to generate in-range (reviewed
  template data); admission *re-checks*, because the generator is untrusted.

*Open:* `ParamSpec`'s home — engine registry (recommended; it is template data) vs
`smash-core`. And whether `admit_candidate` takes the full `Candidate` or an extended
`CandidateProposal`.

## 2. Stage 7 — dedup-merge

**Decision (proposed): a deterministic dedup stage keyed on `CanonicalKey`**, consulting
the run's seen-set and the poison-set, in front of dispatch.

- Before a candidate is dispatched, admission checks its key against (a) the run's
  already-admitted/dispatched set → **merge** (occurrence accrues, no re-dispatch), and
  (b) the poison-set → **drop** (`RejectedAtAdmission`/coverage). Poison binds to the
  canonical key (P3 §0.2), so this is the same identity the generator and the findings
  ledger use.
- **Home:** loop-side (run state lives there), as a stage around `admit_candidate`. The
  seen-set and poison-set are run-scoped loop state.
- **Relation to `smash-findings`:** the ledger's dedup is the *durable, cross-run*
  version; this is the *within-run* version that stops the dispatcher re-firing the same
  probe. They share the key by construction.

*Open:* confirm the loop's poison model is already keyed on `CanonicalKey` (P3 §0.2 says
so); if not, that alignment is part of this stage.

## 3. Stage 5 — the fixture/receipt layer (the honesty upgrade)

The large one, and the real capability gap. Today the differential judges a
`GateDecisionView` (response/decision level): "the gate said yes." The design note is
explicit that **a KILL is only real if the effect occurred**, confirmed by the fixture's
canary receipt — not by the response (discovery-note §6; `adapter.rs` says it in code).

- **The `Fixture` interface (engine):** provision a disposable canary within the
  authorized origin set; take a `StateSnapshot` before a mutating probe; after, take
  another; produce a **`Receipt { effect: Occurred | NotObserved | Unresolved }`**. The
  interface is generic; the **target pack implements the detector** (as it implements the
  `Gate` adapter) — "did the protected effect happen": read the row back, check the file,
  inspect the mocked sink. A probe class whose effect cannot be detected or mocked is
  **not admitted** in that environment (stage-5 unavailable → `Inconclusive`, never pass).
- **Receipt → verdict (combination, not a second oracle):** at the loop seam, the
  recorded decision and the receipt combine. A **confirmed KILL** requires the gate
  approved **and** the receipt is `Occurred`. This is where `evidence_fidelity` is set:
  `Occurred` → `EffectConfirmed`; no receipt (ReadOnly probe, or fixture absent) →
  `ResponseOnly`; `Unresolved` → the **quiescence barrier** fires (autonomous-loop §3):
  halt further mutating dispatch until quiescence/isolation is shown. `smash-findings`
  already carries the `evidence_fidelity` field for exactly this.
- **Containment:** the fixture is the disposable canary (L0/L1, staging-and-containment),
  real sinks mocked, production forbidden. The receipt layer is *also* the containment
  layer — the snapshot/receipt is how an effect is both confirmed and bounded.
- **Home:** `smash-engine` fixture orchestration (lib.rs lists it as a responsibility;
  unbuilt). A new `Fixture`/detector trait the target pack implements. `execute.rs` gains
  a snapshot-around-dispatch step for mutating probes.

**Open decisions — the ones that are yours to steer before I draft the build:**

- **(a) Does the receipt go into the `RunBundle`?** *Recommend yes* — add a receipt field
  to `CaseRecord` so `evidence_fidelity` is reproducible offline by `verify`. This bumps
  `matchlog::SCHEMA_VERSION` (and is why `verify` fails closed on old schemas).
- **(b) How does "Approved + NotObserved" classify?** *Recommend `Inconclusive`*, not a
  Kill — the gate let it through but no effect was confirmed, so honest non-confirmation
  preserves oracle asymmetry and avoids a false KILL. This is the Aegloss-type case made
  rigorous: a 2xx without a confirmed state change is not a finding.
- **(c) Mode A vs Mode B — the honest scoping.** For an **in-process pure-decision gate**
  (Storm Gate Mode A), there is **no backend effect to detect** — the decision *is* the
  outcome. So `EffectConfirmed` is a **Mode-B / live-canary property**; Mode-A KILLs are
  decision-level by nature, and that is correct, not a gap. *Recommend* we state this
  explicitly so nobody "fixes" Mode A to chase a receipt that cannot exist there.

## 4. Build order

1. **Param bounds** — `ParamSpec` on the template + the admission check + the
   `ParamOutOfBounds` denial. Smallest, self-contained, TCB.
2. **Dedup-merge** — run seen-set + poison check around `admit_candidate`. Small, loop-side.
3. **Fixture/receipt** — the `Fixture` trait + `Receipt` + the executor snapshot step +
   the decision/receipt combination + the `CaseRecord` receipt field (schema bump). Large;
   it carries its own sub-steps and is where the open decisions above land.

Each step reuses the capability gate and `judge`; none adds a second verdict rule.

## 5. The rails (unchanged)

Candidate ≠ finding; one oracle; verify replays recorded evidence (the receipt field
*extends* what it can replay — effect reproducibility — it does **not** add a second
oracle); the generator is a player never the referee; pin crates.io deps loose. The
fixture/receipt layer widens what Smash can *honestly observe*; it changes nothing about
who scores or who promotes.

## 6. Decisions to ratify (Jarmo / Hermes)

1. §1 — bounds on the template (not the candidate); `ParamSpec` home.
2. §1 — `admit_candidate` takes the full `Candidate` vs an extended `CandidateProposal`.
3. §3(a) — receipt recorded in the `RunBundle` (+ schema bump).
4. §3(b) — "Approved + NotObserved" → `Inconclusive` (not Kill).
5. §3(c) — `EffectConfirmed` is a Mode-B/live-canary property; Mode-A stays decision-level.
