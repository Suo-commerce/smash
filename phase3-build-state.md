# Smash — phase-3 + generator build state (living doc)

Supersedes `build/phase3-item1-smash-loop-notes.md`. Current as of **2026-10-30**.
2026-11-06 dependency update: Stormgate is explicitly `exclude`d from the active workspace, and
`realfield-core` is absent from its lockfile. The remaining `ring` package comes from `ureq`'s TLS
graph, not Stormlock; building the optional target pack still requires its separate checkout.
Current M1–M4 delivery status is maintained in `llm-red-teaming-roadmap.md`.

Companion to the specs under `specs/` (notably `specs/autonomous-loop.md`,
`specs/findings-management.md`, `specs/admission-funnel.md`),
`build/admission-gap-audit-2026-10-28.md`, and `design/discovery-and-coverage.md`
(§6 = the safe-discovery safety case + Tier A/B ladder).

## Status at a glance (ThinkPad, `cargo test --workspace`, all green)
- `smash-core` 75 · `smash-engine` **98** (89 + 9 `candidate_key`) · `smash-generator` 19 ·
  `smash-loop` **116** (79 + steering 12 + accumulator 7 + admission 8 + run 10), plus
  doctests (generator 1, loop 2 compile-fail). clippy clean under `-D warnings`.
- `smash-findings` **52 tests** (workspace member; `ingest` compiles against the real crates).
- `smash-stormgate` stays excluded from `members` by default (path-deps `realfield_core`).

## The headline: the autonomous discovery loop runs end to end (P3 §12 item 3 DONE)
`smash_loop::run::DiscoveryRun::run()` drives the full P3 §1 order unsupervised:
propose → admit (with the stage-2 dedup lifecycle) → size the plan from the withheld budget
→ dispatch control + probe via the `Controller` → reconcile → feedback → adjust → steer →
conclude. Tested end to end with fake ports (no live gate): completes on earned saturation
(exit 2, complete), a `Fail` flips it to exit 1, the kill switch aborts it, a duplicate
proposal dispatches once (recomputed-key merge — stage 2b through the whole loop), an
unassignable candidate is denied not dispatched.

## Admission funnel (the three missing §4 stages)
- **Stage 1 — parameter bounds: DONE.** `bounds.rs` (engine, 11) + `param_check.rs` (loop, 12)
  + `ports`/`regions` wiring.
- **Stage 2 — dedup-merge: DONE (landed in item 3).**
  - `dedup.rs` (loop, 10) — seen-set + reservation state machine (InFlight/Resolved/Uncertain),
    poison-before-merge (§2.2), atomic reserve (§2.3), merge-not-redispatch (§2.4), the §2.5
    failure split (`release` clean pre-dispatch / `mark_uncertain` holds uncertain forever).
  - `smash-engine::candidate_key` (9) — the §2.1 content-only key recompute
    (`candidate:v1:<sha256(canonical_json({fighter,technique,params}))>`), reusing
    `canonical::canonical_json` as convenience; **distinct from the target-mirroring `CallKey`**.
  - `admission.rs` (loop, 8) — **stage 2b**: `admit_with_dedup` runs the §2 order
    (admit_candidate → recompute key → poison-check → reserve). Proven: the supplied key is
    never trusted (different supplied keys, same content → same recomputed key → merge).
- **Stage 3 — fixture/receipt: NOT STARTED (the big one).** `Fixture`/`Receipt` interface +
  executor collection + the `judge` extension (§3.3 decision×receipt matrix, incl.
  Withheld+Occurred = effect-despite-withholding) + a `CaseRecord` receipt field (bundle schema
  bump). The honesty upgrade that sets `evidence_fidelity = EffectConfirmed`; `smash-findings`
  already carries that field.

## Item-3 bricks (all green, loop-side)
- **`ceiling.rs`** — run-level dispatch ceiling, per-entry reservation, baseline **withholding**
  (N4), feasibility **preflight** (M2). (Was already present; confirmed it carries both.)
- **`steering.rs`** (12) — the §2/§3.3 adaptive math: earned saturation (sample-resolved only),
  intensify-on-Fail, operational throttle (op_error/op_timeout past `attempted_probe_floor`),
  suppression freeze at `suppression_cap`, and the abort check over the *attempted* set
  (`gap_floor`/`gap_tolerance`, unvisited excluded). `validate_floor` enforces M5.
- **`accumulator.rs`** (7) — the run-scoped outcome tally; projects the four views (coverage,
  observations, typed feedback, the any-fail/all-resolved stop signals) from one history.
- **`run.rs`** (10) — `reconcile_outcome` (the quiescence/dedup/accumulator lockstep; the single
  `Inconclusive(Timeout) → AttemptState::Unresolved` bridge) + `DiscoveryRun` (the iteration
  wrapper, including the non-replenishing `intensification_share` ledger cap).

## Crate layout & dependency direction
`core ← engine ← {generator, loop}`, `loop → {engine, generator}`, and
`findings → {core, generator, loop, engine}` (a leaf consumer). The generator wall holds:
`smash-generator` depends on `smash-core` **only** (compile-fail doctest). This is why
`candidate_key` lives in **engine** but takes params as a `serde_json::Value` and the handle as
`&str` — the engine can name neither `ParamValue` nor the generator's types, so the loop lowers
`ParamValue → Value` (via `metamorphic::params_to_json`) and reads `handle.{fighter,technique}.as_str()`
at the call site.

## What runs end to end today
1. **Tier-A model-free discovery** at the in-process differential seam (unchanged, green):
   generator W1 pair → region admission → `metamorphic::judge_pair` → KILL on a vulnerable
   gate, DEFENDED on a fixed one; `reverify` matches live.
2. **The autonomous loop** (new) — `DiscoveryRun::run()`, above.
3. **The findings ledger** (`smash-findings`) — ingest verified bundles → deduped records,
   ranked triage, per-target coverage, human-gated promotion. Offline, never re-judging.

## Gotchas / conventions (do not relearn the hard way)
- **A new module is not in the crate until its `pub mod` line is declared** in `lib.rs`.
- **serde_json / serde pin LOOSE (`"1"`)** — retain workspace-compatible requirements; the active
  resolution is recorded in `Cargo.lock`. The excluded Stormgate target pack's external dependency
  graph no longer constrains this workspace. `smash-generator` takes no serde.
- **`CandidateProposal` carries `handle`** (fighter+technique) now — admission resolves it and
  recomputes the key; the generator's supplied `key` is advisory only.
- **The loop's one unresolved carrier is `ProbeOutcome::Inconclusive(Timeout)`** → it maps to
  `AttemptState::Unresolved` (poison + barrier). A richer `Dispatcher` could return the executor's
  `AttemptState` directly; the port-preserving mapping is what `run::attempt_state` does.
- **No IDE on the user's laptop** — hand back whole edited files ready to save.
- **Builds on the ThinkPad**; the sandbox compiles only the dep-free pure-data crates. (`rg` is not
  installed there — use `grep -rEn`.)

## Not built yet / next units (per `specs/autonomous-loop.md` §12)
- **Admission funnel stage 3 — fixture/receipt** — the `evidence_fidelity = EffectConfirmed` upgrade.
- **Item 4 — the registered deterministic clustering predicate + retention** (P3 §7, §5.2): two
  findings cluster iff identical mechanism id `(template_id, mutator_id, transform_id)` AND a
  matching pinned-oracle evidence signature; default-to-separate; representatives never trimmed.
  (`smash-findings::triage` already has cluster-*suggestion* signals; this is the registered,
  evidence-signature predicate + the retention/summary-marker rules.)
- **Item 5 — the L0 capstone** (P3 §10): register W1 (`taint-launder`) + W2
  (`sensitive-field-selection`) with their oracles and region partitions, run `DiscoveryRun` at L0
  against the pre-fix tree, and autonomously surface W1 + W2 as clusters against the named F-B
  catalogue, each re-verifying offline and Pass on the fixed tree.
- **B1 / B2 (model-assisted discovery)** — ride through the completed funnel; B2 (template-drafter)
  is the novel-mechanism path, human-gated (§13.G).
- **Real Storm Gate — in-process harness** in `smash-stormgate` (`judge_pair(&RealfieldGate, &pair)`),
  then **live HTTP** (the real `Dispatcher`/`Oracle` the loop's ports abstract).
