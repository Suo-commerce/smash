# Smash — Generator boundary spec (candidate discovery, §13.G trust surface)

Status: **SPEC / DRAFT** (Smash-side). Defines the trust surface for *any* candidate
generator — model-free (phase 2) and autonomous test-and-adjust (phase 3) plug into
this same surface without widening it.
Reconciled against **SPEC-SMASH-001 v0.3** (§4, §6, §13.F, §13.G), `design/discovery-and-coverage.md` (§4–§6), the F-B finding, and `specs/fighter-2-delimiter-breakout.md`.
Date: 2026-10-24.

## 0. What this is, and the one idea

A **generator** proposes *candidate* probes. This spec defines the wall around it so
that it can propose freely while holding **no capability** — it never dispatches,
never scores, never widens scope, never authors executable behavior. The design-note
rule stated once: **the generator is a player, never the referee.**

### 0.1 Implemented-workflow clarification (2026-11-06)

The delivered M3 `smash_engine::http` workflow consumes a reviewed, static `HttpCampaignPolicy`
JSON file through deterministic validation. It does **not** instantiate the `Candidate` interface
below, learn routes, or give a model/model response a request-building primitive. Its exact route
IDs, fixed destinations/headers, typed flat parameters, credential references, scalar expectations,
controls, and budgets are policy-owned. That design is one intentionally narrow example of keeping
planned actions inert before admission, not an implementation of model-free/adaptive generation or
the general manifest/adapter registry. A future generator would need an explicit translation into
an admitted policy/draft contract and must not bypass route, scope, authority, budget, or control
validation. The read-only M1 `ExperimentDraft`, M2 typed repro artifact, and M3 campaign policy are
separate formats; none has automatic authority in another workflow.

The delivered M4 investigation protocol likewise does not instantiate this candidate pipeline. Its
planner may select only a fixed queue item and an index into a pre-admitted read-only M3 catalog;
thoughts update bounded hypotheses/queue state but cannot change call authority. The engine checks
the raw response, decision, and digest before dispatch, and replays the same inert decoder offline.
This adds multi-step selection, not model-written requests, candidate generation, new mechanisms,
route discovery, or mutation authority.

The single idea everything below serves: **the generator is untrusted by
construction, so compromising it must buy an attacker nothing.** The decider
containment guarantee keeps adversarial content *out of* the decider; this is its
mirror — it keeps a generator's output *inert* until the trusted admission stage vets
it, and bounds every admitted candidate by the same type cage and capability gate that
already bound every probe. A fully malicious generator can then only produce noise and
waste budget — never an unauthorized effect, never a false verdict.

## 1. Role and non-role

The generator **proposes** `Candidate` artifacts. It is not the decider, the oracle,
the executor, or the fixture manager.

It never: touches the wire or any network client; holds or sees a capability token;
constructs an `AuthorizedCall`; chooses or computes a verdict; reads raw target output
(it receives only typed, manifest-wall-clean feedback — §7); declares scope or
authority; or emits executable code.

It may: read approved inputs (prior findings, coverage gaps, CVE/advisory *handles*,
and — phase 3 — typed verdicts of its own prior candidates); and emit `Candidate`
artifacts in the declarative format of §3.

## 2. Two trust domains, two walls

Smash already has a **content-in wall** (v0.3 §6): no raw adversarial text reaches the
decider. The generator inverts the risk — it *produces* adversarial content — so it
needs a **payload-out wall**:

- The generator is its **own trust domain**, outside the trusted computing base
  (v0.3 §3). Its inputs are untrusted (a CVE feed or model output is adversarial
  content that could try to steer it — design-note §5). Its outputs are **untrusted
  candidate artifacts**.
- Everything crossing out of the generator crosses as **inert, typed data** — a
  `Candidate` carries no free-form request body, URL, authority declaration, or
  instruction string that any downstream component executes or treats as a command.
  Candidate-supplied text can only ever land in evidence as inert data, never in
  decider or model *context* as instructions.

Both walls are the same principle applied in opposite directions: trust flows through
typed, reviewed surfaces, never through free text.

## 3. The declarative candidate format (the crux)

A `Candidate` is a **typed, declarative instantiation of an approved template** — not
code, and not a new primitive. Its fields:

- `template_id` — references one **approved probe template** from the engine registry
  (e.g. `taint-launder`, `delim-echo`, `encoding-equiv`, `arg-reorder`). Templates are
  human-authored, versioned, and define the *mechanism* and its typed parameter slots.
  A candidate cannot define a new template.
- `params` — values filling the template's typed slots, each within the template's
  **declared bounds** (value ranges, enum choices, string generators capped on
  length/charset). Out-of-bounds → rejected at admission.
- `target_handle` — which registered target tool/param the probe exercises, from the
  configured target surface. Not a free-form URL (v0.3 §4).
- `effect_class` — `ReadOnly` or `Mutating`, and must not exceed what `template_id`
  permits (v0.3 §5; required authority is based on possible effect if the target is
  vulnerable).
- `oracle_binding` — the **registered** oracle id/version + invariant this candidate
  claims to test. A candidate **selects** an oracle; it cannot invent one. No oracle,
  no admission.
- `provenance` — generator id/version; source (mutation of fighter X, CVE-Y analog,
  model-artifact hash); RNG seed when algorithmic. Enough to **replay, not regenerate**
  (§5; design-note §4).

### 3.1 The honest bound — instances, not mechanisms

Because a candidate can only instantiate an existing template and select an existing
oracle, a generator discovers new **instances** (new parameter points, new encodings,
new combinations within admitted mechanisms) — **not new mechanisms** (a template
nobody wrote, or an invariant nobody stated).

This is not a weakness to hide; it is the containment. Worked against the real record:

- **F-B W1 (dashes-for-underscores laundering) is a parameter-space point** — findable
  by a generator over a `taint-launder` template with an encoding-mutation slot. A
  model-free generator (phase 2) could have proposed it.
- **Fighter #2 (delimiter break-out) is a mechanism** — it needs a human-authored
  template + the INV-DELIM oracle first. No generator proposes the mechanism; once the
  template exists, a generator searches its parameter space (induction phrasings,
  sinks).

So the division of labor matches the promotion rule: **generators extend reach over
instances; mechanism-level novelty stays human** (and, only under a future explicit
revision, model-*proposed* templates that a human still admits). Expectation set
honestly: a generator makes the admitted mechanism space exhaustively searchable; it
does not invent the space.

## 4. The admission interface (trusted, deterministic)

A `Candidate` becomes runnable only through **admission**, which lives in the trusted
base (not the generator) and is deterministic. It operationalizes the v0.3 §13.F
checklist as a pipeline:

1. **Schema validity** — well-formed; `template_id` and `oracle_binding` reference
   registered, compatible entries at pinned versions.
2. **Parameter bounds** — every `param` within the template's declared range; reject
   out-of-range (no silent clamping).
3. **Effect-class check** — `effect_class` ≤ template's permitted effect; unknown or
   excess → reject (v0.3 §5). Target-side `taint_exempt` cannot lower it.
4. **Scope / authority** — `target_handle` resolves inside the configured scope;
   required Smash authority ≤ the run's ceiling. Off-scope or over-ceiling → `Denied`
   as a recorded fact (v0.3 §5).
5. **Fixture requirements** — resolve what fixture/fidelity the template needs
   (e.g. fighter-#2-class live-model canary); unavailable → `Inconclusive`/`Error`
   coverage, never a pass.
6. **Budget assignment** — bounded requests/duration/bytes per candidate; a candidate
   flood is capped.
7. **Dedup** — canonical candidate key (template + normalized params + target); a
   candidate semantically equal to an existing fighter or a prior candidate is merged,
   not re-run.
8. **Oracle-contract binding** — freeze the selected oracle id/version + invariant +
   evidence schema into the admitted artifact.

Output: an **`AdmittedCandidate`** (immutable handle; runs through the *normal*
capability gate + controlled transport in a disposable fixture — no special path) or a
**`RejectedCandidate`** (reason code, recorded as coverage: a rejected candidate is
unexecuted coverage, never a pass — v0.3 §5).

## 5. Candidate ≠ finding (lifecycle + provenance)

`AdmittedCandidate` → run (capability gate, containment, canary) → recorded evidence →
**the one deterministic oracle** judges → verdict. A KILL from a candidate is an
**exploratory observation / candidate finding**, *not* a catalog fighter.

Promotion into the reviewed regression catalog requires a **human** to: ratify the
invariant, seed a failing fixture, and pin the `probe_set` (design-note §6; v0.3
§12.5, §13.G). Until then it stays a candidate.

**Provenance pinning.** The exact candidate artifact (`template_id` + `params` + seed +
versions) and its recorded evidence are stored in the bundle. `verify` **replays the
recorded evidence** under the pinned oracle; it never re-invokes the generator. A
finding reproducible only by re-asking a generator is not a finding (design-note §4).

## 6. The generator's own threat model (required by §13.G)

The generator is outside the TCB, so its threat model is stated separately. For each
threat, note that the mitigation lives in the *trusted* stages, never in trusting the
generator:

| Threat | Mitigation (all outside the generator) |
|---|---|
| Candidate's effect exceeds its declared class | Admission effect-check (§4.3) **and** the type cage: even admitted, it can only produce an inert `Call`; only `Capability::authorize` + `check_dispatchable` reach the wire. |
| Generator poisoned (CVE feed / model) to target out-of-scope or escalate authority | The format cannot express a free-form target or an authority override (§3; v0.3 §4); admission scope/authority check (§4.4) rejects it. |
| Poisoned input steers the rest of Smash (prompt-injection *into* the engine via a crafted "advisory") | Candidate is inert typed data; names/descriptions come from the reviewed registry, not candidate text; no candidate string enters decider or model context as instructions (§2). |
| Candidate flood / resource exhaustion | Per-candidate budget + admission rate caps + dedup (§4.6–§4.7); candidates are bounded coverage facts. |
| Non-replayable finding | Provenance pinning; replay-not-regenerate (§5). |
| Generator fully compromised | It holds no capability. Worst case is noise and wasted budget — no unauthorized effect (capability gate + containment), no false verdict (model-free oracle, separate domain). **This is the design goal, not a residual risk.** |

## 7. Forward surface for phases 2 and 3

This boundary is generator-agnostic. The two later phases attach here and add nothing
to the trust surface:

- **Phase 2 — model-free generator.** Algorithmic candidate search (mutation,
  combinatorial parameterization, metamorphic-relation enumeration) over §3's format.
  Lowest trust risk: no model. **Quarantined like every generator** (decision, §8.4) —
  it runs in the generator trust domain and emits only §3 candidates through §4
  admission, never from inside the engine domain. No §13.G model revision.
- **Phase 3 — autonomous test-and-adjust loop.** The loop's "adjust" = the generator
  consuming the **typed verdicts/coverage** of its own prior candidates to bias the
  next batch. Two invariants keep autonomy from widening the surface: (a) the feedback
  it consumes is manifest-wall-clean typed facts, **never raw target output**, so a
  self-adjusting loop can't pull adversarial content into its strategy in a way that
  steers effects; (b) every candidate still crosses §4 admission and runs through the
  capability gate — autonomy changes *which* candidates are proposed, never *what a
  candidate is allowed to do*. A model-assisted generator (should a later revision add
  one) is just a phase-3 generator whose proposal step uses a model; it sits in the
  same quarantine, under the same admission, scoring nothing.

The autonomy ceiling, stated plainly: the loop can search the admitted mechanism ×
parameter space without supervision and surface candidate findings; it **cannot**
promote a candidate to a catalog finding, add a mechanism, or establish a verdict —
those remain human and oracle, by construction.

### 7.1 M1 research planner is a separate workflow

The M1 repository-research planner is **not** the candidate generator described above.
It emits bounded `ExperimentDraft`, `HypothesisDraft`, and research `Evaluation` records,
not a `Candidate` or `AdmittedCandidate`. It cannot choose or establish an oracle verdict,
and research `EvaluationStatus::Passed` only supports the recorded inspection/evaluation
claim. A hypothesis does not bypass §4 admission or become a behavioral finding.

This distinction matters for raw source. Bounded `ResearchFact.statement` values can
contain exact source excerpts, so a future model-backed research planner would receive
untrusted repository text rather than only the manifest-wall-clean verdict feedback in
§7. That research path is outside the decider containment guarantee; source comments must
remain inert evidence and cannot become instructions. M1 currently provides a
`ScriptedPlanner`, not a hosted-model provider. Secret filtering is path/name/extension
based, not proof that captured source contains no sensitive material.

A research hypothesis may help a human draft the threat model or a reviewed template. It
must not be converted automatically into a `Candidate`: normal admission, scope and
capability checks, fixture containment, and an independently evaluated runtime evidence
contract are still required. M1's read-only/no-network operation vocabulary likewise
does not satisfy the dynamic sandbox or evidence requirements of later milestones.

### 7.2 M2 typed reproduction is also a separate workflow

The implemented M2 CLI can execute only the reviewed authenticated-retry fixture's exact four-field
JSON artifact against supplied broken/fixed roots. It does not deserialize execution authority,
interpret arbitrary artifact text as code, turn M1 hypotheses into `Candidate` values, or connect a
planner/generator to the Linux runner. `Reproduced` is the scoped fixture oracle result, not the
KILL/DEFENDED lifecycle or human-ratified finding described above. The declarative candidate
registry, admission integration, model-proposed executable adapters, and autonomous feedback path
in this document remain proposed; M2 is not evidence that those general interfaces are live.

## 8. Open questions for ratification (Jarmo + Hermes)

1. **Template registry ownership.** Templates are the mechanism primitives a generator
   searches within. Proposed: Hermes authors/reviews templates (same role as fighter
   specs); this assistant builds the registry + admission. Confirm.
2. **Candidate format schema home.** `smash-core` (dependency-free domain) for the
   `Candidate` / `AdmittedCandidate` / `RejectedCandidate` types + canonical candidate
   key; admission pipeline in `smash-engine`. Confirm placement.
3. **CVE/advisory handles.** Confirm feeds enter only as typed candidate *handles*
   behind the manifest wall (design-note §5), pinned to a snapshot, no live mid-run
   queries.
4. **Phase-2 generator trust placement.** **DECIDED (Jarmo, 2026-10-24): quarantined in
   all cases.** Every generator — model-free included — sits outside the TCB behind the
   §2 payload-out wall and §4 admission. One consistent boundary for phases 2 and 3; no
   generator is ever granted in-engine trust. The containment/fidelity axis (where a
   quarantined generator's probes are allowed to run) is specified separately in
   `specs/staging-and-containment.md`.
5. **Phase-3 feedback typing.** Exact typed-verdict/coverage shape the loop may consume,
   confirmed manifest-wall-clean (no evidence-bundle leakage of raw output into the
   strategy).

## 9. Build order within phase 1

1. `Candidate` / `AdmittedCandidate` / `RejectedCandidate` types + canonical candidate
   key in `smash-core` (dependency-free; compile-fail tests that a `Candidate` cannot
   be turned into an `AuthorizedCall` without admission).
2. Admission pipeline in `smash-engine`, reusing the existing scope/authority/capability
   checks — admission must not duplicate the capability gate, only precede it.
3. One template + oracle wired end-to-end as proof: re-express F-B's `taint-launder` as
   a template with an encoding-mutation slot, and show a hand-written candidate
   (dashes-for-underscores) admits, runs, and KILLs on clean `d2a9205` — proving a
   generator *would* have found W1. That closes the loop from design claim (§3.1) to
   evidence before any generator is built.
