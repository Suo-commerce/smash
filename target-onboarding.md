# Onboarding a new target to Smash

A guide for pointing Smash at one of **your own** applications (or an authorized
staging instance of it). It is written to be followed by *you plus a local coding
agent* (Claude Code, Opencode, …): the agent audits your app's source, fills in the
**target threat-model sheet** (§2), and builds the **target pack** (§4) against the
fixed Smash vocabulary (§3). Storm Gate is used only as the worked example.

Smash is a white-hat harness for hardening apps you own or are cleared to test.
Everything below assumes that authorization. Read §6 (containment) before you run a
single mutating probe — "running locally" is **not** the same as "safe to break".

---

## 1. What Smash can and cannot test (read first — sets expectations)

Smash is a **behavioral enforcement prober**. It is strongest when your app has:

- an **enforcement boundary** — a point that decides whether a proposed action is
  allowed, denied, escalated, or intercepted (an authorization gate, a policy check,
  a tool-call chokepoint); and
- an **observable decision** at that boundary (you can see allow vs. withhold).

Then Smash can state an **invariant** ("this must always hold") and search for inputs
that **violate** it — including attacks you had never specifically heard of. That is
the whole point: you supply the invariant (what you understand), the search finds the
counterexample (the attack you didn't).

Smash is **not**:

- a generic web vulnerability scanner (SQLi/XSS/etc. — use a web scanner);
- a dependency/CVE scanner ("does lib X have CVE-Y" — use `cargo audit`/OSV/Trivy);
- useful against a boundary whose decision you cannot observe in an instrumented
  environment (the epistemic floor: Smash can only find an effect it can see).

If your app has no decision boundary to probe, Smash is the wrong tool. If it does,
continue.

### 1.1 Preliminary read-only source reconnaissance (M1)

Before building a target pack, you can use the separate repository-research workflow to
collect bounded source evidence and **source-informed hypotheses** for the audit:

```console
smash recon --repo /path/to/authorized/checkout --script PLAN.json --out ./recon-result
smash verify --bundle ./recon-result
```

`PLAN.json` is a version-1 `ScriptedPlanner` script with a `responses` array. Each query
consumes exactly one response: either an `experiment` proposal or `complete` with bounded
hypotheses and evaluations. Only `list_files`, `read_file`, `read_manifest`,
`working_tree_status`, and `read_only_command` can be proposed; the last two require the
literal `git-status` command. A `--target MANIFEST.json` with `kind: "repository"` may
replace `--repo`. M1 has no hosted-model integration, general shell, HTTP execution, or
repository build/test execution. It creates the output directory without replacing an
existing one.

The run has finite query, experiment, command-time, file, evidence, and exact serialized
observation budgets. Wall time is checked cooperatively between planner and blocking
repository operations; it is not a hard scheduler or a general process sandbox. Network
off means the M1 workflow makes no network request, not that it establishes an OS network
namespace.

Reads are bounded regular-file UTF-8 reads, with symlinks refused. Files and paths that
look like credentials or keys are excluded by name/extension policy; **this is not secret
content scanning**. Other sensitive text can still enter facts and artifacts, so inspect
an evidence bundle before sharing it. Source comments are inert evidence, never planner
instructions.

A successful campaign or evaluation records coherent source inspection, not a verified
vulnerability or a clean security result. Promotion still requires human threat-model
review and the separate `Candidate` admission, containment, fixture, and oracle path.
Recon does not replace the target-pack acceptance criteria below. Offline verification
needs only the bundle, never the source checkout; it checks integrity and internal
consistency, not authenticity or truth about the original repository.

### 1.2 Opt-in contained reproduction (the narrow implemented M2 slice)

The only implemented M2 execution workflow is the committed **synthetic authenticated-retry
regression fixture**, not a new target pack or generic repository runner. On a supported host:

```console
smash repro --policy /path/to/smash/smash-capstone/fixtures/repro/policy.json \
  --out /tmp/smash-m2-result --json
smash repro-verify --bundle /tmp/smash-m2-result --json
smash repro-resume \
  --policy /path/to/smash/smash-capstone/fixtures/repro/policy.json \
  --bundle /tmp/smash-m2-result --json
smash repro-rerun --policy /path/to/smash/smash-capstone/fixtures/repro/policy.json \
  --out /tmp/smash-m2-rerun --json
```

Use fresh, non-existent output paths. Relative fixture, fixed, and artifact paths in a policy are
resolved relative to that policy file. The supplied policy explicitly selects the authorized
broken/fixed controls, byte-reviewed entrypoint, exact artifact, and concrete resource ceilings;
its `unsafe_seeding`, `build_under_test`, and `privileged_containment` flags are operator
attestations, not proof of ownership or permission. Production paths are not an admitted fallback.

The artifact has exactly four fields:

```json
{"protocol_version":1,"target_tool":"authenticated-retry","action":"retry_after_authenticated_refresh","expected_state":"current-session"}
```

It is declarative data consumed by the reviewed driver. No field is evaluated as Python or a
shell command. The broken control returns `prior-session`, and the fixed control returns
`current-session`; hostile source comments requesting command execution and secret access remain
inert. Arbitrary programs, test commands, build systems, network targets, and other oracles are not
supported by these commands.

A reproduced pair requires all exact source/artifact/policy/entrypoint/contract identities,
checkpoints, bounded declared outputs, and cleanup to validate, with the expected mismatch on
broken and matching state on fixed. **`Reproduced` is an observed scoped policy violation in these
synthetic controls, not an exploitable/security finding or proof that either repository is safe.**
An inverted or incomplete control remains non-green even if its bundle is internally valid. `repro`
and `repro-verify` return `0` only for this reproduced result, `1` for a valid non-reproduced
assessment, and `2` for denial/operational/argument failure. Exact completed resume returns `0`
without replaying; mismatch, unresolved evidence, pending work, and unavailable required inputs
are non-green refusals. Rerun mints a new run ID rather than reusing old authorization.

The real runner requires unprivileged Linux on `x86_64` or `aarch64`, `/usr/bin/python3`, Landlock,
seccomp, and private `/tmp/opencode` storage. It gives admitted source read-only access, a separate
private writable output, fixed argv/minimal environment, no socket creation through seccomp,
resource limits, and process-group cleanup. The architecture and hash of the reviewed helper are
recorded, but Python, libraries, kernel, and hardware are not fingerprinted. There is no silent
uncontained fallback; the explicit `unsafe_development` fixture mode is marked uncontained and
cannot produce a reproduced result. Missing host support, setup/cleanup failure, changed inputs,
output excess, and uncertain termination remain non-green.

A run maintains a private mode-`0700` pending directory and mode-`0600`, per-checkpoint
`sync_data` journal. Only after complete persistence and validation is the bundle atomically
renamed to its destination. `repro-verify` then needs only the bundle—not the original roots,
Python, network, target, or model. Its hashes verify self-consistency and deterministic evaluation,
not truthful collection or an external signature. Resume differs: it requires current producer
files to compare identities before reporting `CompletedWithoutReplay`. Pending journals refuse
verification/resume, and work interrupted mid-run is not automatically resumed. Journal syncing
and atomic reveal are best effort, not a guarantee of crash-durable completion across host failure.

The M2 capstones exercise the complete CLI pair and failure cases; lower-level tests exercise the
listed sandbox mechanisms. They are not exhaustive sandbox review, fuzzing, multi-hardware or
performance qualification, or authorization to run a new target. New targets still require the
threat-model, reviewed adapter/oracle, containment, broken/fixed control, and human admission below.

### 1.3 Typed loopback HTTP/API target pack (the implemented M3 slice)

M3 is separate from both M1 repository recon and the M2 Linux runner. It accepts an
`HttpCampaignPolicy` JSON file containing static reviewed calls, not planner-authored URLs or
HTTP messages:

```console
smash http-discover --policy POLICY.json --out /tmp/smash-http-read --json
smash http-repro --policy POLICY.json --out /tmp/smash-http-repro \
  --execute-fixture-mutations --json
smash http-verify --bundle /tmp/smash-http-repro --json
```

Use fresh output paths. The policy pins schema versions, run/target identities, a
`disposable_fixture` environment, broken and fixed HTTP(S) origins, and exact loopback IP
addresses. Its at-most-16 route templates admit only GET query or POST flat JSON string fields,
fixed paths and headers, declared `CredentialRef` environment-variable names, and exact required
Boolean/nonnegative-integer JSON response fields. Calls must supply exactly the route fields within
their byte ceilings, and every fixed-control response field must be pinned. Discovery rejects a
campaign containing any mutation; reproduction requires explicit opt-in, exactly one mutating
call, and a correlated read-only effect receipt. A model or arbitrary JSON cannot introduce a new
method, path, header, nested body, destination, or raw response extractor.

One `ureq` client disables redirects, ambient proxies, and idle reuse, retains default TLS
verification, and filters the addresses returned by the actual connection resolver. This is not a
pre-request URL check alone. Request/response bytes, call/mutation counts, and per-exchange time
are bounded; the cooperative campaign wall-clock check is `max_calls * timeout_ms` per control.
Admitted non-loopback addresses, userinfo, ambiguous paths, forbidden headers, malformed scalar
responses, redirects, and oversized bodies do not become successful observations. A missing
credential is denied before dispatch. Environment credentials are read only immediately before
the corresponding dispatch and are not persisted in policy or evidence. An unresolved transport
outcome is not treated as proof that no effect occurred.

For the duplicate-effect oracle, before and mutation calls share an explicit correlation argument,
the after receipt uses the same identity, and the unknown-identity negative control remains zero.
The fixed control must match every expectation, including before `0`, fixed after `1`, and unknown
`0`; the broken after-receipt must differ from fixed. **Both real fixture teardown attestations
are required.** The generic `http-repro` CLI does not own an externally configured fixture, so it
records cleanup as unattested and cannot honestly report `Reproduced`; a valid run remains
inconclusive and exits `1`. The owning provider uses `execute_campaign`'s cleanup callback to drop
and join its fixtures before attesting teardown, as demonstrated by the M3 capstone. Do not change
that callback to return `true` without actually establishing cleanup.

Evidence records route/input identities and digests, per-control session/namespace correlations,
call sequence/lifecycle/disposition, bounded status/content-type metadata, selected scalar fields,
body SHA-256 and length, expectations, control cleanup, and limitations. Raw response text,
authorization values, redirects, and arbitrary target strings are not retained. Reproduction
bundles contain strict duplicate-free bounded `policy.json` and `manifest.json`; verification also
demands the exact policy-copy bytes. They are staged and renamed into a fresh destination.
`http-verify` uses no target, model, credential, resolver, or network and recomputes the
`http-scalar-differential-v1` assessment. It returns `0` only for reproduced evidence, `1` for a
valid non-reproduced assessment, and `2` for invalid evidence/arguments or operational failure.
`http-discover` returns `0` only when every declared read is observed; its `discovery.json` is an
observation record, not a vulnerability finding or substitute for paired evidence.

This slice does **not** provide HTTP route discovery, arbitrary external-service containment,
L1 staging, dynamic model-to-HTTP planning, backend sandboxing, signed evidence, or general web
security testing. Loopback socket admission is not a namespace/container sandbox or proof that a
target's downstream sinks are isolated. A reproduced scalar/state difference says only that the
declared fixture contract differed; it does not establish production impact, exploitability,
absence of other flaws, authenticity of collection, or general security. Even a valid bundle may
be legitimately inconclusive. The in-process broken/fixed loopback fixture and capstones test these
mechanisms, including retries, authorization, cleanup, credential exclusion, and post-shutdown
verification; they do not certify a new target or real staging environment.

### 1.4 Bounded multi-step HTTP investigation (the implemented M4 slice)

M4 adds adaptive **selection**, not planner-owned HTTP authority. It uses a separate
`HttpInvestigationPolicy` nested around an M3 read-only `HttpCampaignPolicy`, plus a fixed
investigation queue and explicit call/planner/token budgets:

```console
smash http-investigate --policy INVESTIGATION.json --script PLAN.json \
  --out /tmp/smash-m4-result --json
smash http-investigate-resume --policy INVESTIGATION.json --script PLAN.json \
  --out /tmp/smash-m4-result --json
smash http-investigate-verify --bundle /tmp/smash-m4-result --json
```

Use fresh output paths for a new run. Every campaign call must select an `OperationEffect::ReadOnly`
route and the campaign must omit `EffectContract`; M2/M3 mutation opt-in is neither accepted nor
reused. M4 executes against the campaign target, not its paired fixed-origin control. Queue items
start `pending`, have restricted identifiers, nonempty sorted unique `allowed_calls`, and no initial
evidence. They may admit only indices in the static campaign catalog. Budgets require at least one
read, at most 32 reads, and one more planner turn than reads so the last observation can still be
reviewed. Token ceilings cover cumulative provider-declared input/output deltas; the scripted
provider declares usage explicitly. The per-call HTTP limits and timeouts in §1.3 still apply.

The optional `budgets.max_consecutive_unproductive_turns` limit accepts `1..=32`. Omit it to
preserve legacy sessions and disable this additional stop. When configured, only a newly recorded,
valid typed `Observed` HTTP result or a newly validated hypothesis/queue **status transition**
resets the consecutive counter. Planner prose, usage-only changes, and typed non-observations do
not reset it; repeated unchanged histories increment it once per turn. Each accepted decision is
counted against the previous statuses, then an `Observed` result for that turn resets the counter.
The counter and typed `no_progress` terminal use the same journal replay rules offline. At the
limit the session stops before another planner turn or HTTP read, independently of the existing
call/planner ceilings, without completing queue items or source hypotheses. Resume reconstructs
the counter, requires the exact configured limit in effective-policy identity, and refuses a changed
value. Run and verification reports expose `consecutive_unproductive_turns`.

`PLAN.json` has `schema_version: 1` and a `responses` array. One response is consumed for each
planner turn and is at most 64 KiB. A response is exactly one decision:

- `investigate` with an admitted `item_id` and `call_index`; or
- `complete`, when every queue item is `complete` or `blocked`.

Both forms carry `schema_version: 1` and a `thought` containing a bounded summary, complete
hypothesis/queue histories, and cumulative per-turn usage deltas. Hypothesis and queue identifiers,
statements/purposes, and allowed calls cannot be rewritten; prior entries/evidence are an immutable
prefix. At most one queue item can be active. `supported`/`refuted` hypotheses and completed queue
items require prior **observed** evidence turns, and completed items require same-item evidence.
Denied, malformed, unhandled, and timed-out calls remain non-observations: they neither prove
absence of a flaw nor support a completed item. Unknown fields, trailing responses, unadmitted
indices, evidence edits, invalid transitions, oversized data, or usage beyond the remaining budget
fail closed; an invalid script response is not retried.

The executor independently re-decodes the exact raw bytes, checks their SHA-256 and selected
catalog pair, checkpoints the decision, and only then dispatches one fresh M3 read. The model cannot
supply a URL, method, path, headers, arguments, credential value, mutation, extractor, or effect
seed. Observation context contains only bounded descriptors; response bodies remain reduced to
M3's scalar schema, metadata, and digest. Read count, planner turns, serialization sizes,
catalog/history cardinality, and token deltas are bounded. M4 adds no scheduler, hard global wall
clock, provider cost accounting, concurrency, novelty/deduplication, kill switch, repository-to-HTTP
bridge, dynamic target discovery, hosted-model provider, or arbitrary autonomous mechanism.

Runs start in a private mode-`0700` sibling `.smash-m4-NAME-pending` directory. Raw responses,
strict JSONL decision/observation/terminal records, and a state snapshot use bounded mode-`0600`
files with synced appends/state replacement. Atomic directory publication occurs only after replay
validation. Resume requires the same effective policy and an exact initial response-script prefix;
it consumes no old response or credential again. A durable selected read without its observation is
reported `unresolved` and is never blindly redispatched. A terminal run is published and an already
complete run returns without replay, even if the fixture is gone. Filesystem syncing and rebinding
are best-effort crash safety, not a substitute for a transaction-aware target or a signed audit log.

`http-investigate` and resume return `0` only for `complete`/`already_complete` with every queue
item complete and every hypothesis `supported` or `refuted`; blocked, unresolved, exhausted,
`no_progress`, and planner-rejected work returns `2`. Offline verification returns `0` for structural/replay validity
regardless of whether the bounded investigation completed. It reads only the exact session files,
replays the inert decoder and read-attempt checks, and uses no target, credentials, resolver,
planner, or network. It reports hypotheses and observations, not a vulnerability verdict,
collection authenticity, exhaustive coverage, or production safety.

The M4 capstones exercise two adaptive reads, observed evidence, malformed selection, call budget
exhaustion, exact-prefix resume, no replay after completion or unresolved dispatch, and offline
verification/tamper detection after fixture shutdown. No-progress cases cover consecutive 404
non-observations, prose/usage-only changes, real-observation and status-transition resets, resumed
streak preservation, changed-limit refusal, counter tampering, and the distinct successful-complete
versus `no_progress` outcomes. These are scoped regression checks, not a
certification of a new target or generalized autonomous red teaming.

---

## 2. The audit — fill in the target threat-model sheet

Point the agent at your app source and have it answer these. The answers *are* the
integration design; everything in §3–§4 is mechanical once this sheet is filled.

1. **The gate.** Which function or endpoint makes the allow/deny/escalate decision?
   Name it, its inputs, and its return type. (Storm Gate: `ActionGate::evaluate(&ProposedAction, tier3, &TaintContext) -> GateDecision`.)
2. **Decision surface.** What outcomes can it return, and how does each map to the
   four Smash decisions — **Approved / Escalated / Blocked / Intercepted**? (Anything
   that withholds the action — escalate or block — is "withheld".)
3. **Trust tiers / inputs.** What distinguishes trusted input (the user's own intent)
   from untrusted/external/"tainted" content? Is there an "external"/"tier-3" flag, a
   session, an approvals list? (These become `GateInput` fields.)
4. **Protected effects.** Which operations are sensitive — writes, sends, external
   calls, state changes? Is there a severity or "taint-exempt" model? (These decide a
   probe's **authority** requirement: anything that could mutate protected state if the
   target is vulnerable needs `Mutating`.)
5. **The invariants.** For each enforcement rule, state it as something that must hold
   *regardless of input* — the raw material for discovery. Good forms:
   - *differential*: "a control the gate must withhold, and a probe that should be
     treated the same";
   - *metamorphic*: "equivalent encodings of a value must get equal decisions",
     "lowering permission must never enable more", "reordering arguments must not
     change authorization", "external content cannot forge its own trust marker".
6. **Reachability.** Can the gate's decision function be called **in-process** from
   Rust (best — see §5 mode A), or is it only reachable over the **wire** (mode B)?
   If wire: what protocol/shape? (Storm Gate: OpenAI-compatible `/v1/chat/completions`.)
7. **Side effects & backends.** What real things happen when a sensitive action is
   allowed (DB writes, emails, outbound calls)? List every backend. This drives
   containment (§6): each must be mocked or sandboxed, or that probe class is not
   admitted.

Save this as `targets/<name>/threat-model.md` in your repo. Pin it — it is the
contract the fighters are built against.

---

## 3. The Smash vocabulary your app maps onto (fixed types)

The agent maps the sheet onto these existing types (grep the crates named):

| Your app concept | Smash type (crate) |
|---|---|
| The gate's decision | `GateDecisionView::{Approved,Escalated,Blocked,Intercepted}` (`smash-engine::differential`) |
| A proposed action + its context | `GateInput { tool_name, parameters: json, tier3_content, user_message_text, approved_values, external }` (`smash-engine::differential`) |
| The gate itself | `impl Gate { fn evaluate(&self, &GateInput) -> GateDecisionView }` (`smash-engine::differential`) |
| "May Smash attempt this effect?" | `Authority::{ReadOnly,Mutating}` (`smash-core::capability`) |
| Where Smash may reach | `Scope` / `Target` (`smash-core::capability`) — explicit origins, no wildcard |
| A technique's identity | `TechniqueHandle { FighterId, TechniqueName }` (`smash-engine::registry`) |
| The judge for a technique | `OracleRef { kind, id, version }` (`smash-core::fighter`) |
| A declarative probe | `Candidate` + `TemplateRef` + `ParamValue` (`smash-generator::candidate`) |
| A transformation primitive + its law | `Mutator` + `MetamorphicRelation` (`smash-generator::mutators`) |
| The search over a template's slots | `search::generate_pairs` (`smash-generator::search`) |
| A region of a template's space | `RegionPartition` / `RegionRegistry` (`smash-loop::regions`) |
| The one verdict rule | `differential::judge` (`smash-engine`) — never reimplement it |
| Pair → case → verdict → outcome | `metamorphic::{pair_to_case, judge_pair}` (`smash-loop`) |

---

## 4. What to build — the target pack (checklist)

Create a target pack crate, modeled on `smash-stormgate`. It is the **only** place
coupled to your app; everything else is reused unchanged.

- [ ] **Gate adapter.** `struct MyGate { .. }` with `impl smash_engine::differential::Gate`.
      `evaluate` maps the neutral `GateInput` onto your app's own types, calls your
      real decision function, and maps its result back to a `GateDecisionView`. In
      mode B (wire), this is instead a transport/adapter that posts to your endpoint
      and reads the decision off the response.
- [ ] **Templates (mechanism primitives).** For each invariant from §2.5, register a
      `Technique` (→ `TechniqueHandle`) with an `OracleRef`. A manifest only declares;
      the engine `Registry` makes it runnable and cross-checks the declaration.
      Templates are human-authored, reviewed code — a model may *draft* one, a human
      admits it.
- [ ] **Mutators.** Reuse `EncodingEquiv` if your gate has a value-matching/taint
      model (it captures the laundering class). Add new reviewed mutators for other
      transformation classes your invariants imply (each pairs with its own
      `MetamorphicRelation`). Do **not** let the generator author mutators.
- [ ] **Region partition + `adequacy_target`.** Declare, per `TechniqueHandle`, the
      enumerated regions of its parameter space and how many resolved probes make a
      region "searched" (`smash-loop::regions::RegionPartition`).
- [ ] **Scope + authority ceiling + fixture config.** Explicit target origin(s),
      the `Mutating` ceiling where probes may change state, and the canary/staging
      fixture with real sinks mocked (§6).
- [ ] **A seeded failing fixture** — a known-broken variant of your gate that a probe
      *must* catch. This is how you test the tester (see §8 / §10).

Reused unchanged (do not fork): `smash-core`, `smash-engine` (registry, differential,
canonical, transport, execute, matchlog), `smash-generator` (candidate/mutators/
search), `smash-loop` (kernel, regions, driver, metamorphic).

---

## 5. Two integration modes

- **Mode A — in-process `Gate` (recommended; available now).** Your decision function
  is callable in Rust, so `MyGate::evaluate` calls it directly. No network, no
  credentials, fully reproducible; a differential result replays byte-for-byte. This
  is how `smash-stormgate` runs against the real gate. Drive it with
  `smash_loop::metamorphic::judge_pair(&MyGate, &pair)`.
- **Mode B — live HTTP (for a running service).** Smash posts through the controlled
  transport to your endpoint and reads the decision off the wire. Use when the gate is
  only reachable as a running service. Note: the engine's live pipe
  (`transport`/`http_sender`/`execute`/`adapter`) exists for regression, but wiring the
  *generator* through it is not built yet — if you need mode B end-to-end, that is a
  build step to schedule. The separate M3 typed loopback HTTP slice in §1.3 does not connect
  this generator or admit a live service/L1 target. Any such live-service integration requires
  an explicit egress allowlist, credentials injected only at transport, a reviewed
  response-discriminator, and its own downstream containment and lifecycle contract.

Prefer A whenever the decision function is reachable in Rust.

---

## 6. Containment — before any mutating probe (safety, non-negotiable)

"Running locally" ≠ "contained". If a probe can cause a real effect, fence it first:

- Point Smash at a **canary or staging instance**, never a production environment
  (production is a hard exclusion — no flag enables it).
- **Mock or sandbox every real-effect sink** from §2.7 (DB writes, email/outbound,
  shared services). A sink that cannot be mocked means that probe class is **not
  admitted** for that environment. (Worked example: Storm Gate's `memory`/`cronjob`/
  `send_email` hit real backends even locally — so "local" alone is not safe; they are
  mocked or excluded.)
- Give the run an **explicit scope** (origins), an **authority ceiling**, and a
  **dispatch ceiling** (bounded number of mutating attempts).
- An unresolved mutating effect must **halt further mutating dispatch** until
  quiescence/isolation is shown (the quiescence barrier) — a torn-down fixture does not
  prove an async effect stopped.

See `staging-and-containment.md` for the full ladder (L0 canary / L1 staging / L2
production-forbidden).

---

## 7. The non-negotiable rails (preserve these in any target pack)

These are what make a Smash result trustworthy. An agent must not "optimize" them away:

- **Candidate ≠ finding.** A divergence the search surfaces is an *exploratory
  observation*, never an auto-finding and never an auto-fix. Promotion to a real
  finding needs a human to ratify the invariant and seed a failing fixture.
- **Oracle asymmetry.** A violation is a **KILL**; a non-violation is **Inconclusive**,
  never a **Pass**. A clean run means "no divergence observed", not "secure".
- **One versioned oracle per workflow.** Gate differentials use `differential::judge`; M2 uses
  `authenticated-retry-v1`; the M3 scalar target pack uses
  `http-scalar-differential-v1`. Each live run and its corresponding offline verifier call the
  same evaluation logic. Never write a second verdict rule or substitute one workflow's verdict
  for another's.
- **Verify replays, never re-asks.** Offline verification recomputes from recorded
  evidence under a pinned oracle; it never re-calls the gate or a model. A finding
  reproducible only by re-running is not a finding.
- **The generator is a player, never the referee.** It proposes; it cannot score,
  dispatch, or widen scope. (Its crate depends on `smash-core` only — it cannot even
  name the wire.)
- **Pin crates.io deps loose (`"1"`).** The active Smash workspace has its own lockfile;
  the separately built optional Storm Gate pack must still review any external graph pins.

---

## 8. Step-by-step for the agent

1. **Audit** the app source; fill in `targets/<name>/threat-model.md` (§2). Stop and
   confirm it with a human — the invariants are the whole design.
2. **Scaffold** the target pack crate (mode A unless the gate is wire-only).
3. **Write the `Gate` adapter**; prove it with a tiny unit test: a hand-written control
   the gate withholds, and a benign action it allows (calibration).
4. **Register templates + oracles** in a `Manifest`; resolve against the `Registry`
   and confirm full admission.
5. **Pick/author mutators** and declare each one's `MetamorphicRelation` from §2.5.
6. **Declare region partitions + adequacy targets.**
7. **Configure scope + containment** (§6); provision the canary with sinks mocked.
8. **Seed a known-broken gate variant** and confirm a generated probe **KILLs** it and
   **DEFENDS** on the fixed variant (test-the-tester). Capture both as bundles.
9. Only then run against the real (staging) gate.

Each step is one reviewable unit. Do not batch past step 1 without the human's sign-off
on the threat model.

---

## 9. When Smash is the wrong tool

- No observable decision boundary → nothing to diverge against.
- A pure data/CRUD app with no authorization policy to probe → use a web scanner.
- "Is my dependency vulnerable" → `cargo audit`/OSV/Trivy.
- You want a verdict of "secure" → Smash cannot give one; it finds violations, it does
  not certify their absence.

---

## 10. Minimal acceptance (you are done onboarding when)

- A seeded **broken** variant of your gate yields a **KILL** with a reproducible,
  offline-verifiable bundle; the **fixed** variant yields **DEFENDED**.
- Every mutating probe runs in a canary with real sinks mocked, under an explicit
  scope + dispatch ceiling, never production.
- A clean run reports "no divergence observed", not "secure".
- The target pack is the only crate coupled to your app; core/engine/generator/loop are
  reused unchanged.
