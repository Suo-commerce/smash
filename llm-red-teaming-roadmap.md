# Smash — LLM-directed red-teaming implementation roadmap

Status: M1 recon, the narrow M2 authenticated-retry reproduction slice, the narrow M3 typed loopback HTTP/API slice, bounded M4 read-only HTTP investigation with optional no-progress stopping, and the narrow M5 revoked-invite Linux fixture slice implemented; generalized live-service execution and broad autonomy are not implemented. Handoff updated 2026-11-07.
Purpose: align the repository with the actual product brief and distinguish tested behavior from the proposed interfaces below. **Do not repeat M1, the completed M2 slice, the delivered M3 slice, the bounded M4 slice, or the narrow M5 fixture slice merely because Sections 6 and 9 retain their milestone specifications; use the current-position note and its implementation limits.**

## 1. Product goal

Smash should be a local-first, LLM-directed red-teaming system for repositories, endpoints, and products that the operator owns or is explicitly authorized to test.

The LLM performs reconnaissance, forms vulnerability hypotheses, proposes experiments, and adapts its strategy from observations. Smash supplies the target-specific tools, constrains effects, executes admitted experiments, preserves evidence, evaluates reproducible oracles, and manages findings.

Storm Gate is one target pack and the authority-clamp differential is one technique. Neither defines the product boundary.

The desired output is not an entertaining attack transcript. It is a durable result:

- target and version tested;
- vulnerability hypothesis and affected component;
- exact experiment and reproduction artifacts;
- observations, controls, limitations, and confidence;
- independently checkable evidence where the oracle supports it;
- remediation guidance and a regression test when a finding is confirmed.

A clean or exhausted campaign must report only the searched coverage. It must never claim that the target is secure.

## 2. Product principles

1. **The model can hunt; it cannot grant itself authority.** Model output is untrusted input to admission, never an authorization decision.
2. **Research access is not execution access.** The model may inspect untrusted source and target output without receiving unrestricted shell, filesystem, network, credentials, or product access.
3. **Hypotheses are not findings.** A plausible explanation or suspicious response remains unconfirmed until a suitable experiment establishes the claimed result.
4. **No single universal verdict rule.** Different bug classes need different versioned oracles: tests, sanitizers, state comparisons, differential behavior, backend receipts, workflow assertions, or reviewer-only status when no automatic oracle exists.
5. **New mechanisms need an extension path.** A fixed template registry supports safe replay, but the model must also be able to propose new experiments and adapter capabilities. Novel executable behavior requires explicit admission and an appropriately isolated runner.
6. **Every effect is bounded.** Targets, operations, environments, credentials, requests, wall time, output size, cost, concurrency, and retries are constrained independently of the model.
7. **Replay is separate from rediscovery.** Verification consumes recorded artifacts and pinned evaluators without calling the model or target. Rerunning creates a new execution with fresh authorization.
8. **Build vertically.** Each milestone must produce a working, tested user path rather than a collection of disconnected abstractions.

## 3. What to retain and what to change

### Retain

- `smash-core` as the small domain and authorization keystone.
- `smash-engine` as the controlled execution boundary.
- The inert-candidate, admission, deduplication, and budget concepts.
- `smash-loop` for bounded iterative execution and typed campaign state.
- `smash-findings` for lifecycle, triage, coverage, and regression management.
- The differential/metamorphic engine for bug classes where it is appropriate.
- `smash-stormgate` as an optional target pack and regression fixture.
- `smash-capstone` for end-to-end known-broken/known-good validation.

### Change

- Replace the Storm-Gate-only product framing with generic target and experiment contracts.
- Add an explicitly untrusted research channel. Source files, target bodies, browser text, logs, and model output may be shown to the model as **data**, but can never directly authorize operations.
- Extend the current fixed-template candidate model with model-originated experiment drafts. Keep existing deterministic candidates as a subset, not as the only possible discovery mechanism.
- Generalize evidence from gateway decisions to multiple oracle and reproduction formats.
- Replace the assumption that the decider never sees raw target content. The new boundary is not content blindness; it is that content has no authority.
- Add a real user-facing CLI and model-driver boundary.

Do not rewrite the working differential implementation to accomplish this. Generalize around it and migrate only where reuse is cleaner than maintaining a bridge.

## 4. Target architecture

### 4.1 Trust domains

**Untrusted research domain**

- LLM provider and model responses.
- Repository contents, dependencies, generated files, and comments.
- Target responses, logs, browser content, and external reference material.
- Prior unverified hypotheses generated by the model.

These inputs may be read, summarized, chunked, and fed back to the model with provenance and explicit untrusted-data labels. They do not receive execution authority.

**Trusted control domain**

- Target manifests and per-run policy.
- Admission and capability checks.
- Target adapter registry.
- Sandbox/process/network execution.
- Budget, cancellation, and cleanup.
- Evidence recording and integrity manifests.
- Versioned oracle evaluation.
- Finding lifecycle transitions.

A model requests an operation through a typed proposal. Only the control domain can convert it into an authorized execution.

### 4.2 Main data flow

`target manifest -> recon artifacts -> model hypothesis -> experiment draft -> admission -> authorized action -> contained execution -> observations + raw evidence -> oracle -> verdict/hypothesis -> campaign feedback -> finding lifecycle`

Every transition must be recorded. A malformed proposal, denied operation, broken control, lost evidence, or exhausted budget remains a visible typed outcome rather than disappearing or becoming a pass.

### 4.3 Common contracts

Introduce target-neutral versions of these concepts before adding more target-specific features:

- `TargetManifest`: stable target ID, kind, root/origin, environment, allowed operations, available adapters, and evidence requirements.
- `RunPolicy`: immutable target scope, authority ceiling, environment, resource and model budgets, approval policy, and credential references.
- `ExperimentDraft`: model/human provenance, hypothesis, operations, expected invariant, oracle binding, resource request, and cleanup requirements.
- `AdmittedExperiment`: validated and normalized experiment bound to the exact target and run policy.
- `Observation`: typed result plus opaque evidence references; distinguish target claims from executor-observed facts.
- `EvidenceArtifact`: content digest, media type, provenance, timestamps, target/build identity, and retention information.
- `Evaluation`: oracle ID/version, result, limitations, and required/available evidence.
- `Finding`: hypothesis, affected component, reproduction, evaluation history, confidence, lifecycle state, and remediation/regression references.

Keep raw request/source artifacts outside default model feedback. Expose bounded excerpts or derived observations as needed, with digests linking them to the complete evidence.

### 4.4 Target adapter contract

All target adapters share lifecycle concepts, but not identical operations:

- inspect/preflight;
- enumerate bounded recon capabilities;
- validate experiment compatibility;
- execute only admitted operations;
- collect observations and required controls;
- finalize evidence and clean up resources;
- optionally provide an offline evaluator.

Initial adapter families:

| Adapter | Model capabilities | Typical evidence |
| --- | --- | --- |
| Repository | bounded file/tree reading, search, source excerpts, test/build proposals | source spans, patches, test output, compiler/sanitizer results, minimized repro |
| HTTP/API | approved method/route/request templates, controls, correlation IDs | requests/responses, status/timing classes, backend state/receipts, auth context |
| Product workflow | approved UI/CLI actions and assertions | workflow trace, state snapshots, screenshots/events, before/after assertions |
| In-process/differential | typed calls and metamorphic pairs | existing decision traces, paired cases, deterministic replay |

Storm Gate becomes an in-process/HTTP target pack implementing this contract.

### 4.5 Evidence states

Use explicit states and keep their definitions stable:

- **Hypothesis:** model or human suspicion; no confirming experiment required yet.
- **Observed:** an anomalous result was recorded, but controls or reproduction are insufficient.
- **Reproduced:** the same target behavior was established by a fresh run with adequate controls.
- **Verified:** the recorded evidence satisfies a versioned verifier and establishes the scoped conclusion.
- **Ratified:** a human accepts it as a finding suitable for regression tracking.

Offline bundle integrity and target vulnerability are separate statuses. A valid bundle can contain a failure, an inconclusive run, or an unverified hypothesis.

## 5. Crate direction

- `smash-core`: target-neutral manifests, policies, actions, experiment identity, and authorization vocabulary. Keep it dependency-free.
- `smash-engine`: generic adapter registry, execution orchestration, sandbox/provider interfaces, controlled HTTP, evidence capture, and legacy differential bridge.
- `smash-agent`: new untrusted planner boundary, structured model output validation, scripted-driver replay, and optional model-provider clients. It must not own target credentials or dispatch implementations.
- `smash-generator`: retain deterministic mutation/search. Model-generated candidates enter the same admission concepts without forcing this dependency-free crate to know about an LLM.
- `smash-loop`: resumable campaign state, adaptive next-step selection, hard budgets, link between proposals and attempts, and effective stop controls.
- `smash-findings`: generalized evidence bindings, reproduction history, lifecycle, triage, deduplication, and regression exports.
- `smash-cli`: new application crate with target, campaign, verification, rerun, and findings commands.
- `smash-stormgate`: optional example target pack, not a workspace-wide product assumption.
- `smash-capstone`: cross-adapter acceptance fixtures and end-to-end campaign tests.

Avoid placing provider SDKs or target-specific dependencies in `smash-core`.

## 6. Milestones

### Current implementation position — 2026-11-07

**M1 recon remains supported and read-only.** `smash recon` runs a versioned scripted planner
against a repository, and `smash verify --bundle DIRECTORY` checks its canonical proposal/
observation chain, evidence references, source-derived artifacts, report binding, and digests
without the repository or a model. The capstone surfaces the seeded source hypothesis and location,
treats malicious source comments as inert evidence, prevents excluded secret-path content from
entering the bundle, and rejects report tampering after the original source is deleted.

M1 deliberately does **not** execute builds, tests, arbitrary commands, HTTP requests, generated
code, or source-file instructions. `ExperimentDraft` is a bounded research proposal;
`HypothesisDraft` and source evaluations are not behavioral `Candidate` admission or dynamically
verified vulnerability findings. Secret exclusion is path/name/extension based rather than content
scanning. Wall-clock enforcement is cooperative between blocking operations; the fixed Git status
command additionally has a timeout and descendant cleanup.

**The M2 vertical slice in Section 9 is now implemented, but it is deliberately much narrower than
the general repository-execution milestone in Section 6.** The CLI exposes an opt-in reproduced
regression pair only for the reviewed `authenticated-retry` fixture. An exact four-field JSON
artifact selects `retry_after_authenticated_refresh` and expects `current-session`; it is data, not
Python or shell source. Both control roots must contain the engine's byte-pinned
`target-authenticated-repro.py` driver. Their bounded, symlink-free source snapshots and the exact
artifact are rehashed around admission and execution. The only operation accepts the one typed
entrypoint; arbitrary model/source-supplied programs, commands, URLs, paths, verdicts, command
lines, and artifact-selected drivers are not executable. The policy booleans are operator
attestations, not independently obtained proof of legal authorization.

The real provider requires unprivileged Linux on `x86_64` or `aarch64`, `/usr/bin/python3`, usable
Landlock and seccomp, a private `/tmp/opencode`, and the supported host runtime. It uses fixed argv,
an isolated/minimal environment, read-only admitted source plus `/usr`, `/lib`, and `/lib64`, a
separate private writable output, Landlock filesystem rules, seccomp network-syscall denial,
`no_new_privs`, resource limits, a dedicated process group, bounded collection, and descendant
cleanup. It has no containment fallback. Missing support, setup failure, cleanup failure, uncertain
termination, changed source, or excessive output stays non-green. The identity is
`landlock-seccomp-v1:<architecture>:<SHA-256 of linux_sandbox.py>`; it does **not** fingerprint the
kernel, Python binary, libraries, hardware, or a production deployment. The distinct unsafe-
development fixture mode is visibly `contained: false`, cannot stand in for a failed real provider,
and cannot produce a reproduced result.

The same artifact runs separately against supplied broken and fixed roots. Only the recorded
`prior-session` mismatch on broken together with `current-session` on fixed, all required declared
outputs, bounded observations, exact identities, successful cleanup, and complete receipt/
checkpoint chains yields `Reproduced`. This means **one observed scoped policy violation in these
synthetic controls**. It does not mean secure, exploitable, safe, production-ready, or covered for
other attack classes. Invalid, inverted, incomplete, timed-out, unresolved, and infrastructure-
failed runs remain evidence of a non-green outcome, not a security pass. The M2 CLI uses `0` for a
reproduced pair and `1` for a valid but non-reproduced/non-green assessment; `2` covers denials and
operational/argument failures. This route-specific contract does not implement the proposed general
CI exit contract in `smash-specification.md` Section 10.

`repro` appends and `sync_data`s a private pending directory's `journal.jsonl` at every checkpoint,
then verifies/stages a completed bundle before atomically renaming it to the requested destination.
An observer failure prevents successful completion. Existing destinations are never overwritten.
The completed bundle contains exact source and artifact snapshots, policy/identity bindings,
receipts, checkpoints, bounded output, controls, limitations, and the live journal.
`repro-verify --bundle DIRECTORY` reads only that bundle and recomputes `authenticated-retry-v1`;
it does not execute, access the model, consult a target, or open original repositories. M1 `verify`
and M2 `repro-verify` intentionally address different formats. Digests establish self-consistency,
not collection truth, independent provenance, signatures, or a trust root.

`repro-resume --policy FILE --bundle DIRECTORY` compares current source/artifact/policy identities
with an already verified bundle and reports `CompletedWithoutReplay` without executing an exact
reproduced pair. Mismatches, unresolved effects, pending journals, and incomplete records are
refusal/non-green paths. Unlike `repro-verify`, CLI resume requires the current producer paths so
that it can hash them. `repro-rerun` deliberately obtains fresh execution with a new run ID; it does
not reuse persistence as authorization. Synced checkpoints and atomic reveal are best effort, not
crash-durable completion after arbitrary process/host failure, and partial pending work is not an
automatic recovery workflow.

The committed fixture and CLI invocations are documented in `target-onboarding.md` Section 1.2.
The M2 capstones cover paired controls, offline verification, completed no-replay resume,
fresh rerun identity, inverted controls, invalid artifact/policy denial, pending/journal refusal,
and tampering. Focused tests additionally exercise network/filesystem restrictions, source write
refusal, output/process/memory/file/time ceilings, cancellation/descendant cleanup, cleanup-failure
non-green/unresolved behavior, and restoration. Tests validate selected mechanisms; they are not a
sandbox escape audit, exhaustive syscall analysis, fuzzing campaign, hardware matrix, performance
benchmark, build-system executor, or security certification. These broader guarantees remain
future review work.

### Implemented M3 slice: typed loopback HTTP/API controls (2026-11-06)

`smash-engine::http` now has a separate versioned target/campaign contract and a controlled `ureq`
client. It admits only disposable-fixture declarations, exact loopback addresses and route
schemas, GET/POST flat string fields, fixed headers, environment credential references, bounded
calls/mutations/bytes/time, and exact Boolean/nonnegative-integer response schemas. The actual
connection resolver filters admitted destinations. TLS verification remains enabled; redirects,
idle connection reuse, ambient proxies, arbitrary paths/headers/bodies, and raw response extraction
are not admitted. Non-observations are typed rather than converted to a successful check.

`http-discover` performs only statically planned read-only calls and persists their observations.
`http-repro --execute-fixture-mutations` admits exactly one mutation with before/mutation/after and
unknown-identity correlation. The separate `http-scalar-differential-v1` oracle compares paired
controls and requires fixed before `0`, after `1`, unknown `0`, all fixed expectations, complete
observations, and both actual teardown attestations. The generic CLI does not own external fixture
teardown and therefore never fabricates a positive reproduced result. An owning provider must call
`execute_campaign` with a callback that actually drops and joins the fixtures, as the capstone
provider does; differing responses or an unavailable receipt alone do not establish the mutation.

Bounded duplicate-free JSON stores policy, correlations, lifecycle/disposition, scalar fields,
status/content-type, body digest/length, and controls—not response text or credentials.
`http-verify` reads only the exact bundle/policy copy and recomputes the same assessment offline.
Digests are not signatures or independent collection provenance. Valid inconclusive or
control-invalid evidence remains non-green. `http-discover` success denotes complete declared
scalar reads, not a discovered vulnerability. Loopback admission is not a process/network sandbox
or proof of downstream containment; this is not an L1 staging or arbitrary real-service adapter.

M3 capstones exercise an in-process loopback fixture whose broken commit records two effects and
fixed commit records one. They cover the differential pair, idempotent retry, authenticated
receipts, unknown identity, dropped/joined fixture cleanup, credential exclusion, malformed effect
contracts, CLI read-only and mutation refusals, valid/tampered offline bundles, and verification
after fixture shutdown. Route discovery, unrestricted planner-authored HTTP, live staging,
production execution, and general security assurance remain out of scope. See
`target-onboarding.md` §1.3 for commands and `staging-and-containment.md` §4.2 for the lifecycle
boundary.

### Implemented M4 slice: bounded scripted read-only HTTP investigations

`smash-agent::investigation` defines a separate strict protocol rather than widening M1's planner.
`HttpInvestigationPolicy` wraps a read-only M3 catalog with fixed admitted item/call pairs, pending
queue items, and max 32 calls plus one final planner turn. Each at-most-64-KiB scripted response
selects only a queue item and catalog index or completes; its bounded thought preserves complete
hypothesis/queue histories, validated transitions/evidence, and declared input/output usage.
Supported/refuted conclusions and completed items require known observed evidence. Invalid or
unadmitted responses fail closed with no same-response retry. Non-observations are not evidence of
absence, a vulnerability, or completed work.

`smash-engine::http::investigation` verifies raw bytes/digest/decision agreement before dispatching
one selected M3 read. Planner text never supplies destinations, headers, arguments, credentials,
methods, mutations, or effect seeds. A private pending session journals exact raw responses and
state transitions before atomic publication. Resume checks policy identity and exact response
prefix, refuses to repeat a persisted selected read whose observation is missing, and does not
replay terminal runs. `http-investigate`, `http-investigate-resume`, and
`http-investigate-verify` expose this distinct flow. Offline verification uses only the session,
inert decoder, and read-attempt checks—never target, credentials, resolver, network, or planner.
Completion and offline validity are distinct, and neither is a vulnerability verdict or signed
collection-authenticity claim.

The additive `max_consecutive_unproductive_turns` policy budget is optional and bounded to
`1..=32`; omission preserves legacy behavior. Only a newly recorded valid typed `Observed` result
or a newly validated hypothesis/queue status transition resets the counter. Changed prose, usage,
and non-observations do not. At the configured limit, replay-compatible journal/state persistence
records the distinct non-complete `no_progress` terminal before another planner turn or HTTP read.
Resume preserves the streak and rejects a changed limit. Run and verification reports expose the
counter, while existing call/planner budgets, successful completion, and planner rejection remain
distinct outcomes. Offline verification derives the same counter without a target or planner.

`http-investigate` and `http-investigate-resume` additionally accept an optional
`--recon-bundle DIRECTORY`. Before loading the planner script or dispatching any read, the CLI runs
full M1 verification and constructs the seed from the exact admitted bundle. Bounded source
hypothesis/evidence metadata and existing queue links are copied into the effective policy; source
hypotheses start M4 `Open` with no observations and require same-item HTTP evidence before support,
refutation, or completion. The existing M3 catalog and queue remain the only read authority: source
URLs, routes, commands, credentials, raw excerpts, locators, and other repository instructions never
become executable HTTP inputs. The complete frozen seed is also bound into reconstructed-state
identity by SHA-256, preventing provenance-only edits from surviving replay. CLI resume reopens and
verifies the source bundle; offline session verification needs only the frozen session and continues
to work after repository deletion and fixture shutdown.

M4 capstones cover adaptive multi-read completion, malformed selection, call budgets, observed
evidence, exact-prefix resume, unresolved-dispatch refusal, completed no-replay, and offline/tamper
checks after fixture shutdown. Focused policy/session tests and capstones additionally cover legacy
omission, bounded-limit validation, consecutive non-observations, unchanged histories despite prose
and usage changes, real-observation and both status-transition resets, resumed streaks, changed-limit
refusal, counter tampering, and distinct no-progress versus completed outcomes. The bridge capstones additionally cover repository-to-HTTP execution,
source-instruction non-execution, exact-source resume, omitted/mismatched bundle refusal, invalid
links, pre-dispatch source tampering, source-only completion rejection, oversized seeds, and
provenance-only tampering. This is not broad M4 autonomy: hosted-model providers, interleaved
repository/HTTP planning, model-proposed mechanisms, novelty/dedup, cost accounting, a hard wall
clock, concurrency, kill switches, live staging, and production execution remain unimplemented. See
`target-onboarding.md` §1.4.

### Delivered M5 slice: revoked synthetic invite

The implemented scope is one physical fixture workflow and its offline verifier, not generalized
M5 service execution. The fixture driver is `smash-capstone/fixtures/revoked_invite.py`, pinned by
SHA-256 `de6054ffb6abc4e93e56482c16a90e1ee611173ac1d62900e9a04d2398ff24a8`.

- `smash workflow-repro --execute-fixture-workflow` runs the broken, fixed, and functional-control
  arms. Each receives a fresh synthetic guest, invitation, namespace, and execution ID. Every arm
  invites the guest, begins deferred acceptance against the original pending authorization,
  optionally revokes, then completes acceptance. The broken arm retains authorization and
  re-executes project entry; the fixed arm atomically denies; the control omits revocation and
  accepts normally. The CLI also requires the synthetic-subjects confirmation.
- Linux execution uses a separate `/usr/bin/python3` process per step with cleared inherited
  environment, sanitized `PATH`/`HOME`/`TMPDIR`, nonzero inherited-UID rejection, configured
  rlimits, an isolated mount/private temporary tree, pinned Python/driver digests, Landlock
  least-privilege access, and no-new-privileges seccomp. Process count is one: fork, clone, and
  subsequent exec fail closed. Step timing is wall-clock bounded. Live execution uses synthetic
  `/tmp/opencode` identities and the private smoke gateway, not production authority.
- Every event is schema-, identity-, linkage-, sequence-, oracle-, honest-effect-, and
  action-transition-checked before append and fsync. Hash-chain, execution, or invalid-evidence
  failure is `EvidenceError`/`ManualReview`, not `NoEffect`. Broken/control denial and fixed
  acceptance are well-formed negative results; only `assess` compares the three arms. `Confirmed`
  exits 0, well-formed `NoEffect` exits 1, and validation, interruption, containment, review, or
  publication failure exits 2.
- Staging uses private `NOREPLACE` directories. Publication verifies once internally, then performs
  one atomic `NOREPLACE` directory rename. Parent-sync failure after that rename is reported but
  cannot erase committed evidence. Restart is never resumption of fixture authority: an interrupted
  invocation is permanently abandoned or retained for review, and any retry is wholly fresh.
- Cleanup first claims the reviewed root into a retained private namespace and closes the reviewed
  descriptor before bounded descriptor-relative deletion. Every post-claim failure attempts
  same-directory restoration; replacement or identity conflict quarantines rather than deletes the
  disputed inode. Restoration retry/failure is visible through `CleanupRestoration`. Cleanup depth
  is 32 and every visible entry charges one shared 4096-entry budget across all directories;
  overflow retains evidence and unsets pre-start target paths.
- `smash workflow-verify --bundle DIRECTORY` reopens records and recomputes chain records, binding
  identity, fixture provenance, signed request inputs, and recorded digests. It performs no HTTP,
  subprocess, socket, credential, or environment-dependent fixture execution. Verification uses the
  same sequential schema gate and differential assessment; malformed or missing evidence cannot
  become `NoEffect`.

Validation on 2026-11-06: offline
`cargo clippy --workspace --all-targets --locked --offline -- -D warnings`,
`cargo test --workspace --all-targets --locked --offline` (including 164 engine tests),
and six physical capstone tests covering confirmed reproduction, interruption, stale evidence,
differential `NoEffect`, offline tamper rejection, and cleanup/restoration races; strict checks and
real-signal/TUI/listener integration passed. Explicit per-file format checks passed. An independent
read-only audit of implementation, tests, and plan returned `VERDICT: APPROVED`. Remaining limits
are the single provisioned fixture, Linux-only execution, no automatic resumption, no broad
workflow/service broadening, and no claim of real external-service coverage.

**The external target-pack dependency is decoupled; dependency sign-off remains separate.**
`smash-stormgate` is an excluded optional target pack, not an active workspace member, and the
regenerated workspace lockfile contains no `realfield-core` package. No source or lockfile in the
separate Stormlock checkout changed. `ring 0.17.7` remains in the reduced active graph through
`ureq`'s `rustls`/`rustls-webpki` TLS dependencies; this is not the removed Realfield edge, an
upgrade, or a vulnerability/advisory sign-off. Review or upgrade that normal TLS graph separately
without silently converting successful resolution into M0 approval. Fresh final verification must
also be reported separately from this implementation claim.

**Proposed interfaces are not live adapters.** The target-neutral manifest/adapter registry,
declarative `Candidate` pipeline, compiler/sanitizer/minimized-differential oracles, arbitrary
untrusted build/test handling, generic signing/trust roots, fully resumable interrupted campaigns,
generalized HTTP/API service execution, staging support, and iterative autonomy remain designs.
The delivered M3 slice is the explicit exception described above, not a target-discovery generator
or live-service adapter. Do not expose any proposed path by reusing M1's `read_only_command`, adding
a shell escape, generalizing the M2 artifact or M3 campaign parsers without a new contract, or
placing an unsafe runner behind a reassuring policy label.

### M0 — Establish a trustworthy baseline

Required before enabling generalized live target execution:

- Restore a Rust toolchain and freshly rebuild the complete available workspace; do not rely on existing binaries.
- Turn the audit findings into regression tests, prioritizing final-URL egress validation, authority derived from trusted registrations, strict response classification, HTTP deadlines, and resource bounds.
- Make bundle cardinality, candidate identity, outcome/fidelity binding, verdict coverage, and lifecycle evidence checks fail closed.
- Fix non-atomic persistence, run-ID collisions, ineffective stop controls, and UTF-8/recursive input crashes relevant to shared infrastructure.
- Upgrade `ring` to a non-vulnerable compatible release.
- Preserve evidence limitations in reports; existing green unit tests are not a security acceptance test.

**Exit:** fresh tests and Clippy pass, adversarial regressions fail on the old behavior and pass on the fix, and incomplete evidence cannot produce green output.

### M1 — Read-only repository reconnaissance vertical slice

Deliver the first real user-facing path without dynamic target execution:

- Add `smash-cli` and `smash-agent`.
- Add versioned repository target manifest and bounded repository inspection adapter.
- Normalize paths beneath the configured root; handle symlinks, binary/oversized files, output caps, excluded secrets, and unreadable entries explicitly.
- Define structured planner requests/responses containing target inventory, bounded source excerpts, hypotheses, and next-experiment drafts.
- Implement a scripted planner first, with recorded JSON fixtures for deterministic tests and replay. Add an OpenAI-compatible provider behind the same boundary if configuration is available, but do not make tests depend on a hosted model.
- Record model/provider/version, prompt/template version, source digests, proposals, refusals, and token/time/cost counters when available. Secrets come from environment/credential references and never enter evidence.
- Produce a report and evidence bundle. Findings at this stage are hypotheses or source-observed candidates, not dynamically verified vulnerabilities.

**Exit:** against a seeded vulnerable repository fixture, a scripted campaign identifies the expected hypothesis and source location; malicious source comments cannot trigger an operation; offline verification works without the model or repository being available.

### M2 — Contained repository experimentation

Turn hypotheses into reproducible findings:

- Add an experiment runner contract and a default-deny local runner policy.
- Provide a genuinely isolated Linux sandbox provider for untrusted builds/tests: read-only source where practical, separate writable output, no target network by default, resource/PID/file/wall-time limits, and cleanup.
- Support an explicit unsafe-development runner only for fixtures/tests, visibly marked as not containment.
- Permit model-proposed test or repro artifacts only through sandbox admission; never eval model text in the control process.
- Add oracle kinds for failing/passing regression tests, compiler/sanitizer signals, invariant assertions, and minimized differentials.
- Add controls: the repro fails on the seeded broken fixture and does not fail on the fixed fixture.
- Preserve unresolved outcomes after timeout/cancellation and prevent automatic blind retries.

**Exit:** a model/script-generated repro on a known-broken repository is reproducible, offline-checkable where possible, bounded by resource limits, and reported correctly on both broken and fixed variants. Campaigns are resumable and reject reruns with mismatched policy.

### M3 — Generic HTTP/API target pack

**Narrow delivered exception:** the executed typed loopback fixture workflow described in the
current-position note is available through `http-discover`, `http-repro`, and `http-verify`. The
remaining generic service, target-discovery, and L1 goals below are still proposed; a valid
attested campaign can be inconclusive when teardown is unavailable to the generic CLI.

- Extend target manifests with route/method/header/body schemas, authority requirements, credential references, response and request budgets, controls, and backend observation capabilities.
- Use one controlled client with final-URL validation, redirect policy, explicit proxy behavior, TLS verification, DNS/connection binding where required, and full deadlines.
- Inject credentials at execution; keep them out of planner prompts, request templates, and ordinary evidence.
- Implement typed response handling and explicit `Malformed`, `Unhandled`, `Denied`, `Timeout`, and `Observed` outcomes.
- Build a disposable known-vulnerable HTTP fixture with mocked real-effect sinks and state/receipt observation.
- Support read-only recon first, then authenticated differential and mutating tests only when fixture containment is proven.

**Exit:** a seeded endpoint flaw is discovered by the campaign, captured with correlated evidence, reproduced, and absent on the fixed fixture. Off-scope/userinfo/redirect/DNS attempts and hanging peers cannot bypass policy or stall the campaign.

### M4 — Iterative autonomous campaigns

**Narrow delivered exception:** the bounded scripted HTTP investigation described in the
current-position note is available through `http-investigate`, `http-investigate-resume`, and
`http-investigate-verify`. It supports adaptive selection only inside one fixed read-only M3
catalog, with optional bounded stopping after consecutive turns lacking a valid observation or
status transition. Start and resume can import provenance from one fully verified M1 bundle with
`--recon-bundle`; source-derived hypotheses still require same-item HTTP evidence, and the import
adds no execution authority. Broader interleaved repository/HTTP campaigns, new-mechanism,
scheduling, and live-target goals below remain proposed.

- Connect repository and HTTP observations to multi-step model planning rather than one-shot reports.
- Add hypothesis status, investigation queue, novelty/dedup, coverage dimensions, and typed next-action selection.
- Enforce hard model/token/cost/time/experiment ceilings, concurrency limits, checkpoint/resume, kill switch, and no-progress stop behavior.
- Let the model propose new mechanisms, but keep unsupported operations unexecutable until an adapter/oracle contract admits them.
- Keep deterministic generator plugins available for broad parameter search after the model identifies a promising mechanism.

**Exit:** a campaign can investigate a lead over several steps, abandon a false lead, survive malformed model output, resume after interruption, and stop within budget without silently converting incomplete work into success.

### M5 — Product-workflow adapters

- Add workflow steps, assertions, state snapshots, synthetic identities/data, event collection, and cleanup.
- Begin with deterministic CLI workflows; add browser/mobile/desktop drivers only behind target packs with testable oracles.
- Capture authorization boundaries, asynchronous completion, before/after state, and environment fidelity.
- Seed broken and fixed product workflows as capstones.

**Exit:** at least one product-level authorization or workflow flaw is found and reproduced through a repeatable scenario, with incomplete UI observation reported as inconclusive.

**Narrow delivered first slice (2026-11-06):** `m5-workflow-plan.md` scoped one contained
external-CLI revoked-invite fixture, fresh-rerun-only interruption handling, typed snapshots/events,
real Linux no-network execution, and offline verification. That slice is now implemented as
described in the current-position note; broader M4 and M5 remain deferred.

### M6 — Productization and CI

- Findings inbox, deduplication/cluster review, human ratification, suppression with reason, remediation tracking, and regression export.
- Human-readable reports plus stable machine JSON; clearly distinguish hypotheses, verified flaws, operational errors, and coverage.
- CI runs only pinned regression bundles by default; discovery campaigns remain explicitly budgeted jobs.
- Package model profiles, adapter/target pack examples, retention/redaction controls, audit logs, and update/version compatibility checks.

**Exit:** a developer can onboard a target, run an authorized campaign, inspect and verify a result, rerun a repro, and add a confirmed regression without writing Smash internals.

## 7. Cross-cutting test strategy

Every target pack requires known-broken and known-good fixtures. A probe that cannot catch the seeded break is not accepted as evidence of coverage.

Test at least:

- malformed, contradictory, enormous, and adversarial model output;
- prompt-injection text in source files, responses, logs, and screenshots;
- path traversal, symlink escape, secret leakage, and oversized repository content;
- URL userinfo, redirects, alternate authority forms, DNS changes, proxy variables, and stalled networks;
- untrusted build scripts, fork/output bombs, timeouts, cancellation, and cleanup failure;
- duplicate candidates, replayed evidence at the wrong target/run, missing controls, partial bundles, and out-of-order ledger events;
- exhausted budgets, no-progress loops, resume, and process interruption;
- offline verification with no model credentials, target process, network, or original decider.

Fuzz structured decoding and recursive input processing. Treat every crash, scope escape, phantom pass, unbounded hang, and unrecorded dispatch as a release blocker.

## 8. Risks and controls

| Risk | Required control |
| --- | --- |
| Prompt injection in source or target output | Treat all research content as data, expose only explicit tools, and require admission independently of model intent. |
| Hallucinated vulnerabilities | Hypothesis states, controls, reproduction, versioned oracles, and human ratification. |
| Damage from generated tests or probes | Default-deny execution, isolated runner/fixture, finite resources, no production inheritance, cleanup and unresolved-effect tracking. |
| Scope creep from autonomous planning | Immutable per-run target manifest and admission on every attempt. |
| Endless or costly campaigns | Hard token/cost/time/attempt/no-progress budgets and resumable checkpoints. |
| False confidence from clean results | Coverage reports with unsupported/unsearched surfaces and no general security certification. |
| Unverifiable model-dependent outcomes | Persist exact artifacts and distinguish replayable verification from fresh rediscovery. |

## 9. M2 delivered-slice specification and future extension checklist

The implementation history below records the requirements used for the **now-completed narrow M2
vertical slice** and the narrowly scoped M0 cleanup described above. Use it as a regression and
extension checklist, not as an instruction to repeat that work or widen execution implicitly.
Generalized live HTTP, arbitrary builds, and new execution/oracle families remain unimplemented.
The target is the small committed authorized repository fixture whose paired oracle needs no
network or real credentials.

1. **Recover the actual state before editing.** Read this current-position note, Section 6 M2, and
   Sections 7–8. Read `smash-core/src/research.rs`, `smash-agent/src/protocol.rs`,
   `smash-engine/src/recon/{campaign,repository,bundle}.rs`, the M1 CLI and recon capstone,
   `smash-specification.md`, `target-onboarding.md`, `generator-boundary.md`, and
   `staging-and-containment.md`. Inspect working-tree changes and preserve unrelated work; do not
   reset, clean, mass-format, or commit the existing tree.
2. **Establish a fresh source-built baseline.** Detect the Rust toolchain, use the external build
   target/cache convention already established for this machine rather than generating new project
   `target/` artifacts, and run locked workspace tests plus the recon capstone. Record unrelated
   baseline lint failures separately. Fix new compile/test breakage before relying on a partial
   success signal.
3. **Close the identified M0 debt in small, reviewable changes.** Investigate and apply a compatible
   fixed `ring` update rather than blindly upgrading the shared graph. Resolve the known old Clippy
   warnings narrowly. If a dependency or external target prevents a complete check, document the
   exact blocker and prove every available affected path; do not expand this into a rewrite.
4. **Specify M2's execution boundary before adding a runner.** Keep M1's read-only
   `ExperimentDraft` and repository inspector semantics intact. Introduce distinct untrusted
   execution-request/artifact contracts and a trusted `AdmittedExperiment` (or equivalent private
   authorization type) bound to the exact target, run, immutable policy digest, runner, entry point,
    artifact digests, resource ceiling, oracle, and cleanup requirements. Serialization, a model
    signature, or possession of a hypothesis must never confer execution authority.
5. **Define one default-deny runner lifecycle and test it with a fake first.** Cover admission,
   prepare, spawn, wait, cancellation, bounded collection, cleanup, and unresolved terminal states.
   Reject unsupported runners, unknown entry points, arbitrary shell fragments, excess authority,
   invalid or changed artifacts, moved roots, oversized requests, and mismatched oracle bindings.
   Admission occurs after all trusted checks and cannot be implemented by evaluating planner text.
6. **Implement one real Linux sandbox provider behind that contract.** After checking what is
   available on the host, choose and document the isolation mechanism rather than inventing a fake
   portability layer. The provider must establish read-only source access where practical, a
   separate writable output/build area, a minimal environment with no inherited host credentials,
   default-deny target networking, PID/process-group containment, CPU/memory/file/output/wall-time
   limits, and bounded descendant cleanup. Prepare only trusted staging paths; protect against
   symlink/root escape and output/evidence bombs. Unsupported hosts fail closed. Do not claim that a
   timeout, `git` allowlist, working-directory change, or absence of an HTTP client constitutes a
   sandbox.
7. **Add the explicit unsafe-development runner only as a visibly separate mode.** Restrict it to
   fixture/test targets, require an unmistakable policy opt-in, and label its reports and evidence
   `not_contained`. It must never be the fallback when the real provider is unavailable or be used
   to satisfy a containment assertion. Neither runner may execute arbitrary model prose in the
   control process.
8. **Implement one versioned dynamic oracle end to end before adding more.** Start with a bounded
   regression-test or invariant-assertion oracle; leave compiler/sanitizer and minimized-differential
   variants as separately admitted follow-ups unless required by the smallest capstone. Record the
   oracle/runner versions and the exact artifact/environment identity. Distinguish broken, fixed,
   malformed, denied, timed out, unresolved, and infrastructure-error outcomes. Raw build/test
   output remains bounded untrusted evidence, never admission or verdict instructions.
9. **Require both sides of the control.** The same reproduction artifact, separately admitted to
   each immutable fixture, must establish the scoped failure on the seeded broken fixture and not
   establish that failure on the fixed fixture. A
   broken control, nonzero infrastructure error, missing output, or unexpected outcome is
   inconclusive or operational failure, never a pass. A clean fixed result is scoped to this oracle
   and environment and does not certify the repository secure.
10. **Persist honest lifecycle, evidence, and resume semantics.** Record admission/denial,
    execution attempts, resource observations, cancellation, unresolved effects, artifact and
    cleanup outcomes, controls, and coverage. Checkpoint state after transitions. Resume only when
    target, immutable policy, exact artifacts, runner, and oracle versions match; refuse mismatches.
    A fresh rerun receives a new attempt/authorization identity. Never blindly retry an unknown or
    unresolved effect.
11. **Keep verification offline and execution-free.** `verify` must validate canonical schemas,
    cardinality, hashes, artifact identities, policy/oracle/runner bindings, controls, evidence
    references, cleanup/lifecycle state, and the deterministic evaluation chain without opening the
    repository, executing a repro, consulting a planner, or contacting a target. Where fresh runtime
    evidence is essential, distinguish verified evidence consistency and scope from a claim that
    offline verification has reproduced the vulnerability. A digest proves consistency, not truth at
    collection or authenticity without a trust root.
12. **Expose the narrow CLI only after the fixture is green.** Add the smallest explicit repro and
    resume/rerun path driven by versioned policy and artifact manifests. Execution must be opt-in and
    separate from M1 recon. A missing policy/provider, unsupported operation, invalid fixture, or
    incomplete coverage returns a non-green result. Keep a hosted-model provider optional and out of
    the deterministic acceptance path.
13. **Add one M2 capstone and adversarial regressions.** Use a scripted/declared repro artifact on a
    small authorized repository fixture. Prove broken/fixed behavior, offline evidence checking,
    no-network enforcement, read-only source, separate output, output/PID/memory/file/time limits,
    descendant cancellation, cleanup success and failure, unresolved outcomes, no blind retry,
    policy-mismatched resume rejection, symlink/root escape refusal, unauthorized command refusal,
    and artifact/policy/oracle tamper detection. Include model/source text that requests shell
    execution and prove that only separately admitted typed artifacts can run.
14. **Finish with documentation and fresh verification.** Update this current-position note,
    `smash-specification.md`, `target-onboarding.md`, `generator-boundary.md`, and relevant module
    docs with the implemented—not aspirational—limits. Format changed files only; run strict Clippy
    on changed targets, fresh locked full-workspace tests, the old M1 capstone, and the new M2
    capstone. Run whole-workspace Clippy after M0 cleanup where possible and report any remaining
    unrelated baseline findings honestly. Inspect the final diff for unrelated or generated files.

### M2 delivered-slice definition of done

- No arbitrary command, shell fragment, source comment, model response, or unadmitted artifact can
  reach a runner; an experiment cannot mint its own execution authority.
- The selected known-broken repository repro establishes the intended scoped result, while the
  equivalent fixed-fixture control does not; both outcomes and their coverage are reported honestly.
- The real Linux provider—not just a policy label—enforces the claimed network, filesystem,
  process, resource, timeout, and cleanup boundary. Any unsafe-development mode is unmistakably
  marked `not_contained` and is not used as its substitute.
- Timeout, cancellation, resource exhaustion, broken controls, missing evidence, and cleanup failure
  remain visible and non-green; unresolved execution is never automatically retried.
- Campaign checkpoints resume exactly or reject mismatched target/policy/artifact/runner/oracle
  identities; fresh reruns cannot borrow prior authorization or receipts.
- The evidence bundle verifies offline without the repository, target process, planner, model, or
  network, and distinguishes integrity/evaluation validity from dynamic reproduction and security.
- M1 recon, Storm Gate, and the existing differential paths remain green. The separately described
  M3 typed loopback slice does not count as generalized HTTP/L1 execution; broad iterative autonomy
  (M4) and new target families remain disabled and out of scope.

## 10. Defaults for implementation

These defaults avoid blocking the next session on product decisions; they can be revised explicitly later:

- Local-first Rust CLI; no hosted multi-tenant service.
- Scripted planner as the mandatory deterministic provider; OpenAI-compatible HTTP as the first optional external provider.
- M1's repository reconnaissance remains read-only. M2 admits only the contained typed path above;
  M3 separately admits only reviewed static campaigns on declared loopback fixture routes. M4 adds
  only scripted adaptive selection within those admitted read-only catalogs, with durable/offline
  session checks. General HTTP-service discovery/execution, unrestricted model planning, and
  browser automation remain later work.
- The default M2 runner is the real Linux sandbox. The unsafe-development runner is never an availability fallback or a containment equivalent.
- Explicit target manifests and per-run policies; no ambient authority inherited from the caller's shell beyond deliberately configured access.
- Local/disposable test environments for effect-producing tests. Any future production-read-only mode is a separately reviewed feature, not an incidental consequence of endpoint support.
- Model reasoning may guide triage, but model prose alone cannot establish a verified verdict.
- Human approval for new executable adapters and ratification into the permanent regression catalog.
