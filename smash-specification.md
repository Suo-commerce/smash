# Smash — Product & Technical Specification

Oct 22, 2026 · @Jarmo

Revision 0.3 · Proposed specification, with dated implementation annotations. Except for the annotated M1 and narrow M2, M3, and M4 workflows, requirements below describe intended behavior, not verified implementation. Storm Gate integration details inherited from the original must be confirmed against its source before implementation. Implementation annotations do not ratify the proposed MVP, generalized CLI, target adapters, signing, staging, or release acceptance criteria.

## 1. Product promise

Smash helps developers of AI tool gateways catch authorization regressions before release, using isolated test backends and evidence they can independently verify.

The first user is the developer responsible for Storm Gate’s policy enforcement. Their job is to answer: “Can this gateway perform a forbidden operation, and can I trust the test that says it cannot?”

Smash is an executor-referee: the service constructs and dispatches bounded probes, collects evidence, and evaluates outcomes. A separate decider chooses registered techniques. The decider may be a human, a script, or an AI harness; no model is needed to execute tests or establish verdicts.

### Principles

1. **Protect and teach.** Findings explain the violated policy, observed effect, limits of the evidence, and a concrete remediation and regression test.
2. **Enforce at the boundary.** Types constrain valid operations; transport controls and isolated fixtures constrain their real-world effects.
3. **Make uncertainty visible.** Missing evidence or broken fixtures cannot produce a passing security result.
4. **Make evidence portable.** Verdicts can be verified without the originating harness or a live target.
5. **Test aggressively within permission.** Constrain where Smash can act and which effects are permitted; challenge the target thoroughly inside those boundaries. Testing only harmless inputs is insufficient to establish that enforcement holds.

### Authorization, containment, and adversarial depth

These are separate design dimensions:

| Dimension | Question | Product rule |
| --- | --- | --- |
| Authorization | Whose systems may be tested, and which effects are permitted? | Explicit scope and effect permission are mandatory. |
| Containment | How do effects remain within permission when the target fails? | Enforce isolation, controlled transport, resource limits, and observable completion outside the target’s policy mechanism. |
| Adversarial depth | How thoroughly does Smash challenge the target? | Use realistic, demanding probes within the authorized boundary; do not weaken tests merely to avoid triggering the flaw being tested. |

Testing a read-only session’s write restrictions requires attempting a real write and observing whether it succeeds. The protection comes from explicit Smash Mutating authority and an isolated backend, not from making the attempted operation incapable of demonstrating the vulnerability.

**Payload policy:** probes must serve an authorized test, have bounded effects, and produce evidence useful for remediation. A probe may genuinely trigger a vulnerability inside the permitted environment. A blanket ban on “weaponized payloads” is not an actionable technical requirement and must not substitute for scope, effect classification, and containment controls.

As coverage expands, it should include malformed requests, realistic adversarial inputs, chained operations, permission transitions, and attempts to bypass target enforcement. Each addition still needs an explicit invariant, suitable controls, and an evidence contract.

## 2. Initial scope and user journey

The MVP includes one Storm Gate integration, one authority-clamp differential fighter, one ephemeral canary backend, a local CLI/CI runner, a structured report, and offline evidence verification.

The developer:

1. Configures a test deployment, explicit target origin, and Smash authority ceiling.
2. Runs a preflight that checks fixture isolation, gateway routing, and test prerequisites.
3. Runs the fighter against clean canary state.
4. Receives a verdict, evidence references, and an explanation of the policy tested.
5. Fixes any failure and runs the same technique again.
6. Adds the suite to CI; failures and incomplete required coverage block a green result.

The MVP excludes production scanning, arbitrary remote targets, untrusted third-party executable plugins, general vulnerability discovery, behavioral side-channel tests, autonomous exploit construction, and a hosted multi-tenant service.

These exclusions bound the first release, not the long-term ambition of authorized testing. A fixed technique catalog provides regression coverage; it does not establish resistance to novel attacks. Research mode and representative staging support are proposed extensions in Section 13, with additional admission requirements before either ships.

## 3. Threat model and guarantee boundaries

Treat target responses, target-supplied metadata, and all external harness requests as untrusted. A decider may select invalid handles, request excess authority, repeat calls, or attempt to exceed budgets.

The trusted computing base includes Smash’s authorization module, transport, fixture manager, response-to-signal adapters, oracle, evidence writer, approved technique implementations, and the host isolation configuration. Review and version these components explicitly.

Smash does not claim protection against a compromised host, a malicious administrator changing its binary, or malicious code already executing inside the trusted service. Rust API privacy and `unsafe` prohibitions do not provide that protection.

### Required guarantees

| Guarantee | Enforcement | Limit |
| --- | --- | --- |
| Only approved calls leave the executor | Private authorization token plus a single controlled transport | Requires all execution paths to use that transport |
| Direct connections stay within scope | Origin validation, destination binding, and egress restrictions | An origin allowlist alone does not constrain a proxy’s downstream calls |
| Tests affect only the fixture | Gateway and canary isolation with no production credentials or routes | Must be established by deployment controls, not target claims |
| Decider receives no raw adversarial text | Closed, typed output schema and separate evidence channel | Does not make the decider immune to injection from other sources |
| Incomplete tests cannot pass | Explicit inconclusive/denied/error states and coverage accounting | A pass applies only to the tested invariant and fixture |

The allowlist records where testing is permitted; it does not prove ownership or legal authorization. The operator is responsible for permission to test. The MVP runs only against the isolated test deployment.

## 4. Architecture

### Service responsibilities

The service owns authorization, request construction, transport, run budgets, fixture lifecycle, observations, oracle evaluation, and evidence. Harness adapters are thin clients and contain no verdict logic.

Suggested components:

- `smash-core`: dependency-free domain types, capabilities, manifest schemas, observations, and verdict contracts.
- `smash-engine`: approved technique registry, target adapter, transport, fixture orchestration, and execution state machine.
- `smash-oracle`: deterministic evaluation of recorded evidence; no target network access.
- `smash-cli`: configuration, execution, offline verification, live reruns, and reports.

These are logical boundaries; separate crates are useful where they enforce dependency direction, not as a goal in themselves.

### Fighter contract

A fighter exposes a manifest with a stable ID, version, technique handles, effect requirements, prerequisites, oracle identifier/version, evidence schema, and reviewed descriptions. The core `Fighter` trait may remain `manifest()` only. A versioned engine registry maps each handle to an approved implementation; a manifest alone cannot introduce executable behavior.

The decider selects registered handles and narrowly typed parameters. It cannot submit arbitrary URLs, payloads, free-form request bodies, or an authority declaration that overrides the registered technique.

### Read-only repository reconnaissance (M1)

M1 provides a separate, narrow research workflow beside the behavioral candidate pipeline. `smash recon` accepts a repository path and a versioned, one-response-per-query planner script. Its untrusted planner proposes `ExperimentDraft` values over a closed vocabulary: repository file listing, bounded manifest or source reads, working-tree status, and the single literal read-only command `git-status`. It cannot grant authority, register operations, dispatch behavioral probes, build or test the repository, make HTTP requests, or invoke a general shell. M1 does not implement a hosted-model provider.

Repository inspection uses bounded UTF-8 reads, sorted inventory, and regular-file reads with parent and leaf symlinks refused. Secret exclusion is based on path names and extensions, not content scanning or a guarantee that artifacts contain no credentials. Source text and comments remain untrusted evidence, including when embedded in a bounded `ResearchFact` delivered to this research planner; that path is outside the decider containment guarantee in Section 6.

Query, experiment, file, artifact, evidence, and **exact serialized observation** limits are enforced, with reserved space for a terminal budget refusal. Wall-time checks occur between planner and blocking repository operations, so they are cooperative rather than a hard deadline on arbitrary blocking work. The fixed Git command has a separate timeout and descendant-process cleanup. M1 is not a dynamic sandbox: `read_only_network_off` means this workflow introduces no network client or network operation, not that it creates an OS network namespace.

An M1 source fact, `HypothesisDraft`, or `EvaluationStatus::Passed` is not a behavioral `Candidate`, an oracle verdict, or proof that a vulnerability exists. A `Completed` campaign also does not prove the repository secure. Offline `smash verify --bundle DIRECTORY` validates the canonical proposal/observation chain, evidence references, generated source excerpts, and artifact digests without opening the repository or contacting a planner or model. Integrity and schema validation do not establish provenance, truth at collection time, or a security verdict; the bundle format has no authenticity signature.

### Implemented M2 slice: authenticated-retry fixture (2026-11-06)

A separate opt-in CLI path admits only the exact four-field authenticated-retry JSON artifact and
the reviewed, byte-pinned `target-authenticated-repro.py` entrypoint. It runs the same typed
artifact against distinct supplied broken/fixed synthetic repositories and evaluates the bounded
pair with `authenticated-retry-v1`. Source comments and JSON values are not a general plugin,
Python, build, shell, or command interface. A serialized proposal cannot mint `AdmittedExecution`;
admission binds the exact artifact/target/limits and one cleanup contract, and execution consumes
that authority once. This M2-specific execution vocabulary is not the MVP `Call`/`AuthorizedCall`
contract or a general `AdmittedCandidate` implementation.

The contained runner is available only on supported unprivileged Linux (`x86_64`/`aarch64`) with
`/usr/bin/python3`, working Landlock/seccomp, and private temporary storage. Filesystem rules,
seccomp denial of socket creation, process groups, rlimits, minimal environment, bounded outputs,
and descendant cleanup are used; unsupported setup fails closed. Runner identity includes its
architecture and the containment helper digest, not a complete host/runtime fingerprint. There is a
visibly separate fixture-only unsafe-development mode, but it is not a fallback or containment
substitute and cannot produce `Reproduced`.

`Reproduced` means only that broken returned `prior-session` and fixed returned `current-session`
under otherwise valid paired observations, receipts, controls, and cleanup. It is not a security,
safety, exploitability, production, attack-class-coverage, or general repository-finding verdict.
An inverted control, timeout, denial, infrastructure error, changed source, missing output, or
unresolved cleanup is not green. A valid offline bundle can nevertheless contain one of these
non-green assessments. M2 `repro`/`repro-verify` return `0` only for this reproduced pair, `1` for a
valid non-reproduced assessment, and generally `2` for refusals or operational/argument failures.
This behavior is specifically distinct from the proposed general CI exit table in Section 10.

`repro-verify --bundle DIRECTORY` checks the completed M2 bundle and recomputes the oracle without
the original roots/artifact, code execution, model, or target. `repro-resume --policy FILE --bundle
DIRECTORY` additionally hashes current producer inputs and can report `CompletedWithoutReplay`;
`repro-rerun` uses fresh authorization/run identity. A private per-transition journal is synced best
effort and a fully staged bundle is renamed into place. This is not arbitrary crash-durable
recovery, and pending/incomplete work is not accepted as a completed bundle. The self-hashed bundle
has no external signature/trust root, as with M1. See `target-onboarding.md` for exact commands and
`llm-red-teaming-roadmap.md` for tested boundaries and remaining exclusions.

## 5. Scope, authority, and dispatch

### Scope: where a call may go

Scope is an explicit set of normalized origins: scheme, host, and effective port. There is no wildcard or allow-all constructor. The MVP uses explicitly configured local fixture addresses; hostname-based remote execution is deferred until resolution and connection-binding controls are implemented.

Automatic redirects and environment-derived proxy routing are disabled. The transport validates the actual destination, applies endpoint and method restrictions from the adapter, and enforces request and response size limits. No alternate network client is available to technique implementations.

The gateway and backend run in an isolated environment whose outbound access is limited to fixture dependencies. Allowlisting Storm Gate’s origin is insufficient without this downstream isolation.

### Authority: which effects may be attempted

Keep two authority levels:

- `ReadOnly`: no intended change to protected application state, including when the tested enforcement fails. Incidental logging, metrics, and explicitly documented infrastructure effects are outside this definition.
- `Mutating`: may change protected application state. The MVP permits these effects only inside an isolated canary fixture.

Required authority is based on the probe’s possible effects if the target is vulnerable, not on the response a secure target should return. Unknown effect requirements are rejected until reviewed and classified.

A write attempted through a read-only Storm Gate session requires Mutating authority from Smash. Storm Gate’s session policy is the property under test; Smash’s authority ceiling is the operator’s permission to conduct that test. They are separate concepts.

Target-side severity, including any taint-exemption modifier, remains target metadata. It cannot reduce a technique’s Smash authority requirement.

### Authorization token

`Call` is inert data. Only `Capability::authorize` produces `AuthorizedCall`, which has private fields and no public constructor, deserialization, default, or unchecked conversion.

The token binds the immutable call digest, target, run, capability version, effect requirement, and expiry. Dispatch checks the current run state and remaining budget. Authorization cannot be reused to dispatch altered bytes or a different destination. Capabilities cannot be upgraded within an existing run.

Denials are recorded as facts, including `OutOfScope`, `AuthorityExceeded`, `Expired`, and `BudgetExceeded`. A denied test is unexecuted coverage, not a security pass.

Type privacy prevents ordinary API callers from constructing authorized calls directly. It does not prevent future maintainers from changing the enforcement implementation; architecture checks and review protect that boundary over time.

## 6. Information containment

The manifest wall applies to every service-to-decider surface, including errors, progress events, summaries, and reports returned through the API.

Permitted output consists of registered identifiers, bounded counts, finite status codes, typed measurements, verdicts, and service-generated opaque evidence references. Names and descriptions come from the reviewed registry, not from echoed target content. No arbitrary string field may carry a target response or raw exception.

Target bodies and detailed wire evidence remain in a restricted evidence bundle. Human-facing raw evidence is explicitly marked untrusted and rendered as inert data. It is not automatically appended to model context. Exposing it to a model creates a separate workflow outside the decider containment guarantee.

MVP reports use reviewed templates populated with typed facts. Any later AI-written remediation feature receives only the same bounded summaries and is never a verdict authority.

## 7. First target: Storm Gate

Storm Gate is described in the original specification as a Rust HTTP proxy enforcing tool allowlists and severity policy at `/v1/chat/completions`. The example local origin is `http://127.0.0.1:8019`; the actual test origin must be explicit in run configuration.

Before integration, confirm the gateway’s current request contract, session-policy configuration, canonicalization, and evidence format from its source. Do not treat the original examples as an independently verified API contract.

### Fighter 1: authority-clamp differential

**Invariant:** a session configured read-only must not cause a protected write at the canary backend.

**Smash authority:** Mutating.

**Fixture:** a disposable backend with known initial state, a unique run namespace, an observable write receipt, and an authoritative state snapshot. No production credentials, data mounts, or downstream routes are present.

Procedure:

1. Provision the fixture and verify routing, credentials, health, and known initial state.
2. Run a benign read control through the read-only session to establish that the intended path is reachable.
3. In a separate clean namespace, run the equivalent write through a write-enabled session. Require a backend receipt and expected state change to establish that the write path actually works.
4. In another clean namespace, attempt the write through the read-only session.
5. Correlate gateway evidence, backend receipts, and before/after state. Observe until a fixture-defined completion barrier or bounded deadline; a timeout alone is not proof of no effect.
6. Evaluate the invariant and controls, finalize evidence, and dispose of the fixture.

The fixture contract must make asynchronous completion observable. If it cannot establish a bounded observation window, the test cannot pass.

### Verdict contract

| Result | Meaning |
| --- | --- |
| `Pass` | Controls succeed; the target rejects the prohibited operation for the expected policy reason; complete backend evidence shows no protected write within the established execution boundary. |
| `Fail` | Correlated evidence proves a prohibited protected write. Such positive evidence remains a failure even if another control is unavailable; record the control limitation. |
| `Inconclusive` | Evidence cannot establish pass or fail: broken control, ambiguous routing, incomplete receipt/state data, unexpected rejection, or unresolved completion. |
| `Denied` | Smash refused execution before dispatch. |
| `Error` | Smash could not complete execution or evidence processing because of an internal or operational failure. |

An “accepted” gateway response without a backend effect does not by itself prove this invariant failed. It may justify a separate policy-response finding with its own oracle. A passing result is scoped to this invariant, technique version, target configuration, and fixture.

### Implemented exception: the narrow M3 loopback target pack (2026-11-06)

The `smash_engine::http` module and `http-discover`, `http-repro`, and `http-verify` CLI commands
implement a separate typed workflow. This is not completion of all proposed HTTP/L1 behavior and
does not change the Storm Gate lifecycle or `authenticated-retry-v1` oracle. Admitted policy is a
reviewed `HttpCampaignPolicy` JSON value with exact disposable-fixture loopback origins, GET/POST
routes, fixed headers, flat string fields, declared credential references, scalar JSON response
schemas, controls, and bounded resources. Discovery rejects all mutations; reproduction requires
an explicit flag and exactly one mutation with before/after/unknown-identity correlation. Route
discovery and model-authored plans are not implemented.

One `ureq` builder disables ambient proxies, redirects, and idle connection reuse, retains TLS
verification, and filters the addresses produced by its actual connection resolver. Controlled
timeouts, bounded bodies, declared credential injection, and typed response outcomes apply.
Non-observations, unavailable or malformed receipts, unexpected statuses/scalars, and unresolved
transport outcomes do not become passes. The in-process fixture and its cooperative budgets are
not an L1 environment, an OS-enforced containment boundary, or evidence of downstream isolation.

The M3 oracle is `http-scalar-differential-v1`. A mutation claimed as an effect requires fixed
control before `0`, after `1`, and unknown identity `0`, all fixed expectations, complete
correlated observations, a differing broken receipt, and both teardown attestations. The generic
CLI owns no fixture teardown, so it leaves cleanup unattested and yields a valid inconclusive
result, not a fabricated positive. The capstone's owning engine caller actually drops and joins
fixtures before using the cleanup callback. Cleanup callbacks run after ordinary and error exits;
independence, validity, and completion remain explicit verification conditions.

Reproduction bundles contain bounded strict JSON policy, records, selected scalar observations,
request/control metadata, body digests/lengths, and the exact policy copy. Raw response text and
credential values are not retained. `http-verify` loads only a fresh bounded bundle directory,
rejects unexpected/duplicate/oversized members, and recomputes the same oracle without a network,
model, target, or credential. Bundle consistency is not a signature, collection authenticity, or
production assurance. Read-only discovery persistence is a separate observation artifact.

CLI exit codes are slice-specific: discovery succeeds with `0` only when all declared reads were
observed; reproduction/verification return `0` for a reproduced assessment, `1` for a valid
non-reproduced assessment, and `2` for invalid inputs, denial, or operational/argument errors.
M3 does not implement this specification's proposed general CI semantics, in which confirmed
security failure uses `1`. Valid bundles and reproduced fixture differentials do not imply a
secure, exploitable, signed, independently attested, or production-representative target.

The delivered scope and commands are in `target-onboarding.md` §1.3; containment limits are in
`staging-and-containment.md` §4.2. M3 capstones cover the paired loopback fixture, expected
duplicate/single effects, retry and authentication controls, credential exclusion, malformed
contracts, CLI admission/refusal, actual teardown, and offline bundle/tamper verification after
fixture shutdown. They do not establish a general endpoint scanner, broad staging runner, or
security certification.

### Implemented exception: bounded M4 read-only investigation (2026-11-06)

The `smash_agent::investigation` protocol and `smash_engine::http::investigation` workflow add a
narrow adaptive layer above M3. `http-investigate`, `http-investigate-resume`, and
`http-investigate-verify` consume an `HttpInvestigationPolicy`: a nested M3 campaign whose catalog
contains only read-only calls and no effect contract, a fixed queue of admitted item/call pairs,
and finite read/planner/token budgets. This is separate typed authority; it neither broadens M1
`PlannerOutput`/`ExperimentDraft` nor activates M2 unsafe seeding or M3 mutations.

Each bounded version-1 planner response chooses only an admitted `{item_id, call_index}` or
`complete`. Thoughts contain a bounded summary and full hypothesis/queue histories, immutable
identities and allowed-call policy, status transitions, known observed-evidence references, and
explicit input/output token deltas. Unknown fields, malformed/trailing JSON, fabricated evidence,
history edits, unsupported schema versions, invalid transitions, or budget overruns are rejected
without retrying the same response. Non-observations cannot support findings or completed queue
items and do not imply absence of a target condition.

The engine checks that decision, raw bytes, and digest agree before checkpointing. The only request
selector crossing execution is a pre-admitted catalog index; the trusted adapter retains route,
destination, headers, arguments, credentials, response schema, lifecycle, and scalar evidence. One
selected read executes once with M3's controlled client. No model-authored request, effect seed,
credential, redirect, mutation, or target expansion is accepted.

A private pending directory holds raw responses, a strict append-only JSONL journal, and a state
snapshot before atomic terminal publication. Resume validates policy identity and exact consumed
script prefix. A selected read lacking its observation is unresolved and cannot be replayed;
terminal runs and subsequent resume do not re-ask the planner or redispatch old reads. Call and
planner ceilings include a final turn after the last permitted read. These are cooperative storage
and process controls, not a signed event log or a hard scheduler.

Offline verification re-decodes each exact response against replayed policy/state, correlates every
read attempt to its admitted call, enforces disposition and response schemas, and checks the exact
file set and journal snapshot. It performs no network, target, credential, resolver, or planner
access. A valid or complete session establishes only bounded internal consistency and the planner's
observation-linked hypotheses—not an external signature, a general security verdict, exhaustive
coverage, or L1/L2 containment.

The M4 capstones cover adaptive read selection, malformed/unknown selection, evidence-linked queue
completion, read budgets, interrupted exact-prefix resume, unresolved-dispatch non-replay, completed
no-replay, and post-shutdown offline/tamper checks. Hosted providers, repository/HTTP integrated
planning, new mechanisms, novelty/dedup, cost/wall-time/concurrency controls, kill switches, and
broad autonomy remain proposed. Commands and limits are detailed in `target-onboarding.md` §1.4.

## 8. Evidence and verification

### Two separate operations

- `smash verify <run-id>` verifies the stored bundle offline and recomputes verdicts using the pinned oracle. It never contacts the target or executes probes. Missing required artifacts or unsupported versions produce a verification failure, never a verified pass.
- `smash rerun <run-id>` creates a new run with fresh authorization, current scope checks, and new fixture state. It records its relationship to the original run and any version differences. It may produce different results.

Neither operation depends on the original skill or harness. Deterministic oracle evaluation does not imply deterministic network behavior.

### Required evidence bundle

- Run ID; unique execution ID per attempt; ordered event sequence and timestamps.
- Parent run ID for reruns; technique, engine, adapter, oracle, schema, and fixture versions/digests.
- Target build and configuration identity where available, explicitly unknown otherwise.
- Capability snapshot, target binding, budget, authority requirement, and authorization/denial records.
- Exact relevant request artifacts and response evidence, stored outside decider access.
- Canary initial/final state, receipts, control outcomes, and completion evidence.
- Normalized observations, verdict, reason codes, and evidence references.
- Operator/driver provenance; model and harness version only when applicable.
- Bundle completeness marker and integrity manifest.

A canonical call key identifies semantic call content. It is not a unique execution ID. Bind it to run, attempt, session, and fixture namespace when correlating records; do not accept a receipt from a different execution merely because its call key matches.

Pin cross-implementation canonicalization vectors against the Storm Gate implementation that actually generates its vouches. Include argument ordering, Unicode, numeric representations, nested structures, and rejected inputs. Specify key formatting exactly after source confirmation.

Content hashes detect inconsistency against a trusted digest; they do not prove that a compromised producer recorded truthful events.

Do not store authentication secrets in bundles. Supply credentials out of band and capture verification-relevant artifacts before credential injection where practical. Required evidence must remain available under the retention policy.

## 9. Run lifecycle and operational limits

A run moves through `Created`, `Preflight`, `Ready`, `Running`, `Finalizing`, and a terminal `Completed`, `Aborted`, or `Errored` state. Security verdicts are separate from lifecycle status.

Before dispatch, reserve budget and record authorization intent. After dispatch, record the outcome. An interrupted attempt with unknown effects remains unresolved and is never silently retried as though it did not execute.

Each run sets finite limits for requests, duration, concurrency, response bytes, and fixture resources. The MVP uses serial execution and no automatic retries of mutating attempts. Cancellation stops new dispatches; already dispatched effects may complete and must still be observed where possible.

Fixture cleanup runs on normal completion and failure. Crash recovery identifies abandoned resources. Cleanup failure is reported as an operational error and prevents an overall green CI result, while preserving any established security finding.

## 10. Reporting and CI behavior

Each finding states the expected invariant, observed result, confidence limitations, affected build/configuration, evidence references, remediation guidance, and the command for a fresh rerun. Raw payloads are not needed in the default report.

Reports distinguish a vulnerability from a test infrastructure failure. They show required, executed, passed, failed, and incomplete technique counts. Zero executed tests cannot produce a green run.

### Proposed CLI exit contract

| Exit | Meaning |
| --- | --- |
| `0` | All required tests passed, evidence finalized, and lifecycle completed successfully. |
| `1` | At least one confirmed security failure; report any additional operational issues. |
| `2` | No confirmed failure, but required coverage is inconclusive, denied, errored, or incomplete. |

Offline verification reports bundle validity separately from the recorded security result. A valid bundle can prove that a test failed; verification must not label the target secure simply because the bundle is valid.

## 11. MVP acceptance and validation

Release requires:

1. A correct Storm Gate fixture passes and a deliberately broken authority clamp fails with a correlated backend effect.
2. Wrong credentials, unavailable backends, missing receipts, delayed unresolved writes, and broken controls never yield a pass.
3. A read-only Smash capability denies the mutating fighter before any probe is sent.
4. Altered calls, off-scope destinations, redirects, expired capabilities, and exhausted budgets are refused at the relevant boundary.
5. Adversarial response strings and errors cannot appear in any decider-facing field.
6. Complete bundles verify with the harness removed and target network unavailable. Missing or modified required artifacts fail verification.
7. Repeated identical calls cannot borrow each other’s receipts across sessions or runs.
8. Cancellation, crash recovery, and cleanup failure preserve honest lifecycle and coverage outcomes.

Use compile-fail checks for the public authorization API, property tests for gate and serialization invariants, and integration tests for real transport and fixture effects. Forbid `unsafe` in first-party crates; review dependency risk separately rather than claiming that the lint removes transitive risk.

**Proposed pilot targets:** three gateway developers can configure and interpret the suite without its author; median setup under 15 minutes; the single-fixture CI run under 60 seconds on a documented runner; no false passes across the seeded-fault suite. Record false alarms and inconclusive rates separately.

## 12. Delivery sequence

1. **Prove the oracle:** controlled good/bad fixtures, authoritative backend evidence, and a useful report.
2. **Prove containment:** gated transport, isolated downstream routing, output schema, bounded execution, and failure recovery.
3. **Prove portability:** complete bundles and offline verification independent of harness and target.
4. **Pilot the workflow:** local setup, CI integration, measured usability, and report-driven fixes.
5. **Expand deliberately:** add techniques only after they have an explicit invariant, effect classification, control design, evidence contract, and seeded failing fixture.

## 13. Recommended ways to strengthen the approach

### A. Make technique coverage a matrix

Map each policy invariant to its techniques, controls, known failing fixtures, and evidence requirements. Show unsupported invariants as unsupported. This prevents users interpreting a green dashboard as general security assurance. Establish this with the MVP.

### B. Test the tester with deliberate faults

Keep a small suite of gateway variants with known authorization defects and infrastructure faults. Run it whenever an oracle, adapter, or serializer changes. Expand beyond detection rate to check that each defect produces the correct evidence and explanation. Establish this with the MVP.

### C. Separate oracle evaluation from execution privileges

Give the offline evaluator no target network access and only a versioned evidence bundle. This makes the claim “the harness is disposable” concrete and reduces accidental coupling between evaluation and live state. Establish this with the MVP; a separate process can follow if it materially improves isolation.

### D. Add metamorphic policy tests after the first fighter

Test relationships that should hold across paired inputs: lowering target-session permission must not enable additional protected effects; irrelevant argument ordering must not alter authorization; equivalent representations must retain equivalent policy outcomes. Each relationship needs a precise precondition and oracle, not a generic fuzzing claim.

### E. Test sequences after single-call correctness

Many policy properties concern state across calls. A later fighter can test session renewal, permission reduction, and stale authorization reuse in the same isolated fixture. Keep these distinct from the MVP because they require stronger temporal evidence and reset semantics.

### F. Publish a technique admission checklist

Before admitting a fighter, require its invariant, worst-case effect classification, transport needs, bounded parameters, positive/negative controls, fixture isolation, evidence completeness rules, seeded failure, and decider-output tests. Keep external code out of the trusted process until a sandboxed extension model exists.

### G. Add a separate research mode for candidate discovery

After the regression workflow is established, consider a separate sandboxed research component that generates candidate probes, including model-assisted candidates. It is not the handle-only decider and is outside that decider’s content-containment guarantee. Its exposure to adversarial content must be treated explicitly in its own threat model.

The research component cannot dispatch directly, grant authority, modify scope, or establish verdicts. Candidate artifacts pass through an admission stage that assigns bounded parameters, an effect classification, fixture requirements, an execution budget, and an evidence/oracle contract. An automated assessment alone cannot guarantee the effects of arbitrary code: initially restrict candidates to a supported declarative probe format executed by approved implementations, and reject unsupported behavior.

Accepted candidates receive immutable handles and execute through the same capability gate and controlled transport in disposable fixtures. Store the exact candidate artifact and provenance so offline verification does not depend on regenerating model output. A candidate without a validated oracle remains an exploratory observation, not a verified security finding. Promote useful discoveries into the reviewed regression catalog with a seeded failing fixture.

This extension requires an explicit architecture revision: the current model-free service promise applies to execution and verdict evaluation; any model-assisted generation is a distinct component. Do not silently grant the existing decider arbitrary payload submission or weaken its output boundary.

### H. Increase environment fidelity through representative staging

Canaries provide controlled state and strong observability but can miss deployment-specific behavior. After the MVP, support dedicated staging environments that reproduce relevant gateway versions, policy configuration, authentication paths, and downstream behavior using synthetic data and test credentials.

Staging admission requires explicit target and downstream scope, implemented remote destination controls, a documented effect budget, observable completion, and a cleanup or reset mechanism. Shared dependencies need their own authorization and containment; permission for a gateway does not imply permission for every service it can reach. Production testing remains outside this proposed extension.

Reports must identify the environment profile, configuration differences from the intended deployment, and resulting coverage limits. A staging result must not imply production assurance where relevant differences remain unknown. Expand realism while retaining defensible evidence, rather than replacing known canary limits with unmeasured assumptions.

## 14. Decisions to confirm during implementation

- The precise protected-state definition and permitted incidental effects for each adapter.
- Storm Gate’s current vouch/canonicalization contract and a reliable way to correlate backend execution.
- The fixture’s completion barrier for asynchronous operations.
- How the test gateway’s configuration is bound to a run and prevented from changing mid-test.
- Default budgets and evidence retention, based on pilot measurements.
- Whether portable signed bundles are needed beyond local CI artifacts.
- Before research mode: the candidate format, admission mechanism, separate generation threat model, and promotion criteria for regression techniques.
- Before staging support: the environment fidelity requirements, downstream authorization, and controls needed to preserve bounded effects outside disposable local fixtures.

These decisions must be resolved before claiming the corresponding guarantees. The core product remains a trustworthy, bounded regression test with evidence a developer can use to fix a real enforcement failure.
