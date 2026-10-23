# Smash — Product & Technical Specification

Oct 22, 2026 · @Jarmo

Revision 0.3 · Proposed specification. Requirements below describe intended behavior, not verified implementation. Storm Gate integration details inherited from the original must be confirmed against its source before implementation.

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
