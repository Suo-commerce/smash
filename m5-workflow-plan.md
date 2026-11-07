# Smash — narrow M5 product-workflow plan

Status: approved planning baseline for the next implementation session, 2026-11-06.
No M5 workflow execution is implemented by this document. M1–M4 behavior must remain unchanged.

## 1. Goal and user-approved decisions

Build one repeatable, deterministic product-workflow vertical slice before adding broader M4
planning or broader M5 drivers. The slice must demonstrate a scoped authorization-workflow defect
on a known-broken fixture, a differing fixed control, contained execution, honest lifecycle evidence,
and execution-free offline verification.

| Decision | Approved choice |
| --- | --- |
| Priority | Narrow M5 first; broader M4 expansion is deferred. |
| Product workflow | Revoked-invite acceptance. An owner invites a synthetic guest, acceptance becomes pending, the owner revokes the invite, and a deferred completion is processed. |
| Broken/fixed behavior | Broken grants guest membership using authorization captured before revocation; fixed revalidates at completion and denies membership. |
| Execution boundary | A contained external fixture CLI, using new M5-specific admission and the existing Linux sandbox substrate where compatible. No in-process-only substitute. |
| Interrupted runs | Non-green, never automatically replayed, and resumed only as a fresh run with fresh namespace and authorization. First slice has no resume mode. |
| Retained evidence | Bounded typed steps, assertions, events, state snapshots, process/effect/cleanup disposition, and digests only. No arbitrary stdout/logs, real credentials, or free-form target text. |

There are no remaining blocking product decisions. Filenames, private helper factoring, bounded
field limits, and the smallest safe reuse of existing process-launch helpers are implementation
choices, provided they do not change the decisions above. Changing the workflow, weakening process
containment, adding resume, or retaining arbitrary diagnostics requires an explicit scope revision.

## 2. Narrow outcome and non-goals

The intended oracle is scoped to this invariant:

> Once an invitation is revoked while guest acceptance is pending, completing that acceptance must
> not make the guest a project member.

`Reproduced` means the broken fixture records successful deferred acceptance and guest membership
after revocation, while the fixed fixture records denial and no guest membership, with every other
required step, observation, and cleanup condition satisfied. It does not mean the product is
exploitable in production, that every authorization check is covered, or that the fixed fixture is
generally secure.

The first slice includes:

- One scenario: `revoked-invite-acceptance-v1`.
- One oracle: a versioned revoked-invite differential oracle, not a configurable assertion language.
- One Linux-only, no-network external CLI target-pack fixture and its trusted typed adapter.
- Broken and fixed variants, synthetic owner/guest/project/invitation identities, deferred manual
  completion rather than background threads, ordered state snapshots, and an exact event sequence.
- Explicit mutation opt-in, private disposable target state, sequential bounded execution, terminal
  publication, fresh reruns, and offline verification.
- One M5 capstone plus focused unit and adversarial tests.

The first slice excludes:

- Hosted models, planner integration, M1/M4 protocol changes, or planner-authored workflow steps.
- Generic workflow DSLs, arbitrary argv, shell fragments, dynamic executable selection, or general
  repository/build execution.
- Browser/mobile/desktop drivers, real SaaS services, external networks, ambient credentials,
  production or staging targets, and unsafe-development execution.
- General asynchronous runtimes or wall-clock races. Asynchrony is deterministic: acceptance is
  persisted as pending and completed only by a separate admitted worker-style CLI step.
- Automatic resume/replay of incomplete runs, signatures, provenance attestation, generalized CI
  verdict semantics, or proof of collection authenticity.

## 3. Trust and execution boundary

### Policy and authority

Use a separate `WorkflowPolicy`; do not widen `ReproductionPolicy`, M1 `ExperimentDraft`, M3 HTTP
policies, or M4 investigation actions to carry workflow commands. Policy JSON is strict,
duplicate-free, size-bounded, and `deny_unknown_fields`.

A reviewed policy may select only the compiled scenario/oracle, the Linux sandbox provider, exact
broken/fixed fixture-driver identities and digests, disposable run roots, bounded symbolic identities,
credential references, expected evidence schemas, and finite resource budgets. It may not contain
argv, an interpreter option, a shell command, an arbitrary environment map, a URL, or a new oracle.

The trusted adapter owns the fixed ordered step catalog and constructs typed argv from validated
symbolic fields. A one-shot M5 admitted-step token binds scenario, target variant, exact driver and
digest, step identity/index, arguments, synthetic credential reference, declared output, limits, run
namespace, and sequence. Constructing or serializing a proposal must not construct that token.

Prefer a dependency-free fixture CLI run by the existing fixed Python interpreter boundary if source
inspection confirms compatibility. This remains an external OS process with a source/digest-bound
driver; it must not expose Python `-c`, a caller-selected script, or unrestricted arguments. If the
existing Linux runner cannot accept M5 authority without weakening M2, extract a private common
process/sandbox primitive or add a narrow M5 entry point. Do not loosen M2 admission to make reuse
convenient.

### Sandbox and effects

Every step runs sequentially with the actual no-network Linux sandbox, minimal fixed environment,
source access limited to the exact fixture driver, a separate private writable target/output area,
and explicit wall-time, output, memory, process, and descendant-cleanup limits. Unsupported hosts or
unavailable containment fail closed; there is no fallback to an uncontained runner.

All invitations and credentials are synthetic. Credential values are injected only at dispatch,
never placed in policy evidence, planner context (there is no planner), journals, snapshots, or
bundles. Policy stores only bounded references. The engine, not the target, owns fixture teardown
and must prove deletion of only its private run root. Cleanup failure or uncertain descendant
termination is non-green and unresolved.

The bundle is an internally verifiable observation record, not a signed claim that a target emitted
truthful events. A fixed output schema and digest cannot independently establish collection
authenticity.

## 4. Fixture and expected evidence

The capstone owns a small committed `revoked_invite.py` (or equivalent dependency-free CLI) with a
deliberate broken variant and a fixed variant. It persists only its own synthetic target state.
Variant selection is an admitted fixed value, not arbitrary target input. The external interface
uses named typed operations and emits versioned strict JSON to one declared file per step.

| Ordered trusted step | Required pre-completion meaning | Broken completion | Fixed completion |
| --- | --- | --- | --- |
| `create_project` | Owner and project exist; guest is not a member. | Same. | Same. |
| `create_invitation` | Guest invitation is `pending`; only a synthetic credential reference crosses the adapter. | Same. | Same. |
| `begin_acceptance` | A deferred guest acceptance is persisted as pending, with no membership yet. | Same. | Same. |
| `revoke_invitation` | The invitation is revoked before deferred completion; guest is still not a member. | Same. | Same. |
| `complete_acceptance` | Completion re-evaluates the committed invitation state. | Reports accepted and adds guest membership, deliberately using stale pre-revocation authorization. | Reports revoked/denied and leaves guest membership absent. |
| `observe_membership` | Produces the final typed membership snapshot. | Guest membership is present. | Guest membership is absent. |

Before every step, and after the final step, retain a bounded typed snapshot containing only symbolic
project/owner/guest/invitation identities, invitation/acceptance status, membership, and a monotonic
state sequence. Retain typed events with step identity, action, result, and state digest. Exclude
credentials and arbitrary text.

Add a non-revoked acceptance control against the fixed fixture: it must accept and establish guest
membership. The broken, fixed, and functional-control runs use independent fresh target namespaces;
none reuses another run's state or authorization. This distinguishes revocation-sensitive behavior
from a fixture that merely denies every acceptance. It is a functional control, not additional proof
of security.

## 5. Proposed implementation seams

Keep the dependency direction `core <- engine <- cli`, with capstones depending on the engine and
CLI as test consumers. Do not put fixture behavior in `smash-engine`.

| Location | Responsibility |
| --- | --- |
| `smash-engine/src/workflow/policy.rs` | Versioned scenario/target/resource policy, fixed scenario catalog, strict validation, and private one-shot step admission. |
| `smash-engine/src/workflow/execute.rs` | M5-to-Linux typed process execution, strict declared-output parsing, one-shot dispatch, and process/effect disposition. |
| `smash-engine/src/workflow/session.rs` | Sequential driver, snapshots/events, private pending journal, terminal publication, cleanup, and fresh-rerun refusal semantics. |
| `smash-engine/src/workflow/oracle.rs` | Versioned revoked-invite differential evaluation and non-revoked functional-control checks. |
| `smash-engine/src/workflow/bundle.rs` | Exact bounded file set, strict decoding, state/event/identity/digest validation, cleanup checks, and offline oracle recomputation. |
| `smash-engine/src/workflow/mod.rs` and `smash-engine/src/lib.rs` | Narrow exports only. |
| `smash-cli/src/workflow.rs` and CLI routing | `workflow-repro` and `workflow-verify` only; explicit target-mutation opt-in and JSON reports. |
| `smash-capstone/src/workflow_fixture.rs` | Start/configure/stop corresponding fixture instances, trusted policy generation for tests, and actual teardown. |
| `smash-capstone/fixtures/revoked_invite.py` | Known-broken/fixed external CLI behavior and synthetic state machine. |
| `smash-capstone/tests/workflow_capstone.rs` | End-to-end, post-shutdown offline verification, tamper and containment regressions. |

These filenames are guides, not authorization to create a generic framework. Combine small modules
when that is clearer; keep policy/admission, execution, and offline evaluation logically separated.

## 6. Session and evidence semantics

Use a fresh private sibling pending directory with mode `0700`, fixed mode-`0600` files, bounded
strict JSON, synced response/journal entries and state replacement, and atomic publication of a
terminal bundle. The exact layout must include policy bytes, a journal, a state snapshot, and only
referenced typed step/snapshot/event records. Reject symlinks, special files, duplicates, aliases,
unexpected files, oversized inputs, incomplete final journal lines, and inconsistent state.

Before each target dispatch, synchronously persist admitted step identity and authority binding.
After dispatch, persist process disposition, typed outcome, event, snapshot, and state digest. A
process exit code of zero is not itself a workflow observation. Invalid JSON, unknown fields,
malformed transitions, stale state sequences, missing events, and target-claimed success are not
promoted to trusted assertions without matching typed state evidence.

An interrupted pending directory cannot be passed to `workflow-repro` or renamed into a successful
result. There is no `workflow-resume` command and no automatic reconstruction by rerunning old
steps. The operator starts a fresh run with a new output path, run namespace, sandbox state, and
fresh authority. Unresolved process, effect, or cleanup states remain non-green.

Offline verification reads only the published bundle. It checks exact policy encoding, schema and
scenario/oracle identity, step order, all symbolic identities, pre/post transitions, event/state hash
correlation, process/effect/cleanup disposition, the broken/fixed differential, the non-revoked
functional control, exact files/digests, and journal/state agreement. It never opens the fixture
source or executable, invokes a target, reads credentials, uses a resolver, or accesses the network.

## 7. Delivery sequence

1. **Recover and preserve the baseline.** Read the current-position roadmap, M2 execution/repro
   implementation, Linux sandbox, M3/M4 session and bundle patterns, staging boundaries, and this
   plan. Inspect the working tree without resetting, cleaning, committing, or mass-formatting it.
   Run locked offline workspace tests from the established external build target.
2. **Write the M5 contract first.** Add policy/admission types and deny-by-default validation tests.
   Prove arbitrary argv, shell text, interpreter escapes, new scenarios/oracles, ambient environment,
   network, credential values, oversized data, and non-disposable roots are refused before launch.
3. **Implement the external fixture independently.** Test its fixed ordered state transitions,
   broken stale-authorization behavior, fixed revalidation, deferred pending state, non-revoked
   functional control, malformed requests, credential misuse, and deterministic bounded output.
4. **Add one contained step execution.** Reuse or narrowly factor Linux process/sandbox helpers
   without weakening M2. Verify source/digest binding, private roots, no inherited environment or
   network, per-step limits, typed output refusal, process-group cancellation, and cleanup.
5. **Drive the complete scenario.** Enforce ordered one-shot steps, typed observations/snapshots,
   durable pre-dispatch records, terminal-only publication, actual teardown, and fresh-rerun-only
   handling of every incomplete state.
6. **Implement the oracle and offline verifier.** Require both broken/fixed outcomes and the valid
   functional control. Reversed, missing, malformed, unresolved, or incomplete evidence must not
   produce `Reproduced`. Recompute the same oracle without touching original fixtures.
7. **Expose only the narrow CLI.** Add `workflow-repro` and `workflow-verify`, separate from M1–M4
   commands. Execution requires an unmistakable fixture-mutation flag; verification has no such
   flag and cannot dispatch.
8. **Add capstones and adversarial regressions.** Prove post-shutdown verification and detection of
   altered steps, states, events, identities, assertions, policies, digests, cleanup evidence, and
   control outcome. Include symlink/path escape, special file, oversized output, timeout, hostile
   structured fields, missing effects, failed cleanup, unresolved process termination, fixed-only
   denial, non-revoked acceptance, interrupted rerun, and no-replay checks.
9. **Document and verify exactly what landed.** Update the roadmap's current-position note, M5
   milestone exception, product specification, target onboarding, staging/containment, and relevant
   module docs. Format changed crates only, run the full locked offline workspace suite and strict
   Clippy, build the `smash` binary, confirm the reduced dependency graph, and inspect the final diff.

## 8. CLI and result contract

Proposed commands, to be retained only if implementation matches:

```console
smash workflow-repro --policy WORKFLOW.json --out /tmp/smash-m5-result \
  --execute-fixture-workflow --json
smash workflow-verify --bundle /tmp/smash-m5-result --json
```

A fresh run requires fresh output and target state. The execution command returns:

- `0` only for a valid scoped `Reproduced` assessment with the required broken/fixed and functional
  controls, observations, and completed cleanup;
- `1` for a structurally valid assessment that is not reproduced, including an honest inconclusive
  outcome; and
- `2` for denial, invalid policy/evidence, unavailable containment, unsafe arguments, operational
  failure, interrupted/unresolved work, or incomplete required evidence.

`workflow-verify` returns `0` only when offline consistency and the scoped reproduced oracle hold,
`1` for a valid non-reproduced assessment, and `2` for invalid evidence or arguments. It does not
turn a valid or complete bundle into a general security verdict. If CLI semantics differ from M3
for a concrete reason, document the difference rather than silently inheriting either convention.

## 9. Definition of done

- The exact external broken CLI demonstrates post-revocation guest membership; the fixed CLI denies
  it under the same admitted steps, and the fixed non-revoked control accepts normally.
- Every process used the claimed no-network Linux containment boundary. Missing containment, policy
  mismatch, driver tampering, unsafe paths/arguments, timeout, output/resource overrun, cleanup
  failure, and uncertain process/effect completion cannot yield green results.
- No caller/model text can supply argv, a shell, an executable, a new oracle, credentials, arbitrary
  environment, or target authority. M2's authenticated-retry contract and M1/M3/M4 remain intact.
- The typed evidence chain rejects skipped/reordered steps, contradictory snapshots/events, revoked
  versus pending confusion, stale identities, missing controls, cleanup fabrication, and exact-file
  or digest tampering.
- Verification succeeds after fixture processes and original target state are gone, without opening
  the network or executing any target code. Its scope and authenticity limits are explicit.
- Incomplete work has no resume shortcut, is never silently replayed, and requires a fresh run with
  fresh authority and state.
- New unit/capstone tests pass, all pre-existing workspace tests pass, and strict Clippy passes.
- Documentation labels this as the **narrow M5 revoked-invite Linux fixture slice**, not broad M5,
  general product-workflow automation, production assurance, or a complete product security proof.

## 10. First actions in the next session

Start at Delivery sequence steps 1–2. Do not begin by building a runner or general workflow DSL.
The immediate review question is whether M5-specific admitted-step authority can use private Linux
sandbox helpers without modifying M2 admission semantics. Once that seam is established, implement
and test the policy/fixture contract before wiring scenario execution. Finish the session with the
verification and documentation scope above; do not treat this plan itself as M5 implementation.
