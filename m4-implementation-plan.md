# M4 implementation plan: bounded no-progress stopping

**Status:** implemented and verified on 2026-11-07.

This records the narrowly scoped increment after the delivered M1-to-M4 recon-seeded,
read-only HTTP investigation bridge. Read `llm-red-teaming-roadmap.md`, especially the
current-position material, the implemented M4 slice, Section 6 M4, and Sections 7-8,
before changing code. Treat the roadmap as the record of what already exists; do not
reimplement the bridge or broaden this plan into general autonomous execution.

## 1. Recover and preserve the existing state

Inspect the working tree and preserve all unrelated changes. Do not stage, commit, reset,
clean, rebase, mass-format, or replace existing work. The tree contains extensive untracked
files, including implementation and documentation files.

Read at least:

- `smash-agent/src/investigation.rs`
- `smash-engine/src/http/investigation/policy.rs`
- `smash-engine/src/http/investigation/session.rs`
- `smash-engine/src/recon/bundle.rs`
- `smash-cli/src/http.rs`
- `smash-capstone/tests/investigation_capstone.rs`
- `target-onboarding.md` Section 1.4

Establish a source-built test baseline before editing. Use the existing external build/cache
convention: `RUSTUP_HOME=/tmp/opencode/rustup`, `CARGO_HOME=/tmp/opencode/cargo`, and
`CARGO_TARGET_DIR=/tmp/opencode/smash-baseline-target`, with tools under
`/tmp/opencode/cargo/bin/`. Do not generate a new project `target/` tree for these checks.

## 2. Implement exactly one new control

Add a bounded policy limit for consecutive unproductive investigation turns.

A turn is productive only when it produces at least one of:

- a newly recorded typed HTTP `Observed` result that is valid for the selected admitted read;
- a newly validated hypothesis status transition; or
- a newly validated queue status transition.

Planner prose, changed thoughts or usage counters, an additional dispatched read, a typed
non-observation, and repeated identical hypothesis/queue histories are not progress by
themselves. Replaying an already stored result during verification must not manufacture new
progress. Preserve the strict investigation decision protocol; do not introduce another
model action or execution authority.

Define deterministic counter/reset behavior before editing state serialization. Missing or
legacy fields must have explicit compatibility semantics rather than silently changing the
meaning or terminal outcome of an existing session. Keep unrelated unseeded policy/state
encoding stable where practical.

## 3. Stop deterministically without inventing completion

When the configured consecutive-unproductive-turn ceiling is reached:

- terminate with a distinct typed non-complete non-progress outcome;
- perform no further planner turn or HTTP read for that run;
- journal and persist the terminal outcome through the existing fail-closed publication path;
- report valid but incomplete evidence honestly;
- never convert non-observations into evidence of absence, safety, refutation, or support;
- never mark a source-seeded hypothesis complete without the required same-item HTTP evidence.

The existing total-call and planner-turn ceilings remain independent controls. Reaching one
must not be relabeled as another. Offline validity and investigation completion also remain
distinct.

Resume must reconstruct the same counter and stopping decision, include the configured limit
in effective-policy identity, and reject a changed policy. Pending selections whose dispatched
read lacks its persisted observation must retain the existing unresolved-dispatch refusal;
no-progress handling must never bypass it. Completed runs must retain completed no-replay
behavior. CLI resume with a recon seed must still require the exact verified source bundle,
while offline verification must continue to use only the session snapshot.

## 4. Preserve all current authority and evidence boundaries

The M3 catalog and existing queue remain the only HTTP read authority. Do not add repository
operations during an HTTP run, source-derived routes or URLs, arbitrary headers/bodies,
credentials, mutations, raw source instructions, or new model-proposed mechanisms.

Keep the complete recon seed and its reconstructed-state SHA-256 binding intact. Offline
verification must require no repository, target, credentials, resolver, network, or planner.
This increment must not weaken exact raw-response prefix checks, response/digest/decision
agreement, journal integrity, atomic publication, or tamper detection.

## 5. Tests required before calling the slice complete

Add focused policy/session tests and extend the physical investigation capstone to prove:

1. Consecutive non-observations reach the configured ceiling with no extra HTTP dispatch and
   a valid offline-verifiable, non-complete terminal record.
2. Repeated unchanged planner histories also stop; thought text and usage changes do not count
   as progress.
3. A real new HTTP observation resets the counter, and each kind of valid hypothesis/queue
   transition has the explicitly documented reset behavior.
4. Interrupted/resumed sessions preserve the counter and exact response prefix without
   replaying a terminal run or redispatching an unresolved read.
5. Changing the no-progress limit on resume is refused.
6. Existing unseeded and recon-seeded sessions retain their verification and resume behavior;
   legacy compatibility cases are tested explicitly.
7. Non-progress stopping cannot complete queue items or source hypotheses without observed
   same-item HTTP evidence.
8. Journal, policy, state, response, and recon-provenance tampering remain fail closed.
9. Offline verification works after repository deletion and fixture shutdown, using no network.
10. Call exhaustion, planner rejection, successful completion, and no-progress termination stay
    distinguishable in persisted state and reports.

Run at minimum:

- `cargo test --workspace --all-targets --locked --offline`
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`
- focused `rustfmt --check` for every changed Rust file
- `git -c safe.directory=/srv/oc-projects/smash diff --check`

Investigate any failed test rather than attributing it to unrelated work without evidence.
The repository-wide format check has a known unrelated `smash-loop` formatting blocker;
format changed files explicitly rather than mass-formatting that crate.

## 6. Documentation and handoff

After all checks pass, narrowly update the implemented M4 slice and Section 6 M4 exception in
`llm-red-teaming-roadmap.md` with the delivered stopping semantics, replay/resume behavior,
and test evidence. Update other existing operator documentation only if the new policy/report
surface actually requires it. Do not describe this plan file as delivered until implementation
and verification are complete.

Explicitly leave these for later decisions: hard wall-clock scheduling, model/token/cost
accounting, concurrency, kill switches, broader interleaved repository/HTTP planning,
novelty/dedup redesign, model-proposed mechanisms, hosted-model providers, live staging, and
production execution. Do not commit or stage files unless separately authorized.
