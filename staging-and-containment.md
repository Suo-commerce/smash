# Smash — Staging & containment envelope (environment fidelity ladder)

Status: **SPEC / DRAFT** (Smash-side). Cross-cutting: governs where *any* fighter or
quarantined generator's probes are allowed to run, and how mutating effects stay fenced.
Reconciled against **SPEC-SMASH-001 v0.3** (§1 axes, §3, §5, §9, §13.H, §10),
`design/discovery-and-coverage.md`, and `specs/generator-boundary.md`.
Date: 2026-10-24.

## 0. The axis, and the one rule

v0.3 §1 keeps three design dimensions separate: **Authorization** (whose systems, which
effects), **Containment** (how effects stay within permission when the target fails),
and **Adversarial depth** (how hard we push). The generator spec bounds *trust*
(quarantine). This spec bounds *containment* and *fidelity* — a different axis.

**The one rule: as environment fidelity rises, containment must rise with it, and
authority and scope are re-established per environment, never inherited.**

And the distinction that makes "mutations may hamper the system, safely" coherent:

> **Damage to the target-under-test is in scope** — that is the test; breaking it is
> how we learn it is breakable. **Escape of effects beyond the fenced environment is
> never in scope.** The containment guarantee is not "don't break the target." It is
> "breakage stays inside the fence, and nothing reaches a real-world or shared service."

Testing *production software* (the real released code + config) in a *staging or
equivalent testing environment* is in scope. Testing a *production environment* (live
deployment, real users, real downstream) is out, with no override (§1 L2).

## 1. The fidelity ladder

| Rung | What's real | What's synthetic | Blast radius | Reset |
|---|---|---|---|---|
| **L0 Canary** (MVP; v0.3 §5/§7) | nothing but the gate logic under test | all data, credentials, downstream | fully reversible | dispose + reprovision |
| **L1 Staging / production-version** (v0.3 §13.H) | real gateway *version*, real policy config, real auth *paths* | data (synthetic), credentials (test), downstream (isolated/mocked) | bounded, resettable, no external effect | documented reset/reprovision |
| **L2 Production** | everything | nothing | real users / real downstream | — |

- **L0** is the default and the only rung the MVP uses. Mutations are fully reversible.
- **L1** is what "try on production software safely" means: the *software* is
  production-grade, the *environment* is one you own or are explicitly authorized to
  break, with real downstream effects mocked or sandboxed. This is v0.3 §13.H staging,
  with its full admission requirements (§2–§5 below).
- **L2 is a hard exclusion.** No capability, flag, config, or autonomous mode may target
  a production environment. v0.3 §13.H: "Production testing remains outside this
  proposed extension." Stated here as an invariant, not a default.

## 2. Per-environment authorization — no inheritance

Each environment declares, explicitly and fresh:

- its **target origin(s)** (normalized scheme/host/port; no wildcard — v0.3 §5);
- its **downstream scope** — the services the gateway is permitted to reach from within
  that environment;
- its **authority ceiling** (ReadOnly/Mutating) for that environment;
- an **operator authorization attestation** that the environment is owned or the
  operator is explicitly cleared to test it (v0.3 §3: the allowlist records *where*
  testing is permitted; it does not *prove* authorization — the operator is
  responsible). Targets are the operator's own projects or ones they are authorized to
  harden; nothing in this spec permits testing third-party systems without that.

**Nothing is inherited.** Permission for the gateway is not permission for every service
it can reach (v0.3 §13.H). Moving from L0 to L1 is a new scope declaration, a new
ceiling, a new preflight — not a promoted canary config. A quarantined generator's
candidates are admitted against *this environment's* scope/authority (generator spec
§4.4), so a candidate valid at L0 is re-checked, not grandfathered, at L1.

## 3. Downstream containment (the real blast-radius control)

The gateway under test can *reach* other services; that reach, not the gate itself, is
where real-world effects escape. Controls, strongest at higher fidelity:

- **Fenced egress.** The staging deployment's own outbound is restricted to fixture/mock
  dependencies. Allowlisting the gateway origin is insufficient without this downstream
  isolation (v0.3 §5, §7, §13.H). Transport keeps destination binding, no redirects, no
  env-proxy (v0.3 §5).
- **Real-effect sinks mocked or sandboxed.** Email, payments, external APIs, shared
  databases, message queues — any sink whose effect is externally visible or
  irreversible — are mocked at L1, never live. A sink that cannot be mocked and could
  cause such an effect is a **hard stop**: the probe class touching it is **not admitted
  for that environment**.
- **Shared dependencies need their own authorization + containment** (v0.3 §13.H). A
  dependency shared with anything real is treated as out-of-scope until separately
  fenced.

### 3.1 Storm Gate — concrete downstream catch (verify before any L1 mutating run)

Per the project facts, Storm Gate at `127.0.0.1:8019` has tools that hit **real**
backends even locally: `memory` / `cronjob_manage` reach `astral-memory-server` and
cron, and `send_email` is a real-effect sink (also PowerMove). **So "local" is not
automatically contained.** For any mutating probe at L1 (and for mutating canary runs
that route to these), either those backends are mocked/sandboxed for the test
environment, or the `memory` / `cronjob_manage` / `send_email` probe classes are not
admitted there. `web_extract` (plain-Write, non-taint_exempt) is the safe mutating
target precisely because its effect is a bounded fetch, not a real-world state change —
confirm it stays fenced (no egress to real sites) at L1 too.

## 4. Effect budget, observable completion, kill switch, reset

- **Documented effect budget per run** (v0.3 §13.H): bounded mutating operations and
  resource use, declared per environment. An autonomous mutating generator (phase 3) is
  the highest-blast-radius mode, so admission's per-candidate budgets **sum into a
  run-level ceiling** the loop cannot exceed; the loop halts at the ceiling.
- **Observable completion barrier** (v0.3 §7 step 5, §9): a timeout alone is never proof
  of no effect. L1's realer async makes this harder; if a bounded observation window
  cannot be established, the test cannot pass — it is Inconclusive, not green.
- **Kill switch.** Cancellation stops new dispatches immediately; already-dispatched
  effects may complete and must still be observed (v0.3 §9). For the autonomous loop,
  an operator kill-switch halts *generation and dispatch* at once.
- **Cleanup / reset** runs on completion and failure; crash recovery identifies
  abandoned resources. Cleanup failure blocks a green CI result while preserving any
  established finding (v0.3 §9).

### 4.1 Implemented M2 boundary — one synthetic fixture, not L1 staging

As of 2026-11-06, the opt-in authenticated-retry workflow uses supplied synthetic broken/fixed
roots and a reviewed byte-pinned Python driver. Its default runner requires supported unprivileged
Linux, Landlock/seccomp, `/usr/bin/python3`, and private temporary storage. Read-only source,
separate writable output, fixed argv/minimal environment, socket-syscall denial, resource limits,
and process-group cleanup are enforced for this path. Helper architecture/digest identity is not a
full host fingerprint. Unsupported setup, changed source, excess output, and cleanup/termination
uncertainty stay non-green; unsafe-development is explicitly uncontained and never a fallback.

This is a contained local pair for one scoped policy observation, not acceptance of arbitrary L0
canaries, L1 staging, production targets, untrusted builds, downstream effects, or executable
target packs. Its policy booleans do not independently prove operator authorization. Synced
checkpoints and atomic final reveal are best-effort persistence, not the complete crash-recovery and
abandoned-resource system above. Every new environment still needs the separate controls in this
draft; do not infer them from the M2 runner label or `Reproduced` result.

### 4.2 Implemented M3 boundary — typed loopback fixtures, not L1 staging

As of 2026-11-06, the separate `smash_engine::http` target pack admits reviewed static JSON
campaigns against declared disposable-fixture loopback origins. GET/POST route templates allow
only bounded flat strings, fixed paths/headers, declared credential names, and exact scalar JSON
fields. Redirects, idle connection reuse, and ambient proxies are disabled; TLS verification
remains enabled and admitted addresses are filtered by the actual connection resolver. Calls,
mutations, bodies, value sizes, and per-exchange timeouts are bounded. The campaign wall-clock
covers each control's `max_calls * timeout_ms` cooperatively between operations/timeouts.

Read-only discovery rejects any mutation. Mutation reproduction requires an explicit operator
flag and produces before/mutation/after and unknown-identity observations for both controls. The
`http-scalar-differential-v1` evaluator also requires all fixed expectations and a broken receipt
difference. It does not infer an effect from an accepted response alone. Both fixtures must be
genuinely dropped/closed by the owning provider; a callback is evidence of that lifecycle act, not
permission to assert `true` without it. Callbacks run after normal completion and campaign errors.
The generic CLI cannot attest teardown of an external fixture and therefore remains inconclusive
even with a scalar difference. The capstone owns its fixture, drops it and joins its server thread,
and verifies the completed offline evidence after shutdown.

Neither loopback socket checks nor bounded in-process fixture memory/threads are OS sandboxing.
The M3 capstones do not install seccomp/Landlock rules, isolate a child process, restrict arbitrary
fixture downstream sinks, discover routes, or implement L1 preflight/reset/crash recovery.
Credential environment lookup before dispatch and no ambient proxy inherit no declared downstream
egress restriction. Policy declarations are not independent proof of authority or containment.
A real-service/L1 adapter still requires the target-specific downstream fencing, synthetic data,
resource isolation, reset, and fresh authorization demanded by §§2–§5. M2's Linux sandbox does not
implicitly wrap these HTTP sockets or an external fixture.

An internally consistent reproduced result establishes only the specified scalar contract on the
provided fixture pair. It does not establish collection provenance, a signed assessment,
production fidelity, general exploitability, or security. Read-only observations are not
vulnerability findings. Cleanup failure, unknown or incomplete effects, and invalid/broken controls
are non-green outcomes rather than evidence that a target is safe.

## 5. Reporting fidelity — do not overclaim

Every report states the **environment profile**, its configuration differences from the
intended deployment, and the resulting **coverage limits** (v0.3 §13.H, §10). An L1
result must not imply production assurance where differences remain unknown.

The oracle asymmetry *widens* with fidelity. A KILL at L1 is a real, evidence-backed
finding. But a *clean* L1 run says even less than a clean L0 run: beyond "not secure"
(design-note §1), it is also "not production-assured," because fidelity gaps can mask
effects. A non-finding is never promoted to assurance at any rung, and least of all at
higher fidelity where more could be hidden.

## 6. Gating matrix — generator mode × fidelity rung

| | L0 Canary | L1 Staging | L2 Production |
|---|---|---|---|
| Fixed fighter (e.g. F-B, fighter #2) | allowed | allowed under §2–§5 | **forbidden** |
| Quarantined model-free generator (phase 2) | allowed | allowed under §2–§5 + effect ceiling (§4) | **forbidden** |
| Quarantined autonomous loop (phase 3) | allowed | allowed only with full §2–§5 set: downstream isolation, run-level effect ceiling, kill switch, reset, per-env authorization | **forbidden** |

Autonomy and fidelity compound blast radius, so the highest-autonomy mode at the
highest permitted fidelity (phase-3 loop at L1) carries the strictest containment set.
L2 is forbidden for every row.

## 7. Open questions for ratification (Jarmo + Hermes)

1. **L1 reset mechanism per target** — snapshot/reprovision, DB reset, container
   teardown? Needed before any mutating L1 run.
2. **Storm Gate L1 downstream list** — which sinks the staging gateway actually has, and
   which are mockable (§3.1). The `memory`/`cron`/`email` real-backend catch must be
   closed before L1.
3. **Effect-budget defaults** — pilot-measured per environment (v0.3 §11).
4. **Operator authorization attestation** — the mechanism that binds "I own / am cleared
   to test this environment" to a run config (§2).
5. **Autonomous-loop run-level ceiling + kill-switch** — the exact halt semantics for
   phase 3 at L1 (§4), to be fixed in the phase-3 spec.

## 8. Relationship to the other specs

- `specs/generator-boundary.md` bounds **trust** (quarantine, admission, candidate ≠
  finding). This spec bounds **containment/fidelity** (where admitted probes may run).
  They are orthogonal and both must hold.
- The **phase-3 autonomous loop** (blocked on this spec) inherits §4's run-level effect
  ceiling and kill switch as hard limits; its "adjust" feedback stays manifest-wall-clean
  typed verdicts (generator spec §7), so higher fidelity never pulls raw target output
  into the loop's strategy.
