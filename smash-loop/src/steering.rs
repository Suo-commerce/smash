//! The adaptive steering math (P3 §2 throttle/saturation split + §3.3 suppression
//! and the abort threshold). Build-order item 3, sub-unit 1.
//!
//! This is the decision core of the "adjust" step, kept — like [`crate::driver`] — as
//! a **pure function of already-evaluated per-region signals**, so the whole steering
//! contract is testable without a generator, a gate, or a live budget. The orchestrator
//! computes each region's two-axis [`RegionCoverage`] (via [`crate::coverage`]) and the
//! per-region attempt count, hands them here, and acts on the returned decision:
//!
//! - **Earned saturation (§2).** A region counts as covered *only* when it is
//!   sample-resolved (`Sampled` and every attempt `Pass`/`Fail`). Fails in a
//!   sample-resolved region are findings, not a reason to keep probing.
//! - **Intensify on `Fail` (§2).** A region that produced a `Fail` is flagged for
//!   intensification *within that region*; the orchestrator sizes the extra draws from
//!   the intensification ledger ([`crate::ceiling`]).
//! - **Operational throttle (§2, §3.3).** A region showing a *target-induced*
//!   operational signal (`OpError`/`OpTimeout`) once it has had a fair sample
//!   (`attempts ≥ attempted_probe_floor`) is throttled — dispatch to it is reduced so
//!   the run does not burn budget on an unresolved gap. Throttling **never** marks a
//!   region covered.
//! - **Suppression freeze (§3.3).** `suppression_fraction = |throttled| / |envelope|`.
//!   Once it reaches `suppression_cap`, the run **freezes**: it stops throttling
//!   *additional* regions and holds the current ones (it does not restore them — n6),
//!   and it keeps exploring the un-throttled regions. Freeze does **not** halt.
//! - **Abort threshold (§3.3, N1).** Over the **attempted** set only,
//!   `unresolved_fraction = |{attempted ∧ cause_set ≠ ∅}| / |{attempted}|`, evaluated
//!   once `|attempted| ≥ gap_floor`; the run aborts when it exceeds `gap_tolerance`.
//!   `unvisited` regions are excluded from both numerator and denominator, so the
//!   fraction is not pinned near 1.0 on the first iteration (the rev-4 bug).
//!
//! The two fractions range over different universes — throttled/all vs
//! unresolved/attempted — so there is no ordering constraint between `suppression_cap`
//! and `gap_tolerance` (the retired rev-3 inequality). Their joint intent: *freeze
//! throttling before the attempted set is mostly unresolved; abort only if, among
//! regions actually tried, the unresolved share exceeds tolerance.*

use crate::coverage::{Cause, RegionCoverage};
use crate::RegionId;

/// The steering parameters (the subset of P3 §13 item 1 this stage needs).
#[derive(Clone, Debug)]
pub struct SteeringConfig {
    /// Minimum dispatched probes in a region before it may be throttled (M5). Must be
    /// `≤` every envelope region's `adequacy_target` — see [`validate_floor`] — or a
    /// region could be throttled out of resolvability before it could ever be sampled.
    pub attempted_probe_floor: u64,
    /// The throttled-fraction ceiling. On reaching it the run freezes (holds current
    /// throttles, throttles no more). In `[0.0, 1.0]`.
    pub suppression_cap: f64,
    /// The unresolved-fraction (over the attempted set) above which the run aborts.
    pub gap_tolerance: f64,
    /// Minimum number of *attempted* regions before the abort check is evaluated.
    pub gap_floor: u64,
}

/// One region's already-evaluated state for this iteration. The orchestrator fills it
/// from the run's counters; `coverage` is the two-axis state from [`crate::coverage`].
#[derive(Clone, Debug)]
pub struct RegionObservation {
    pub region: RegionId,
    /// Dispatched-probe count (N3). A region is *attempted* iff this is `> 0`.
    pub attempts: u64,
    /// The region's two-axis coverage (status + cause set), already computed.
    pub coverage: RegionCoverage,
    /// A `Fail` was observed in this region this run (the intensify trigger).
    pub fail_seen: bool,
    /// The region is already throttled from a prior iteration (throttling is sticky —
    /// n6: held, never restored). Such a region is not re-added to `throttle_now`.
    pub already_throttled: bool,
}

/// The steering decision for one iteration. Only [`abort`](SteeringDecision::abort)
/// stops the run (→ `StopReason::GapToleranceExceeded`); the rest shape the next batch.
#[derive(Clone, Debug, PartialEq)]
pub struct SteeringDecision {
    /// Regions newly throttled this iteration (bounded by the suppression freeze).
    pub throttle_now: Vec<RegionId>,
    /// Regions that are sample-resolved — covered, stop probing them.
    pub saturated: Vec<RegionId>,
    /// Fault regions to intensify within (ledger-sized by the orchestrator).
    pub intensify: Vec<RegionId>,
    /// `|throttled| / |envelope|` after this iteration's throttling.
    pub suppression_fraction: f64,
    /// The suppression cap has been reached — throttle no additional regions.
    pub frozen: bool,
    /// The unresolved fraction over the attempted set exceeded `gap_tolerance`.
    pub abort: bool,
}

/// `attempted_probe_floor > adequacy_target` for some region — the M5 invariant is
/// violated and throttling could strand a region short of sample-resolution.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FloorAboveAdequacy {
    pub floor: u64,
    pub adequacy_target: u64,
}

/// Validate the M5 invariant at run start: `attempted_probe_floor ≤ adequacy_target`
/// for every envelope region. Call once before the loop; the per-iteration
/// [`decide`] then stays infallible.
pub fn validate_floor(
    attempted_probe_floor: u64,
    adequacy_targets: &[u64],
) -> Result<(), FloorAboveAdequacy> {
    for &adequacy_target in adequacy_targets {
        if attempted_probe_floor > adequacy_target {
            return Err(FloorAboveAdequacy { floor: attempted_probe_floor, adequacy_target });
        }
    }
    Ok(())
}

fn fraction(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

/// A target-induced operational signal — the only throttle trigger (N3). A broken
/// control or other oracle-inconclusive (`UnresolvedVerdict`) is *not* target-induced
/// and never throttles.
fn has_operational_signal(cov: &RegionCoverage) -> bool {
    cov.causes.iter().any(|c| matches!(c, Cause::OpError | Cause::OpTimeout))
}

/// The abort check (§3.3, N1): over the attempted set only, once at least `gap_floor`
/// regions have been attempted, abort when the unresolved share exceeds `gap_tolerance`.
fn abort_check(cfg: &SteeringConfig, envelope: &[RegionObservation]) -> bool {
    let attempted: Vec<&RegionObservation> =
        envelope.iter().filter(|o| o.attempts > 0).collect();
    if attempted.is_empty() || (attempted.len() as u64) < cfg.gap_floor {
        return false;
    }
    // `cause_set ≠ ∅` for an attempted region is exactly "not sample-resolved".
    let unresolved = attempted.iter().filter(|o| !o.coverage.causes.is_empty()).count();
    fraction(unresolved, attempted.len()) > cfg.gap_tolerance
}

/// Decide the iteration's steering from the per-region observations. Pure and
/// deterministic: throttle selection follows `envelope` order, so a given run state
/// always yields the same decision.
pub fn decide(cfg: &SteeringConfig, envelope: &[RegionObservation]) -> SteeringDecision {
    let total = envelope.len();
    let mut throttle_now = Vec::new();
    let mut saturated = Vec::new();
    let mut intensify = Vec::new();

    // Regions already throttled coming in (sticky — n6) count toward the fraction.
    let mut throttled_count = envelope.iter().filter(|o| o.already_throttled).count();

    for obs in envelope {
        let resolved = obs.coverage.is_sample_resolved();
        if resolved {
            saturated.push(obs.region.clone());
        }
        if obs.fail_seen {
            intensify.push(obs.region.clone());
        }

        // Throttle eligibility: a fresh region (not already throttled), unresolved, that
        // has had a fair sample and shows a target-induced operational signal. Once the
        // throttled fraction has reached the cap, freeze — add no more (§3.3).
        let eligible = !obs.already_throttled
            && !resolved
            && obs.attempts >= cfg.attempted_probe_floor
            && has_operational_signal(&obs.coverage);
        if eligible && fraction(throttled_count, total) < cfg.suppression_cap {
            throttle_now.push(obs.region.clone());
            throttled_count += 1;
        }
    }

    let suppression_fraction = fraction(throttled_count, total);
    let frozen = suppression_fraction >= cfg.suppression_cap;
    let abort = abort_check(cfg, envelope);

    SteeringDecision { throttle_now, saturated, intensify, suppression_fraction, frozen, abort }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::RegionCoverage;
    use crate::verdict::{InconclusiveReason, ProbeOutcome::*};

    fn region(n: &str) -> RegionId {
        RegionId(n.into())
    }

    /// A sample-resolved region (every attempt Pass/Fail at adequacy).
    fn resolved_obs(n: &str) -> RegionObservation {
        RegionObservation {
            region: region(n),
            attempts: 2,
            coverage: RegionCoverage::compute(&[Pass, Fail], 2, false, 0, false),
            fail_seen: true, // a Fail in a sample-resolved region is a finding, still covered
            already_throttled: false,
        }
    }

    /// An op-timeout region (target-induced signal), given attempt count.
    fn timeout_obs(n: &str, attempts: u64, already_throttled: bool) -> RegionObservation {
        let outcomes: Vec<_> = (0..attempts)
            .map(|i| if i == 0 { Pass } else { Inconclusive(InconclusiveReason::Timeout) })
            .collect();
        RegionObservation {
            region: region(n),
            attempts,
            coverage: RegionCoverage::compute(&outcomes, attempts.max(1), false, 0, already_throttled),
            fail_seen: false,
            already_throttled,
        }
    }

    fn unvisited_obs(n: &str) -> RegionObservation {
        RegionObservation {
            region: region(n),
            attempts: 0,
            coverage: RegionCoverage::compute(&[], 2, false, 0, false),
            fail_seen: false,
            already_throttled: false,
        }
    }

    fn cfg() -> SteeringConfig {
        SteeringConfig {
            attempted_probe_floor: 2,
            suppression_cap: 1.0, // never freeze, unless a test overrides
            gap_tolerance: 0.5,
            gap_floor: 100, // no abort, unless a test overrides
        }
    }

    #[test]
    fn fail_region_is_flagged_for_intensification() {
        let d = decide(&cfg(), &[resolved_obs("r0")]);
        assert_eq!(d.intensify, vec![region("r0")]);
    }

    #[test]
    fn sample_resolved_region_is_saturated_not_throttled() {
        let d = decide(&cfg(), &[resolved_obs("r0")]);
        assert_eq!(d.saturated, vec![region("r0")]);
        assert!(d.throttle_now.is_empty(), "a covered region is never throttled");
    }

    #[test]
    fn op_signal_below_floor_is_not_throttled() {
        // floor is 2; one attempt with a timeout is below the fair-sample floor.
        let d = decide(&cfg(), &[timeout_obs("r0", 1, false)]);
        assert!(d.throttle_now.is_empty());
    }

    #[test]
    fn op_signal_at_floor_is_throttled() {
        let d = decide(&cfg(), &[timeout_obs("r0", 2, false)]);
        assert_eq!(d.throttle_now, vec![region("r0")]);
    }

    #[test]
    fn broken_control_is_not_a_throttle_trigger() {
        // A non-timeout inconclusive is UnresolvedVerdict (N2), not target-induced.
        let obs = RegionObservation {
            region: region("r0"),
            attempts: 2,
            coverage: RegionCoverage::compute(
                &[Pass, Inconclusive(InconclusiveReason::BrokenControl)],
                2, false, 0, false,
            ),
            fail_seen: false,
            already_throttled: false,
        };
        let d = decide(&cfg(), &[obs]);
        assert!(d.throttle_now.is_empty(), "only op_error/op_timeout throttle");
    }

    #[test]
    fn already_throttled_region_is_not_re_added() {
        let d = decide(&cfg(), &[timeout_obs("r0", 2, true)]);
        assert!(d.throttle_now.is_empty(), "sticky throttle is held, not re-added");
        assert_eq!(d.suppression_fraction, 1.0);
    }

    #[test]
    fn suppression_freezes_at_cap() {
        // cap 0.5, 4 regions, 2 already throttled (frac 0.5) → frozen, no new throttle
        // even though the other two are throttle-eligible.
        let mut c = cfg();
        c.suppression_cap = 0.5;
        let env = vec![
            timeout_obs("r0", 2, true),
            timeout_obs("r1", 2, true),
            timeout_obs("r2", 2, false),
            timeout_obs("r3", 2, false),
        ];
        let d = decide(&c, &env);
        assert!(d.throttle_now.is_empty(), "frozen at the cap: throttle no more");
        assert!(d.frozen);
        assert_eq!(d.suppression_fraction, 0.5);
    }

    #[test]
    fn abort_waits_for_gap_floor() {
        // Two attempted, both unresolved (fraction 1.0 > tolerance), but gap_floor is 5.
        let mut c = cfg();
        c.gap_floor = 5;
        let env = vec![timeout_obs("r0", 2, false), timeout_obs("r1", 2, false)];
        assert!(!decide(&c, &env).abort, "below gap_floor, no abort");
    }

    #[test]
    fn abort_when_unresolved_fraction_exceeds_tolerance() {
        let mut c = cfg();
        c.gap_floor = 1;
        c.gap_tolerance = 0.5;
        // Two attempted, both unresolved → 1.0 > 0.5.
        let env = vec![timeout_obs("r0", 2, false), timeout_obs("r1", 2, false)];
        assert!(decide(&c, &env).abort);
    }

    #[test]
    fn unvisited_regions_are_excluded_from_the_abort_denominator() {
        // The rev-4 bug: 1 attempted-resolved + 3 unvisited must be 0/1, not 3/4.
        let mut c = cfg();
        c.gap_floor = 1;
        c.gap_tolerance = 0.5;
        let env = vec![
            resolved_obs("r0"), // attempted, cause_set empty
            unvisited_obs("r1"),
            unvisited_obs("r2"),
            unvisited_obs("r3"),
        ];
        let d = decide(&c, &env);
        assert!(!d.abort, "unvisited regions do not pin the unresolved fraction");
    }

    #[test]
    fn validate_floor_rejects_a_floor_above_any_adequacy_target() {
        assert!(validate_floor(2, &[8, 4, 2]).is_ok());
        assert_eq!(
            validate_floor(5, &[8, 4]),
            Err(FloorAboveAdequacy { floor: 5, adequacy_target: 4 }),
        );
    }

    #[test]
    fn empty_envelope_is_safe() {
        let d = decide(&cfg(), &[]);
        assert!(d.throttle_now.is_empty() && !d.abort && !d.frozen);
        assert_eq!(d.suppression_fraction, 0.0);
    }
}
