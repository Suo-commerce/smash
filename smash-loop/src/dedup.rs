//! Stage 7 — within-run dedup/merge (P3 §4 stage 7; `admission-funnel` spec §2).
//!
//! The *identity* half of admission, complementary to [`crate::quiescence`] (the
//! *safety* half). Quiescence answers "did an effect hang?" (poison + barrier); this
//! answers "have we already seen — or are we already running — this exact validated
//! candidate?" It is keyed on [`CanonicalKey`], the content-only **finding** identity
//! shared by the generator and the findings ledger. This reservation table is the
//! *within-run* twin of the ledger's durable cross-run dedup: it stops the dispatcher
//! re-firing the same probe inside a single run.
//!
//! **Ordering (spec §2), enforced by the caller around this table:**
//!   validate params → recompute `CanonicalKey` from the validated inputs → **poison
//!   check** → **atomic reserve** → merge later occurrences. This module owns the
//!   reserve / merge / commit state machine; the caller supplies the poison verdict
//!   (poison lives in `quiescence`, run-scoped) so this table stays independently
//!   testable. Poison is checked **before** any merge — a poisoned key drops, it never
//!   merges (spec §2.2).
//!
//! **Failure handling (spec §2.5).** A clean failure *before* dispatch may
//! [`release`](DedupTable::release) the reservation so the key can be proposed again
//! later in the run. An **uncertain** execution (effect unknown) must NOT silently
//! retry — [`mark_uncertain`](DedupTable::mark_uncertain) holds the slot permanently so
//! neither a duplicate nor a fresh re-proposal can ever re-dispatch that key. That is
//! belt-and-braces with the quiescence poison the caller sets on the same event.
//!
//! **Finding identity vs execution identity (spec §2).** The key is content-only. This
//! increment **freezes environment/context for the run** (one per run, consistent with
//! the Tier-A loop); widening the *execution* identity to carry context so distinct
//! contexts don't collapse into one execution is a documented later addition, not an
//! accident.

use crate::CanonicalKey;
use std::collections::BTreeMap;

/// The stringified execution identity (e.g. a `smash_core::correlation::CorrelationKey`)
/// the first dispatch ran under, kept so merged duplicates point at the original
/// execution rather than re-dispatching.
pub type ExecutionRef = String;

/// A provenance tag for one sighting (e.g. proposal id / epoch), retained for audit.
pub type Provenance = String;

/// The lifecycle of a reserved key within a run.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SlotState {
    /// Reserved, dispatch in flight, not yet resolved.
    InFlight,
    /// Reserved then resolved terminally; carries the original execution reference.
    Resolved(ExecutionRef),
    /// Reserved then ended uncertain — held permanently, never re-dispatchable.
    Uncertain,
}

#[derive(Clone, Debug)]
struct Slot {
    state: SlotState,
    /// The first sighting's provenance, then every merged duplicate's.
    sightings: Vec<Provenance>,
}

/// The ordered outcome of presenting one validated candidate to the table (spec §2
/// steps 2–4). Only [`Reserved`](DedupOutcome::Reserved) authorizes a dispatch; every
/// other variant means "do not dispatch."
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DedupOutcome {
    /// First sighting of this key: reserved. The caller proceeds to dispatch and must
    /// later [`commit`](DedupTable::commit) (resolved), [`release`](DedupTable::release)
    /// (clean pre-dispatch failure), or [`mark_uncertain`](DedupTable::mark_uncertain)
    /// (uncertain effect).
    Reserved,
    /// A duplicate arrived while the key is still in flight — merged, no re-dispatch.
    MergedInFlight,
    /// A duplicate of an already-resolved key — merged into the original execution
    /// (carried here), no re-dispatch.
    MergedResolved(ExecutionRef),
    /// A duplicate of an uncertain-held key — merged, never re-dispatched.
    MergedUncertain,
    /// The key is poisoned — dropped before any merge (spec §2.2). The caller records a
    /// `RejectedAtAdmission` coverage row.
    DroppedPoisoned,
}

/// Run-scoped seen-set + reservation table. The seen-set is the `Resolved` slots; the
/// reservation table is the `InFlight`/`Uncertain` slots. Durable cross-run dedup is
/// the findings ledger's job, not this one.
#[derive(Debug, Default)]
pub struct DedupTable {
    slots: BTreeMap<CanonicalKey, Slot>,
}

impl DedupTable {
    pub fn new() -> Self {
        Self { slots: BTreeMap::new() }
    }

    /// The ordered reserve/merge decision for one validated candidate (spec §2 steps
    /// 2–4). `poisoned` is the caller's poison verdict (from `quiescence`), checked
    /// **before** any merge; `provenance` tags this sighting for audit.
    ///
    /// Poison wins over everything: a poisoned key is dropped even if a reservation
    /// already exists, and the drop records no merge.
    pub fn reserve(
        &mut self,
        key: &CanonicalKey,
        poisoned: bool,
        provenance: Provenance,
    ) -> DedupOutcome {
        // Step 2: poison precedes merge.
        if poisoned {
            return DedupOutcome::DroppedPoisoned;
        }
        match self.slots.get_mut(key) {
            None => {
                // Step 3: the atomic first reservation.
                self.slots.insert(
                    key.clone(),
                    Slot { state: SlotState::InFlight, sightings: vec![provenance] },
                );
                DedupOutcome::Reserved
            }
            Some(slot) => {
                // Step 4: merge later occurrences into the reservation, never re-dispatch.
                slot.sightings.push(provenance);
                match &slot.state {
                    SlotState::InFlight => DedupOutcome::MergedInFlight,
                    SlotState::Resolved(r) => DedupOutcome::MergedResolved(r.clone()),
                    SlotState::Uncertain => DedupOutcome::MergedUncertain,
                }
            }
        }
    }

    /// Terminal clean resolution: move an in-flight reservation to resolved, recording
    /// the execution reference that later duplicates merge into. Returns `false` (a
    /// no-op) if the key is not in flight — a resolved/uncertain slot is never
    /// overwritten.
    pub fn commit(&mut self, key: &CanonicalKey, execution: ExecutionRef) -> bool {
        match self.slots.get_mut(key) {
            Some(slot) if matches!(slot.state, SlotState::InFlight) => {
                slot.state = SlotState::Resolved(execution);
                true
            }
            _ => false,
        }
    }

    /// A clean failure *before* dispatch releases the reservation so the key may be
    /// proposed again later in the run (spec §2.5, the permitted release). Only an
    /// in-flight slot is released; a resolved or uncertain slot is never released, so
    /// this returns `false` for them.
    pub fn release(&mut self, key: &CanonicalKey) -> bool {
        match self.slots.get(key) {
            Some(slot) if matches!(slot.state, SlotState::InFlight) => {
                self.slots.remove(key);
                true
            }
            _ => false,
        }
    }

    /// An uncertain execution (effect unknown): hold the slot permanently (spec §2.5 —
    /// "an uncertain execution must not silently allow a retry"). The key can never be
    /// re-reserved or re-dispatched for the rest of the run; duplicates and fresh
    /// re-proposals both return [`DedupOutcome::MergedUncertain`]. Returns `false` if the
    /// key is not in flight.
    pub fn mark_uncertain(&mut self, key: &CanonicalKey) -> bool {
        match self.slots.get_mut(key) {
            Some(slot) if matches!(slot.state, SlotState::InFlight) => {
                slot.state = SlotState::Uncertain;
                true
            }
            _ => false,
        }
    }

    /// Whether the key currently occupies a slot (in flight, resolved, or uncertain).
    pub fn is_reserved(&self, key: &CanonicalKey) -> bool {
        self.slots.contains_key(key)
    }

    /// Sightings recorded for a key (1 original + each merge), or 0 if unseen. A
    /// poisoned drop records nothing, so it never increments this.
    pub fn sighting_count(&self, key: &CanonicalKey) -> usize {
        self.slots.get(key).map(|s| s.sightings.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> CanonicalKey {
        CanonicalKey(s.into())
    }

    #[test]
    fn first_sighting_reserves() {
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), false, "p1".into()), DedupOutcome::Reserved);
        assert!(t.is_reserved(&k("a")));
        assert_eq!(t.sighting_count(&k("a")), 1);
    }

    #[test]
    fn concurrent_duplicate_only_one_executes() {
        // §7: concurrent duplicate proposals — only one is reserved (dispatched).
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), false, "first".into()), DedupOutcome::Reserved);
        assert_eq!(t.reserve(&k("a"), false, "second".into()), DedupOutcome::MergedInFlight);
        // The merge is recorded as provenance; no second reservation, no re-dispatch.
        assert_eq!(t.sighting_count(&k("a")), 2);
    }

    #[test]
    fn poisoned_duplicate_dropped_before_merge() {
        // §7 / §2.2: a poisoned key drops before any merge — sighting count unchanged.
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), false, "first".into()), DedupOutcome::Reserved);
        assert_eq!(t.reserve(&k("a"), true, "poisoned-dup".into()), DedupOutcome::DroppedPoisoned);
        assert_eq!(t.sighting_count(&k("a")), 1, "a dropped duplicate must not be merged");
    }

    #[test]
    fn poisoned_first_sighting_is_dropped_not_reserved() {
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), true, "p1".into()), DedupOutcome::DroppedPoisoned);
        assert!(!t.is_reserved(&k("a")), "a poisoned key must never reserve");
    }

    #[test]
    fn resolved_duplicate_merges_into_original_execution() {
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), false, "first".into()), DedupOutcome::Reserved);
        assert!(t.commit(&k("a"), "exec-7".into()));
        match t.reserve(&k("a"), false, "late-dup".into()) {
            DedupOutcome::MergedResolved(e) => assert_eq!(e, "exec-7"),
            other => panic!("expected merge into resolved execution, got {other:?}"),
        }
        assert_eq!(t.sighting_count(&k("a")), 2);
    }

    #[test]
    fn clean_pre_dispatch_failure_releases_for_reproposal() {
        // §2.5: a clean failure before dispatch releases the reservation.
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), false, "p1".into()), DedupOutcome::Reserved);
        assert!(t.release(&k("a")));
        assert!(!t.is_reserved(&k("a")));
        // Freed: the key may be reserved again cleanly.
        assert_eq!(t.reserve(&k("a"), false, "p2".into()), DedupOutcome::Reserved);
    }

    #[test]
    fn release_only_applies_to_in_flight() {
        let mut t = DedupTable::new();
        t.reserve(&k("a"), false, "p1".into());
        assert!(t.commit(&k("a"), "exec".into()));
        assert!(!t.release(&k("a")), "a resolved reservation must not be released");
        assert!(t.is_reserved(&k("a")));
    }

    #[test]
    fn uncertain_execution_is_never_retried() {
        // §2.5: an uncertain execution must not silently allow a retry.
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), false, "first".into()), DedupOutcome::Reserved);
        assert!(t.mark_uncertain(&k("a")));
        // A duplicate merges — never re-dispatches.
        assert_eq!(t.reserve(&k("a"), false, "dup".into()), DedupOutcome::MergedUncertain);
        // A fresh re-proposal of the same key is also held, not reserved.
        assert_eq!(t.reserve(&k("a"), false, "reproposal".into()), DedupOutcome::MergedUncertain);
        assert!(!t.release(&k("a")), "an uncertain-held slot can never be released");
    }

    #[test]
    fn commit_and_uncertain_only_apply_to_in_flight() {
        let mut t = DedupTable::new();
        assert!(!t.commit(&k("ghost"), "exec".into()));
        assert!(!t.mark_uncertain(&k("ghost")));
    }

    #[test]
    fn distinct_keys_are_independent() {
        let mut t = DedupTable::new();
        assert_eq!(t.reserve(&k("a"), false, "pa".into()), DedupOutcome::Reserved);
        assert_eq!(t.reserve(&k("b"), false, "pb".into()), DedupOutcome::Reserved);
        assert!(t.commit(&k("a"), "exec-a".into()));
        // b is untouched by a's resolution.
        assert_eq!(t.reserve(&k("b"), false, "pb2".into()), DedupOutcome::MergedInFlight);
    }
}
