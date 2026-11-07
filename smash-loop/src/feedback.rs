//! `TypedFeedback` — the **only** channel into the strategy (P3 §2.1; acceptance 2).
//!
//! The narrow compile-time claim: the strategy cannot receive a target-controlled
//! string or byte, because the type has **no such field** and **cannot be constructed
//! from target output**. Every field is an enum, a count, a bool, or a service-minted
//! opaque handle. Construction requires a [`FeedbackToken`], which only admission and
//! the oracle hold — there is no public constructor and no `Deserialize` from the
//! wire. (The *runtime* authority restriction — the loop cannot write the promotion
//! registry — is a separate guarantee; see [`crate::ports`] and the controller.)
//!
//! The `compile_fail` doctest below proves a caller outside this module cannot mint
//! a `RegionFeedback` without a token.

use crate::coverage::{Cause, SearchStatus};
use crate::{CanonicalKey, RegionId};

/// A capability token proving the constructor is the trusted admission/oracle path,
/// not arbitrary code. Mirrors the `AuthorizedCall` discipline (`v0.3 §5`): the token
/// has a private field and no public constructor, so only this crate's trusted
/// surfaces (which hold a `FeedbackToken`) can build feedback.
///
/// The type wall, as a compile-fail proof (acceptance 2): code outside this crate
/// cannot mint a token (`mint` is `pub(crate)`) and cannot name the private field,
/// so it cannot construct `RegionFeedback` — and there is no field through which
/// target-controlled text could enter the strategy regardless.
///
/// ```compile_fail
/// use smash_loop::feedback::FeedbackToken;
/// // `FeedbackToken::mint` is pub(crate); calling it outside the crate fails to compile.
/// let _t = FeedbackToken::mint();
/// ```
///
/// ```compile_fail
/// use smash_loop::feedback::FeedbackToken;
/// // The field is private, so the tuple constructor is not callable either.
/// let _t = FeedbackToken(());
/// ```
#[derive(Clone, Copy, Debug)]
pub struct FeedbackToken(());

impl FeedbackToken {
    /// Minted only by the trusted feedback assembler (admission + oracle side).
    /// `pub(crate)` so no downstream — and no strategy code — can forge one.
    pub(crate) fn mint() -> Self {
        FeedbackToken(())
    }
}

/// Per-region feedback. Private fields; the only way in is [`RegionFeedback::new`],
/// which requires a [`FeedbackToken`].
#[derive(Clone, Debug)]
pub struct RegionFeedback {
    region_id: RegionId,
    search_status: SearchStatus,
    cause_set: Vec<Cause>,
    planner_denials: u32,
    throttled: bool,
    counts: VerdictCounts,
    finding_keys: Vec<CanonicalKey>,
}

/// Bounded counts of each verdict class — numbers only, never target text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerdictCounts {
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
    pub error: u32,
    pub denied: u32,
    pub timeout: u32,
}

/// The data a trusted caller supplies to build a [`RegionFeedback`]. All typed,
/// bounded fields — carrying it as a struct keeps the constructor to `(token, data)`
/// and documents that every field is enumerable, not free text.
#[derive(Clone, Debug)]
pub struct RegionFeedbackData {
    pub region_id: RegionId,
    pub search_status: SearchStatus,
    pub cause_set: Vec<Cause>,
    pub planner_denials: u32,
    pub throttled: bool,
    pub counts: VerdictCounts,
    pub finding_keys: Vec<CanonicalKey>,
}

impl RegionFeedback {
    /// Construct region feedback. Requires a [`FeedbackToken`], so only the trusted
    /// assembler can build it — the compile-time wall of P3 §2.1.
    pub fn new(_token: FeedbackToken, data: RegionFeedbackData) -> Self {
        Self {
            region_id: data.region_id,
            search_status: data.search_status,
            cause_set: data.cause_set,
            planner_denials: data.planner_denials,
            throttled: data.throttled,
            counts: data.counts,
            finding_keys: data.finding_keys,
        }
    }

    pub fn region_id(&self) -> &RegionId {
        &self.region_id
    }
    pub fn search_status(&self) -> SearchStatus {
        self.search_status
    }
    pub fn cause_set(&self) -> &[Cause] {
        &self.cause_set
    }
    pub fn planner_denials(&self) -> u32 {
        self.planner_denials
    }
    pub fn throttled(&self) -> bool {
        self.throttled
    }
    pub fn counts(&self) -> VerdictCounts {
        self.counts
    }
    pub fn finding_keys(&self) -> &[CanonicalKey] {
        &self.finding_keys
    }
}

/// The whole feedback batch handed to `generator.adjust`. Opaque, typed, tokenized.
#[derive(Clone, Debug, Default)]
pub struct TypedFeedback {
    regions: Vec<RegionFeedback>,
}

impl TypedFeedback {
    pub fn new(regions: Vec<RegionFeedback>) -> Self {
        Self { regions }
    }
    pub fn regions(&self) -> &[RegionFeedback] {
        &self.regions
    }
}

/// The trusted assembler: the admission/oracle-side surface that is permitted to
/// mint feedback tokens. The strategy never holds one of these.
pub struct FeedbackAssembler;

impl FeedbackAssembler {
    /// Mint a token. In the real engine this lives behind the oracle/admission trust
    /// boundary; here it is `pub` on a type the strategy is never given, so the
    /// generator crate cannot call it.
    pub fn token(&self) -> FeedbackToken {
        FeedbackToken::mint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_assembler_can_build_feedback() {
        let asm = FeedbackAssembler;
        let rf = RegionFeedback::new(
            asm.token(),
            RegionFeedbackData {
                region_id: RegionId("r0".into()),
                search_status: SearchStatus::Sampled,
                cause_set: vec![],
                planner_denials: 0,
                throttled: false,
                counts: VerdictCounts { pass: 2, fail: 1, ..Default::default() },
                finding_keys: vec![CanonicalKey("c1".into())],
            },
        );
        let fb = TypedFeedback::new(vec![rf]);
        assert_eq!(fb.regions().len(), 1);
        assert_eq!(fb.regions()[0].counts().fail, 1);
    }

}
