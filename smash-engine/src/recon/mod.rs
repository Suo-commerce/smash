//! M1 read-only repository reconnaissance.

pub mod bundle;
pub mod campaign;
pub mod repository;

pub use bundle::{
    bundle_digest, canonical_bundle_json, load_verified_campaign, verify_bundle, verify_campaign,
    write_campaign, ReconBundle, VerificationReport, VerifiedReconBundle,
    RECON_BUNDLE_SCHEMA_VERSION,
};
pub use campaign::{Campaign, CampaignRunner, CampaignStatus, ProposalRecord, ProviderRecord};
pub use repository::{Inspection, ReadOnlyRepository, RepositoryInspector};
