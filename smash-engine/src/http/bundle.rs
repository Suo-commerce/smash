//! Bounded execution-free HTTP evidence. Raw bodies and execution credentials
//! are intentionally not retained; a digest proves identity within a record,
//! not authenticity of the external target or its fixture provider.

use crate::canonical::parse_no_duplicates;
use crate::http::campaign::{
    verify_assessment, DifferentialVerdict, HttpCampaignError, HttpCampaignPolicy,
    HttpControlEvidence, HttpDifferentialAssessment,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const BUNDLE_VERSION: u32 = 1;
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpEvidenceBundle {
    pub bundle_version: u32,
    pub oracle_version: String,
    pub policy: HttpCampaignPolicy,
    pub broken: HttpControlEvidence,
    pub fixed: HttpControlEvidence,
    pub assessment: HttpDifferentialAssessment,
}

impl HttpEvidenceBundle {
    pub fn verify(&self) -> Result<DifferentialVerdict, HttpCampaignError> {
        if self.bundle_version != BUNDLE_VERSION
            || self.oracle_version != self.assessment.oracle_version
        {
            return Err(HttpCampaignError("unsupported HTTP bundle identity".into()));
        }
        verify_assessment(
            &self.policy,
            &self.broken,
            &self.fixed,
            &self.assessment,
            self.broken.cleanup_completed,
            self.fixed.cleanup_completed,
        )?;
        Ok(self.assessment.verdict)
    }
}

impl From<std::io::Error> for HttpCampaignError {
    fn from(value: std::io::Error) -> Self {
        Self(format!("HTTP evidence I/O failed: {value}"))
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, HttpCampaignError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_BUNDLE_BYTES
    {
        return Err(HttpCampaignError(
            "HTTP bundle input is not a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(HttpCampaignError(
            "HTTP bundle input exceeds its byte limit".into(),
        ));
    }
    Ok(bytes)
}

fn parse<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, HttpCampaignError> {
    let value = parse_no_duplicates(bytes)
        .map_err(|_| HttpCampaignError("HTTP bundle is not strict duplicate-free JSON".into()))?;
    serde_json::from_value(value)
        .map_err(|_| HttpCampaignError("HTTP bundle does not match its typed schema".into()))
}

pub fn verify_bundle(root: &Path) -> Result<HttpEvidenceBundle, HttpCampaignError> {
    let policy_bytes = read_bounded(&root.join("policy.json"))?;
    let bundle_bytes = read_bounded(&root.join("manifest.json"))?;
    let policy: HttpCampaignPolicy = parse(&policy_bytes)?;
    let bundle: HttpEvidenceBundle = parse(&bundle_bytes)?;
    if bundle.policy != policy || serde_json::to_vec(&bundle.policy)? != policy_bytes {
        return Err(HttpCampaignError(
            "HTTP policy differs from its exact bundle copy".into(),
        ));
    }
    bundle.verify()?;
    Ok(bundle)
}

pub fn persist_bundle(
    root: &Path,
    policy: HttpCampaignPolicy,
    broken: HttpControlEvidence,
    fixed: HttpControlEvidence,
    assessment: HttpDifferentialAssessment,
) -> Result<HttpEvidenceBundle, HttpCampaignError> {
    let bundle = HttpEvidenceBundle {
        bundle_version: BUNDLE_VERSION,
        oracle_version: assessment.oracle_version.clone(),
        policy,
        broken,
        fixed,
        assessment,
    };
    bundle.verify()?;
    if root.exists() {
        return Err(HttpCampaignError(
            "refusing to overwrite an HTTP evidence bundle".into(),
        ));
    }
    let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
    let stage = std::env::temp_dir().join(format!(
        ".smash-m3-bundle-write-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&stage)?;
    let result = (|| {
        write_json(&stage.join("policy.json"), &bundle.policy)?;
        write_json(&stage.join("manifest.json"), &bundle)?;
        verify_bundle(&stage)?;
        fs::rename(&stage, root)?;
        Ok(bundle)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), HttpCampaignError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(HttpCampaignError(
            "HTTP evidence exceeds its serialization bound".into(),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn persist_discovery(
    root: &Path,
    evidence: &HttpControlEvidence,
) -> Result<(), HttpCampaignError> {
    if crate::http::campaign::HttpControl::Observed != evidence.control {
        return Err(HttpCampaignError(
            "discovery requires an observed-only record".into(),
        ));
    }
    fs::create_dir(root)?;
    write_json(&root.join("discovery.json"), evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn partial_bundle_is_not_offline_verified() {
        let root = std::env::temp_dir().join(format!("smash-m3-empty-{}", std::process::id()));
        let _temp = Temp(root.clone());
        fs::create_dir(&root).unwrap();
        assert!(verify_bundle(&root).is_err());
    }
}
