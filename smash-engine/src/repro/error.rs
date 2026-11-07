use smash_core::execution::ReproDenial;
use std::fmt;

#[derive(Debug)]
pub enum ReproError {
    Io(std::io::Error),
    Json(serde_json::Error),
    ExecutionUnavailable(String),
    Policy(String),
    Evidence(String),
    Spawn(String),
    Cleanup(String),
    CleanupRestoration(String),
    Admission(ReproDenial),
    ArtifactChanged(String),
    Interrupted,
}
impl fmt::Display for ReproError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Json(e) => write!(f, "JSON: {e}"),
            Self::ExecutionUnavailable(s) => write!(f, "execution unavailable: {s}"),
            Self::Policy(s) => write!(f, "policy denied: {s}"),
            Self::Evidence(s) => write!(f, "evidence invalid: {s}"),
            Self::Spawn(s) => write!(f, "spawn error: {s}"),
            Self::Cleanup(s) => write!(f, "cleanup: {s}"),
            Self::CleanupRestoration(s) => write!(f, "cleanup restoration: {s}"),
            Self::Admission(e) => write!(f, "admission denied: {e:?}"),
            Self::ArtifactChanged(s) => write!(f, "artifact changed: {s}"),
            Self::Interrupted => write!(f, "interrupted with unresolved effects"),
        }
    }
}
impl std::error::Error for ReproError {}
impl From<std::io::Error> for ReproError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<serde_json::Error> for ReproError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<ReproDenial> for ReproError {
    fn from(e: ReproDenial) -> Self {
        Self::Admission(e)
    }
}
