//! M3 HTTP/API target pack.
//!
//! This is a separate, typed HTTP path; it does not turn M1 repository paths or
//! M2 artifact contents into executable HTTP requests. The initial target pack
//! admits only explicitly declared flat query/JSON fields on an attested
//! disposable fixture. Redirects and ambient proxies are disabled, credentials
//! are supplied only at dispatch, and the resolver filters the addresses used by
//! the actual connection rather than performing a separate advisory DNS check.

pub mod bundle;
pub mod campaign;
pub mod client;
pub mod investigation;
pub mod policy;
