//! Transport — the single controlled egress path.
//!
//! Every probe that reaches the network goes through here, and nowhere else.
//! That is the point: a controlled transport is where the "only approved calls
//! leave the executor, and only to where they are permitted" guarantee is
//! actually enforced on the wire, as a second wall independent of the capability
//! gate. The capability gate ([`Capability::authorize`]) decides whether a probe
//! *may* be built; this decides whether the bytes may actually *leave*, and to
//! where.
//!
//! [`Capability::authorize`]: smash_core::capability::Capability::authorize
//!
//! ## What it enforces
//!
//! - **Destination binding / egress allowlist.** The transport holds its own
//!   [`Scope`] of permitted origins and re-validates every request's target
//!   against it. An origin allowlist on the *target* does not constrain where a
//!   proxy's downstream calls go, so egress is restricted here, independently.
//!   A request to anything off the allowlist never reaches the sender.
//! - **No cross-origin redirect.** A redirect whose `Location` points off the
//!   target's origin is refused, not followed — a redirect is a classic way to
//!   turn an in-scope request into an off-scope one. Unparseable locations fail
//!   closed.
//! - **Bounded response.** A response larger than the run's byte limit is
//!   refused, bounding the blast radius of a hostile or runaway response.
//!
//! ## The Sender seam
//!
//! [`ControlledTransport`] wraps a [`Sender`] — the thing that actually speaks
//! HTTP. The controlled-egress rules live in the wrapper and are unit-tested
//! here with a fake sender, no network required. The real HTTP client is a
//! `Sender` impl added later (it is also where the walking-skeleton integration
//! slice plugs in). Any real `Sender` MUST:
//!
//! - never disable TLS verification, and never unset or bypass the configured
//!   proxy;
//! - bound the response read to the caller's limit while streaming, not merely
//!   report an over-limit body after the fact;
//! - not auto-follow redirects — surface the `Location` so the wrapper can apply
//!   the cross-origin rule.
//!
//! These cannot be enforced by a trait signature, so they are stated as the
//! contract every `Sender` is reviewed against.

use smash_core::capability::{Scope, Target};
use std::fmt;

// ── Request / response ──────────────────────────────────────────────────────

/// A request to send through the controlled egress. The `target` must be in the
/// transport's egress allowlist; `max_response_bytes` is the run's cap.
///
/// `headers` are connection headers (e.g. `Authorization`). They are injected by
/// the transport from its own configuration, not supplied by the probe layer,
/// and they are **never** recorded in evidence or logged — the `Debug` impl
/// redacts their values. Credentials are supplied out of band (spec §8).
#[derive(Clone, PartialEq, Eq)]
pub struct EgressRequest {
    pub target: Target,
    pub path: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub max_response_bytes: u64,
}

impl fmt::Debug for EgressRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact header values — an Authorization header must never land in a
        // log line or a Debug dump.
        let headers: Vec<String> = self
            .headers
            .iter()
            .map(|(k, _)| format!("{k}: <redacted>"))
            .collect();
        f.debug_struct("EgressRequest")
            .field("target", &self.target)
            .field("path", &self.path)
            .field("body", &self.body)
            .field("headers", &headers)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// What the sender returned before the wrapper's post-checks: a status, a body,
/// and any redirect `Location` the sender encountered (it must not follow one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub body: String,
    pub redirect_location: Option<String>,
}

/// A response that has passed the controlled-egress post-checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressResponse {
    pub status: u16,
    pub body: String,
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Why a dispatch was refused or failed. Each is a loggable fact; a refused
/// dispatch is unexecuted coverage, never a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// The request's target is not in the egress allowlist. Refused before the
    /// sender is ever called.
    DestinationNotInScope { target: Target },
    /// The sender encountered a redirect to a different origin. Refused, not
    /// followed.
    CrossOriginRedirect { to: String },
    /// The response exceeded the run's byte limit.
    ResponseTooLarge { limit: u64, got: u64 },
    /// The underlying send failed (connection, timeout, TLS, DNS, ...).
    Io { detail: String },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::DestinationNotInScope { target } => {
                write!(f, "destination {target} is not in the egress allowlist")
            }
            TransportError::CrossOriginRedirect { to } => {
                write!(f, "refused to follow cross-origin redirect to {to}")
            }
            TransportError::ResponseTooLarge { limit, got } => {
                write!(f, "response of {got} bytes exceeds the {limit}-byte limit")
            }
            TransportError::Io { detail } => write!(f, "transport error: {detail}"),
        }
    }
}

impl std::error::Error for TransportError {}

// ── The sender seam ──────────────────────────────────────────────────────────

/// The raw send. Implementations: a real HTTP client, or a fake for tests. See
/// the module docs for the invariants a real `Sender` is reviewed against.
///
/// The whole [`EgressRequest`] is passed, including `headers` (which the
/// transport has already populated from its configuration) and
/// `max_response_bytes` so a real client can bound the response read *while
/// streaming* rather than after the fact — a hostile multi-gigabyte response
/// must never be fully buffered. The wrapper applies the cap again as defense in
/// depth.
pub trait Sender {
    fn send(&self, request: &EgressRequest) -> Result<RawResponse, TransportError>;
}

// ── Controlled transport ─────────────────────────────────────────────────────

/// The single controlled egress path. Holds the egress allowlist and a
/// [`Sender`]; applies destination binding, the cross-origin redirect rule, and
/// the response-byte cap around every send.
pub struct ControlledTransport<S: Sender> {
    egress_allowlist: Scope,
    sender: S,
    default_headers: Vec<(String, String)>,
}

impl<S: Sender> ControlledTransport<S> {
    pub fn new(egress_allowlist: Scope, sender: S) -> Self {
        ControlledTransport {
            egress_allowlist,
            sender,
            default_headers: Vec::new(),
        }
    }

    /// Build a transport with connection headers (e.g. an `Authorization`
    /// header) applied to every request that does not carry its own. The
    /// credential is held here, at the connection, not in the probe layer, and
    /// the `EgressRequest` `Debug` impl redacts it.
    pub fn with_headers(
        egress_allowlist: Scope,
        sender: S,
        default_headers: Vec<(String, String)>,
    ) -> Self {
        ControlledTransport {
            egress_allowlist,
            sender,
            default_headers,
        }
    }

    /// The egress allowlist this transport enforces.
    pub fn allowlist(&self) -> &Scope {
        &self.egress_allowlist
    }

    /// The underlying sender. Exposed for inspection and composition; the
    /// controlled-egress rules are applied by [`dispatch`](Self::dispatch),
    /// never by reaching the sender directly.
    pub fn sender(&self) -> &S {
        &self.sender
    }

    /// Send a request through the controlled egress. Order matters: the
    /// destination is validated *before* the sender is touched, so an
    /// off-allowlist target never results in a network call.
    pub fn dispatch(&self, request: &EgressRequest) -> Result<EgressResponse, TransportError> {
        // 1. Destination binding — the independent second wall.
        if !self.egress_allowlist.contains(&request.target) {
            return Err(TransportError::DestinationNotInScope {
                target: request.target.clone(),
            });
        }

        // 2. Inject connection headers from configuration (unless the caller
        //    already set its own), then send. The probe layer never supplies
        //    credentials; they live here.
        let mut effective = request.clone();
        if effective.headers.is_empty() {
            effective.headers = self.default_headers.clone();
        }
        let raw = self.sender.send(&effective)?;

        // 3. No cross-origin redirect.
        if let Some(location) = &raw.redirect_location {
            if !same_origin(&request.target, location) {
                return Err(TransportError::CrossOriginRedirect {
                    to: location.clone(),
                });
            }
        }

        // 4. Bounded response.
        let got = raw.body.len() as u64;
        if got > request.max_response_bytes {
            return Err(TransportError::ResponseTooLarge {
                limit: request.max_response_bytes,
                got,
            });
        }

        Ok(EgressResponse {
            status: raw.status,
            body: raw.body,
        })
    }
}

/// Whether a redirect `location` stays on the target's origin. A relative
/// location (no scheme) stays on-origin; an absolute location must match the
/// target's origin exactly; an unparseable absolute location fails closed.
fn same_origin(target: &Target, location: &str) -> bool {
    if !location.contains("://") {
        // Relative redirect — same origin by definition.
        return true;
    }
    match origin_of(location) {
        Some(origin) => origin == target.as_str(),
        None => false,
    }
}

/// Extract `scheme://authority` from an absolute URL, dropping any path.
fn origin_of(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end];
    if scheme.is_empty() {
        return None;
    }
    let after = &url[scheme_end + 3..];
    let authority_end = after.find('/').unwrap_or(after.len());
    let authority = &after[..authority_end];
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn storm_gate() -> Target {
        Target::new("http://127.0.0.1:8019")
    }

    /// A fake sender: returns a canned result and records whether it was called,
    /// so tests can prove the destination check short-circuits before any send.
    struct FakeSender {
        result: Result<RawResponse, TransportError>,
        called: Cell<bool>,
    }

    impl FakeSender {
        fn ok(body: &str) -> Self {
            FakeSender {
                result: Ok(RawResponse {
                    status: 200,
                    body: body.to_string(),
                    redirect_location: None,
                }),
                called: Cell::new(false),
            }
        }

        fn raw(raw: RawResponse) -> Self {
            FakeSender {
                result: Ok(raw),
                called: Cell::new(false),
            }
        }

        fn failing() -> Self {
            FakeSender {
                result: Err(TransportError::Io {
                    detail: "connection refused".into(),
                }),
                called: Cell::new(false),
            }
        }
    }

    impl Sender for FakeSender {
        fn send(&self, _request: &EgressRequest) -> Result<RawResponse, TransportError> {
            self.called.set(true);
            self.result.clone()
        }
    }

    fn req(target: Target, max: u64) -> EgressRequest {
        EgressRequest {
            target,
            path: "/v1/chat/completions".into(),
            body: "{}".into(),
            headers: Vec::new(),
            max_response_bytes: max,
        }
    }

    // ── Destination binding ──────────────────────────────────────────

    #[test]
    fn in_scope_target_dispatches() {
        let t = ControlledTransport::new(Scope::new([storm_gate()]), FakeSender::ok("pong"));
        let resp = t.dispatch(&req(storm_gate(), 1024)).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "pong");
    }

    #[test]
    fn out_of_scope_target_never_reaches_the_sender() {
        let sender = FakeSender::ok("should not be sent");
        // Hold a handle to inspect `called` after dispatch.
        let t = ControlledTransport::new(Scope::new([storm_gate()]), sender);
        let elsewhere = Target::new("http://127.0.0.1:9999");
        let err = t.dispatch(&req(elsewhere.clone(), 1024)).unwrap_err();
        assert_eq!(
            err,
            TransportError::DestinationNotInScope { target: elsewhere }
        );
        assert!(
            !t.sender.called.get(),
            "destination check must short-circuit before the sender is called"
        );
    }

    // ── Redirect rule ────────────────────────────────────────────────

    #[test]
    fn cross_origin_redirect_is_refused() {
        let raw = RawResponse {
            status: 302,
            body: String::new(),
            redirect_location: Some("http://evil.example.com/collect".into()),
        };
        let t = ControlledTransport::new(Scope::new([storm_gate()]), FakeSender::raw(raw));
        let err = t.dispatch(&req(storm_gate(), 1024)).unwrap_err();
        assert_eq!(
            err,
            TransportError::CrossOriginRedirect {
                to: "http://evil.example.com/collect".into()
            }
        );
    }

    #[test]
    fn same_origin_redirect_is_allowed() {
        let raw = RawResponse {
            status: 302,
            body: "ok".into(),
            redirect_location: Some("http://127.0.0.1:8019/v2/chat".into()),
        };
        let t = ControlledTransport::new(Scope::new([storm_gate()]), FakeSender::raw(raw));
        assert!(t.dispatch(&req(storm_gate(), 1024)).is_ok());
    }

    #[test]
    fn relative_redirect_is_allowed() {
        let raw = RawResponse {
            status: 302,
            body: "ok".into(),
            redirect_location: Some("/v2/chat".into()),
        };
        let t = ControlledTransport::new(Scope::new([storm_gate()]), FakeSender::raw(raw));
        assert!(t.dispatch(&req(storm_gate(), 1024)).is_ok());
    }

    #[test]
    fn unparseable_absolute_redirect_fails_closed() {
        let raw = RawResponse {
            status: 302,
            body: String::new(),
            redirect_location: Some("://no-scheme/path".into()),
        };
        let t = ControlledTransport::new(Scope::new([storm_gate()]), FakeSender::raw(raw));
        assert!(matches!(
            t.dispatch(&req(storm_gate(), 1024)),
            Err(TransportError::CrossOriginRedirect { .. })
        ));
    }

    // ── Byte cap ─────────────────────────────────────────────────────

    #[test]
    fn oversized_response_is_refused() {
        let t = ControlledTransport::new(
            Scope::new([storm_gate()]),
            FakeSender::ok("0123456789"), // 10 bytes
        );
        let err = t.dispatch(&req(storm_gate(), 4)).unwrap_err();
        assert_eq!(err, TransportError::ResponseTooLarge { limit: 4, got: 10 });
    }

    #[test]
    fn response_at_the_limit_is_allowed() {
        let t = ControlledTransport::new(Scope::new([storm_gate()]), FakeSender::ok("1234"));
        assert!(t.dispatch(&req(storm_gate(), 4)).is_ok());
    }

    // ── Header injection ─────────────────────────────────────────────

    /// A sender that records the headers it was handed.
    struct HeaderRecordingSender {
        seen: std::cell::RefCell<Vec<(String, String)>>,
    }
    impl Sender for HeaderRecordingSender {
        fn send(&self, request: &EgressRequest) -> Result<RawResponse, TransportError> {
            *self.seen.borrow_mut() = request.headers.clone();
            Ok(RawResponse {
                status: 200,
                body: "ok".into(),
                redirect_location: None,
            })
        }
    }

    #[test]
    fn configured_headers_are_injected() {
        let sender = HeaderRecordingSender {
            seen: std::cell::RefCell::new(Vec::new()),
        };
        let t = ControlledTransport::with_headers(
            Scope::new([storm_gate()]),
            sender,
            vec![("Authorization".into(), "Bearer sk-test".into())],
        );
        t.dispatch(&req(storm_gate(), 1024)).unwrap();
        let seen = t.sender().seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "Authorization");
        assert_eq!(seen[0].1, "Bearer sk-test");
    }

    #[test]
    fn egress_request_debug_redacts_header_values() {
        let r = EgressRequest {
            target: storm_gate(),
            path: "/v1/chat/completions".into(),
            body: "{}".into(),
            headers: vec![("Authorization".into(), "Bearer super-secret".into())],
            max_response_bytes: 1024,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Authorization: <redacted>"));
        assert!(
            !dbg.contains("super-secret"),
            "the key must never appear in Debug"
        );
    }

    // ── IO propagation ───────────────────────────────────────────────

    #[test]
    fn sender_io_error_propagates() {
        let t = ControlledTransport::new(Scope::new([storm_gate()]), FakeSender::failing());
        let err = t.dispatch(&req(storm_gate(), 1024)).unwrap_err();
        assert!(matches!(err, TransportError::Io { .. }));
    }

    // ── origin_of unit checks ────────────────────────────────────────

    #[test]
    fn origin_of_extracts_scheme_and_authority() {
        assert_eq!(
            origin_of("http://127.0.0.1:8019/v1/chat"),
            Some("http://127.0.0.1:8019".into())
        );
        assert_eq!(
            origin_of("https://host.example"),
            Some("https://host.example".into())
        );
        assert_eq!(origin_of("://nope"), None);
        assert_eq!(origin_of("http://"), None);
    }
}
