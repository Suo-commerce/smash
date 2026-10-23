//! The live HTTP [`Sender`] — the real network behind the controlled transport.
//!
//! This is the one place in the engine that actually opens a socket. Everything
//! above it ([`ControlledTransport`](crate::transport::ControlledTransport),
//! [`execute_probe`](crate::execute::execute_probe)) is unit-tested with a fake;
//! this impl is what turns the vertical slice into a real probe against a live
//! Storm Gate. It is intentionally small and holds to the `Sender` contract:
//!
//! - **No redirect following.** The agent is built with `redirects(0)`. A 3xx
//!   comes back as a response with its `Location` header surfaced, so the
//!   transport — not the client — applies the cross-origin rule.
//! - **Bounded read.** The response body is read through `take(max + 1)`, so a
//!   hostile or runaway response is never fully buffered; one byte over the cap
//!   is enough for the transport to reject it.
//! - **No TLS bypass, no proxy games.** `ureq` verifies TLS by default and this
//!   impl never disables it; it uses `ureq`'s default agent configuration and
//!   does not unset or override the environment's proxy.
//!
//! An HTTP error status (4xx/5xx) is a *response*, not a transport failure: the
//! gateway answered. Only a genuine transport fault (connection refused, reset,
//! timeout, TLS failure, DNS) becomes [`TransportError::Io`], which the executor
//! treats as `Unresolved` — effects unknown.
//!
//! What this sender does **not** do: attach authentication or session headers.
//! Credentials are supplied out of band per the spec, and header injection is a
//! transport-config concern to add when a target needs it — it is deliberately
//! not baked into this minimal sender.

use crate::transport::{EgressRequest, RawResponse, Sender, TransportError};
use std::io::Read;

/// A blocking HTTP sender built on `ureq`.
pub struct HttpSender {
    agent: ureq::Agent,
}

impl HttpSender {
    /// Build a sender with redirect-following disabled (the transport applies
    /// the cross-origin rule) and `ureq`'s default, TLS-verifying configuration.
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new().redirects(0).build();
        HttpSender { agent }
    }
}

impl Default for HttpSender {
    fn default() -> Self {
        Self::new()
    }
}

impl Sender for HttpSender {
    fn send(&self, request: &EgressRequest) -> Result<RawResponse, TransportError> {
        let url = format!("{}{}", request.target.as_str(), request.path);

        let mut req = self.agent.post(&url).set("Content-Type", "application/json");
        // Connection headers (e.g. Authorization) are set here. They are not
        // logged by this crate; the EgressRequest Debug impl redacts them.
        for (name, value) in &request.headers {
            req = req.set(name, value);
        }

        let response = match req.send_string(&request.body) {
            Ok(resp) => resp,
            // An HTTP error status is still a response from the gateway, not a
            // transport failure. Carry it through so the signal layer can read
            // it (a gate block may well surface as a 4xx).
            Err(ureq::Error::Status(_code, resp)) => resp,
            // A genuine transport fault: the send may have reached the target,
            // so the executor will treat this as Unresolved.
            Err(ureq::Error::Transport(t)) => {
                return Err(TransportError::Io {
                    detail: t.to_string(),
                })
            }
        };

        let status = response.status();
        let redirect_location = response.header("location").map(|s| s.to_string());

        // Bounded read: at most max + 1 bytes, so "over the cap" is detectable
        // without buffering an unbounded body. The +1 lets the transport's
        // post-check see a length strictly greater than the limit.
        let cap = request.max_response_bytes.saturating_add(1);
        let mut buf = Vec::new();
        response
            .into_reader()
            .take(cap)
            .read_to_end(&mut buf)
            .map_err(|e| TransportError::Io {
                detail: e.to_string(),
            })?;
        let body = String::from_utf8_lossy(&buf).into_owned();

        Ok(RawResponse {
            status,
            body,
            redirect_location,
        })
    }
}
