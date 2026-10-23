//! The minimal probe executor — the glue that makes one dispatch happen.
//!
//! This is the thin vertical slice: it takes an
//! [`AuthorizedCall`](smash_core::capability::AuthorizedCall) and the real
//! arguments behind it, and runs the whole pipeline — bind the arguments to the
//! token, apply the dispatch gate, build the wire request, send it through the
//! controlled transport, and read the response back into a
//! [`Signal`](smash_core::fighter::Signal). It is deliberately small: one probe,
//! one dispatch, no run loop, no fixtures, no match log. Those are later layers.
//! What this file exists for is to let us stand up a *real* probe against a real
//! Storm Gate as soon as possible — swap the fake transport for a live `Sender`
//! and this same code runs end-to-end.
//!
//! ## The honesty contract, threaded through
//!
//! The hard part is not the happy path; it is being honest about what happened
//! when things go sideways. Every outcome carries the
//! [`AttemptState`](smash_core::lifecycle::AttemptState) it ended in, and the
//! executor obeys the one rule that matters: **a probe whose bytes may have left
//! the building is never recorded as "did not execute."**
//!
//! - Refused *before* any byte leaves — argument binding mismatch, a capability
//!   denial (expired / budget), or a destination the transport's egress
//!   allowlist rejects (which the transport guarantees is pre-send) — the
//!   attempt stays [`Intended`], the one state safe to treat as not executed.
//! - A clean round-trip — the attempt reaches [`Resolved`] and carries an
//!   [`Observation`].
//! - A response that came back but can't yield a signal (transport-rejected, or
//!   unparseable) — [`Resolved`], but no signal: the oracle will read that as
//!   inconclusive, not as a pass.
//! - A transport failure that may have happened mid-flight — [`Unresolved`]:
//!   effects unknown, surfaced as such, never retried as if it had not run.
//!
//! [`Intended`]: smash_core::lifecycle::AttemptState::Intended
//! [`Resolved`]: smash_core::lifecycle::AttemptState::Resolved
//! [`Unresolved`]: smash_core::lifecycle::AttemptState::Unresolved

use crate::adapter::{
    bind_arguments, build_probe_request, interpret_response, AdapterError, ResponseInterpretation,
};
use crate::transport::{ControlledTransport, EgressRequest, Sender, TransportError};
use serde_json::Value;
use smash_core::capability::{AuthorizedCall, Denial};
use smash_core::fighter::{Observation, TechniqueName};
use smash_core::lifecycle::AttemptState;
use std::time::SystemTime;

/// The per-dispatch context the executor needs that is not carried by the
/// authorized call itself.
#[derive(Debug, Clone)]
pub struct DispatchContext {
    /// The model string for the chat-completions request.
    pub model: String,
    /// The request path on the target (e.g. `/v1/chat/completions`).
    pub path: String,
    /// The run's response-byte cap, passed to the transport.
    pub max_response_bytes: u64,
    /// The clock reading for the dispatch gate. Injected, so the executor needs
    /// no clock of its own and tests are deterministic.
    pub now: SystemTime,
    /// The run's remaining dispatch budget, for the dispatch gate.
    pub remaining_budget: u32,
    /// The technique this probe belongs to — recorded in the observation.
    pub technique: TechniqueName,
}

/// Why a probe was not executed (no byte left the building).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotExecuted {
    /// The supplied arguments do not match the authorized token.
    Binding(AdapterError),
    /// The capability dispatch gate refused (expired token or budget exhausted).
    Denied(Denial),
    /// The transport's egress allowlist rejected the destination. The transport
    /// guarantees nothing was sent.
    DestinationRefused(TransportError),
}

/// Why a dispatched probe produced no usable signal, though it did execute.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoSignal {
    /// A response was received but the transport rejected it (cross-origin
    /// redirect, or over the byte cap).
    TransportRejected(TransportError),
    /// The target returned a non-success HTTP status. Not a gate verdict —
    /// typically an auth or request-shape problem. Carries the status and a
    /// short body snippet.
    HttpError { status: u16, snippet: String },
    /// The target returned an error envelope (`{"error":{...}}`). Not a gate
    /// verdict. Carries the error message.
    ErrorEnvelope { message: String },
    /// A response body was received but could not be parsed as a
    /// chat-completions response.
    UnparseableResponse,
}

/// The outcome of one probe dispatch. Every variant names the
/// [`AttemptState`] it ended in, so a recorder can log an honest lifecycle.
#[derive(Debug, Clone)]
pub enum DispatchOutcome {
    /// The probe fired and a signal was observed. Attempt: `Resolved`.
    Observed { observation: Observation },
    /// The probe never fired; safe to treat as not executed. Attempt:
    /// `Intended`.
    NotExecuted(NotExecuted),
    /// The probe fired and a response came back, but no usable signal could be
    /// derived. Attempt: `Resolved`.
    NoSignal(NoSignal),
    /// The probe was dispatched but its outcome is unknown. Attempt:
    /// `Unresolved` — never retried as though it had not executed.
    Unresolved(TransportError),
}

impl DispatchOutcome {
    /// The attempt state this outcome ended in.
    pub fn attempt(&self) -> AttemptState {
        match self {
            DispatchOutcome::Observed { .. } | DispatchOutcome::NoSignal(_) => {
                AttemptState::Resolved
            }
            DispatchOutcome::NotExecuted(_) => AttemptState::Intended,
            DispatchOutcome::Unresolved(_) => AttemptState::Unresolved,
        }
    }

    /// Whether any byte left the building. False only for `NotExecuted`.
    pub fn was_executed(&self) -> bool {
        !matches!(self, DispatchOutcome::NotExecuted(_))
    }

    /// The observation, if the probe produced one.
    pub fn observation(&self) -> Option<&Observation> {
        match self {
            DispatchOutcome::Observed { observation } => Some(observation),
            _ => None,
        }
    }
}

/// A short, single-line snippet of a response body for diagnostics — never the
/// whole thing (it could be large or noisy).
fn snippet(body: &str) -> String {
    const MAX: usize = 200;
    let one_line: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.len() <= MAX {
        one_line
    } else {
        format!("{}…", &one_line[..MAX])
    }
}

/// Execute one probe through the controlled transport. See the module docs for
/// the honesty contract each outcome upholds.
pub fn execute_probe<S: Sender>(
    transport: &ControlledTransport<S>,
    ctx: &DispatchContext,
    authorized: &AuthorizedCall,
    arguments: &Value,
) -> DispatchOutcome {
    // 1. Bind the arguments to the token. A mismatch is a harness bug, not a
    //    target finding — refuse before anything is built. Attempt: Intended.
    if let Err(e) = bind_arguments(authorized, arguments) {
        return DispatchOutcome::NotExecuted(NotExecuted::Binding(e));
    }

    // 2. Dispatch gate: expiry and budget. A denial means the probe never
    //    fires. Attempt: Intended.
    if let Err(denial) = authorized.check_dispatchable(ctx.now, ctx.remaining_budget) {
        return DispatchOutcome::NotExecuted(NotExecuted::Denied(denial));
    }

    // 3. Build the wire request (already bound above, so this cannot mismatch).
    let request = match build_probe_request(&ctx.model, authorized, arguments) {
        Ok(r) => r,
        Err(e) => return DispatchOutcome::NotExecuted(NotExecuted::Binding(e)),
    };
    let body = serde_json::to_string(&request).unwrap_or_else(|_| "{}".to_string());

    let egress = EgressRequest {
        target: authorized.call().target.clone(),
        path: ctx.path.clone(),
        body,
        // The probe layer supplies no credentials; the transport injects any
        // connection headers from its own configuration.
        headers: Vec::new(),
        max_response_bytes: ctx.max_response_bytes,
    };

    // 4. Dispatch. The typed transport errors tell us whether bytes left: the
    //    destination check is guaranteed pre-send; a response (even a rejected
    //    one) means they left and came back; an Io failure may have happened
    //    mid-flight.
    match transport.dispatch(&egress) {
        Ok(resp) => {
            // Bytes left and a response returned → Resolved. But a response is
            // not automatically a gate verdict: a non-2xx status or an error
            // envelope is an auth/request-shape problem, and must not surface as
            // a false `accepted: false`.
            if !(200..=299).contains(&resp.status) {
                return DispatchOutcome::NoSignal(NoSignal::HttpError {
                    status: resp.status,
                    snippet: snippet(&resp.body),
                });
            }
            match interpret_response(&resp.body, &authorized.key()) {
                ResponseInterpretation::Signal(signal) => {
                    let observation =
                        Observation::new(ctx.technique.clone(), authorized.key(), signal);
                    DispatchOutcome::Observed { observation }
                }
                ResponseInterpretation::ErrorEnvelope(message) => {
                    DispatchOutcome::NoSignal(NoSignal::ErrorEnvelope { message })
                }
                ResponseInterpretation::Unparseable => {
                    DispatchOutcome::NoSignal(NoSignal::UnparseableResponse)
                }
            }
        }
        Err(err) => match err {
            // Transport guarantees the sender was never called.
            TransportError::DestinationNotInScope { .. } => {
                DispatchOutcome::NotExecuted(NotExecuted::DestinationRefused(err))
            }
            // A response was received, then rejected. The probe executed, but
            // there is no usable signal.
            TransportError::CrossOriginRedirect { .. }
            | TransportError::ResponseTooLarge { .. } => {
                DispatchOutcome::NoSignal(NoSignal::TransportRejected(err))
            }
            // The send may have reached the target. Effects unknown — never
            // retried as though it had not executed.
            TransportError::Io { .. } => DispatchOutcome::Unresolved(err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::args_digest;
    use crate::transport::RawResponse;
    use serde_json::json;
    use smash_core::capability::{
        Authority, Call, Capability, CapabilityVersion, RunId, Scope, Target,
    };
    use smash_core::fighter::Signal;
    use std::cell::Cell;
    use std::time::Duration;

    fn storm_gate() -> Target {
        Target::new("http://127.0.0.1:8019")
    }

    fn expiry() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(10_000)
    }

    fn authorized_over(args: &Value) -> AuthorizedCall {
        let cap = Capability::new(
            Scope::new([storm_gate()]),
            Authority::Mutating,
            RunId::new("run-1"),
            CapabilityVersion(1),
            expiry(),
        );
        cap.authorize(Call {
            session: "s-1".into(),
            tool: "send_payment".into(),
            args_digest: args_digest(args),
            required: Authority::Mutating,
            target: storm_gate(),
        })
        .unwrap()
    }

    struct FakeSender {
        result: Result<RawResponse, TransportError>,
        called: Cell<bool>,
    }
    impl FakeSender {
        fn body(body: &str) -> Self {
            FakeSender {
                result: Ok(RawResponse {
                    status: 200,
                    body: body.to_string(),
                    redirect_location: None,
                }),
                called: Cell::new(false),
            }
        }
        fn io() -> Self {
            FakeSender {
                result: Err(TransportError::Io { detail: "reset".into() }),
                called: Cell::new(false),
            }
        }
        fn status(code: u16, body: &str) -> Self {
            FakeSender {
                result: Ok(RawResponse {
                    status: code,
                    body: body.to_string(),
                    redirect_location: None,
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

    fn transport_to(target: Target, sender: FakeSender) -> ControlledTransport<FakeSender> {
        ControlledTransport::new(Scope::new([target]), sender)
    }

    fn ctx(now: SystemTime, budget: u32) -> DispatchContext {
        DispatchContext {
            model: "gpt-4o".into(),
            path: "/v1/chat/completions".into(),
            max_response_bytes: 64 * 1024,
            now,
            remaining_budget: budget,
            technique: TechniqueName::new("write-via-readonly-session"),
        }
    }

    fn accept_body(args: &Value) -> String {
        // A chat response whose tool_call reproduces the authorized key.
        let canon = crate::canonical::canonical_json(args);
        format!(
            r#"{{"choices":[{{"message":{{"role":"assistant","tool_calls":[{{"id":"x","type":"function","function":{{"name":"send_payment","arguments":{}}}}}]}},"finish_reason":"tool_calls"}}]}}"#,
            serde_json::to_string(&canon).unwrap()
        )
    }

    // ── Happy path ───────────────────────────────────────────────────

    #[test]
    fn clean_accept_resolves_with_signal() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let t = transport_to(storm_gate(), FakeSender::body(&accept_body(&args)));
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &args);

        assert_eq!(outcome.attempt(), AttemptState::Resolved);
        assert!(outcome.was_executed());
        let obs = outcome.observation().expect("observed");
        assert_eq!(obs.signal(), &Signal::GateVerdict { accepted: true });
        assert_eq!(obs.call_key(), &authorized.key());
    }

    #[test]
    fn clean_withhold_resolves_not_accepted() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        // A plain assistant message, no tool_calls → the gate withheld it.
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"no"},"finish_reason":"stop"}]}"#;
        let t = transport_to(storm_gate(), FakeSender::body(body));
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &args);
        assert_eq!(
            outcome.observation().unwrap().signal(),
            &Signal::GateVerdict { accepted: false }
        );
        assert_eq!(outcome.attempt(), AttemptState::Resolved);
    }

    // ── Not executed: never left the building ────────────────────────

    #[test]
    fn binding_mismatch_is_not_executed() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let tampered = json!({"amount": "100", "recipient": "attacker"});
        let t = transport_to(storm_gate(), FakeSender::body("unused"));
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &tampered);

        assert!(!outcome.was_executed());
        assert_eq!(outcome.attempt(), AttemptState::Intended);
        assert!(matches!(outcome, DispatchOutcome::NotExecuted(NotExecuted::Binding(_))));
        assert!(!t.sender().called.get(), "nothing should reach the sender");
    }

    #[test]
    fn expired_token_is_denied_not_executed() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let t = transport_to(storm_gate(), FakeSender::body("unused"));
        // now is past expiry.
        let past = expiry() + Duration::from_secs(1);
        let outcome = execute_probe(&t, &ctx(past, 5), &authorized, &args);
        assert_eq!(outcome.attempt(), AttemptState::Intended);
        assert!(matches!(
            outcome,
            DispatchOutcome::NotExecuted(NotExecuted::Denied(Denial::Expired { .. }))
        ));
        assert!(!t.sender().called.get());
    }

    #[test]
    fn zero_budget_is_denied_not_executed() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let t = transport_to(storm_gate(), FakeSender::body("unused"));
        let outcome = execute_probe(&t, &ctx(expiry(), 0), &authorized, &args);
        assert!(matches!(
            outcome,
            DispatchOutcome::NotExecuted(NotExecuted::Denied(Denial::BudgetExceeded))
        ));
        assert!(!t.sender().called.get());
    }

    #[test]
    fn destination_not_in_egress_scope_is_not_executed() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args); // target = storm_gate
        // Transport's egress allowlist does NOT include storm_gate.
        let t = transport_to(
            Target::new("http://127.0.0.1:9999"),
            FakeSender::body("unused"),
        );
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &args);
        assert_eq!(outcome.attempt(), AttemptState::Intended);
        assert!(matches!(
            outcome,
            DispatchOutcome::NotExecuted(NotExecuted::DestinationRefused(_))
        ));
        assert!(!t.sender().called.get(), "destination check is pre-send");
    }

    // ── Executed but no usable signal ────────────────────────────────

    #[test]
    fn unparseable_response_is_resolved_no_signal() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let t = transport_to(storm_gate(), FakeSender::body("not json at all"));
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &args);
        assert_eq!(outcome.attempt(), AttemptState::Resolved);
        assert!(outcome.was_executed());
        assert!(matches!(
            outcome,
            DispatchOutcome::NoSignal(NoSignal::UnparseableResponse)
        ));
    }

    #[test]
    fn oversized_response_is_resolved_no_signal() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let t = transport_to(storm_gate(), FakeSender::body(&accept_body(&args)));
        // Tiny cap so the response is rejected as too large.
        let mut c = ctx(expiry(), 5);
        c.max_response_bytes = 4;
        let outcome = execute_probe(&t, &c, &authorized, &args);
        assert_eq!(outcome.attempt(), AttemptState::Resolved);
        assert!(matches!(
            outcome,
            DispatchOutcome::NoSignal(NoSignal::TransportRejected(
                TransportError::ResponseTooLarge { .. }
            ))
        ));
    }

    // ── Dispatched, outcome unknown ──────────────────────────────────

    #[test]
    fn auth_401_is_no_signal_not_a_false_verdict() {
        // The exact failure the first live run hit: a 401 error envelope must
        // NOT surface as accepted:false. It is NoSignal (executed, no verdict).
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let body = r#"{"error":{"message":"Authentication Error, No api key passed in.","type":"auth_error","code":"401"}}"#;
        let t = transport_to(storm_gate(), FakeSender::status(401, body));
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &args);
        assert_eq!(outcome.attempt(), AttemptState::Resolved);
        assert!(outcome.was_executed());
        assert!(outcome.observation().is_none(), "a 401 is not a gate verdict");
        assert!(matches!(
            outcome,
            DispatchOutcome::NoSignal(NoSignal::HttpError { status: 401, .. })
        ));
    }

    #[test]
    fn error_envelope_with_200_is_no_signal() {
        // Some proxies return an error envelope with a 200. It must still be
        // caught as an error, not parsed as an empty (withheld) response.
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let body = r#"{"error":{"message":"model not found"}}"#;
        let t = transport_to(storm_gate(), FakeSender::status(200, body));
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &args);
        assert!(matches!(
            outcome,
            DispatchOutcome::NoSignal(NoSignal::ErrorEnvelope { .. })
        ));
    }

    #[test]
    fn io_failure_is_unresolved() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let t = transport_to(storm_gate(), FakeSender::io());
        let outcome = execute_probe(&t, &ctx(expiry(), 5), &authorized, &args);
        assert_eq!(outcome.attempt(), AttemptState::Unresolved);
        assert!(outcome.was_executed(), "an unresolved probe DID leave the building");
        assert!(matches!(outcome, DispatchOutcome::Unresolved(TransportError::Io { .. })));
    }
}
