//! Target adapter — translating between core's typed world and the wire.
//!
//! Core speaks in [`Call`](smash_core::capability::Call)s and
//! [`Signal`](smash_core::fighter::Signal)s and never sees a byte of wire
//! format. The target (Storm Gate) speaks OpenAI-compatible chat-completions
//! JSON at `/v1/chat/completions`. This module is the seam between the two: it
//! builds the request that carries a probe, and it reads the response back into
//! an abstract signal.
//!
//! ## The binding invariant (why this module is trusted)
//!
//! An [`AuthorizedCall`](smash_core::capability::AuthorizedCall) binds a digest
//! over the probe's arguments — but core holds only the *digest*, never the
//! arguments themselves (the adversarial payload stays out of core by design).
//! The real arguments live here, in the engine. So before this module will put
//! a single byte on the wire, it checks that the arguments it was handed hash,
//! under the same canonical form Storm Gate uses, to the key the authorized
//! token carries ([`bind_arguments`]). A token authorizes *these exact bytes*;
//! the adapter refuses to send any others. That is what stops an authorization
//! for one call being reused to dispatch different content.
//!
//! ## What is faithful here, and what is a pinned seam
//!
//! The chat-completions envelope ([`ChatRequest`], [`ChatResponse`],
//! [`ToolCall`]) is the stable OpenAI standard, represented faithfully. Two
//! things are **target-specific** and marked as seams to confirm against Storm
//! Gate's proxy surface before relying on them in anger:
//!
//! - **Request induction** ([`build_probe_request`]) carries the proposed tool
//!   call as an assistant message with `tool_calls`, arguments serialized in
//!   canonical form so the wire bytes match the bound digest. Exactly which
//!   field the proxy reads a *proposed* action from (assistant turn vs. a forced
//!   `tool_choice`) is a proxy detail to pin.
//! - **Decision surfacing** ([`response_signal`]) reads "did the call pass the
//!   gate?" from whether the matching tool call is present in the response. How
//!   Storm Gate renders a Blocked/Escalated decision on the OpenAI-compatible
//!   wire (status code, error body, a synthetic message) is a proxy detail to
//!   pin. And per spec §5: a gateway "accepted" without a backend effect does
//!   not prove the invariant held — the authoritative effect observation is the
//!   fixture's canary receipt, not this response. This signal is one input to
//!   the oracle, not the verdict.

use crate::canonical::{canonical_json, power_move_vouch};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use smash_core::capability::{AuthorizedCall, CallKey};
use smash_core::fighter::Signal;
use std::fmt;

// ── Wire envelope (OpenAI-compatible, faithful) ─────────────────────────────

/// A function tool-call as it appears on the chat-completions wire. `arguments`
/// is a JSON *string* (OpenAI encodes it that way), not a nested object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// One tool call in an assistant message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub function: FunctionCall,
}

impl ToolCall {
    /// Parse this call's `arguments` string into a JSON value. `None` if the
    /// arguments are not well-formed JSON.
    pub fn arguments_value(&self) -> Option<Value> {
        serde_json::from_str(&self.function.arguments).ok()
    }
}

/// A chat message. Minimal: enough to carry a proposed tool call and to read a
/// response message back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool_calls: Option<Vec<ToolCall>>,
}

/// A chat-completions request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tools: Option<Vec<Value>>,
}

/// One choice in a chat-completions response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    pub message: ChatMessage,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

/// A chat-completions response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatResponse {
    #[serde(default)]
    pub choices: Vec<Choice>,
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Why the adapter refused to translate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdapterError {
    /// The arguments handed to the adapter do not hash to the key the
    /// authorized token carries. The token authorizes exact bytes; these are
    /// different bytes, so they are refused before reaching the wire.
    ArgumentBindingMismatch {
        /// The key the token authorized.
        expected: CallKey,
        /// The key the supplied arguments actually produce.
        got: String,
    },
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::ArgumentBindingMismatch { expected, got } => write!(
                f,
                "arguments do not match the authorized token: expected {expected}, got {got}"
            ),
        }
    }
}

impl std::error::Error for AdapterError {}

// ── Binding: arguments must match the authorized token ──────────────────────

/// Verify that `arguments` are the exact bytes the `authorized` token
/// authorizes: `power_move:<tool>:<sha256_hex(canonical_json(arguments))>` must
/// equal the token's key. This is the gate the adapter applies before building
/// any request — a token can never be reused to dispatch different content.
pub fn bind_arguments(authorized: &AuthorizedCall, arguments: &Value) -> Result<(), AdapterError> {
    let tool = &authorized.call().tool;
    let produced = power_move_vouch(tool, arguments);
    let expected = authorized.key();
    if produced == expected.as_str() {
        Ok(())
    } else {
        Err(AdapterError::ArgumentBindingMismatch {
            expected,
            got: produced,
        })
    }
}

// ── Call → request ──────────────────────────────────────────────────────────

/// Build the chat-completions request that carries a probe's proposed tool
/// call. The arguments are bound to the authorized token first (see
/// [`bind_arguments`]); a mismatch is refused, never sent.
///
/// The proposed call is carried as an assistant message with `tool_calls`, and
/// the arguments are serialized in canonical form so the wire bytes are exactly
/// the ones the bound digest covers. (Which field the proxy reads a proposed
/// action from is a target seam — see the module docs.)
pub fn build_probe_request(
    model: &str,
    authorized: &AuthorizedCall,
    arguments: &Value,
) -> Result<ChatRequest, AdapterError> {
    bind_arguments(authorized, arguments)?;

    let tool = authorized.call().tool.clone();
    let tool_call = ToolCall {
        id: "probe-0".to_string(),
        kind: "function".to_string(),
        function: FunctionCall {
            name: tool,
            // Canonical form: the wire bytes match the digest exactly.
            arguments: canonical_json(arguments),
        },
    };

    Ok(ChatRequest {
        model: model.to_string(),
        messages: vec![ChatMessage {
            role: "assistant".to_string(),
            content: None,
            tool_calls: Some(vec![tool_call]),
        }],
        tools: None,
    })
}

// ── Response → signal ────────────────────────────────────────────────────────

/// Whether `tool_call` is the call identified by `expected` — i.e. its function
/// name and canonical arguments reproduce the expected key. Arguments that do
/// not parse, or that hash to a different key, do not match.
pub fn tool_call_matches(tool_call: &ToolCall, expected: &CallKey) -> bool {
    match tool_call.arguments_value() {
        Some(args) => power_move_vouch(&tool_call.function.name, &args) == expected.as_str(),
        None => false,
    }
}

/// Read a gate verdict out of a response, relative to the call we expected.
///
/// `accepted` is `true` iff the response carries the matching tool call — the
/// gate let the probe through to execution. Its absence means the gate withheld
/// it. This is a [`Signal::GateVerdict`]; it is **one input** to the oracle, not
/// the verdict. Per spec §5, the authoritative confirmation that an effect
/// actually occurred is the fixture's canary receipt — an "accepted" response
/// without a backend effect does not by itself prove the invariant failed.
pub fn response_signal(response: &ChatResponse, expected: &CallKey) -> Signal {
    let accepted = response
        .choices
        .iter()
        .filter_map(|c| c.message.tool_calls.as_ref())
        .flatten()
        .any(|tc| tool_call_matches(tc, expected));
    Signal::GateVerdict { accepted }
}

/// An OpenAI-style error envelope: `{"error": {"message": "...", ...}}`. Many
/// proxies (LiteLLM included) return this on auth failure, bad request, etc.
#[derive(Debug, Clone, Deserialize)]
struct WireError {
    error: WireErrorBody,
}

#[derive(Debug, Clone, Deserialize)]
struct WireErrorBody {
    #[serde(default)]
    message: String,
}

/// What a response body turned out to be. The crucial distinction the first
/// live run exposed: an error envelope must **not** be read as an empty-but-
/// valid [`ChatResponse`] (which would surface as a false `accepted: false`).
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseInterpretation {
    /// A well-formed chat response; here is its gate-verdict signal.
    Signal(Signal),
    /// An error envelope from the proxy/gateway — not a gate verdict. Carries
    /// the error message.
    ErrorEnvelope(String),
    /// The body parsed as neither an error envelope nor a chat response.
    Unparseable,
}

/// Interpret a response body. Checks for an error envelope **first** — because
/// an error body like `{"error":{...}}` would otherwise parse as a
/// [`ChatResponse`] with an empty `choices` list (defaulted) and masquerade as a
/// gate that withheld the call. A real chat response has no top-level `error`
/// key, so this discriminates cleanly.
pub fn interpret_response(body: &str, expected: &CallKey) -> ResponseInterpretation {
    if let Ok(err) = serde_json::from_str::<WireError>(body) {
        return ResponseInterpretation::ErrorEnvelope(err.error.message);
    }
    match serde_json::from_str::<ChatResponse>(body) {
        Ok(parsed) => ResponseInterpretation::Signal(response_signal(&parsed, expected)),
        Err(_) => ResponseInterpretation::Unparseable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::args_digest;
    use serde_json::json;
    use smash_core::capability::{
        Authority, Call, Capability, CapabilityVersion, RunId, Scope, Target,
    };
    use std::time::{Duration, SystemTime};

    fn storm_gate() -> Target {
        Target::new("http://127.0.0.1:8019")
    }

    /// An authorized call over the given arguments, tool `send_payment`.
    fn authorized_over(args: &Value) -> AuthorizedCall {
        let cap = Capability::new(
            Scope::new([storm_gate()]),
            Authority::Mutating,
            RunId::new("run-1"),
            CapabilityVersion(1),
            SystemTime::UNIX_EPOCH + Duration::from_secs(10_000),
        );
        let call = Call {
            session: "s-1".into(),
            tool: "send_payment".into(),
            args_digest: args_digest(args),
            required: Authority::Mutating,
            target: storm_gate(),
        };
        cap.authorize(call).expect("in scope, within authority")
    }

    // ── Binding invariant ────────────────────────────────────────────

    #[test]
    fn matching_arguments_bind() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        assert!(bind_arguments(&authorized, &args).is_ok());
    }

    #[test]
    fn altered_arguments_are_refused() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        // Same tool, different arguments — must not bind.
        let tampered = json!({"amount": "100", "recipient": "attacker"});
        let err = bind_arguments(&authorized, &tampered).unwrap_err();
        assert!(matches!(err, AdapterError::ArgumentBindingMismatch { .. }));
    }

    #[test]
    fn key_order_does_not_break_binding() {
        // Canonical form sorts keys, so a different insertion order still binds.
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let reordered = json!({"recipient": "landlord", "amount": "100"});
        assert!(bind_arguments(&authorized, &reordered).is_ok());
    }

    #[test]
    fn build_request_refuses_unbound_arguments() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let tampered = json!({"amount": "999999", "recipient": "attacker"});
        assert!(build_probe_request("gpt-4o", &authorized, &tampered).is_err());
    }

    // ── Request construction ─────────────────────────────────────────

    #[test]
    fn build_request_carries_canonical_arguments() {
        let args = json!({"recipient": "landlord", "amount": "100"});
        let authorized = authorized_over(&args);
        let req = build_probe_request("gpt-4o", &authorized, &args).unwrap();
        assert_eq!(req.model, "gpt-4o");
        let tc = &req.messages[0].tool_calls.as_ref().unwrap()[0];
        assert_eq!(tc.function.name, "send_payment");
        // Wire arguments are canonical (keys sorted), matching the digest.
        assert_eq!(
            tc.function.arguments,
            r#"{"amount":"100","recipient":"landlord"}"#
        );
        // And the built call round-trips to the authorized key.
        assert!(tool_call_matches(tc, &authorized.key()));
    }

    // ── Response → signal ────────────────────────────────────────────

    fn response_with_tool_call(name: &str, arguments: &str) -> ChatResponse {
        ChatResponse {
            choices: vec![Choice {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: None,
                    tool_calls: Some(vec![ToolCall {
                        id: "x".into(),
                        kind: "function".into(),
                        function: FunctionCall {
                            name: name.into(),
                            arguments: arguments.into(),
                        },
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
        }
    }

    #[test]
    fn matching_tool_call_is_accepted() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let resp =
            response_with_tool_call("send_payment", r#"{"amount":"100","recipient":"landlord"}"#);
        assert_eq!(
            response_signal(&resp, &authorized.key()),
            Signal::GateVerdict { accepted: true }
        );
    }

    #[test]
    fn absent_tool_call_is_not_accepted() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        // The gate withheld the call: a plain assistant message, no tool_calls.
        let resp = ChatResponse {
            choices: vec![Choice {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: Some("I can't do that.".into()),
                    tool_calls: None,
                },
                finish_reason: Some("stop".into()),
            }],
        };
        assert_eq!(
            response_signal(&resp, &authorized.key()),
            Signal::GateVerdict { accepted: false }
        );
    }

    #[test]
    fn different_arguments_in_response_do_not_match() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        // A tool call went through, but for different arguments — not our probe.
        let resp = response_with_tool_call(
            "send_payment",
            r#"{"amount":"100","recipient":"someone_else"}"#,
        );
        assert_eq!(
            response_signal(&resp, &authorized.key()),
            Signal::GateVerdict { accepted: false }
        );
    }

    #[test]
    fn unparseable_arguments_do_not_match() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let resp = response_with_tool_call("send_payment", "not json");
        assert_eq!(
            response_signal(&resp, &authorized.key()),
            Signal::GateVerdict { accepted: false }
        );
    }

    // ── Wire serde round-trips ───────────────────────────────────────

    #[test]
    fn request_serde_round_trip() {
        let args = json!({"amount": "100", "recipient": "landlord"});
        let authorized = authorized_over(&args);
        let req = build_probe_request("gpt-4o", &authorized, &args).unwrap();
        let wire = serde_json::to_string(&req).unwrap();
        let back: ChatRequest = serde_json::from_str(&wire).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn response_deserializes_from_openai_shape() {
        let wire = r#"{
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {"id": "call_1", "type": "function",
                             "function": {"name": "send_payment", "arguments": "{\"amount\":\"100\",\"recipient\":\"landlord\"}"}}
                        ]
                    },
                    "finish_reason": "tool_calls"
                }
            ]
        }"#;
        let resp: ChatResponse = serde_json::from_str(wire).unwrap();
        assert_eq!(resp.choices.len(), 1);
        let tc = &resp.choices[0].message.tool_calls.as_ref().unwrap()[0];
        assert_eq!(tc.function.name, "send_payment");
        assert_eq!(
            tc.arguments_value().unwrap(),
            json!({"amount": "100", "recipient": "landlord"})
        );
    }
}
