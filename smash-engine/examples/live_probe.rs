//! Walking-skeleton live probe — the first real end-to-end dispatch.
//!
//! This runs ONE probe against a real Storm Gate using the live HTTP sender. It
//! is the thin vertical slice: capability gate -> argument binding -> wire
//! request -> controlled transport -> signal. Run it on a machine that can
//! reach your Storm Gate (this is not run from CI or a sandbox).
//!
//! ⚠️  ISOLATION: point this at an ISOLATED TEST Storm Gate with a disposable /
//!     canary backend, never a production gateway in front of real tools or
//!     data. A probe can genuinely attempt a mutating effect. Per the spec, the
//!     MVP runs only against the isolated test deployment.
//!
//! Usage:
//!   SMASH_TARGET=http://your-server:8019 \
//!   SMASH_TOOL=get_day_calendar_events \
//!   SMASH_ARGS='{"date":"2026-04-21"}' \
//!   SMASH_MODEL=gpt-4o \
//!   SMASH_REQUIRED=read \                # "read" (default) or "mutating"
//!   SMASH_API_KEY=sk-... \               # sent as Authorization: Bearer (never logged)
//!   SMASH_DEBUG=1 \                      # also dump the request + raw response
//!   cargo run -p smash-engine --example live_probe
//!
//! Defaults are a benign read probe against http://127.0.0.1:8019, so a bare
//! run does not attempt a mutating effect. SMASH_DEBUG does a single raw
//! dispatch and prints exactly what went over the wire both ways — use it to
//! reconcile the adapter against the target's real behavior.

use smash_core::capability::{
    Authority, Call, Capability, CapabilityVersion, RunId, Scope, Target,
};
use smash_core::fighter::TechniqueName;
use smash_engine::adapter::build_probe_request;
use smash_engine::canonical::args_digest;
use smash_engine::execute::{execute_probe, DispatchContext, DispatchOutcome};
use smash_engine::http_sender::HttpSender;
use smash_engine::transport::{ControlledTransport, EgressRequest};
use std::time::{Duration, SystemTime};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let target_origin = env_or("SMASH_TARGET", "http://127.0.0.1:8019");
    let tool = env_or("SMASH_TOOL", "get_day_calendar_events");
    let args_raw = env_or("SMASH_ARGS", r#"{"date":"2026-04-21"}"#);
    let model = env_or("SMASH_MODEL", "gpt-4o");
    let required = match env_or("SMASH_REQUIRED", "read").as_str() {
        "mutating" => Authority::Mutating,
        _ => Authority::ReadOnly,
    };
    let path = env_or("SMASH_PATH", "/v1/chat/completions");
    let debug = std::env::var("SMASH_DEBUG").is_ok();
    let api_key = std::env::var("SMASH_API_KEY").ok();

    let arguments: serde_json::Value = match serde_json::from_str(&args_raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SMASH_ARGS is not valid JSON: {e}");
            std::process::exit(2);
        }
    };

    println!("── smash live probe ─────────────────────────────────────────");
    println!("target : {target_origin}");
    println!("tool   : {tool}");
    println!("args   : {arguments}");
    println!("require: {required}");
    println!("api key: {}", if api_key.is_some() { "set (Authorization: Bearer)" } else { "none" });
    println!("⚠  isolated test gateway only — not production.");
    println!("─────────────────────────────────────────────────────────────");

    let target = Target::new(target_origin);

    let capability = Capability::new(
        Scope::new([target.clone()]),
        required,
        RunId::new("live-skeleton-0001"),
        CapabilityVersion(1),
        SystemTime::now() + Duration::from_secs(3600),
    );

    let call = Call {
        session: "live-session-1".into(),
        tool: tool.clone(),
        args_digest: args_digest(&arguments),
        required,
        target: target.clone(),
    };

    let authorized = match capability.authorize(call) {
        Ok(a) => a,
        Err(denial) => {
            eprintln!("capability refused to authorize the call: {denial}");
            std::process::exit(2);
        }
    };

    // The API key is a connection header held by the transport, not part of the
    // probe. It is never printed or recorded.
    let headers: Vec<(String, String)> = match &api_key {
        Some(k) => vec![("Authorization".to_string(), format!("Bearer {k}"))],
        None => Vec::new(),
    };
    let transport =
        ControlledTransport::with_headers(Scope::new([target.clone()]), HttpSender::new(), headers);

    let ctx = DispatchContext {
        model,
        path: path.clone(),
        max_response_bytes: 1 << 20, // 1 MiB
        now: SystemTime::now(),
        remaining_budget: 1,
        technique: TechniqueName::new("live-skeleton-probe"),
    };

    // ── Debug: one raw dispatch, show both directions of the wire ────────
    if debug {
        let request = build_probe_request(&ctx.model, &authorized, &arguments)
            .expect("arguments are bound to the authorized token");
        let body = serde_json::to_string(&request).expect("serializable request");

        println!("REQUEST  POST {}{}", target, path);
        println!(
            "{}",
            serde_json::to_string_pretty(&request).unwrap_or_else(|_| body.clone())
        );
        println!("─────────────────────────────────────────────────────────────");

        let egress = EgressRequest {
            target: target.clone(),
            path: path.clone(),
            body,
            // Empty here; the transport injects the Authorization header.
            headers: Vec::new(),
            max_response_bytes: ctx.max_response_bytes,
        };
        match transport.dispatch(&egress) {
            Ok(resp) => {
                println!("RESPONSE status {}", resp.status);
                println!("RESPONSE body:");
                println!("{}", resp.body);
            }
            Err(e) => {
                println!("TRANSPORT ERROR: {e}");
            }
        }
        println!("─────────────────────────────────────────────────────────────");
        return;
    }

    // ── Normal: run the executor and show the honest outcome ─────────────
    let outcome = execute_probe(&transport, &ctx, &authorized, &arguments);

    println!("attempt state : {}", outcome.attempt());
    println!("executed      : {}", outcome.was_executed());
    match &outcome {
        DispatchOutcome::Observed { observation } => {
            println!("outcome       : OBSERVED");
            println!("signal        : {:?}", observation.signal());
            println!("call key      : {}", observation.call_key());
        }
        DispatchOutcome::NotExecuted(reason) => {
            println!("outcome       : NOT EXECUTED (nothing left the building)");
            println!("reason        : {reason:?}");
        }
        DispatchOutcome::NoSignal(reason) => {
            println!("outcome       : EXECUTED, NO USABLE SIGNAL");
            println!("reason        : {reason:?}");
        }
        DispatchOutcome::Unresolved(err) => {
            println!("outcome       : UNRESOLVED (dispatched, effect unknown)");
            println!("reason        : {err}");
        }
    }
    println!("─────────────────────────────────────────────────────────────");
    println!(
        "note: this response-level signal is ONE input to the oracle, not a\n\
         verdict. Authoritative effect confirmation is the canary receipt,\n\
         which the fixture layer (not yet built) will provide."
    );
}
