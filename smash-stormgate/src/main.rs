//! Run the F-B evaluate()-level differential against the real Storm Gate, and
//! write a replayable evidence bundle.
//!
//! Two modes:
//!
//!   # run the fighters and write a bundle to ./smash-runs/<run-id>.json
//!   STORMLOCK_PATH=/srv/oc-projects/stormlock cargo run -p smash-stormgate
//!
//!   # verify a previously written bundle offline (no gate, no network)
//!   cargo run -p smash-stormgate -- verify smash-runs/<run-id>.json
//!
//! The run calls `realfield_core::gate::ActionGate::evaluate` directly — no
//! network, no credential, no model. It self-tests first (a blind harness is
//! withheld), prints KILL/DEFENDED per case, then writes the bundle and
//! immediately verifies it as a self-check. The pre-fix KILL bundle and the
//! post-fix DEFENDED bundle — same fighter ids, differing only by gate build —
//! are the §5 regression evidence.

use serde_json::json;
use smash_core::verdict::Verdict;
use smash_engine::differential::{run_case, DifferentialResult, Gate, GateDecisionView, GateInput};
use smash_engine::matchlog::{self, RunBundle, SelfTestRecord, VerifyOutcome};
use smash_stormgate::{fb_cases, provenance, RealfieldGate};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn classify(result: &DifferentialResult) -> &'static str {
    match &result.verdict {
        Verdict::Fail { .. } => "KILL",
        Verdict::Pass { .. } => "DEFENDED",
        Verdict::Inconclusive { .. } => "INCONCLUSIVE",
        Verdict::Error { .. } => "FIXTURE-INVALID",
        _ => "UNKNOWN",
    }
}

/// Prove the harness isn't blind and diagnose the gate. Returns the recorded
/// self-test (S1/S2 decisions + trustworthiness).
fn self_test(gate: &RealfieldGate) -> SelfTestRecord {
    let s1 = gate.evaluate(&GateInput {
        tool_name: "send_money".into(),
        parameters: json!({ "recipient": "SANITY_VALUE_IN_T3" }),
        tier3_content: vec!["ref SANITY_VALUE_IN_T3".into()],
        user_message_text: String::new(),
        approved_values: Vec::new(),
        external: false,
    });
    let s2 = gate.evaluate(&GateInput::external_action(
        "send_money",
        json!({ "recipient": "UNTAINTED_RECIPIENT_XYZ" }),
        vec!["completely unrelated tier-3 content".into()],
    ));

    println!("self-test:");
    println!("  S1 non-external write        → {s1:?}   (must be Approved)");
    println!("  S2 external, value NOT tainted → {s2:?}");

    let trustworthy = s1 == GateDecisionView::Approved;
    if !trustworthy {
        println!("  ⚠ HARNESS BLIND: a non-external action escalated — severity is not");
        println!("    resolving to Write (likely PowerMove). Verdicts are NOT trustworthy.");
    } else {
        match s2 {
            GateDecisionView::Approved => {
                println!("  → gate is SUBSTRING-shaped: an untainted sensitive value passes");
                println!("    (vulnerable-shaped; a laundered-but-untainted probe should slip).");
            }
            GateDecisionView::Escalated | GateDecisionView::Blocked => {
                println!("  → gate escalates sensitive external writes BY DEFAULT");
                println!("    (provenance-by-default present — fixed-shaped).");
            }
            GateDecisionView::Intercepted => println!("  → S2 intercepted; inconclusive."),
        }
    }
    println!("─────────────────────────────────────────────────────────────");

    SelfTestRecord { s1, s2, trustworthy }
}

/// Replace anything but [A-Za-z0-9] with '-', for a filesystem-safe run id.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn run_mode() -> i32 {
    let stormlock =
        std::env::var("STORMLOCK_PATH").unwrap_or_else(|_| "/srv/oc-projects/stormlock".to_string());
    let build = provenance::gate_build(&stormlock);

    println!("── smash-stormgate · F-B evaluate() differential ────────────");
    println!("gate build : {build}");
    println!("mode       : in-process (no network, no credential, no model)");
    println!("─────────────────────────────────────────────────────────────");

    let gate = RealfieldGate;
    let self_test = self_test(&gate);
    let trustworthy = self_test.trustworthy;

    let cases = fb_cases();
    let results: Vec<DifferentialResult> = cases.iter().map(|c| run_case(&gate, c)).collect();

    let mut kills = 0u32;
    for result in &results {
        println!("[{}] {}", result.name, classify(result));
        println!("   control = {:?}   probe = {:?}", result.control, result.probe);
        println!("   verdict : {}", result.verdict);
        if result.is_kill() {
            kills += 1;
        }
    }
    println!("─────────────────────────────────────────────────────────────");

    // Build and write the bundle.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let run_id = format!("fb-{}-{}", sanitize(&build), now);
    let bundle = RunBundle::build(&run_id, &build, self_test, &cases, &results);

    let dir = PathBuf::from("smash-runs");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("could not create {}: {e}", dir.display());
        return 3;
    }
    let path = dir.join(format!("{run_id}.json"));
    match matchlog::write_bundle(&path, &bundle) {
        Ok(()) => println!("bundle written: {}", path.display()),
        Err(e) => {
            eprintln!("could not write bundle: {e}");
            return 3;
        }
    }

    // Self-check: the bundle we just wrote must verify.
    match matchlog::verify(&bundle) {
        VerifyOutcome::Verified { cases } => {
            println!("bundle verify : VERIFIED ({cases} case(s), offline)")
        }
        VerifyOutcome::Failed(f) => println!("bundle verify : FAILED — {f:?}"),
    }
    println!("─────────────────────────────────────────────────────────────");

    if !trustworthy {
        println!("RESULT WITHHELD: self-test failed; verdicts are not trustworthy.");
        return 2;
    }
    println!("{kills} KILL(s) against gate build {build}");
    println!(
        "note: evaluate()-level finding of record. §4 live-pipe confirmation must\n\
         target a plain-Write, non-taint_exempt deployed tool (web_extract/url)."
    );
    if kills > 0 {
        1
    } else {
        0
    }
}

fn verify_mode(path: &str) -> i32 {
    let p = Path::new(path);
    let bundle = match matchlog::read_bundle(p) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("could not read bundle {path}: {e}");
            return 3;
        }
    };
    println!("── smash verify ─────────────────────────────────────────────");
    println!("bundle   : {path}");
    println!("run id   : {}", bundle.run_id);
    println!("gate     : {}", bundle.gate_build);
    println!("offline  : no gate, no network — recomputed from recorded evidence");
    println!("─────────────────────────────────────────────────────────────");
    match matchlog::verify(&bundle) {
        VerifyOutcome::Verified { cases } => {
            println!("VERIFIED: {cases} case(s) reproduce under the pinned oracle.");
            0
        }
        VerifyOutcome::Failed(f) => {
            println!("VERIFICATION FAILED: {f:?}");
            1
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let code = match args.next().as_deref() {
        Some("verify") => match args.next() {
            Some(path) => verify_mode(&path),
            None => {
                eprintln!("usage: smash-stormgate verify <bundle.json>");
                3
            }
        },
        _ => run_mode(),
    };
    std::process::exit(code);
}
