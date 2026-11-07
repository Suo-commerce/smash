//! M5's pinned synthetic revoked-invitation workflow capstone.
//!
//! The only executable driver is the reviewed fixture. Broken/fixed acceptance and
//! the functional control are compared from typed behavior, and verification never
//! reopens the original driver or target roots. These tests do not make vulnerability,
//! target-authenticity, production-safety, or general execution claims.

use serde_json::Value;
use sha2::{Digest, Sha256};
use smash_engine::workflow::{
    read_policy, run_from_path, verify, WorkflowConclusion, WorkflowError, WorkflowManifest,
    WorkflowPolicy,
};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const POLICY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/revoked_invite-policy.json"
);

struct Fixture {
    root: PathBuf,
    policy_path: PathBuf,
    policy: WorkflowPolicy,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let identity = format!("{}-{label}-{nonce}", std::process::id());
        let root = PathBuf::from(format!("/tmp/opencode/smash-m5-capstone-{identity}"));
        assert!(!root.exists());
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        let driver = source.join("revoked_invite.py");
        fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/revoked_invite.py"),
            &driver,
        )
        .unwrap();
        let mut policy = read_policy(Path::new(POLICY)).unwrap();
        policy.run_id = format!("m5-capstone-{identity}");
        policy.broken_driver.path = driver.clone();
        policy.fixed_driver.path = driver;
        policy.broken_root =
            PathBuf::from(format!("/tmp/opencode/smash-m5-target-{identity}-broken"));
        policy.fixed_root =
            PathBuf::from(format!("/tmp/opencode/smash-m5-target-{identity}-fixed"));
        policy.control_root =
            PathBuf::from(format!("/tmp/opencode/smash-m5-target-{identity}-control"));
        let policy_path = root.join("policy.json");
        fs::write(&policy_path, serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
        Self {
            root,
            policy_path,
            policy,
        }
    }
    fn bundle(&self) -> PathBuf {
        self.root.join("bundle")
    }
    fn remove_original_provenance(&self) {
        assert!(!self.policy.broken_root.exists());
        assert!(!self.policy.fixed_root.exists());
        assert!(!self.policy.control_root.exists());
        fs::remove_dir_all(self.root.join("source")).unwrap();
    }
    fn roots_absent(&self) {
        for root in self.roots() {
            assert!(!root.exists(), "left target root: {}", root.display());
        }
    }
    fn roots(&self) -> [&Path; 3] {
        [
            &self.policy.broken_root,
            &self.policy.fixed_root,
            &self.policy.control_root,
        ]
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for root in self.roots() {
            if fs::symlink_metadata(root)
                .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            {
                let _ = fs::remove_dir_all(root);
            } else {
                let _ = fs::remove_file(root);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn complete(fixture: &Fixture) -> WorkflowManifest {
    let manifest = run_from_path(
        &fixture.policy_path,
        &fixture.bundle(),
        true,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(manifest.conclusion, WorkflowConclusion::Confirmed);
    assert!(manifest.assessment.eligible);
    assert!(manifest.assessment.broken_effect);
    assert!(manifest.assessment.fixed_effect_prevented);
    assert!(manifest.assessment.functional_control_normal);
    fixture.roots_absent();
    manifest
}

fn cli(arguments: &[&str]) -> (i32, Option<Value>, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = smash_cli::run(
        arguments.iter().map(OsString::from),
        &mut stdout,
        &mut stderr,
    );
    let error = String::from_utf8(stderr).unwrap();
    let text = String::from_utf8(stdout).unwrap();
    let value =
        if text.is_empty() {
            None
        } else {
            Some(serde_json::from_str(&text).unwrap_or_else(|cause| {
                panic!("invalid CLI JSON {cause}: {text}; stderr: {error}")
            }))
        };
    (code, value, error)
}

fn rehash(bundle: &Path) {
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
    let hashes = manifest["evidence_sha256"].as_object_mut().unwrap();
    for (name, digest) in hashes {
        *digest = Value::String(hex(&Sha256::digest(fs::read(bundle.join(name)).unwrap())));
    }
    fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}
fn copy_bundle(original: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        "policy.json",
        "state.json",
        "journal.jsonl",
        "broken.json",
        "fixed.json",
        "control.json",
        "manifest.json",
    ] {
        fs::copy(original.join(name), destination.join(name)).unwrap();
    }
}
fn rewrite_acceptance_result(step: &mut Value, accepted: bool, invitation: &str) {
    let result = &mut step["result"];
    result["action_status"] = Value::String(if accepted { "granted" } else { "revoked" }.into());
    result["membership_observed"] = Value::Bool(accepted);
    result["state"]["invitation_status"] = Value::String(invitation.into());
    result["state"]["acceptance_status"] =
        Value::String(if accepted { "complete" } else { "denied" }.into());
    result["state"]["guest_is_member"] = Value::Bool(accepted);
    let state_sha256 = hex(&Sha256::digest(
        smash_engine::canonical::canonical_json(&result["state"]).as_bytes(),
    ));
    let action_status = result["action_status"].clone();
    let membership_observed = result["membership_observed"].clone();
    for event in step["events"].as_array_mut().unwrap() {
        event["action_status"] = action_status.clone();
        event["membership_observed"] = membership_observed.clone();
        event["state_sha256"] = Value::String(state_sha256.clone());
    }
}

fn coherent_negative_bundle(original: &Path, destination: &Path, scenario: &str) {
    copy_bundle(original, destination);
    let (file, completion, observation, accepted) = match scenario {
        "broken-denial" => ("broken.json", 4, 5, false),
        "fixed-acceptance" => ("fixed.json", 4, 5, true),
        "control-denial" => ("control.json", 3, 4, false),
        _ => panic!("unknown negative scenario"),
    };
    let prior_invitation = mutate(&destination.join(file), |run| {
        run["steps"][completion - 1]["result"]["state"]["invitation_status"]
            .as_str()
            .unwrap()
            .to_owned()
    });
    let mutated_invitation = if accepted {
        "accepted"
    } else {
        prior_invitation.as_str()
    };
    mutate(&destination.join(file), |run| {
        rewrite_acceptance_result(&mut run["steps"][completion], accepted, mutated_invitation);
        rewrite_acceptance_result(&mut run["steps"][observation], accepted, mutated_invitation);
    });
    mutate(&destination.join("manifest.json"), |manifest| {
        let broken_effect = scenario != "broken-denial";
        let fixed_prevented = scenario != "fixed-acceptance";
        let control_normal = scenario != "control-denial";
        manifest["conclusion"] = Value::String("no_effect".into());
        manifest["assessment"]["eligible"] = Value::Bool(true);
        manifest["assessment"]["interpretation"] = Value::String("no_effect".into());
        for field in ["actions_match", "states_match", "membership_matches"] {
            manifest["assessment"][field] = Value::Bool(false);
        }
        manifest["assessment"]["broken_effect"] = Value::Bool(broken_effect);
        manifest["assessment"]["fixed_effect_prevented"] = Value::Bool(fixed_prevented);
        manifest["assessment"]["functional_control_normal"] = Value::Bool(control_normal);
        manifest["runs"][0]["final_effect_observed"] = Value::Bool(broken_effect);
        manifest["runs"][1]["final_effect_observed"] = Value::Bool(false);
        manifest["runs"][1]["effect_prevented"] = Value::Bool(fixed_prevented);
        manifest["runs"][2]["final_effect_observed"] = Value::Bool(control_normal);
    });
    rehash(destination);
}

fn mutate<T>(path: &Path, mutation: impl FnOnce(&mut Value) -> T) -> T {
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let result = mutation(&mut value);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    result
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn pending_bundles(output: &Path) -> Vec<PathBuf> {
    let prefix = format!(
        ".{}.pending-",
        output.file_name().unwrap().to_string_lossy()
    );
    let mut paths = fs::read_dir(output.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[test]
fn differential_controls_are_real_and_verification_has_no_original_inputs() {
    let fixture = Fixture::new("positive");
    let output = fixture.bundle().to_str().unwrap().to_owned();
    let policy = fixture.policy_path.to_str().unwrap().to_owned();
    let (code, response, errors) = cli(&[
        "workflow-repro",
        "--policy",
        &policy,
        "--out",
        &output,
        "--execute-fixture-workflow",
        "--json",
    ]);
    assert_eq!(code, 0, "{response:?}; {errors}");
    assert_eq!(response.unwrap()["conclusion"], "confirmed");
    fixture.roots_absent();
    for root in fixture.roots() {
        assert!(root.to_string_lossy().contains("smash-m5-target-"));
    }
    for name in [
        "policy.json",
        "state.json",
        "journal.jsonl",
        "broken.json",
        "fixed.json",
        "control.json",
        "manifest.json",
    ] {
        let bytes = fs::read(fixture.bundle().join(name)).unwrap();
        assert!(!bytes
            .windows(b"synthetic-only:".len())
            .any(|part| part == b"synthetic-only:"));
        assert!(!bytes
            .windows(b"SMASH_WORKFLOW_CREDENTIAL".len())
            .any(|part| part == b"SMASH_WORKFLOW_CREDENTIAL"));
    }
    fixture.remove_original_provenance();
    let (code, response, errors) = cli(&["workflow-verify", "--bundle", &output, "--json"]);
    assert_eq!(code, 0, "{response:?}; {errors}");
    let response = response.unwrap();
    assert_eq!(response["conclusion"], "confirmed");
    assert_eq!(response["complete"], true);
    assert_eq!(response["assessment"]["eligible"], true);
    assert_eq!(response["assessment"]["broken_effect"], true);
    assert_eq!(response["assessment"]["fixed_effect_prevented"], true);
    assert_eq!(response["assessment"]["functional_control_normal"], true);
    fixture.roots_absent();
}

#[test]
fn rehashed_tampering_is_rejected_and_inverted_semantics_are_not_green() {
    let fixture = Fixture::new("tampering");
    complete(&fixture);
    fixture.remove_original_provenance();
    type Mutation = (&'static str, &'static str, fn(&mut Value));
    let mutations: [Mutation; 13] = [
        ("argv", "broken.json", |step: &mut Value| {
            let argv = step["steps"][0]["binding"]["argv"].as_array_mut().unwrap();
            let operation = argv
                .iter()
                .position(|value| value == "--operation")
                .unwrap();
            argv[operation + 1] = Value::String("create_invitation".into());
            step["steps"][0]["binding_sha256"] = Value::String(hex(&Sha256::digest(
                serde_json::to_vec(&step["steps"][0]["binding"]).unwrap(),
            )));
        }),
        ("resources", "broken.json", |step| {
            step["steps"][0]["resource_observation"]["wall_ms"] = Value::from(0);
            step["steps"][0]["result"]["resources"]["wall_ms"] = Value::from(0);
        }),
        ("result-schema", "broken.json", |step| {
            for result in step["steps"].as_array_mut().unwrap() {
                result["result"]["schema_version"] = Value::from(2);
            }
        }),
        ("credential", "fixed.json", |step| {
            step["credential_sha256"] = Value::String("00".repeat(32));
        }),
        ("summary", "manifest.json", |step| {
            step["runs"][1]["effect_prevented"] = Value::Bool(false);
        }),
        ("state", "fixed.json", |step| {
            step["steps"][3]["result"]["state"]["authorization"] =
                Value::String("caller-runner".into());
        }),
        ("event-operation", "broken.json", |step| {
            step["steps"][0]["events"][0]["operation"] = Value::String("observe_membership".into());
        }),
        ("event-namespace", "broken.json", |step| {
            step["steps"][0]["events"][0]["run_namespace"] = Value::String("foreign-run".into());
        }),
        ("event-sequence", "broken.json", |step| {
            step["steps"][0]["events"][0]["sequence"] = Value::from(99);
        }),
        ("event-kind", "broken.json", |step| {
            step["steps"][0]["events"][1]["kind"] = Value::String("step_started".into());
        }),
        ("event-action", "broken.json", |step| {
            step["steps"][0]["events"][0]["action_status"] = Value::String("granted".into());
        }),
        ("event-membership", "broken.json", |step| {
            step["steps"][0]["events"][0]["membership_observed"] = Value::Bool(true);
        }),
        ("event-state-digest", "broken.json", |step| {
            step["steps"][0]["events"][0]["state_sha256"] = Value::String("00".repeat(32));
        }),
    ];
    for (label, file, mutation) in mutations {
        let bundle = fixture.root.join(label);
        copy_bundle(&fixture.bundle(), &bundle);
        mutate(&bundle.join(file), mutation);
        rehash(&bundle);
        assert!(verify(&bundle).is_err(), "rehashed {label} was accepted");
        assert_eq!(
            cli(&[
                "workflow-verify",
                "--bundle",
                bundle.to_str().unwrap(),
                "--json"
            ])
            .0,
            2,
            "rehashed {label} did not use the invalid-evidence exit"
        );
    }
    for label in ["reformatted-policy", "duplicate-policy-key"] {
        let bundle = fixture.root.join(label);
        copy_bundle(&fixture.bundle(), &bundle);
        let path = bundle.join("policy.json");
        let bytes = fs::read(&path).unwrap();
        let changed = if label == "reformatted-policy" {
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            serde_json::to_vec_pretty(&value).unwrap()
        } else {
            let mut changed = b"{\"protocol_version\":1,".to_vec();
            changed.extend_from_slice(&bytes[1..]);
            changed
        };
        fs::write(&path, changed).unwrap();
        rehash(&bundle);
        assert!(
            verify(&bundle).is_err(),
            "noncanonical persisted policy was accepted"
        );
        assert_eq!(
            cli(&[
                "workflow-verify",
                "--bundle",
                bundle.to_str().unwrap(),
                "--json"
            ])
            .0,
            2
        );
    }
    let bundle = fixture.root.join("runner");
    copy_bundle(&fixture.bundle(), &bundle);
    mutate(&bundle.join("manifest.json"), |manifest| {
        manifest["runner_version"] = Value::String("caller-runner-v1".into());
    });
    assert!(verify(&bundle).is_err());

    let no_effect = fixture.root.join("no-effect");
    copy_bundle(&fixture.bundle(), &no_effect);
    mutate(&no_effect.join("broken.json"), |run| {
        run["steps"][5]["result"]["membership_observed"] = Value::Bool(false);
        run["steps"][5]["result"]["state"]["guest_is_member"] = Value::Bool(false);
    });
    mutate(&no_effect.join("manifest.json"), |manifest| {
        manifest["conclusion"] = Value::String("no_effect".into());
        manifest["assessment"]["interpretation"] = Value::String("no_effect".into());
        manifest["assessment"]["states_match"] = Value::Bool(false);
        manifest["assessment"]["membership_matches"] = Value::Bool(false);
        manifest["assessment"]["broken_effect"] = Value::Bool(false);
        manifest["runs"][0]["final_effect_observed"] = Value::Bool(false);
    });
    rehash(&no_effect);
    assert!(
        verify(&no_effect).is_err(),
        "inverted decoded behavior was accepted"
    );
    let (code, _, _) = cli(&[
        "workflow-verify",
        "--bundle",
        no_effect.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 2);

    let malformed = fixture.root.join("malformed");
    copy_bundle(&fixture.bundle(), &malformed);
    fs::write(malformed.join("broken.json"), b"{\"not\":\"closed\"}").unwrap();
    fs::write(malformed.join("state.json"), b"{\"phase\":").unwrap();
    fs::write(
        malformed.join("journal.jsonl"),
        b"{\"kind\":\"bundle_created\"}",
    )
    .unwrap();
    fs::remove_file(malformed.join("manifest.json")).unwrap();
    let incomplete = verify(&malformed).unwrap();
    assert_eq!(
        incomplete.conclusion,
        WorkflowConclusion::InterpretationFailed
    );
    assert!(incomplete.assessment.is_none());
    fixture.roots_absent();
}

#[test]
fn coherent_negative_outcomes_are_completed_no_effect_evidence() {
    let fixture = Fixture::new("negative-outcomes");
    complete(&fixture);
    fixture.remove_original_provenance();
    for scenario in ["broken-denial", "fixed-acceptance", "control-denial"] {
        let bundle = fixture.root.join(scenario);
        coherent_negative_bundle(&fixture.bundle(), &bundle, scenario);
        let verified = verify(&bundle).unwrap();
        assert_eq!(
            verified.conclusion,
            WorkflowConclusion::NoEffect,
            "{scenario}"
        );
        let assessment = verified.assessment.unwrap();
        assert!(assessment.eligible, "{scenario}");
        assert_eq!(
            assessment.interpretation,
            smash_engine::workflow::Interpretation::NoEffect
        );
        assert_eq!(assessment.broken_effect, scenario != "broken-denial");
        assert_eq!(
            assessment.fixed_effect_prevented,
            scenario != "fixed-acceptance"
        );
        assert_eq!(
            assessment.functional_control_normal,
            scenario != "control-denial"
        );
        let (code, response, errors) = cli(&[
            "workflow-verify",
            "--bundle",
            bundle.to_str().unwrap(),
            "--json",
        ]);
        assert_eq!(code, 1, "{scenario}: {response:?}; {errors}");
        assert_eq!(response.unwrap()["conclusion"], "no_effect");
    }
    fixture.roots_absent();
}

#[test]
fn unauthorized_policy_execution_flags_and_target_namespaces_never_execute() {
    let fixture = Fixture::new("denied");
    let policy = fixture.policy_path.to_str().unwrap();
    let output_path = fixture.bundle();
    let output = output_path.to_str().unwrap();
    let (code, _, errors) = cli(&[
        "workflow-repro",
        "--policy",
        policy,
        "--out",
        output,
        "--json",
    ]);
    assert_eq!(code, 2);
    assert!(!errors.is_empty());
    assert!(!fixture.bundle().exists());
    fixture.roots_absent();

    mutate(&fixture.policy_path, |policy| {
        policy["unsafe_development"] = Value::Bool(true)
    });
    let (code, _, _) = cli(&[
        "workflow-repro",
        "--policy",
        policy,
        "--out",
        output,
        "--execute-fixture-workflow",
        "--json",
    ]);
    assert_eq!(code, 2);
    assert!(!fixture.bundle().exists());
    fixture.roots_absent();
    mutate(&fixture.policy_path, |policy| {
        policy["unsafe_development"] = Value::Bool(false)
    });
    mutate(&fixture.policy_path, |policy| {
        policy["run_id"] = Value::String("m5-capstone-denied-other-flags".into())
    });
    let (code, _, _) = cli(&[
        "workflow-repro",
        "--policy",
        policy,
        "--out",
        output,
        "--execute-fixture-workflow",
        "--execute-fixture-mutations",
        "--json",
    ]);
    assert_eq!(code, 2);
    assert!(!fixture.bundle().exists());

    fs::create_dir(&fixture.policy.control_root).unwrap();
    fs::set_permissions(
        &fixture.policy.control_root,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(fixture.policy.control_root.join("prior-state"), b"stale").unwrap();
    let error = run_from_path(
        &fixture.policy_path,
        &fixture.bundle(),
        true,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::Policy(_)), "{error}");
    assert_eq!(
        fs::read(fixture.policy.control_root.join("prior-state")).unwrap(),
        b"stale"
    );
    assert!(!fixture.policy.broken_root.exists());
    assert!(!fixture.policy.fixed_root.exists());
    assert!(!fixture.bundle().exists());
    fs::remove_dir_all(&fixture.policy.control_root).unwrap();
    fs::create_dir(&fixture.policy.broken_root).unwrap();
    fs::set_permissions(
        &fixture.policy.broken_root,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let error = run_from_path(
        &fixture.policy_path,
        &fixture.bundle(),
        true,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::Policy(_)), "{error}");
    assert!(!fixture.bundle().exists());
    fs::remove_dir_all(&fixture.policy.broken_root).unwrap();
    fixture.roots_absent();
}

#[test]
fn fresh_invocations_never_replay_namespaces_authority_or_published_output() {
    let fixture = Fixture::new("fresh");
    let first = complete(&fixture);
    let first_runs = ["broken.json", "fixed.json", "control.json"].map(|name| {
        serde_json::from_slice::<Value>(&fs::read(fixture.bundle().join(name)).unwrap()).unwrap()
    });
    let first_bytes = fs::read(fixture.bundle().join("manifest.json")).unwrap();

    let second_bundle = fixture.root.join("second-bundle");
    let second = run_from_path(
        &fixture.policy_path,
        &second_bundle,
        true,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(second.conclusion, WorkflowConclusion::Confirmed);
    assert_ne!(first.invocation_id, second.invocation_id);
    let second_runs = ["broken.json", "fixed.json", "control.json"].map(|name| {
        serde_json::from_slice::<Value>(&fs::read(second_bundle.join(name)).unwrap()).unwrap()
    });
    for (before, after) in first_runs.iter().zip(&second_runs) {
        assert_ne!(before["run_namespace"], after["run_namespace"]);
        assert_ne!(before["credential_sha256"], after["credential_sha256"]);
        for (left, right) in before["steps"]
            .as_array()
            .unwrap()
            .iter()
            .zip(after["steps"].as_array().unwrap())
        {
            assert_ne!(
                left["binding"]["run_namespace"],
                right["binding"]["run_namespace"]
            );
            assert_ne!(left["binding_sha256"], right["binding_sha256"]);
            for (left_event, right_event) in left["events"]
                .as_array()
                .unwrap()
                .iter()
                .zip(right["events"].as_array().unwrap())
            {
                assert_ne!(left_event["run_namespace"], right_event["run_namespace"]);
            }
        }
    }
    assert_eq!(
        verify(&second_bundle).unwrap().conclusion,
        WorkflowConclusion::Confirmed
    );

    let error = run_from_path(
        &fixture.policy_path,
        &fixture.bundle(),
        true,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::Policy(_)), "{error}");
    assert_eq!(
        fs::read(fixture.bundle().join("manifest.json")).unwrap(),
        first_bytes
    );
    assert_eq!(
        verify(&fixture.bundle()).unwrap().conclusion,
        WorkflowConclusion::Confirmed
    );
    fixture.roots_absent();
}

#[test]
fn budgets_interruption_and_invalid_results_never_leave_green_or_live_targets() {
    let timeout = Fixture::new("timeout");
    mutate(&timeout.policy_path, |policy| {
        policy["limits"]["wall_ms"] = Value::from(1);
    });
    let timeout_manifest = run_from_path(
        &timeout.policy_path,
        &timeout.bundle(),
        true,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(
        timeout_manifest.conclusion,
        WorkflowConclusion::EnvironmentManualReview
    );
    assert!(!timeout_manifest.assessment.eligible);
    timeout.roots_absent();
    let non_green = verify(&timeout.bundle()).unwrap();
    assert_eq!(
        non_green.conclusion,
        WorkflowConclusion::EnvironmentManualReview
    );
    assert_eq!(
        cli(&[
            "workflow-verify",
            "--bundle",
            timeout.bundle().to_str().unwrap(),
            "--json"
        ])
        .0,
        2
    );

    let bounded = Fixture::new("bounded");
    mutate(&bounded.policy_path, |policy| {
        policy["limits"]["output_bytes"] = Value::from(16);
    });
    let (code, response, errors) = cli(&[
        "workflow-repro",
        "--policy",
        bounded.policy_path.to_str().unwrap(),
        "--out",
        bounded.bundle().to_str().unwrap(),
        "--execute-fixture-workflow",
        "--json",
    ]);
    assert_eq!(code, 2, "{response:?}; {errors}");
    let response = response.unwrap();
    assert_eq!(response["conclusion"], "environment_manual_review");
    assert_eq!(response["manifest"]["assessment"]["eligible"], false);
    bounded.roots_absent();
    assert_eq!(
        verify(&bounded.bundle()).unwrap().conclusion,
        WorkflowConclusion::EnvironmentManualReview
    );
    assert_eq!(
        cli(&[
            "workflow-verify",
            "--bundle",
            bounded.bundle().to_str().unwrap(),
            "--json"
        ])
        .0,
        2
    );

    let cancelled = Fixture::new("cancelled");
    let signal = Arc::new(AtomicBool::new(false));
    let canceller = {
        let signal = Arc::clone(&signal);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            signal.store(true, Ordering::SeqCst);
        })
    };
    let error =
        run_from_path(&cancelled.policy_path, &cancelled.bundle(), true, &signal).unwrap_err();
    canceller.join().unwrap();
    assert!(matches!(error, WorkflowError::Interrupted), "{error}");
    cancelled.roots_absent();
    assert!(
        !cancelled.bundle().exists(),
        "an interruption exposed the final bundle"
    );
    let pending = pending_bundles(&cancelled.bundle());
    assert_eq!(pending.len(), 1);
    assert!(!pending[0].join("manifest.json").exists());
    assert_eq!(
        fs::symlink_metadata(&pending[0])
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let interrupted = verify(&pending[0]).unwrap();
    assert_eq!(
        interrupted.conclusion,
        WorkflowConclusion::InterpretationFailed
    );
    assert!(interrupted.assessment.is_none());
    assert_eq!(
        cli(&[
            "workflow-verify",
            "--bundle",
            pending[0].to_str().unwrap(),
            "--json"
        ])
        .0,
        2
    );
    let (code, _, _) = cli(&[
        "workflow-resume",
        "--bundle",
        pending[0].to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 2, "an interrupted run acquired a resume command");

    let manifest = complete(&cancelled);
    let interrupted_state: Value =
        serde_json::from_slice(&fs::read(pending[0].join("state.json")).unwrap()).unwrap();
    assert_ne!(interrupted_state["invocation_id"], manifest.invocation_id);
    assert_eq!(pending_bundles(&cancelled.bundle()), pending);
    assert!(verify(&pending[0]).unwrap().assessment.is_none());

    let changed = Fixture::new("changed");
    fs::write(
        changed.policy.broken_driver.path.clone(),
        b"not the pinned driver",
    )
    .unwrap();
    let error = run_from_path(
        &changed.policy_path,
        &changed.bundle(),
        true,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert!(matches!(error, WorkflowError::Policy(_)), "{error}");
    assert!(!changed.bundle().exists());
    changed.roots_absent();
}
