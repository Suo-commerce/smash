//! M3 HTTP target pack: seeded state effect, differential controls, and
//! execution-free evidence after the fixture processes have terminated.

use serde_json::Value;
use smash_capstone::http_fixture::{ControlVariant, HttpFixture};
use smash_engine::http::bundle::{persist_bundle, verify_bundle};
use smash_engine::http::campaign::{
    execute_campaign, DifferentialVerdict, EffectContract, HttpCampaignPolicy, HttpControl,
    HttpPlannedCall,
};
use smash_engine::http::policy::*;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

const CREDENTIAL: &str = "SMASH_M3_CAPSTONE_SECRET";
const SECRET: &str = "fixture-secret-not-real";

fn arguments(attempt_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("attempt_id".into(), attempt_id.into())])
}

fn route(id: &str, method: HttpMethod, path: &str, authenticated: bool) -> RoutePolicy {
    let field = FieldLimit { max_utf8_bytes: 96 };
    RoutePolicy {
        route_id: id.into(),
        method,
        effect: if method == HttpMethod::POST {
            OperationEffect::Mutating
        } else {
            OperationEffect::ReadOnly
        },
        path: path.into(),
        credential: authenticated.then(|| CredentialRef {
            environment_variable: CREDENTIAL.into(),
        }),
        query_fields: if method == HttpMethod::GET {
            BTreeMap::from([("attempt_id".into(), field.clone())])
        } else {
            BTreeMap::new()
        },
        body_fields: if method == HttpMethod::POST {
            BTreeMap::from([("attempt_id".into(), field)])
        } else {
            BTreeMap::new()
        },
        headers: if method == HttpMethod::POST {
            BTreeMap::from([("Content-Type".into(), "application/json".into())])
        } else {
            BTreeMap::new()
        },
        response_fields: match id {
            "health" => BTreeMap::from([("ready".into(), ResponseFieldKind::Boolean)]),
            "commit" => BTreeMap::from([("accepted".into(), ResponseFieldKind::Boolean)]),
            _ => BTreeMap::from([
                ("effect_count".into(), ResponseFieldKind::NonNegativeInteger),
                ("authorized".into(), ResponseFieldKind::Boolean),
            ]),
        },
    }
}

fn call(
    route_id: &str,
    attempt_id: &str,
    bool_field: &str,
    expected: bool,
    count: Option<u64>,
) -> HttpPlannedCall {
    let mut expected_fields =
        BTreeMap::from([(bool_field.into(), ResponseValue::Boolean(expected))]);
    if let Some(count) = count {
        expected_fields.insert(
            "effect_count".into(),
            ResponseValue::NonNegativeInteger(count),
        );
    }
    HttpPlannedCall {
        call: PlannedHttpCall {
            route_id: route_id.into(),
            arguments: arguments(attempt_id),
        },
        expected: expected_fields,
    }
}

fn fixture_policy(broken: &HttpFixture, fixed: &HttpFixture) -> HttpCampaignPolicy {
    HttpCampaignPolicy {
        schema_version: 1,
        run_id: "m3-capstone-run".into(),
        target: HttpTargetPolicy {
            schema_version: 1,
            target_id: "authenticated-duplicate-effect-http".into(),
            environment: HttpEnvironment::DisposableFixture,
            origin: broken.origin(),
            resolved_addresses: vec![broken.local_addr().ip(), fixed.local_addr().ip()],
            routes: vec![
                route("health", HttpMethod::GET, "/v1/health", false),
                route("receipt", HttpMethod::GET, "/v1/receipt", true),
                route("commit", HttpMethod::POST, "/v1/commit", true),
            ],
            limits: HttpLimits {
                max_calls: 8,
                max_mutations: 1,
                max_request_bytes: 4_096,
                max_response_bytes: 4_096,
                timeout_ms: 500,
            },
        },
        fixed_origin: fixed.origin(),
        calls: vec![
            call("health", "m3-attempt", "ready", true, None),
            call("receipt", "m3-attempt", "authorized", false, Some(0)),
            call("commit", "m3-attempt", "accepted", true, None),
            call("receipt", "m3-attempt", "authorized", true, Some(1)),
            call("receipt", "unknown-attempt", "authorized", false, Some(0)),
        ],
        effect: Some(EffectContract {
            before_case: 1,
            mutation_case: 2,
            after_case: 3,
            unknown_case: 4,
            correlation_field: "attempt_id".into(),
            effect_field: "effect_count".into(),
        }),
    }
}

#[test]
fn seeded_effect_is_differential_and_bundle_verifies_after_fixture_shutdown() {
    let mut broken = Some(HttpFixture::start(ControlVariant::Broken).unwrap());
    let mut fixed = Some(HttpFixture::start(ControlVariant::Fixed).unwrap());
    let policy = fixture_policy(broken.as_ref().unwrap(), fixed.as_ref().unwrap());
    let (broken_record, fixed_record, assessment) = execute_campaign(
        &policy,
        |name| (name == CREDENTIAL).then(|| SECRET.to_owned()),
        |control| {
            // The provider drops and joins the actual fixture before attesting cleanup.
            match control {
                HttpControl::Broken => drop(broken.take()),
                HttpControl::Fixed => drop(fixed.take()),
                HttpControl::Observed => panic!("paired execution cannot be observed-only"),
            }
            true
        },
    )
    .unwrap();
    assert_eq!(assessment.verdict, DifferentialVerdict::Reproduced);
    assert_eq!(
        broken_record.calls[3].observation.as_ref().unwrap().fields["effect_count"],
        ResponseValue::NonNegativeInteger(2)
    );
    assert_eq!(
        fixed_record.calls[3].observation.as_ref().unwrap().fields["effect_count"],
        ResponseValue::NonNegativeInteger(1)
    );
    assert!(broken_record.cleanup_completed && fixed_record.cleanup_completed);
    assert!(
        broken_record.calls[4].observation.as_ref().unwrap().fields["effect_count"]
            == ResponseValue::NonNegativeInteger(0)
    );

    let root = PathBuf::from(format!(
        "/tmp/opencode/smash-m3-capstone-{}",
        std::process::id()
    ));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let bundle = persist_bundle(&root, policy, broken_record, fixed_record, assessment).unwrap();
    let evidence = fs::read_to_string(root.join("manifest.json")).unwrap();
    assert!(!evidence.contains(SECRET));
    assert!(!evidence.contains("Bearer"));
    assert!(evidence.contains("body_sha256"));
    assert!(evidence.contains("attempt_id"));
    assert_eq!(verify_bundle(&root).unwrap(), bundle);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = smash_cli::run(
        [
            "http-verify".into(),
            "--bundle".into(),
            root.as_os_str().to_owned(),
            "--json".into(),
        ]
        .into_iter(),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&stdout).unwrap()["valid"],
        true
    );
    // No running target, resolver, or original planner is needed by verification.
    assert_eq!(bundle.broken.control, HttpControl::Broken);

    let mut tampered = bundle;
    tampered.broken.calls[3]
        .observation
        .as_mut()
        .unwrap()
        .fields
        .insert("effect_count".into(), ResponseValue::NonNegativeInteger(1));
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    assert!(verify_bundle(&root).is_err());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        smash_cli::run(
            vec![
                OsString::from("http-verify"),
                OsString::from("--bundle"),
                root.clone().into_os_string(),
            ]
            .into_iter(),
            &mut stdout,
            &mut stderr,
        ),
        2
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn incomplete_cleanup_is_inconclusive_and_invalid_effect_contracts_are_rejected() {
    let broken = HttpFixture::start(ControlVariant::Broken).unwrap();
    let fixed = HttpFixture::start(ControlVariant::Fixed).unwrap();
    let policy = fixture_policy(&broken, &fixed);
    let (broken_record, fixed_record, assessment) =
        execute_campaign(&policy, |_| Some(SECRET.into()), |_| false).unwrap();
    assert_eq!(assessment.verdict, DifferentialVerdict::Inconclusive);
    assert!(!broken_record.cleanup_completed);
    assert!(!fixed_record.cleanup_completed);
    drop((broken, fixed));

    // An acknowledgment/status response is not interchangeable with the
    // declared nonnegative integer receipt used to establish the effect.
    let mut response_only = policy.clone();
    response_only.effect.as_mut().unwrap().effect_field = "accepted".into();
    assert!(response_only.validate().is_err());
    let mut uncorrelated = policy.clone();
    uncorrelated.effect.as_mut().unwrap().correlation_field = "other_id".into();
    assert!(uncorrelated.validate().is_err());
    let mut wrong_unknown_control = policy;
    wrong_unknown_control.calls[4]
        .expected
        .insert("effect_count".into(), ResponseValue::NonNegativeInteger(1));
    assert!(wrong_unknown_control.validate().is_err());
}

#[test]
fn cli_observes_only_admitted_reads_and_requires_explicit_mutation_opt_in() {
    let broken = HttpFixture::start(ControlVariant::Broken).unwrap();
    let fixed = HttpFixture::start(ControlVariant::Fixed).unwrap();
    let mut policy = fixture_policy(&broken, &fixed);
    policy
        .target
        .routes
        .retain(|route| route.route_id == "health");
    policy.calls.retain(|case| case.call.route_id == "health");
    policy.effect = None;
    assert!(policy.validate().is_ok());

    let root = PathBuf::from(format!("/tmp/opencode/smash-m3-cli-{}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir_all(&root).unwrap();
    let file = root.join("policy.json");
    fs::write(&file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = smash_cli::run(
        vec![
            OsString::from("http-discover"),
            OsString::from("--policy"),
            file.clone().into_os_string(),
            OsString::from("--out"),
            root.join("discovery").into_os_string(),
            OsString::from("--run-id"),
            OsString::from("m3-cli-read-only"),
            OsString::from("--json"),
        ]
        .into_iter(),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, 0, "{}", String::from_utf8_lossy(&stderr));
    let report: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["completed"], true);
    assert_eq!(report["discovered"], false);
    assert_eq!(
        report["evidence"]["session_id"],
        "m3-cli-read-only:authenticated-duplicate-effect-http:observed:session"
    );
    assert_eq!(report["evidence"]["calls"][0]["outcome"], "observed");
    assert_eq!(
        report["evidence"]["calls"][0]["observation"]["fields"]["ready"]["boolean"],
        true
    );
    assert!(!String::from_utf8_lossy(&stdout).contains(SECRET));

    for execute in [false, true] {
        let out = root.join(if execute {
            "unplanned-mutation"
        } else {
            "without-opt-in"
        });
        let mut argv = vec![
            OsString::from("http-repro"),
            OsString::from("--policy"),
            file.clone().into_os_string(),
            OsString::from("--out"),
            out.clone().into_os_string(),
        ];
        if execute {
            argv.push(OsString::from("--execute-fixture-mutations"));
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            smash_cli::run(argv.into_iter(), &mut stdout, &mut stderr),
            2
        );
        assert!(!out.exists());
    }
    drop((broken, fixed));
    fs::remove_dir_all(root).unwrap();
}
