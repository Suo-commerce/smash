//! M1 capstone: scripted source reconnaissance, explicit refusal, and offline checks.

use serde_json::{json, Value};
use smash_engine::recon::verify_campaign;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

fn copy_repository(source: &Path, destination: &Path) {
    fs::create_dir_all(destination.join("src")).unwrap();
    fs::copy(
        source.join("src/dispatcher.rs"),
        destination.join("src/dispatcher.rs"),
    )
    .unwrap();
}

fn os(value: &str) -> OsString {
    OsString::from(value)
}

#[test]
fn seeded_repository_hypothesis_survives_source_deletion_and_detects_tampering() {
    let base = std::env::temp_dir().join(format!("recon-capstone-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let repository = base.join("repository");
    copy_repository(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/vulnerable-repository"),
        &repository,
    );
    fs::write(
        repository.join(".env"),
        "CAPSTONE_MUST_NOT_APPEAR=fixture-only",
    )
    .unwrap();
    let manifest = base.join("target.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "target_id": "seeded-repository",
            "kind": "repository",
            "locator": repository,
            "description": "Seeded source-only capstone"
        }))
        .unwrap(),
    )
    .unwrap();
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/recon-script.json");
    let bundle = base.join("bundle");
    let arguments = vec![
        os("recon"),
        os("--target"),
        manifest.into_os_string(),
        os("--script"),
        script.into_os_string(),
        os("--out"),
        bundle.clone().into_os_string(),
        os("--run-id"),
        os("recon-capstone"),
    ];
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let code = smash_cli::run(arguments.into_iter(), &mut output, &mut errors);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&errors));
    assert!(!repository.join("escaped").exists());

    let report_bytes = fs::read(bundle.join("report.json")).unwrap();
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    let hypothesis = &report["hypotheses"][0];
    assert_eq!(hypothesis["hypothesis_id"], "dispatcher-validation-order");
    assert_eq!(hypothesis["source_locations"][0], "src/dispatcher.rs");
    assert_eq!(hypothesis["evidence_state"], "source_observed");
    assert_eq!(hypothesis["dynamically_verified_vulnerability"], false);
    assert_eq!(report["coverage"]["dynamic_behavior_tested"], false);
    assert_eq!(report["evaluations"][0]["status"], "missing");
    let observations = fs::read_to_string(bundle.join("bundle.json")).unwrap();
    assert!(observations.contains("secret-like path excluded"));
    assert!(!observations.contains("CAPSTONE_MUST_NOT_APPEAR"));
    for entry in fs::read_dir(bundle.join("artifacts")).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("CAPSTONE_MUST_NOT_APPEAR"));
    }

    // The verifier uses only the bundle. No source, model, credential, or Git
    // availability is required after this point.
    fs::remove_dir_all(&repository).unwrap();
    let verification = verify_campaign(&bundle);
    assert!(verification.is_valid(), "{:?}", verification.failures);
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let verify_code = smash_cli::run(
        vec![
            os("verify"),
            os("--bundle"),
            bundle.clone().into_os_string(),
            os("--json"),
        ]
        .into_iter(),
        &mut output,
        &mut errors,
    );
    assert_eq!(verify_code, 0);
    let verification_json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(verification_json["valid"], true);

    fs::write(bundle.join("report.md"), "# falsely verified\n").unwrap();
    let mut output = Vec::new();
    let mut errors = Vec::new();
    assert_eq!(
        smash_cli::run(
            vec![
                os("verify"),
                os("--bundle"),
                bundle.clone().into_os_string()
            ]
            .into_iter(),
            &mut output,
            &mut errors,
        ),
        1
    );
    assert!(!verify_campaign(&bundle).is_valid());
    fs::remove_dir_all(base).unwrap();
}
