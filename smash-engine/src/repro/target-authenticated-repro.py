"""Seeded local authenticated-retry fixture entrypoint; no network or credentials."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys


def main():
    if sys.argv[1:3] != ["--control", sys.argv[2]] or len(sys.argv) != 3:
        return 64
    artifact_path = Path(sys.argv[2])
    raw = artifact_path.read_bytes()
    if len(raw) > 65536:
        return 64
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return 64
    if (not isinstance(document, dict)
            or set(document) != {"protocol_version", "target_tool", "action", "expected_state"}
            or document["protocol_version"] != 1
            or document["target_tool"] != "authenticated-retry"
            or document["action"] != "retry_after_authenticated_refresh"
            or document["expected_state"] != "current-session"):
        return 64
    # The trusted adapter selects this immutable fixture; nothing in artifact JSON
    # selects a Python path, a shell command, credentials, or an oracle verdict.
    source = os.environ.get("SMASH_CONTROL_SOURCE", "")
    if not source:
        return 64
    spec = importlib.util.spec_from_file_location("m2_seeded_control", source)
    if spec is None or spec.loader is None:
        return 64
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    observed_state = module.refresh_authenticated_session()
    if not isinstance(observed_state, str) or len(observed_state) > 256:
        return 64
    result = {
        "oracle_version": "authenticated-retry-v1",
        "target_tool": "authenticated-retry",
        "control": os.environ["SMASH_CONTROL_VARIANT"],
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_state": observed_state,
        "expected_state": document["expected_state"],
    }
    with open("result.json", "x", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True, separators=(",", ":"))
    return 10 if observed_state != document["expected_state"] else 0


if __name__ == "__main__":
    sys.exit(main())
