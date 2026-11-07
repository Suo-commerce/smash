#!/usr/bin/python3
"""Deterministic synthetic revoked-invitation fixture; no third-party dependencies."""

import argparse
import hashlib
import json
import os
import resource
import sys
import time


OPERATIONS = {
    "create_project",
    "create_invitation",
    "begin_acceptance",
    "revoke_invitation",
    "complete_acceptance",
    "observe_membership",
}
STATE_KEYS = {
    "schema_version",
    "snapshot",
    "credential_sha256",
    "current_credential_sha256",
    "acceptance_authorized",
}
SNAPSHOT_KEYS = {
    "schema_version",
    "state_sequence",
    "project",
    "owner",
    "guest",
    "invitation",
    "invitation_status",
    "acceptance_status",
    "guest_member",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def read_json(path):
    with open(path, "r", encoding="utf-8") as source:
        value = json.load(source, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("object required")
    return value


def write_json(path, value, replace):
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if replace else os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def initial_state(arguments):
    return {
        "schema_version": 1,
        "snapshot": {
            "schema_version": 1,
            "state_sequence": 0,
            "project": arguments.project,
            "owner": arguments.owner,
            "guest": arguments.guest,
            "invitation": arguments.invitation,
            "invitation_status": "absent",
            "acceptance_status": "absent",
            "guest_member": False,
        },
        "credential_sha256": None,
        "current_credential_sha256": None,
        "acceptance_authorized": False,
    }


def load_state(arguments):
    if not os.path.exists(arguments.state):
        return initial_state(arguments)
    state = read_json(arguments.state)
    if set(state) != STATE_KEYS or set(state["snapshot"]) != SNAPSHOT_KEYS:
        raise ValueError("invalid state schema")
    snapshot = state["snapshot"]
    if state["schema_version"] != 1 or snapshot["schema_version"] != 1:
        raise ValueError("invalid state version")
    if not isinstance(snapshot["state_sequence"], int) or isinstance(
        snapshot["state_sequence"], bool
    ):
        raise ValueError("invalid sequence")
    expected = {
        "project": arguments.project,
        "owner": arguments.owner,
        "guest": arguments.guest,
        "invitation": arguments.invitation,
    }
    for key, value in expected.items():
        if snapshot[key] != value:
            raise ValueError("identity mismatch")
    if snapshot["invitation_status"] not in {"absent", "pending", "revoked", "accepted"}:
        raise ValueError("invalid invitation")
    if snapshot["acceptance_status"] not in {"absent", "pending", "accepted", "denied"}:
        raise ValueError("invalid acceptance")
    if not isinstance(snapshot["guest_member"], bool) or not isinstance(
        state["acceptance_authorized"], bool
    ):
        raise ValueError("invalid booleans")
    for key in ("credential_sha256", "current_credential_sha256"):
        value = state[key]
        if value is not None and (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("invalid credential digest")
    return state


def advance(state, operation, result):
    state["snapshot"]["state_sequence"] += 1
    return {
        "schema_version": 1,
        "operation": operation,
        "result": result,
        "snapshot": state["snapshot"],
    }


def apply(state, arguments, credential_digest):
    snapshot = state["snapshot"]
    invitation = snapshot["invitation_status"]
    acceptance = snapshot["acceptance_status"]
    operation = arguments.operation

    if operation == "create_project":
        if snapshot["state_sequence"] != 0 or invitation != "absent" or acceptance != "absent":
            raise ValueError("project already initialized")
        return advance(state, operation, "project_created")

    if snapshot["state_sequence"] == 0:
        raise ValueError("project missing")
    if operation == "create_invitation":
        if invitation != "absent" or acceptance != "absent" or credential_digest is None:
            raise ValueError("invalid invitation transition")
        snapshot["invitation_status"] = "pending"
        state["credential_sha256"] = credential_digest
        state["current_credential_sha256"] = credential_digest
        return advance(state, operation, "invitation_pending")

    if operation == "begin_acceptance":
        if (
            invitation != "pending"
            or acceptance != "absent"
            or credential_digest is None
            or credential_digest != state["current_credential_sha256"]
        ):
            raise ValueError("invalid acceptance start")
        snapshot["acceptance_status"] = "pending"
        state["acceptance_authorized"] = True
        return advance(state, operation, "acceptance_pending")

    if operation == "revoke_invitation":
        if invitation != "pending" or acceptance != "pending":
            raise ValueError("invalid revocation")
        snapshot["invitation_status"] = "revoked"
        state["current_credential_sha256"] = None
        # Deliberate broken behavior: begin_acceptance captured authority and the
        # broken completion path below never revalidates the revoked invitation.
        return advance(state, operation, "invitation_revoked")

    if operation == "complete_acceptance":
        if acceptance != "pending" or credential_digest is None:
            raise ValueError("invalid completion")
        authorized = state["acceptance_authorized"]
        current = (
            invitation == "pending"
            and state["current_credential_sha256"] == credential_digest
        )
        if authorized and (arguments.variant == "broken" or current):
            if credential_digest != state["credential_sha256"]:
                raise ValueError("wrong guest credential")
            snapshot["invitation_status"] = "accepted"
            snapshot["acceptance_status"] = "accepted"
            snapshot["guest_member"] = True
            return advance(state, operation, "acceptance_accepted")
        if invitation == "revoked":
            snapshot["acceptance_status"] = "denied"
            snapshot["guest_member"] = False
            return advance(state, operation, "acceptance_denied_revoked")
        raise ValueError("completion is not authorized")

    if operation == "observe_membership":
        return advance(state, operation, "membership_observed")
    raise ValueError("unsupported operation")


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_result(path, result):
    # Resolve the otherwise self-referential exact result-file byte count.
    result["resources"]["output_bytes"] = 0
    for _ in range(8):
        encoded = encode(result)
        result["resources"]["output_bytes"] = len(encoded)
    if result["resources"]["output_bytes"] != len(encode(result)):
        raise ValueError("unstable resource output length")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encode(result))
        output.flush()
        os.fsync(output.fileno())
    return result["resources"]["output_bytes"]


def response(snapshot, action, started, arguments):
    statuses = {
        "absent": "not_started",
        "pending": "pending",
        "accepted": "complete",
        "denied": "denied",
    }
    action_status = None
    if action == "acceptance_accepted":
        action_status = "granted"
    elif action == "acceptance_denied_revoked":
        action_status = "revoked"
    # Observation independently reads membership; it does not reapply authorization.
    if arguments.operation == "observe_membership":
        action_status = "granted" if snapshot["guest_member"] else "revoked"
    usage = resource.getrusage(resource.RUSAGE_SELF)
    result = {
        "schema_version": 1,
        "state": {
            "schema_version": snapshot["schema_version"],
            "sequence": snapshot["state_sequence"],
            "project": snapshot["project"],
            "owner": snapshot["owner"],
            "guest": snapshot["guest"],
            "invitation": snapshot["invitation"],
            "invitation_status": snapshot["invitation_status"],
            "acceptance_status": statuses[snapshot["acceptance_status"]],
            "guest_is_member": snapshot["guest_member"],
        },
        "action_status": action_status,
        "membership_observed": snapshot["guest_member"],
        "resources": {
            "wall_ms": (time.monotonic_ns() - started) // 1_000_000,
            "cpu_user_us": int(usage.ru_utime * 1_000_000),
            "cpu_system_us": int(usage.ru_stime * 1_000_000),
            "max_rss_bytes": usage.ru_maxrss * 1024,
            "output_bytes": 0,
            "memory_limit_bytes": arguments.memory_limit_bytes,
        },
    }
    if result["state"]["invitation_status"] == "absent":
        result["state"]["invitation_status"] = "pending"
    return result


def main():
    started = time.monotonic_ns()
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--variant", required=True, choices=("broken", "fixed"))
    parser.add_argument("--operation", required=True, choices=tuple(sorted(OPERATIONS)))
    parser.add_argument("--state", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--guest", required=True)
    parser.add_argument("--invitation", required=True)
    parser.add_argument("--credential-reference", required=True)
    parser.add_argument("--memory-limit-bytes", required=True, type=int)
    arguments = parser.parse_args()
    if not 16 * 1024 * 1024 <= arguments.memory_limit_bytes <= 128 * 1024 * 1024:
        raise ValueError("invalid memory limit")
    if arguments.credential_reference != "synthetic-guest":
        raise ValueError("unknown synthetic credential reference")
    credential = os.environ.get("SMASH_WORKFLOW_CREDENTIAL")
    credential_digest = (
        hashlib.sha256(credential.encode("utf-8")).hexdigest() if credential else None
    )
    state = load_state(arguments)
    result = apply(state, arguments, credential_digest)
    write_json(arguments.state, state, replace=os.path.exists(arguments.state))
    result = response(state["snapshot"], result["result"], started, arguments)
    write_result(arguments.output, result)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # Target diagnostics are deliberately outside the retained evidence contract.
        sys.exit(2)
