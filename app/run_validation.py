
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


RUNS_DIR = Path("data/runs")
REGION = "eu-north-1"

SCENARIOS = {
    "curl": {
        "name": "Shell / download utility execution",
        "expected_behaviour": (
            "A user invokes curl to retrieve remote content "
            "and write it to a local file."
        ),
        "attack_techniques": ["T1059.004", "T1105"],
    },
    "systemd": {
        "name": "Systemd service creation and execution",
        "expected_behaviour": (
            "A systemd unit file is created and its "
            "configured harmless command executes."
        ),
        "attack_techniques": ["T1543.002"],
    },
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def save_json(path, data):
    path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def aws(*arguments):
    result = subprocess.run(
        ["aws", *arguments, "--region", REGION],
        capture_output=True,
        text=True,
        check=True,
        timeout=140,
    )
    return result.stdout.strip()


def find_target():
    """Discover exactly one running SEC598 instance."""

    output = aws(
        "ec2", "describe-instances",
        "--filters",
        "Name=tag:Project,Values=sec598-coin",
        "Name=instance-state-name,Values=running",
        "--query", "Reservations[].Instances[].InstanceId",
        "--output", "json",
    )

    instance_ids = json.loads(output)

    if len(instance_ids) != 1:
        raise RuntimeError(
            f"Expected one running target, found {len(instance_ids)}"
        )

    return instance_ids[0]


def verify_target(instance_id):
    """Verify an explicitly supplied EC2 instance belongs to our lab."""

    if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
        raise RuntimeError("Invalid EC2 instance ID format")

    output = aws(
        "ec2", "describe-instances",
        "--instance-ids", instance_id,
        "--query",
        "Reservations[].Instances[].{"
        "Id:InstanceId,"
        "State:State.Name,"
        "Tags:Tags"
        "}",
        "--output", "json",
    )

    instances = json.loads(output)

    if len(instances) != 1:
        raise RuntimeError("Target instance not found")

    instance = instances[0]

    tags = {
        tag["Key"]: tag["Value"]
        for tag in instance.get("Tags", [])
    }

    if tags.get("Project") != "sec598-coin":
        raise RuntimeError(
            "Target does not have the expected SEC598 project tag"
        )

    if instance["State"] != "running":
        raise RuntimeError(
            f"Target is not running: {instance['State']}"
        )

    return instance_id


def send_ssm(instance_id, command):
    return aws(
        "ssm", "send-command",
        "--instance-ids", instance_id,
        "--document-name", "AWS-RunShellScript",
        "--parameters", json.dumps({"commands": [command]}),
        "--query", "Command.CommandId",
        "--output", "text",
    )


def get_ssm_result(instance_id, command_id):
    wait_error = None

    try:
        aws(
            "ssm", "wait", "command-executed",
            "--command-id", command_id,
            "--instance-id", instance_id,
        )
    except subprocess.CalledProcessError as exc:
        wait_error = str(exc)

    invocation = json.loads(
        aws(
            "ssm", "get-command-invocation",
            "--command-id", command_id,
            "--instance-id", instance_id,
            "--output", "json",
        )
    )

    return {
        "command_id": command_id,
        "instance_id": instance_id,
        "status": invocation["Status"],
        "response_code": invocation["ResponseCode"],
        "stdout": invocation.get("StandardOutputContent", ""),
        "stderr": invocation.get("StandardErrorContent", ""),
        "wait_error": wait_error,
    }


def check_success(result, stage):
    if result["status"] != "Success" or result["response_code"] != 0:
        raise RuntimeError(
            f"{stage} failed: {result['status']}\n"
            f"{result['stderr']}"
        )


def build_test(scenario, run_id):
    """Build one of our predefined, approved validation tests."""

    if scenario == "curl":
        destination = f"/tmp/sec598-curl-{run_id}.txt"

        command = (
            "set -e\n"
            "curl --fail --silent --show-error "
            "--max-time 20 "
            f"--output {destination} "
            "https://example.com\n"
            f"test -s {destination}\n"
            "echo SEC598_CURL_TEST_OK"
        )

        return command, {
            "output_path": destination,
            "success_marker": "SEC598_CURL_TEST_OK",
        }

    unit = f"sec598-coin-{run_id.lower()}.service"
    unit_path = f"/etc/systemd/system/{unit}"
    marker_path = f"/tmp/sec598-systemd-{run_id}.ok"

    command = f"""set -e
cat > {unit_path} <<'UNIT'
[Unit]
Description=SEC598 benign validation {run_id}

[Service]
Type=oneshot
ExecStart=/usr/bin/touch {marker_path}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now {unit}
systemctl is-enabled {unit} | grep -qx enabled
systemctl is-active {unit} | grep -qx active
test -f {marker_path}
echo SEC598_SYSTEMD_TEST_OK
"""

    return command, {
        "unit": unit,
        "unit_path": unit_path,
        "marker_path": marker_path,
        "success_marker": "SEC598_SYSTEMD_TEST_OK",
    }


def audit_time(iso_timestamp):
    timestamp = datetime.fromisoformat(
        iso_timestamp
    ).astimezone(timezone.utc)

    return (
        timestamp.strftime("%m/%d/%y"),
        timestamp.strftime("%H:%M:%S"),
    )


def capture_remote(instance_id, command, output_path, stage):
    """Capture SSM output and reject missing or truncated results."""

    marker = "SEC598_REMOTE_OUTPUT_COMPLETE"

    remote_command = (
        "set -e\n"
        f"{command}\n"
        f"printf '\\n{marker}\\n'"
    )

    command_id = send_ssm(instance_id, remote_command)
    result = get_ssm_result(instance_id, command_id)

    save_json(
        output_path.with_suffix(".ssm.json"),
        result,
    )

    check_success(result, stage)

    output = result["stdout"]

    if not output.rstrip().endswith(marker):
        raise RuntimeError(
            f"{stage}: completion marker missing; "
            "output may be truncated"
        )

    if len(output.encode("utf-8")) >= 23000:
        raise RuntimeError(
            f"{stage}: output exceeds safe inline limit"
        )

    clean_output = output.rsplit(marker, 1)[0]

    if not clean_output.strip():
        raise RuntimeError(f"{stage}: empty output")

    output_path.write_text(
        clean_output,
        encoding="utf-8",
    )

    return command_id


def collect_audit(instance_id, manifest, details, run_dir):
    start_date, start_time = audit_time(
        manifest["execution_requested_at_utc"]
    )

    end_date, end_time = audit_time(
        manifest["execution_finished_at_utc"]
    )

    window = (
        f"-ts '{start_date}' '{start_time}' "
        f"-te '{end_date}' '{end_time}' -i"
    )

    if manifest["scenario"] == "curl":
        command = (
            "sudo ausearch -k sec598_exec "
            f"-x /usr/bin/curl {window}"
        )
    else:
        command = (
            "sudo ausearch -k sec598_systemd "
            f"-f {details['unit_path']} {window}\n"
            "sudo ausearch -k sec598_exec "
            f"-x /usr/bin/touch {window}"
        )

    output_path = run_dir / "audit-raw.txt"

    command_id = capture_remote(
        instance_id,
        command,
        output_path,
        "Audit collection",
    )

    manifest["audit_ssm_command_id"] = command_id

    return output_path


def collect_systemd_context(instance_id, details, run_dir):
    unit = details["unit"]
    marker_path = details["marker_path"]

    command = f"""echo '==== UNIT_DEFINITION ===='
systemctl cat {unit}

echo '==== UNIT_STATE ===='
systemctl show {unit} \
  -p FragmentPath \
  -p ExecStart \
  -p UnitFileState \
  -p ActiveState \
  -p Result \
  -p ExecMainStatus

echo '==== SERVICE_JOURNAL ===='
journalctl -u {unit} --no-pager -n 10

echo '==== MARKER_FILE ===='
test -f {marker_path}
ls -l {marker_path}
"""

    output_path = run_dir / "systemd-context.txt"

    capture_remote(
        instance_id,
        command,
        output_path,
        "Systemd context collection",
    )

    return output_path


def parse_and_select(run_dir, manifest, details):
    raw_path = run_dir / "audit-raw.txt"
    parsed_path = run_dir / "audit-parsed.json"
    evidence_path = run_dir / "evidence.json"

    subprocess.run(
        [
            sys.executable,
            "-m", "app.parse_audit",
            str(raw_path),
            str(parsed_path),
        ],
        check=True,
        timeout=60,
    )

    events = json.loads(
        parsed_path.read_text(encoding="utf-8")
    )

    if manifest["scenario"] == "curl":
        evidence = [
            event for event in events
            if event.get("exe") == "/usr/bin/curl"
            and manifest["run_id"] in event.get("command", "")
        ]

        if not evidence:
            raise RuntimeError(
                "Expected curl audit event missing"
            )

    else:
        file_events = [
            event for event in events
            if event.get("event_type") == "file_create"
            and event.get("created_path") == details["unit_path"]
            and event.get("success") == "yes"
        ]

        execution_events = [
            event for event in events
            if event.get("exe") == "/usr/bin/touch"
            and details["marker_path"] in event.get("command", "")
        ]

        if not file_events:
            raise RuntimeError(
                "Expected systemd unit creation event missing"
            )

        if not execution_events:
            raise RuntimeError(
                "Expected systemd command execution event missing"
            )

        evidence = file_events + execution_events

    save_json(evidence_path, evidence)

    return evidence


def assess_run(run_dir, manifest, evidence):
    execution = json.loads(
        (run_dir / "execution.json").read_text(
            encoding="utf-8"
        )
    )

    combined = evidence + [{
        "event_type": "ssm_execution_result",
        "source": "AWS Systems Manager",
        "command": manifest["command"],
        "status": execution["status"],
        "response_code": execution["response_code"],
        "stdout": execution["stdout"],
        "stderr": execution["stderr"],
    }]

    if manifest["scenario"] == "systemd":
        context = (
            run_dir / "systemd-context.txt"
        ).read_text(encoding="utf-8")

        combined.append({
            "event_type": "systemd_context",
            "source": "systemctl and journalctl via SSM",
            "content": context,
        })

    combined_path = run_dir / "assessment-evidence.json"
    assessment_path = run_dir / "assessment.json"

    save_json(combined_path, combined)

    subprocess.run(
        [
            sys.executable,
            "-m", "app.assess_validation",
            str(combined_path),
            str(assessment_path),
            manifest["expected_behaviour"],
        ],
        check=True,
        timeout=240,
    )

    assessment = json.loads(
        assessment_path.read_text(encoding="utf-8")
    )

    required_fields = [
        "behaviour_observed",
        "execution_confirmed",
        "telemetry_confirmed",
        "detection_confirmed",
    ]

    for field in required_fields:
        if not isinstance(assessment.get(field), bool):
            raise RuntimeError(
                f"Invalid assessment field: {field}"
            )

    return assessment


def cleanup_target(instance_id, scenario, details, run_dir):
    """Remove only artifacts belonging to this validation run."""

    if scenario == "curl":
        command = (
            "set -e\n"
            f"rm -f -- {details['output_path']}\n"
            f"test ! -e {details['output_path']}\n"
            "echo SEC598_CLEANUP_OK"
        )
    else:
        command = (
            "set -e\n"
            f"systemctl disable --now {details['unit']} || true\n"
            f"rm -f -- {details['unit_path']}\n"
            f"rm -f -- {details['marker_path']}\n"
            "systemctl daemon-reload\n"
            f"test ! -e {details['unit_path']}\n"
            f"test ! -e {details['marker_path']}\n"
            "echo SEC598_CLEANUP_OK"
        )

    command_id = send_ssm(instance_id, command)
    result = get_ssm_result(instance_id, command_id)

    save_json(run_dir / "cleanup.json", result)
    check_success(result, "Cleanup")

    if "SEC598_CLEANUP_OK" not in result["stdout"]:
        raise RuntimeError(
            "Cleanup confirmation missing"
        )


def main():
    parser = argparse.ArgumentParser(
        description="SEC598 coin validation controller"
    )

    parser.add_argument(
        "scenario",
        choices=SCENARIOS.keys(),
    )

    parser.add_argument(
        "--approve",
        action="store_true",
    )

    # NEW: allow a specific target from Terraform.
    parser.add_argument(
        "--instance-id",
        help="Specific EC2 instance supplied by Terraform",
    )

    args = parser.parse_args()
    scenario = SCENARIOS[args.scenario]

    print(f"Scenario: {scenario['name']}")
    print(f"Expected: {scenario['expected_behaviour']}")

    if not args.approve:
        print("No action taken. Add --approve to execute.")
        return

    now = datetime.now(timezone.utc)
    run_id = (
        now.strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:6]
    )

    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    manifest_path = run_dir / "manifest.json"

    manifest = {
        "run_id": run_id,
        "scenario": args.scenario,
        "name": scenario["name"],
        "expected_behaviour": scenario["expected_behaviour"],
        "attack_techniques": scenario["attack_techniques"],
        "created_at_utc": now.isoformat(),
        "approved": True,
        "status": "prepared",
        "cleanup_status": "not_started",
    }

    def save_manifest():
        save_json(manifest_path, manifest)

    save_manifest()
    print(f"Run directory: {run_dir}", flush=True)

    instance_id = None
    remote_attempted = False

    command, details = build_test(
        args.scenario,
        run_id,
    )

    try:
        # Use the Terraform-supplied target when provided.
        # Otherwise preserve our original discovery method.
        if args.instance_id is not None:
            instance_id = verify_target(args.instance_id)
        else:
            instance_id = find_target()

        manifest["instance_id"] = instance_id
        manifest["command"] = command
        manifest["artifacts"] = details
        manifest["execution_requested_at_utc"] = utc_now()
        save_manifest()

        remote_attempted = True

        command_id = send_ssm(instance_id, command)

        manifest["ssm_command_id"] = command_id
        manifest["status"] = "submitted"
        save_manifest()

        print(
            f"SSM command submitted: {command_id}",
            flush=True,
        )

        execution = get_ssm_result(
            instance_id,
            command_id,
        )

        save_json(
            run_dir / "execution.json",
            execution,
        )

        check_success(execution, "Test execution")

        if details["success_marker"] not in execution["stdout"]:
            raise RuntimeError(
                "Test success marker missing"
            )

        manifest["execution_finished_at_utc"] = utc_now()
        manifest["status"] = "executed"
        save_manifest()

        print(
            "Test execution confirmed.",
            flush=True,
        )

        # Collect evidence before cleanup.
        collect_audit(
            instance_id,
            manifest,
            details,
            run_dir,
        )

        if args.scenario == "systemd":
            collect_systemd_context(
                instance_id,
                details,
                run_dir,
            )

        manifest["status"] = "telemetry_captured"
        save_manifest()

        evidence = parse_and_select(
            run_dir,
            manifest,
            details,
        )

        manifest["evidence_count"] = len(evidence)
        manifest["status"] = "evidence_ready"
        save_manifest()

        print(
            f"Collected {len(evidence)} relevant event(s).",
            flush=True,
        )

        # Assess only the captured evidence.
        manifest["status"] = "assessment_pending"
        save_manifest()

        assessment = assess_run(
            run_dir,
            manifest,
            evidence,
        )

        manifest["assessment_summary"] = {
            "behaviour_observed": assessment["behaviour_observed"],
            "execution_confirmed": assessment["execution_confirmed"],
            "telemetry_confirmed": assessment["telemetry_confirmed"],
            "detection_confirmed": assessment["detection_confirmed"],
        }

        manifest["assessment_completed_at_utc"] = utc_now()
        manifest["status"] = "assessed"
        save_manifest()

        print(
            "AI assessment completed.",
            flush=True,
        )

        print(
            json.dumps(
                manifest["assessment_summary"],
                indent=2,
            )
        )

    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = str(exc)
        save_manifest()
        raise

    finally:
        if instance_id and remote_attempted:
            try:
                cleanup_target(
                    instance_id,
                    args.scenario,
                    details,
                    run_dir,
                )

                manifest["cleanup_status"] = "succeeded"

                print(
                    "Target cleanup completed.",
                    flush=True,
                )

            except Exception as cleanup_error:
                manifest["cleanup_status"] = "failed"
                manifest["cleanup_error"] = str(cleanup_error)

                print(
                    f"WARNING: Cleanup needs attention: "
                    f"{cleanup_error}",
                    file=sys.stderr,
                )

            save_manifest()


if __name__ == "__main__":
    main()
