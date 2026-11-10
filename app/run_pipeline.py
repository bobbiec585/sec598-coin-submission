
#!/usr/bin/env python3
"""SEC598 disposable AWS validation pipeline."""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parent.parent
TERRAFORM_SOURCE = ROOT / "infra" / "terraform"
RUNS_DIR = ROOT / "data" / "runs"

REGION = "eu-north-1"
EXPECTED_ACCOUNT = "REPLACE_WITH_ACCOUNT_ID"
SCENARIOS = ("curl", "systemd")


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


class CommandFailed(RuntimeError):
    def __init__(self, command, code, output):
        super().__init__(
            f"Command failed with exit code {code}: "
            + " ".join(map(str, command))
        )
        self.output = output


def run(command, log_path=None, cwd=ROOT):
    """Run a command, display its output, optionally retain a log."""
    command = [str(part) for part in command]
    print(f"\n$ {' '.join(command)}", flush=True)

    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    output = result.stdout or ""
    if output:
        print(output, end="" if output.endswith("\n") else "\n")

    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(output, encoding="utf-8")

    if result.returncode != 0:
        raise CommandFailed(command, result.returncode, output)

    return output.strip()


def terraform(workdir, *args):
    return ["terraform", f"-chdir={workdir}", *args]


def read_json_command(command):
    result = subprocess.run(
        [str(item) for item in command],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def check_aws_identity():
    try:
        identity = read_json_command(
            ["aws", "sts", "get-caller-identity", "--output", "json"]
        )
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        raise RuntimeError(
            "AWS credentials are unavailable. Run 'aws login' first."
        )

    account = identity["Account"]
    if account != EXPECTED_ACCOUNT:
        raise RuntimeError(
            f"Wrong AWS account: {account}. "
            f"Expected {EXPECTED_ACCOUNT}."
        )

    print(f"AWS identity verified: {account}")
    return identity


def copy_terraform(workdir):
    workdir.mkdir(parents=True, exist_ok=False)

    sources = sorted(TERRAFORM_SOURCE.glob("*.tf"))
    lock = TERRAFORM_SOURCE / ".terraform.lock.hcl"

    if not sources or not lock.is_file():
        raise RuntimeError(
            "Terraform source files or provider lock file missing."
        )

    for source in [*sources, lock]:
        shutil.copy2(source, workdir / source.name)


def verify_backend(workdir, expected_key):
    cache = workdir / ".terraform" / "terraform.tfstate"

    if not cache.exists():
        raise RuntimeError("Terraform backend has not been initialised.")

    backend = json.loads(cache.read_text(encoding="utf-8"))
    config = backend.get("backend", {}).get("config", {})

    if backend.get("backend", {}).get("type") != "s3":
        raise RuntimeError("Unexpected Terraform backend type.")

    if config.get("key") != expected_key:
        raise RuntimeError(
            f"Unsafe Terraform backend key: {config.get('key')}"
        )

    if config.get("key") == "coin/terraform.tfstate":
        raise RuntimeError("Refusing to use the original lab state.")

    if config.get("region") != REGION:
        raise RuntimeError("Unexpected Terraform backend region.")

    print(f"Isolated state verified: {expected_key}")


def inspect_plan(workdir, plan_path):
    plan = read_json_command(
        terraform(workdir, "show", "-json", plan_path)
    )

    managed = set()

    for change in plan.get("resource_changes", []):
        if change.get("mode") == "data":
            continue

        actions = change["change"]["actions"]

        if actions != ["create"]:
            raise RuntimeError(
                f"Unsafe Terraform plan action for "
                f"{change['address']}: {actions}"
            )

        managed.add(change["address"])

    required = {
        "aws_instance.target",
        "aws_s3_bucket.ansible_transfer",
    }

    if not required.issubset(managed):
        raise RuntimeError(
            "Terraform plan is missing required temporary resources."
        )

    print(
        f"Plan approved for review: {len(managed)} creations, "
        "zero changes, zero destroys."
    )
    return managed


def check_owned_state(workdir, expected_key, allowed_resources):
    verify_backend(workdir, expected_key)

    output = run(terraform(workdir, "state", "list"))

    managed = {
        line.strip()
        for line in output.splitlines()
        if line.strip() and not line.startswith("data.")
    }

    unexpected = managed - allowed_resources

    if unexpected:
        raise RuntimeError(
            "Refusing teardown: unexpected resources in run state: "
            + ", ".join(sorted(unexpected))
        )

    return managed


def wait_for_ssm(instance_id, timeout_seconds=300):
    deadline = time.monotonic() + timeout_seconds

    print(f"Waiting for SSM: {instance_id}")

    while time.monotonic() < deadline:
        result = read_json_command([
            "aws", "ssm", "describe-instance-information",
            "--region", REGION,
            "--filters", f"Key=InstanceIds,Values={instance_id}",
            "--output", "json",
        ])

        instances = result.get("InstanceInformationList", [])

        if any(
            item.get("InstanceId") == instance_id
            and item.get("PingStatus") == "Online"
            for item in instances
        ):
            print("SSM status: Online")
            return

        time.sleep(10)

    raise RuntimeError(
        f"Instance {instance_id} did not become SSM Online."
    )


def write_inventory(path, instance_id, transfer_bucket):
    # No hardcoded AWS profile: use the environment's credential chain.
    content = f"""all:
  hosts:
    coin-target:
      ansible_host: "{instance_id}"
      ansible_connection: amazon.aws.aws_ssm
      ansible_aws_ssm_region: "{REGION}"
      ansible_aws_ssm_bucket_name: "{transfer_bucket}"
"""
    path.write_text(content, encoding="utf-8")


def find_validation_manifest(output):
    match = re.search(
        r"Run directory:\s*(data/runs/[^\s]+)",
        output,
    )
    if not match:
        return None

    path = (ROOT / match.group(1)) / "manifest.json"
    return path if path.is_file() else None


def make_report(path, manifest):
    lines = [
        "# SEC598 Disposable Validation Run",
        "",
        f"**Pipeline ID:** `{manifest['run_id']}`",
        f"**Started:** {manifest['created_at_utc']}",
        f"**Status:** {manifest['status']}",
        f"**AWS account:** {EXPECTED_ACCOUNT}",
        f"**Region:** {REGION}",
        f"**Terraform state:** `{manifest['state_key']}`",
        "",
        "## Validation results",
        "",
    ]

    if not manifest["validations"]:
        lines.append("No completed validation results.")
    else:
        for result in manifest["validations"]:
            lines.append(f"### {result['scenario']}")
            lines.append("")
            lines.append(f"- Status: {result['status']}")
            lines.append(
                f"- Evidence manifest: `{result.get('manifest', 'none')}`"
            )

            for key, value in result.get("assessment", {}).items():
                lines.append(f"- {key}: {value}")

            lines.append("")

    lines.extend([
        "## Infrastructure cleanup",
        "",
        f"**Teardown:** {manifest['teardown_status']}",
        "",
    ])

    if manifest.get("error"):
        lines.extend([
            "## Error",
            "",
            manifest["error"],
            "",
        ])

    if manifest["teardown_status"] == "failed":
        lines.extend([
            "## Recovery",
            "",
            "The disposable Terraform state has been retained.",
            "Do not delete the run directory until cleanup is verified.",
            "",
            "Recovery command:",
            "",
            "```bash",
            manifest["recovery_command"],
            "```",
            "",
        ])

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="SEC598 ephemeral AWS validation pipeline"
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=SCENARIOS,
        help="Approved scenario; repeat for more than one",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Authorise infrastructure creation and test execution",
    )
    args = parser.parse_args()

    selected = list(dict.fromkeys(args.scenario or SCENARIOS))

    check_aws_identity()

    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%Sz")
        + "-" + uuid4().hex[:6]
    )

    run_dir = RUNS_DIR / run_id
    workdir = run_dir / "terraform"
    logs = run_dir / "logs"
    state_key = f"runs/{run_id}/terraform.tfstate"

    run_dir.mkdir(parents=True, exist_ok=False)
    logs.mkdir()

    manifest_path = run_dir / "pipeline-manifest.json"
    report_path = run_dir / "pipeline-report.md"

    manifest = {
        "run_id": run_id,
        "created_at_utc": timestamp(),
        "status": "preparing",
        "approved": args.approve,
        "scenarios": selected,
        "state_key": state_key,
        "terraform_dir": str(workdir),
        "instance_id": None,
        "validations": [],
        "teardown_status": "not_started",
        "error": None,
        "recovery_command": (
            f'terraform -chdir="{workdir}" destroy '
            f'-var="deployment_suffix={run_id}"'
        ),
    }

    def save():
        write_json(manifest_path, manifest)

    save()

    apply_started = False
    allowed_resources = set()
    exit_code = 0

    try:
        copy_terraform(workdir)

        manifest["status"] = "initialising"
        save()

        run(
            terraform(
                workdir,
                "init",
                "-input=false",
                "-reconfigure",
                f"-backend-config=key={state_key}",
            ),
            logs / "terraform-init.log",
        )

        verify_backend(workdir, state_key)

        manifest["status"] = "planning"
        save()

        plan_path = workdir / "deployment.tfplan"

        run(
            terraform(
                workdir,
                "plan",
                "-input=false",
                "-no-color",
                f"-var=deployment_suffix={run_id}",
                f"-out={plan_path}",
            ),
            logs / "terraform-plan.log",
        )

        allowed_resources = inspect_plan(workdir, plan_path)

        manifest["planned_resources"] = sorted(allowed_resources)
        save()

        if not args.approve:
            manifest["status"] = "planned_only"
            print(
                "\nPLAN ONLY. No AWS resources created. "
                "Use --approve to authorise a full run."
            )
        else:
            manifest["status"] = "provisioning"
            save()

            verify_backend(workdir, state_key)
            apply_started = True

            run(
                terraform(
                    workdir,
                    "apply",
                    "-input=false",
                    "-no-color",
                    plan_path,
                ),
                logs / "terraform-apply.log",
            )

            outputs = read_json_command(
                terraform(workdir, "output", "-json")
            )

            instance_id = outputs["target_instance_id"]["value"]
            bucket = outputs["ansible_transfer_bucket"]["value"]

            if outputs["aws_account_id"]["value"] != EXPECTED_ACCOUNT:
                raise RuntimeError("Terraform returned wrong AWS account.")

            if outputs["aws_region"]["value"] != REGION:
                raise RuntimeError("Terraform returned wrong AWS region.")

            if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
                raise RuntimeError("Terraform returned invalid EC2 ID.")

            manifest["instance_id"] = instance_id
            manifest["transfer_bucket"] = bucket
            manifest["status"] = "waiting_for_ssm"
            save()

            wait_for_ssm(instance_id)

            inventory = run_dir / "inventory.yml"
            write_inventory(inventory, instance_id, bucket)

            manifest["status"] = "configuring_telemetry"
            save()

            run(
                [
                    "ansible-playbook",
                    "-i", inventory,
                    ROOT / "config/ansible/telemetry.yaml",
                ],
                logs / "ansible.log",
            )

            manifest["status"] = "validating"
            save()

            for scenario in selected:
                log_path = logs / f"validation-{scenario}.log"

                try:
                    output = run(
                        [
                            sys.executable,
                            "-m", "app.run_validation",
                            scenario,
                            "--instance-id", instance_id,
                            "--approve",
                        ],
                        log_path,
                    )
                    validation_status = "completed"
                except CommandFailed as exc:
                    output = exc.output
                    validation_status = "failed"

                child_manifest_path = find_validation_manifest(output)
                assessment = {}

                if child_manifest_path:
                    child = json.loads(
                        child_manifest_path.read_text(encoding="utf-8")
                    )
                    assessment = child.get("assessment_summary", {})

                manifest["validations"].append({
                    "scenario": scenario,
                    "status": validation_status,
                    "manifest": (
                        str(child_manifest_path)
                        if child_manifest_path else None
                    ),
                    "assessment": assessment,
                })
                save()

                if validation_status != "completed":
                    raise RuntimeError(
                        f"Validation scenario failed: {scenario}. "
                        f"See {log_path}"
                    )

            manifest["status"] = "validated"
            save()

    except (Exception, KeyboardInterrupt) as exc:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
        exit_code = 1
        print(f"\nPIPELINE ERROR: {exc}", file=sys.stderr)

    finally:
        if apply_started:
            try:
                manifest["teardown_status"] = "in_progress"
                save()

                remaining = check_owned_state(
                    workdir,
                    state_key,
                    allowed_resources,
                )

                print(
                    f"\nTeardown: {len(remaining)} managed "
                    "resources in disposable state."
                )

                run(
                    terraform(
                        workdir,
                        "destroy",
                        "-auto-approve",
                        "-input=false",
                        "-no-color",
                        f"-var=deployment_suffix={run_id}",
                    ),
                    logs / "terraform-destroy.log",
                )

                remaining = check_owned_state(
                    workdir,
                    state_key,
                    allowed_resources,
                )

                if remaining:
                    raise RuntimeError(
                        f"{len(remaining)} resources remain after destroy."
                    )

                manifest["teardown_status"] = "succeeded"
                print("Disposable AWS environment destroyed.")

            except (Exception, KeyboardInterrupt) as exc:
                manifest["teardown_status"] = "failed"
                manifest["teardown_error"] = str(exc)
                exit_code = 1
                print(
                    f"WARNING: Teardown incomplete: {exc}",
                    file=sys.stderr,
                )

        if (
            manifest["status"] == "validated"
            and manifest["teardown_status"] == "succeeded"
        ):
            manifest["status"] = "completed"

        manifest["finished_at_utc"] = timestamp()
        save()
        make_report(report_path, manifest)

        print(f"\nPipeline manifest: {manifest_path}")
        print(f"Pipeline report:   {report_path}")

        if manifest["teardown_status"] == "failed":
            print(
                "\nRECOVERY COMMAND:\n"
                + manifest["recovery_command"],
                file=sys.stderr,
            )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
