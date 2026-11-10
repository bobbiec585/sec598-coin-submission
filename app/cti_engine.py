
#!/usr/bin/env python3
"""Connect structured CTI analysis to the SEC598 validation pipeline."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.schemas.threat_analysis import ThreatAnalysis


ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "data" / "runs"

DEFAULT_ANALYSIS = (
    ROOT / "data/runs/zimbra-cve-2026-73570-analysis.json"
)
DEFAULT_REPORT = (
    ROOT / "data/reports/zimbra-cve-2026-73570.txt"
)

CATALOGUE = {
    "curl": {
        "description": "Benign shell/download utility execution",
        "limitation": (
            "Tests local command execution and audit visibility. "
            "Does not reproduce the original payload, exploit or C2."
        ),
    },
    "systemd": {
        "description": "Benign systemd service creation and execution",
        "limitation": (
            "Tests service-file creation, execution and audit visibility. "
            "Does not establish adversary persistence or detection."
        ),
    },
}


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
    )


def normalise(text):
    return " ".join(text.split()).casefold()


def matches_scenarios(behaviour):
    """Conservative deterministic matching, not AI test generation."""
    technique = (
        behaviour.attack_technique_id or ""
    ).strip().upper()

    description = behaviour.behaviour.lower()
    matches = []

    # T1105: Ingress Tool Transfer.
    # T1059.004: Unix Shell, but only with transfer language.
    transfer_words = re.search(
        r"\b(curl|wget|download\w*|fetch\w*|"
        r"retriev\w*|transfer\w*)\b",
        description,
    )

    if (
        technique == "T1105"
        or (technique == "T1059.004" and transfer_words)
    ):
        matches.append("curl")

    # T1543.002: Systemd Service.
    # Also recognise explicit systemd references for human review.
    if technique == "T1543.002" or "systemd" in description:
        matches.append("systemd")

    return matches


def build_candidates(analysis, report_text):
    source = normalise(report_text)
    candidates = {name: [] for name in CATALOGUE}

    for number, behaviour in enumerate(analysis.behaviours, 1):
        evidence = []

        for item in behaviour.evidence:
            verified = bool(
                normalise(item.quote)
                and normalise(item.quote) in source
            )

            evidence.append({
                "quote": item.quote,
                "explanation": item.explanation,
                "source_quote_verified": verified,
            })

        record = {
            "behaviour_number": number,
            "behaviour": behaviour.behaviour,
            "attack_technique_id": behaviour.attack_technique_id,
            "attack_technique_name": behaviour.attack_technique_name,
            "confidence": behaviour.confidence,
            "evidence": evidence,
        }

        for scenario in matches_scenarios(behaviour):
            candidates[scenario].append(record)

    return candidates


def print_review(analysis, candidates):
    print(f"\nReport: {analysis.report_title}")
    print(f"Extracted behaviours: {len(analysis.behaviours)}")

    for name, catalogue_entry in CATALOGUE.items():
        matches = candidates[name]
        print(f"\n--- {name.upper()} ---")
        print(catalogue_entry["description"])

        if not matches:
            print("No matching behaviour found in the analysis.")
            continue

        for item in matches:
            print(
                f"\nBehaviour {item['behaviour_number']}: "
                f"{item['behaviour']}"
            )
            print(
                "ATT&CK: "
                f"{item['attack_technique_id'] or 'Unmapped'}"
            )
            print(f"Confidence: {item['confidence']}")

            for evidence in item["evidence"]:
                status = (
                    "verified in source"
                    if evidence["source_quote_verified"]
                    else "NOT verified in source"
                )
                print(f"  Evidence [{status}]:")
                print(f"  {evidence['quote'][:250]}")

        print("\nAnalogue limitation:")
        print(catalogue_entry["limitation"])


def safe_run_path(value):
    path = Path(value).resolve()

    if not path.is_relative_to(RUNS_DIR.resolve()):
        raise RuntimeError(
            f"Refusing to read path outside run directory: {path}"
        )

    return path


def execute_pipeline(selected, log_path):
    command = [
        sys.executable,
        "-m",
        "app.run_pipeline",
    ]

    for scenario in selected:
        command.extend(["--scenario", scenario])

    command.append("--approve")

    print("\nLaunching approved AWS pipeline:")
    print(" ".join(command), flush=True)

    pipeline_manifest = None
    pattern = re.compile(r"^Pipeline manifest:\s*(.+?)\s*$")

    with log_path.open("w", encoding="utf-8") as logfile:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        assert process.stdout is not None

        for line in process.stdout:
            print(line, end="", flush=True)
            logfile.write(line)
            logfile.flush()

            match = pattern.match(line.strip())

            if match:
                pipeline_manifest = safe_run_path(match.group(1))

        return_code = process.wait()

    return return_code, pipeline_manifest


def preserve_pipeline_evidence(cti_dir, pipeline_manifest):
    """Copy results, not Terraform state or credential caches."""
    if pipeline_manifest is None or not pipeline_manifest.is_file():
        return None

    child = json.loads(
        pipeline_manifest.read_text(encoding="utf-8")
    )

    destination = cti_dir / "evidence"
    destination.mkdir(exist_ok=True)

    shutil.copy2(
        pipeline_manifest,
        destination / "pipeline-manifest.json",
    )

    pipeline_report = pipeline_manifest.parent / "pipeline-report.md"

    if pipeline_report.is_file():
        shutil.copy2(
            pipeline_report,
            destination / "pipeline-report.md",
        )

    logs = pipeline_manifest.parent / "logs"

    if logs.is_dir():
        shutil.copytree(
            logs,
            destination / "logs",
            dirs_exist_ok=True,
        )

    for validation in child.get("validations", []):
        manifest_name = validation.get("manifest")
        scenario = validation.get("scenario")

        if not manifest_name or scenario not in CATALOGUE:
            continue

        source_manifest = safe_run_path(manifest_name)

        if source_manifest.is_file():
            shutil.copytree(
                source_manifest.parent,
                destination / "validations" / scenario,
                dirs_exist_ok=True,
            )

    return child


def render_report(path, analysis, candidates, manifest, child):
    lines = [
        "# SEC598 Threat-Informed Validation Report",
        "",
        f"**Threat report:** {analysis.report_title}",
        f"**CTI run:** `{manifest['run_id']}`",
        f"**Status:** {manifest['status']}",
        f"**Original report SHA-256:** `{manifest['source_sha256']}`",
        "",
        "## Intelligence assessment",
        "",
        analysis.summary,
        "",
        "## Analyst-approved validation scope",
        "",
    ]

    results = {}

    if child:
        results = {
            result["scenario"]: result
            for result in child.get("validations", [])
        }

    for scenario in manifest["selected_scenarios"]:
        lines.extend([
            f"### {scenario}",
            "",
            f"**Analogue:** {CATALOGUE[scenario]['description']}",
            "",
            "**Reported behaviour and source evidence:**",
            "",
        ])

        for item in candidates[scenario]:
            lines.append(
                f"- Behaviour {item['behaviour_number']}: "
                f"{item['behaviour']}"
            )
            lines.append(
                f"  - ATT&CK: "
                f"{item['attack_technique_id'] or 'Unmapped'}"
            )

            for evidence in item["evidence"]:
                if evidence["source_quote_verified"]:
                    lines.append(
                        f"  - Verified report excerpt: "
                        f"{evidence['quote']}"
                    )

        lines.extend([
            "",
            f"**Limitation:** {CATALOGUE[scenario]['limitation']}",
            "",
        ])

        result = results.get(scenario)

        if result:
            lines.append(
                f"**Validation status:** {result.get('status')}"
            )

            for key, value in result.get("assessment", {}).items():
                lines.append(f"- {key}: {value}")

            lines.append("")
        else:
            lines.append("**Validation result:** Not available.")
            lines.append("")

    lines.extend([
        "## What remains unproven",
        "",
        "- The actual Zimbra exploit chain was not reproduced.",
        "- Benign emulation is not equivalent to real adversary execution.",
        "- An observed audit event is not a detection alert.",
        "- MDR detection and response effectiveness remain untested.",
        "",
        "## Reported uncertainties",
        "",
    ])

    if analysis.uncertainties:
        for item in analysis.uncertainties:
            lines.append(f"- {item}")
    else:
        lines.append("No uncertainties recorded in the analysis.")

    lines.extend([
        "",
        "## Infrastructure and evidence",
        "",
        f"**Pipeline status:** {child.get('status', 'unknown') if child else 'unknown'}",
        f"**Teardown:** {child.get('teardown_status', 'unknown') if child else 'unknown'}",
        "",
        "Local evidence bundle: `evidence/`",
        "Source analysis: `source-analysis.json`",
        "Source report: `source-report.txt`",
        "Pipeline console log: `pipeline-console.log`",
        "",
    ])

    if manifest.get("error"):
        lines.extend([
            "## Execution issue",
            "",
            manifest["error"],
            "",
        ])

    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Threat-informed SEC598 validation controller"
    )

    parser.add_argument(
        "--analysis",
        type=Path,
        default=DEFAULT_ANALYSIS,
    )
    parser.add_argument(
        "--report-text",
        type=Path,
        default=DEFAULT_REPORT,
    )
    parser.add_argument(
        "--select",
        action="append",
        choices=CATALOGUE.keys(),
        help="Analyst-selected test; repeat for multiple tests",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Authorise AWS provisioning and selected test execution",
    )

    args = parser.parse_args()

    analysis_bytes = args.analysis.read_bytes()
    report_bytes = args.report_text.read_bytes()

    analysis = ThreatAnalysis.model_validate_json(
        analysis_bytes
    )

    candidates = build_candidates(
        analysis,
        report_bytes.decode("utf-8"),
    )

    print_review(analysis, candidates)

    selected = list(dict.fromkeys(args.select or []))

    if not args.approve:
        print(
            "\nREVIEW ONLY. No AWS resources created.\n"
            "Select supported scenarios and add --approve "
            "when ready."
        )
        return 0

    if not selected:
        parser.error(
            "--approve requires at least one explicit --select"
        )

    for scenario in selected:
        matches = candidates[scenario]

        if not matches:
            parser.error(
                f"No report-supported candidate for {scenario}"
            )

        verified = any(
            evidence["source_quote_verified"]
            for item in matches
            for evidence in item["evidence"]
        )

        if not verified:
            parser.error(
                f"{scenario} has no source-verified evidence. "
                "Review the CTI extraction before executing."
            )

    run_id = (
        "cti-"
        + datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%Sz")
        + "-"
        + uuid4().hex[:6]
    )

    cti_dir = RUNS_DIR / run_id
    cti_dir.mkdir(parents=True, exist_ok=False)

    (cti_dir / "source-analysis.json").write_bytes(
        analysis_bytes
    )
    (cti_dir / "source-report.txt").write_bytes(
        report_bytes
    )

    manifest = {
        "run_id": run_id,
        "report_title": analysis.report_title,
        "source_sha256": hashlib.sha256(
            report_bytes
        ).hexdigest(),
        "selected_scenarios": selected,
        "status": "running",
        "pipeline_manifest": None,
        "pipeline_return_code": None,
        "error": None,
    }

    save_json(cti_dir / "cti-manifest.json", manifest)

    child = None
    return_code = 1

    try:
        return_code, child_manifest = execute_pipeline(
            selected,
            cti_dir / "pipeline-console.log",
        )

        manifest["pipeline_return_code"] = return_code

        if child_manifest:
            manifest["pipeline_manifest"] = str(child_manifest)

        child = preserve_pipeline_evidence(
            cti_dir,
            child_manifest,
        )

        completed_scenarios = {
            item.get("scenario")
            for item in (child or {}).get("validations", [])
            if item.get("status") == "completed"
        }

        success = (
            return_code == 0
            and child is not None
            and child.get("status") == "completed"
            and child.get("teardown_status") == "succeeded"
            and set(selected).issubset(completed_scenarios)
        )

        manifest["status"] = (
            "completed" if success else "failed"
        )

        if not success:
            manifest["error"] = (
                "Pipeline execution or teardown was incomplete. "
                "Inspect the child pipeline manifest and AWS state."
            )

    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
        print(f"CTI integration error: {exc}", file=sys.stderr)

    finally:
        save_json(cti_dir / "cti-manifest.json", manifest)

        render_report(
            cti_dir / "cti-report.md",
            analysis,
            candidates,
            manifest,
            child,
        )

        print(f"\nCTI report: {cti_dir / 'cti-report.md'}")
        print(f"CTI manifest: {cti_dir / 'cti-manifest.json'}")

        if manifest["status"] != "completed":
            print(
                "WARNING: Check the pipeline's Terraform state "
                "before assuming infrastructure was destroyed.",
                file=sys.stderr,
            )

    return 0 if manifest["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
