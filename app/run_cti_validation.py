#!/usr/bin/env python3
"""Human-friendly terminal dashboard for SEC598 CTI validation."""

import argparse
import os
import queue
import re
import select
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "data" / "runs"

STAGE_NAMES = {
    "cti": "CTI behaviour matching",
    "auth": "AWS identity verification",
    "backend": "Isolated Terraform backend",
    "plan": "Terraform safety plan",
    "provision": "Provision disposable AWS lab",
    "ssm": "SSM connectivity",
    "ansible": "Configure auditd telemetry",
    "curl": "Curl validation and AI assessment",
    "systemd": "Systemd validation and AI assessment",
    "teardown": "Destroy temporary AWS lab",
    "report": "Package evidence and report",
}


class Dashboard:
    def __init__(self, selected):
        self.selected = selected
        self.keys = [
            "cti",
            "auth",
            "backend",
            "plan",
            "provision",
            "ssm",
            "ansible",
            *selected,
            "teardown",
            "report",
        ]

        self.status = {
            key: "Not started"
            for key in self.keys
        }

        self.active = None
        self.scenario = None
        self.ai_completed = set()
        self.detail = "Reviewing source-backed validation candidates"
        self.report_path = None
        self.warning = False

        self.interactive = (
            sys.stdout.isatty()
            and os.environ.get("TERM", "") != "dumb"
        )

        self.start("cti")

    def change(self, key, status):
        if key not in self.status:
            return

        if self.status[key] == status:
            return

        self.status[key] = status

        if not self.interactive:
            print(
                f"[{status.upper()}] {STAGE_NAMES[key]}",
                flush=True,
            )

    def start(self, key, detail=None):
        """
        Start a stage only if it has not already finished.

        This prevents duplicate Terraform log messages from
        restarting a stage that is already complete.
        """

        if self.status.get(key) in ("Complete", "Failed"):
            return

        self.change(key, "In progress")
        self.active = key

        if detail:
            self.detail = detail

    def complete(self, key):
        if self.status.get(key) != "Failed":
            self.change(key, "Complete")

    def fail(self, key):
        self.change(key, "Failed")

    def handle_line(self, raw):
        """Interpret lifecycle events from the existing CTI engine."""

        line = raw.strip()

        if line.startswith("Launching approved AWS pipeline:"):
            self.complete("cti")
            self.start(
                "auth",
                "Checking AWS identity and account",
            )

        elif line.startswith("AWS identity verified:"):
            self.complete("auth")
            self.start(
                "backend",
                "Initialising per-run Terraform state",
            )

        elif line.startswith("Isolated state verified:"):
            # Terraform verifies its backend more than once.
            # Only the initial verification advances the dashboard.
            if self.status.get("backend") == "In progress":
                self.complete("backend")
                self.start(
                    "plan",
                    "Reviewing the Terraform resource plan",
                )

        elif line.startswith("Plan approved for review:"):
            self.complete("plan")
            self.start(
                "provision",
                "Terraform is creating the disposable lab",
            )

        elif line.startswith("Waiting for SSM:"):
            self.complete("provision")
            self.start(
                "ssm",
                "Waiting for the target to register with SSM",
            )

        elif line.startswith("SSM status: Online"):
            self.complete("ssm")
            self.start(
                "ansible",
                "Installing and configuring auditd",
            )

        elif "app.run_validation" in line:
            match = re.search(
                r"\bapp\.run_validation\s+(curl|systemd)\b",
                line,
            )

            if match:
                scenario = match.group(1)

                if scenario in self.selected:
                    self.complete("ansible")
                    self.scenario = scenario
                    self.start(
                        scenario,
                        f"{scenario}: executing benign emulation",
                    )

        elif line.startswith("Test execution confirmed."):
            if self.scenario:
                self.detail = (
                    f"{self.scenario}: collecting telemetry"
                )

        elif (
            line.startswith("Collected ")
            and "relevant event" in line
        ):
            if self.scenario:
                self.detail = (
                    f"{self.scenario}: assessing evidence with AI"
                )

        elif line.startswith("AI assessment completed."):
            if self.scenario:
                self.ai_completed.add(self.scenario)
                self.detail = (
                    f"{self.scenario}: cleaning test artefacts"
                )

        elif line.startswith("Target cleanup completed."):
            if self.scenario in self.ai_completed:
                self.complete(self.scenario)
                self.scenario = None

        elif line.startswith("WARNING: Cleanup needs attention:"):
            self.warning = True

            if self.scenario:
                self.fail(self.scenario)

        elif (
            line.startswith("$ terraform ")
            and " destroy " in f" {line} "
        ):
            if (
                self.scenario
                and self.status.get(self.scenario) == "In progress"
            ):
                self.fail(self.scenario)

            self.scenario = None
            self.start(
                "teardown",
                "Removing disposable AWS resources",
            )

        elif line.startswith(
            "Disposable AWS environment destroyed."
        ):
            self.complete("teardown")
            self.start(
                "report",
                "Consolidating reports and evidence",
            )

        elif line.startswith("WARNING: Teardown incomplete:"):
            self.warning = True
            self.fail("teardown")

        elif line.startswith("CTI report:"):
            reported_path = line.partition(":")[2].strip()
            self.report_path = Path(reported_path)

    def finish(self, successful):
        """Finalise the display after the engine exits."""

        if successful:
            for key in self.keys:
                if self.status[key] != "Failed":
                    self.complete(key)

            self.detail = "All stages completed"

        else:
            if (
                self.active
                and self.status.get(self.active) == "In progress"
            ):
                self.fail(self.active)

            self.detail = (
                "Pipeline needs attention. "
                "Review the saved console log."
            )

    def render(self):
        """Draw the live dashboard using an activity indicator."""

        if not self.interactive:
            return

        tick = int(time.monotonic() * 7)

        width = 16
        block = 5
        position = tick % (width - block + 1)

        progress = (
            "["
            + "░" * position
            + "█" * block
            + "░" * (width - block - position)
            + "]"
        )

        lines = [
            "SEC598 | THREAT-INFORMED VALIDATION",
            "=" * 72,
            "Selected tests: " + ", ".join(self.selected),
            "",
        ]

        for key in self.keys:
            state = self.status[key]

            if state == "Complete":
                symbol = "✓"
                display = "Complete"

            elif state == "Failed":
                symbol = "✗"
                display = "Failed"

            elif state == "In progress":
                symbol = "●"
                display = f"In progress {progress}"

            else:
                symbol = "○"
                display = "Not started"

            lines.append(
                f" {symbol}  "
                f"{STAGE_NAMES[key]:<36} {display}"
            )

        lines.extend([
            "",
            "-" * 72,
            self.detail,
            "",
            "Detailed console output is being saved to a log.",
            "The progress bar shows activity, not estimated completion.",
        ])

        sys.stdout.write("\033[2J\033[H")
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()


def open_report_prompt(report_path):
    """
    Ask whether to open the report.

    Wait up to 30 seconds.
    Default to No on timeout or missing input.
    """

    if not report_path or not report_path.is_file():
        print("\nNo report is available to open.")
        return

    print(f"\nReport saved: {report_path}")

    if not sys.stdin.isatty():
        print(
            "Non-interactive terminal: not opening report."
        )
        return

    print(
        "\nOpen the report in the terminal? [y/N] "
        "(30 seconds, default No): ",
        end="",
        flush=True,
    )

    try:
        ready, _, _ = select.select(
            [sys.stdin],
            [],
            [],
            30,
        )

    except (OSError, ValueError):
        print("\nInput unavailable. Defaulting to No.")
        return

    if not ready:
        print(
            "\nTimed out after 30 seconds. "
            "Report not opened."
        )
        return

    answer = sys.stdin.readline().strip().lower()

    if answer not in ("y", "yes"):
        print("Report not opened.")
        return

    if shutil.which("less"):
        print("Opening report. Press Q to close.")
        subprocess.run(
            ["less", "-R", str(report_path)],
            check=False,
        )

    else:
        print(
            report_path.read_text(encoding="utf-8")
        )


def forward_arguments(args):
    """Pass supported arguments to the existing CTI engine."""

    forwarded = []

    if args.analysis:
        forwarded.extend([
            "--analysis",
            args.analysis,
        ])

    if args.report_text:
        forwarded.extend([
            "--report-text",
            args.report_text,
        ])

    for scenario in args.select or []:
        forwarded.extend([
            "--select",
            scenario,
        ])

    if args.approve:
        forwarded.append("--approve")

    return forwarded


def run_dashboard(command, selected):
    """Launch the existing engine and show a live status display."""

    RUNS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    run_stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    log_path = RUNS_DIR / (
        f"cti-ui-{run_stamp}-{os.getpid()}.log"
    )

    dashboard = Dashboard(selected)

    events = queue.Queue()

    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"

    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            errors="replace",
        )

    except OSError as exc:
        print(f"Unable to start CTI engine: {exc}")
        return 1

    def read_output():
        assert process.stdout is not None

        with log_path.open(
            "w",
            encoding="utf-8",
        ) as log:

            for line in process.stdout:
                log.write(line)
                log.flush()
                events.put(line)

        events.put(None)

    reader = threading.Thread(
        target=read_output,
        daemon=True,
    )

    reader.start()

    output_finished = False
    last_lines = []

    if dashboard.interactive:
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

    try:
        while not output_finished:
            try:
                item = events.get(timeout=0.12)

                if item is None:
                    output_finished = True

                else:
                    dashboard.handle_line(item)
                    last_lines.append(item.rstrip())

                    if len(last_lines) > 15:
                        last_lines.pop(0)

            except queue.Empty:
                pass

            dashboard.render()

        return_code = process.wait()

        successful = (
            return_code == 0
            and not dashboard.warning
            and dashboard.report_path is not None
            and dashboard.report_path.is_file()
        )

        dashboard.finish(successful)
        dashboard.render()

    finally:
        if dashboard.interactive:
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()

    print("\n" + "=" * 72)

    if successful:
        print(
            "RESULT: CTI validation pipeline completed."
        )

    else:
        print(
            "RESULT: Pipeline failed or needs attention."
        )

        print("\nRecent console output:")

        for line in last_lines:
            print("  " + line[:200])

    print(f"\nFull console log: {log_path}")

    open_report_prompt(dashboard.report_path)

    return 0 if successful else 1


def main():
    parser = argparse.ArgumentParser(
        description="SEC598 CTI validation dashboard"
    )

    parser.add_argument("--analysis")
    parser.add_argument("--report-text")

    parser.add_argument(
        "--select",
        action="append",
        choices=("curl", "systemd"),
    )

    parser.add_argument(
        "--approve",
        action="store_true",
        help="Authorise AWS creation and test execution",
    )

    parser.add_argument(
        "--plain",
        action="store_true",
        help="Show original verbose engine output",
    )

    args = parser.parse_args()
    forwarded = forward_arguments(args)

    command = [
        sys.executable,
        "-u",
        "-m",
        "app.cti_engine",
        *forwarded,
    ]

    # Review-only mode retains the full CTI evidence.
    # Plain mode is the troubleshooting fallback.
    if not args.approve or args.plain:
        return subprocess.call(
            command,
            cwd=ROOT,
        )

    if not args.select:
        parser.error(
            "--approve requires at least one --select"
        )

    selected = list(dict.fromkeys(args.select))

    return run_dashboard(
        command,
        selected,
    )


if __name__ == "__main__":
    sys.exit(main())
