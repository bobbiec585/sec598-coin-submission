"""Render a short, self-contained SEC598 HTML report from an existing CTI run.

This is reporting only: it makes no AWS or OpenAI calls and does not
modify the existing CTI, Terraform or validation controllers.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import date, datetime
from html import escape
from pathlib import Path

from app.cti_engine import build_candidates
from app.schemas.threat_analysis import ThreatAnalysis


SCENARIOS = {
    "curl": {
        "title": "Command-line retrieval",
        "attack": "T1105 · Ingress Tool Transfer",
        "test": "A harmless curl download to a unique temporary file.",
        "limit": "No Zimbra exploit, malicious payload, C2 or pipe-to-shell execution.",
    },
    "systemd": {
        "title": "Systemd service creation",
        "attack": "T1543.002 · Systemd Service",
        "test": "A harmless one-shot systemd unit that creates a marker file.",
        "limit": "No original payload, timestamp camouflage or proof of persistence across reboot.",
    },
}

CSS = """
:root{--ink:#16283c;--muted:#526777;--line:#dce5e9;--teal:#087c70;--wash:#f5f8f9}
*{box-sizing:border-box}body{margin:0;background:#edf1f3;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Arial,sans-serif;color:var(--ink)}
main{max-width:970px;margin:30px auto 55px;background:#fff;border-radius:15px;overflow:hidden;box-shadow:0 14px 42px #17314b13}
header{background:#11273f;color:white;padding:38px 50px}.wrap{padding:0 50px}
header h1{font-size:34px;line-height:1.15;letter-spacing:-.7px;margin:8px 0 10px}
header p{font-size:16px;color:#d2e1eb;max-width:710px;margin:0}
.kicker{font-size:11px;letter-spacing:1.1px;text-transform:uppercase;color:var(--teal);font-weight:800}
header .kicker{color:#9fdbd3}section{padding:27px 0;border-bottom:1px solid var(--line)}section:last-child{border-bottom:0}
h2{font-size:21px;line-height:1.25;margin:4px 0 14px;letter-spacing:-.3px}h3{font-size:16px;line-height:1.3;margin:0 0 7px}
p{margin:0 0 11px}p:last-child{margin-bottom:0}.muted{color:var(--muted)}.sm{font-size:12px}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}
.metric{padding:13px 16px;background:var(--wash);border:1px solid var(--line);border-radius:9px}
.metric strong{font-size:23px;line-height:1.15;display:block;color:#183e51}.metric span{font-size:11px;color:var(--muted)}
.vision{padding:16px;background:var(--wash);border-radius:10px;margin:13px 0}
.flow{display:grid;grid-template-columns:repeat(6,1fr);gap:7px;margin-top:17px}
.flow div{background:#edf8f5;border:1px solid #c8e4dc;border-radius:8px;text-align:center;padding:11px 5px;font-size:11px;font-weight:700}
.flow small{display:block;font-weight:400;color:var(--muted);font-size:10px}
.build,.future{display:grid;grid-template-columns:1fr 1fr;gap:15px}
.build article{padding:0 0 11px;border-bottom:1px solid var(--line)}
.build h3{font-size:14px}.build p,.future p{font-size:13px;color:var(--muted)}
.build .n{color:var(--teal);font-size:11px;font-weight:800;margin-right:8px}
.test{border:1px solid var(--line);border-radius:12px;padding:19px;margin:15px 0}
.test-top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.test .kicker{font-size:10px}.test p,.test li{font-size:13px}
.badge{display:inline-block;border-radius:30px;padding:4px 9px;background:#e6f4f0;color:#096c61;font-size:11px;font-weight:750}
.badge.grey{background:#edf1f4;color:#526575}.badge.warn{background:#fff2d9;color:#815718}
.verdicts{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:15px 0}
.verdicts div{padding:9px;background:var(--wash);border-radius:8px}
.verdicts small{display:block;color:var(--muted);font-size:11px;margin-bottom:6px}
ul{padding-left:20px;margin:5px 0 12px}li{margin-bottom:5px}
.insight{padding:9px 0 9px 12px;border-left:3px solid var(--teal)}
.note{background:#edf3f8;border-left:3px solid #406484;padding:13px 15px;border-radius:5px;font-size:13px}
details{border-top:1px solid var(--line);padding-top:10px;margin-top:12px}
summary{cursor:pointer;font-size:12px;color:#275778;font-weight:700}
.detail{padding:8px 0}.detail p,.detail li{font-size:12px}
.future article{border:1px solid var(--line);border-radius:8px;padding:13px}
.future h3{font-size:14px}.future p{margin:0}
footer{padding:19px 50px;background:var(--wash);font-size:11px;color:var(--muted)}
a{color:#295c84} .small-gap{margin-top:11px}
@media(max-width:760px){main{margin:0;border-radius:0}.wrap{padding:0 20px}header{padding:30px 20px}header h1{font-size:27px}.metrics,.build,.future{grid-template-columns:1fr 1fr}.flow{grid-template-columns:repeat(3,1fr)}.verdicts{grid-template-columns:1fr 1fr}footer{padding:20px}}
@media(max-width:490px){.metrics,.build,.future{grid-template-columns:1fr}header h1{font-size:25px}}
@media print{@page{size:A4;margin:13mm}body{background:white;font-size:11px}main{box-shadow:none;margin:0;max-width:none;border-radius:0}header{background:white;color:var(--ink);border-bottom:2px solid var(--teal);padding:0 0 15px}header p{color:var(--muted)}header h1{font-size:24px}header .kicker{color:var(--teal)}.wrap{padding:0}section{padding:12px 0}h2{font-size:16px;margin-bottom:8px}h3{font-size:13px}.metrics{margin-top:9px}.metric{padding:8px}.metric strong{font-size:18px}.vision{padding:8px}.build p,.future p,.test p,.test li{font-size:10px}.test{padding:11px;margin:8px 0;break-inside:avoid}.test details{display:none}.future article{padding:9px}footer{padding:8px 0;background:white}}
"""


def load_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return value


def h(value: object) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def run_date(run_id: str) -> str:
    matched = re.search(r"cti-(\d{8})t", run_id)
    if not matched:
        return "Date not recorded"
    day = datetime.strptime(matched.group(1), "%Y%m%d")
    return f"{day.day} {day.strftime('%B %Y')}"


def pill(value: object, detection: bool = False) -> str:
    if value is True:
        return '<span class="badge">Confirmed</span>'
    if value is False and detection:
        return '<span class="badge grey">Not tested</span>'
    if value is False:
        return '<span class="badge warn">Not confirmed</span>'
    return '<span class="badge grey">Not recorded</span>'


def audit_summary(name: str, records: list[dict]) -> list[str]:
    if name == "curl":
        return ["auditd recorded /usr/bin/curl with the expected URL and output path."
                for event in records if event.get("exe") == "/usr/bin/curl"]
    observations = []
    for event in records:
        if event.get("event_type") == "file_create":
            observations.append("auditd recorded successful systemd unit-file creation.")
        if event.get("exe") == "/usr/bin/touch":
            suffix = " (parent PID 1, consistent with systemd)." if event.get("ppid") == 1 else "."
            observations.append("auditd recorded the service's harmless touch command" + suffix)
    return observations


def scenario_card(name: str, run_dir: Path, candidates: list[dict]) -> tuple[str, int]:
    location = run_dir / "evidence" / "validations" / name
    manifest = load_object(location / "manifest.json")
    assessment = load_object(location / "assessment.json")
    try:
        events = json.loads((location / "evidence.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read {name} evidence: {exc}") from exc
    if not isinstance(events, list):
        raise ValueError(f"{name} evidence must be an array")
    if manifest.get("evidence_count") != len(events):
        raise ValueError(f"{name}: evidence count disagrees with manifest")
    for key in ("behaviour_observed", "execution_confirmed", "telemetry_confirmed", "detection_confirmed"):
        if assessment.get(key) != manifest.get("assessment_summary", {}).get(key):
            raise ValueError(f"{name}: assessment and manifest disagree on {key}")

    spec = SCENARIOS[name]
    label = "Assessed and cleaned up" if (manifest.get("status") == "assessed"
                                          and manifest.get("cleanup_status") == "succeeded") else "Review required"
    selected = candidates[0].get("behaviour", "No CTI behaviour matched") if candidates else "No CTI behaviour matched"
    observations = audit_summary(name, events)
    evidence_items = "".join(f"<li>{h(x)}</li>" for x in observations) or "<li>No expected audit event selected.</li>"

    quotes = []
    for candidate in candidates:
        for item in candidate.get("evidence", []):
            quote = item.get("quote")
            if quote and item.get("source_quote_verified") and quote not in quotes:
                quotes.append(quote)
    quote_html = "".join(f"<li>“{h(q)}”</li>" for q in quotes[:2]) or "<li>No exact source quote confirmed.</li>"
    findings_html = "".join(
        f"<li><strong>{h(f.get('observation', ''))}</strong> {h(f.get('significance', ''))}</li>"
        for f in assessment.get("findings", []) if isinstance(f, dict)
    )
    uncertainties_html = "".join(f"<li>{h(x)}</li>" for x in assessment.get("uncertainties", []))
    status_class = "badge" if label.startswith("Assessed") else "badge warn"
    return f"""
<article class="test">
<div class="test-top"><div><div class="kicker">{h(spec['attack'])}</div><h3>{h(spec['title'])}</h3></div><span class="{status_class}">{h(label)}</span></div>
<p class="muted"><strong>Reported:</strong> {h(selected)}</p>
<p><strong>Safe test:</strong> {h(spec['test'])}</p>
<div class="verdicts">
<div><small>Behaviour</small>{pill(assessment.get('behaviour_observed'))}</div>
<div><small>Execution</small>{pill(assessment.get('execution_confirmed'))}</div>
<div><small>Telemetry</small>{pill(assessment.get('telemetry_confirmed'))}</div>
<div><small>Detection</small>{pill(assessment.get('detection_confirmed'), True)}</div>
</div>
<p><strong>Selected audit evidence ({len(events)} event{'s' if len(events) != 1 else ''})</strong></p>
<ul>{evidence_items}</ul>
<p class="insight"><strong>Assessment:</strong> {h(assessment.get('conclusion', 'No conclusion recorded.'))}</p>
<p class="muted"><strong>Not demonstrated:</strong> {h(spec['limit'])}</p>
<details><summary>Source excerpts, detailed findings and uncertainties</summary><div class="detail">
<p><strong>Source-verified excerpts</strong></p><ul>{quote_html}</ul>
<p><strong>AI findings</strong></p><ul>{findings_html or '<li>No findings supplied.</li>'}</ul>
<p><strong>Uncertainties</strong></p><ul>{uncertainties_html or '<li>None recorded.</li>'}</ul>
</div></details>
</article>""", len(events)


def render_report(cti_dir: Path, verified_state_date: str | None = None) -> str:
    run = load_object(cti_dir / "cti-manifest.json")
    pipeline = load_object(cti_dir / "evidence" / "pipeline-manifest.json")
    analysis = ThreatAnalysis.model_validate_json((cti_dir / "source-analysis.json").read_bytes())
    report_text = (cti_dir / "source-report.txt").read_text(encoding="utf-8")
    candidates = build_candidates(analysis, report_text)
    selected = run.get("selected_scenarios")
    if not isinstance(selected, list) or not selected or any(x not in SCENARIOS for x in selected):
        raise ValueError("No supported approved scenarios in CTI run")

    cards = []
    count = 0
    for name in selected:
        card, total = scenario_card(name, cti_dir, candidates.get(name, []))
        cards.append(card)
        count += total

    if verified_state_date:
        checked = date.fromisoformat(verified_state_date)
        state_note = (f"I checked the run-specific Terraform state on "
                      f"{checked.day} {checked.strftime('%B %Y')} and found no managed resources. "
                      "This is my recorded check, not a fresh query by the report renderer.")
    else:
        state_note = ("I have not recorded a separate Terraform state verification date here; "
                      "the teardown status above comes from the pipeline manifest.")

    successful = (run.get("status") == "completed" and pipeline.get("status") == "completed")
    teardown = pipeline.get("teardown_status") == "succeeded"
    cleanup = [load_object(cti_dir / "evidence" / "validations" / name / "manifest.json")
               for name in selected]
    completed = sum(m.get("status") == "assessed" and m.get("cleanup_status") == "succeeded"
                    for m in cleanup)
    if not successful or completed != len(selected):
        summary_status = "Review required"
    else:
        summary_status = f"{completed}/{len(selected)}"

    return f"""<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SEC598 | Threat-informed security validation</title><style>{CSS}</style></head><body><main>
<header><div class="kicker">SEC598 · Coin challenge · Proof of concept</div>
<h1>From threat intelligence to security validation</h1>
<p>I built an evidence-led pipeline using AI, Terraform, Ansible and a disposable AWS lab.</p>
<div class="sm" style="margin-top:15px;color:#bdd1df">{h(run_date(str(run.get('run_id', ''))))} · {h(analysis.report_title)}</div></header>
<div class="wrap">
<section><div class="kicker">01 · Executive summary</div><h2>What I set out to prove</h2>
<p>I wanted to explore how AI and security automation can turn published threat intelligence into repeatable, evidence-backed security validation. The longer-term aim is a pipeline that ingests selected reporting, identifies useful adversary behaviours, builds a temporary test environment, executes controlled tests, assesses what defenders can see and tears everything down.</p>
<p>For SEC598, I focused on proving the structure rather than building a complete red- and blue-team platform. I used source-specific parsing, structured AI extraction and human approval to drive a Terraform-provisioned, Ansible-configured AWS lab. I started with two basic tests to demonstrate the validation and reporting stages.</p>
<p>Both tests reported successful execution and relevant Linux telemetry. <strong>Detection effectiveness was not tested.</strong> The pipeline reported successful teardown.</p>
<div class="metrics">
<div class="metric"><strong>{h(summary_status)}</strong><span>Approved tests assessed</span></div>
<div class="metric"><strong>{count}</strong><span>Selected audit events</span></div>
<div class="metric"><strong>{'Successful' if teardown else 'Unconfirmed'}</strong><span>Reported lab teardown</span></div>
</div></section>
<section><div class="kicker">02 · Overview and goals</div><h2>A platform, not two isolated tests</h2>
<p>My intended end state is automated CTI ingestion and analysis, targeted adversary emulation, richer defensive telemetry and evidence-based detection validation. I kept the initial red- and blue-side implementations deliberately small to prove the structure before adding complexity.</p>
<div class="vision"><strong>My focus for this iteration:</strong> demonstrate the CTI → analysis → approval → provision → execute → assess → destroy flow, with analyst control and reproducible infrastructure. I left automated source monitoring and more advanced testing agents for future work.</div>
<div class="flow"><div>CTI report<small>Source-specific parsing</small></div><div>AI analysis<small>TTPs and evidence</small></div><div>Human review<small>Approve scenarios</small></div><div>AWS build<small>Terraform + Ansible</small></div><div>Validation<small>Benign test + audit</small></div><div>Teardown<small>Report + destroy</small></div></div></section>
<section><div class="kicker">03 · Implementation</div><h2>What I built</h2>
<div class="build">
<article><h3><span class="n">01</span>Source parsing</h3><p>I wrote an HTML parser tailored to the Microsoft article structure, stripping unrelated page material before analysis. I currently save and supply the article manually.</p></article>
<article><h3><span class="n">02</span>CTI analysis and selection</h3><p>I used OpenAI to extract behaviours, ATT&amp;CK candidates, source evidence and uncertainties into a structured schema. I matched these to supported tests and checked source quotations before approval.</p></article>
<article><h3><span class="n">03</span>Terraform</h3><p>I used Terraform to provision isolated EC2, network, IAM and transfer-bucket resources. A run-specific state key keeps the disposable environment separate from my original lab.</p></article>
<article><h3><span class="n">04</span>Ansible</h3><p>I used Ansible over AWS Systems Manager to configure auditd and its rules without opening inbound SSH. This captured process execution and systemd unit activity.</p></article>
<article><h3><span class="n">05</span>Basic red/blue tests</h3><p>I ran two predefined, harmless tests as stand-ins for future emulation. I collected SSM execution results, parsed audit events and used AI to assess the evidence.</p></article>
<article><h3><span class="n">06</span>Reporting and teardown</h3><p>I automated test artefact cleanup and Terraform teardown, retaining the assessment, evidence, run logs and recovery details. Teardown is attempted even if an earlier stage fails.</p></article></div>
<p class="muted sm small-gap">Further implementation detail is in the <a href="https://github.com/bobbiec585/sec598-coin-submission">project repository</a> (public submission copy).</p></section>
<section><div class="kicker">04 · Demonstrated results</div><h2>What the tests showed</h2>
<p class="muted">The source report covers several Zimbra compromises. I have not assumed that every reported behaviour occurred on one host, and I tested safe analogues rather than the exploit itself.</p>
{''.join(cards)}
<div class="note"><strong>Important:</strong> telemetry visibility is not the same as detection coverage. I did not test an EDR analytic, alert, Sigma rule or MDR response in this proof of concept.</div>
<p class="muted sm small-gap"><strong>Teardown verification:</strong> {h(state_note)}</p></section>
<section><div class="kicker">05 · Future development</div><h2>Building on the framework</h2>
<p>I plan to build on the deliberately small implementations using tools and techniques from SEC598, while keeping the working lifecycle.</p>
<div class="future">
<article><h3>CTI and orchestration</h3><p>I want to pull reports from selected sources, improve parsing and prioritise useful TTPs. I also plan to explore <strong>CrewAI</strong>, used on the course, to coordinate specialist agents.</p></article>
<article><h3>Red-side emulation</h3><p>I plan to expand beyond the two basic tests using <strong>Atomic Red Team</strong>, <strong>MITRE CALDERA</strong> and suitable AI-assisted penetration-testing tools.</p></article>
<article><h3>Blue-side validation</h3><p>I want to collect richer telemetry and use AI agents to propose detection logic and <strong>Sigma rules</strong>, then test those detections against actual events.</p></article>
<article><h3>Lifecycle and outcome</h3><p>I'll keep the disposable lab and consolidated reporting, extending my assessment from “Was the behaviour visible?” to “Did the proposed detection work?”</p></article>
</div></section></div>
<footer>SEC598 coin proof of concept · {h(run.get('run_id', cti_dir.name))} · Generated from locally saved CTI and validation JSON. Not a reproduction of the Zimbra exploit or a certification of detection coverage.</footer>
</main></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Render a stand-alone CTI validation HTML report")
    parser.add_argument("--cti-dir", required=True, type=Path, help="Existing data/runs/cti-... directory")
    parser.add_argument("--output", type=Path, help="Default: <cti-dir>/cti-report.html")
    parser.add_argument("--verified-state-date", metavar="YYYY-MM-DD",
                        help="Optional operator-attested date of an empty Terraform state check")
    options = parser.parse_args()
    cti_dir = options.cti_dir.resolve()
    if not cti_dir.is_dir():
        parser.error(f"CTI directory does not exist: {cti_dir}")
    output = options.output.resolve() if options.output else cti_dir / "cti-report.html"
    text = render_report(cti_dir, options.verified_state_date)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(f"HTML report: {output}")
    print("No AWS or OpenAI calls made. Review the report before sharing.")


if __name__ == "__main__":
    main()
