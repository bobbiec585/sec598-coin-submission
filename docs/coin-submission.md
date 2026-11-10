# SEC598 coin challenge: submission write-up draft

> **Draft for review.** This is a technical narrative based on the repository and the local run output shared during development. The full input report, raw execution evidence, screenshots and final submission instructions are **not** committed in this repository. Confirm the exact submission format against the course's official guidance.

## Title

**From threat intelligence to evidence-backed validation: an AI-assisted, human-approved disposable AWS firing range**

## Problem statement

Operationalising CTI is not the same as summarising it. A public report can describe many techniques and behaviours, but defenders still need to decide what matters, what they can test, whether a host records useful evidence, and what would remain unproven before a detection could be claimed.

Manual testing was slow to repeat and easy to leave in an inconsistent state. A credible proof of concept needed to combine the **breadth of AI extraction** with **analyst judgement**, predictable benign tests, reproducible infrastructure, and conservative assessment of telemetry.

The test case is Microsoft's [30 September 2026 report on CVE-2026-73570 exploitation against Zimbra](https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/). The source combines observations across multiple compromises. It is not treated as one complete chain on a single host.

## Requirements and design decisions

| Requirement | Implementation and why |
| --- | --- |
| Extract useful behaviours, not just indicators | OpenAI Responses API with a Pydantic `ThreatAnalysis` schema, including evidence, ATT&CK candidates and uncertainties |
| Preserve analyst judgement | Human baseline captured in `docs/zimbra-human-baseline.md`; candidate matching is presented for review |
| Restrict execution | Only prewritten `curl` and `systemd` analogues; mandatory explicit `--select` and `--approve` |
| Avoid the original AWS lab | Unique run ID, temporary Terraform working directory and separate remote S3 state key |
| Generate reproducible host telemetry | Terraform Amazon Linux instance + Ansible auditd rules deployed over AWS SSM |
| Collect traceable evidence | SSM execution result, bounded audit collection, deterministic parsing and per-run files |
| Assess conservatively | Structured `ValidationAssessment` with four distinct booleans and supporting findings |
| Avoid orphaned infrastructure where possible | Attempt Terraform destroy in a `finally` block, retain state and recovery instructions |
| Support repeatable demonstration | CLI controller, terminal stage dashboard, plain-log fallback, report and evidence bundle |

## SEC598-relevant techniques applied

1. **LLM-assisted security research:** structured threat behaviour extraction from a sourced report using a constrained Pydantic output schema.
2. **AI-assisted evidence assessment:** a second schema-constrained call evaluates a *defined test and its captured evidence*, with explicit instructions not to infer detection from telemetry.
3. **Security automation/orchestration:** Python coordinates Terraform, AWS SSM, Ansible, Linux auditd collection and deterministic parsing.
4. **Human-in-the-loop control:** an analyst chooses from a fixed safe test catalogue. AI never writes or authorises arbitrary emulation commands.

This is **one controlled workflow**, not an autonomous offensive agent.

## Method and implementation

### 1. Human baseline and CTI extraction

The source HTML is saved locally, parsed into text, then analysed with a hosted model. The model returns report title, summary, affected technologies, threat actors, evidence-linked behaviour records and uncertainties.

The first-pass human baseline independently called out web/reverse shells, download utilities, SNMP command execution, privilege escalation, service persistence, credentials, SSH, loader/payload chains and C2. The AI output surfaced additional candidate behaviours such as reconnaissance, cron persistence and staging. The developer's local review showed **20 extracted behaviours** for this report; this count comes from the local run output, not files committed in Git.

The bridge uses deterministic rules to match ATT&CK IDs and text to the supported scenarios, then checks whether evidence excerpts occur in the saved report text after whitespace/case normalisation. One extracted curl quotation was not an exact source match; the other curl excerpt and both systemd excerpts were verified. Unverified text was not used as verified supporting evidence in the final CTI report.

### 2. Analyst selects safe analogues

| Reported technique | Analogue and test | Validation scope |
| --- | --- | --- |
| T1105, with shell-related execution context | Run benign `curl` to download `https://example.com` to a uniquely named temporary file | Process execution and Linux audit visibility; **not** payload execution or exploit reproduction |
| T1543.002 | Write, enable and start a harmless systemd one-shot service that touches a marker file | Unit-file creation, start/execution evidence and audit visibility; **not** timestomping or persistence-across-reboot proof |

The analyst reviews the evidence and supplies `--select ... --approve`. The system does not invent test commands or exploit Zimbra.

### 3. Disposable target and collection

The Python pipeline validates the expected AWS identity, copies Terraform into a per-run directory, uses a unique remote S3 state key, refuses plans containing replacements/updates/deletions, and creates an isolated Amazon Linux target. Ansible configures auditd via the SSM connection. There is no inbound SSH rule.

The runner sends a bounded benign command with AWS Run Command, retains command result and success markers, collects relevant audit events and extra systemd service context when applicable, and runs the deterministic audit parser. An OpenAI assessment produces `behaviour_observed`, `execution_confirmed`, `telemetry_confirmed` and `detection_confirmed`, plus findings and uncertainties.

Test artefacts are removed and Terraform teardown is attempted, even if a normal execution stage fails. Run manifests retain status, state key, log locations and recovery commands.

### 4. Report and audit trail

The top-level CTI report links the original threat report, selected CTI behaviours, verified source excerpts, chosen analogues, four outcome fields, reported uncertainties and infrastructure teardown status. Local evidence includes the source snapshots, assessment JSON, raw/parsed audit and SSM execution details.

The full [architecture diagram](architecture.md) illustrates the control plane, AWS data plane, hosted model interactions and evidence flow.

## Demonstrated results

The following **locally reported** test results were shared during development on 7 November 2026. They are useful checkpoints, but the original per-run evidence is stored on the Ubuntu VM and is not published in Git.

| Run | Scenario | Behaviour | Execution | Telemetry | Detection | Teardown |
| --- | --- | --- | --- | --- | --- | --- |
| `20261107t151854z-be2243` | curl | True | True | True | **False** | Reported succeeded |
| `20261107t152824z-aec71a` | systemd | True | True | True | **False** | Reported succeeded |
| `cti-20261107t154553z-75a5ff` | Both via CTI bridge | True for both | True for both | True for both | **False for both** | Reported succeeded |

For the integrated run, the local `cti-report.md` recorded the Microsoft report title, extracted behaviour numbers **4** (curl) and **11** (systemd), verified supporting excerpts, both completed validations and `teardown: succeeded`.

**Interpretation:** the lab reproduced two benign behaviour analogues and captured supporting host telemetry. It did **not** validate an MDR analytic, an alert, response effectiveness, the real exploit chain or detection coverage against the named threat.

## Security and reliability considerations

**Controls built:** static allowlist, explicit approval, AWS account check, unique instance selection, no inbound access, remote-state separation, Terraform create-only plan inspection, run-owned teardown check, local evidence and recovery manifests.

**Known residual risks:** host crash, forced process kill, expired credentials or AWS errors can prevent teardown; the dashboard is log-driven; the cloud account and state bucket are currently hard-coded; the source-report parser is article-specific; no CI regression suite exists; and source quote matching does not substitute for full independent source review.

The pipeline's use of hosted AI requires an authorised input/evidence-sharing decision. It is a research lab and should not be described as production-ready.

## Demonstration walkthrough

1. Show the public report and the earlier independent human baseline.
2. Show the `ThreatAnalysis` schema and a source-backed behaviour record.
3. Run `python -m app.run_cti_validation` in review-only mode and explain candidate matching and the approval boundary.
4. Show the isolated Terraform plan: creations only, no changes/deletions.
5. Run the approved curl/systemd CTI workflow and show the terminal stages; explain the roles of SSM, Ansible and auditd.
6. Inspect the final `cti-report.md` and source-to-test traceability.
7. Show a real `assessment.json` and a relevant audit record; point out `detection_confirmed = false`.
8. Verify the disposable Terraform state is empty and the original lab was not modified.

**Do not manufacture example evidence or present the screenshot of a report as proof of cloud teardown.** Include actual output or a recorded state verification from the lab.

## Submission preparation checklist

- [ ] Confirm the official coin submission requirements, format and destination.
- [ ] Capture a short demo or screenshots from a fresh approved run.
- [ ] Preserve a **sanitised** evidence sample outside the default gitignored runs (after checking for source/report rights, account metadata, keys and tokens).
- [ ] Include the GitHub repository URL or an archive that the assessors can actually access; confirm that the public submission repository is accessible to the assessors.
- [ ] Include the architecture diagram, source-report attribution, explicit analyst-approval step and all four outcome fields.
- [ ] Include limits: no full exploit, no actual detection, and possible incomplete teardown after abrupt failure.
- [ ] Verify teardown independently and inspect that the intended original lab still exists.
- [ ] Run a final secret/history review before sharing code or artefacts.

## Why this was useful

The proof of concept reduces the friction of taking one well-supported CTI behaviour from *reported activity* to *safe execution and collected telemetry*. It preserves the analyst's choice and uses the LLM where judgement over text and evidence can help, without delegating unrestricted execution to the model. The next engineering step would be detection-rule validation, but that was explicitly **outside the coin scope**.
