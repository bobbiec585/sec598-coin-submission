# Zimbra CVE-2026-73570: validation plan (implemented v1)

**Source:** [Microsoft Security Research, 30 September 2026](https://www.microsoft.com/en-us/security/blog/2026/09/30/unauthenticated-command-injection-on-internet-facing-mail-servers-tracking-cve-2026-73570/).

**Context:** This is a **behavioural telemetry validation**, not a reproduction of CVE-2026-73570. The original report combines different observations from multiple compromised hosts. The two selected analogues were chosen by the analyst after reviewing a human baseline and the structured AI extraction.

## Decision record

| Topic | Decision |
| --- | --- |
| Target | A separate disposable Amazon Linux instance, **not a vulnerable Zimbra server** |
| Access | AWS Systems Manager (SSM) commands and Ansible's SSM transport; no inbound SSH |
| Instrumentation | `auditd` with `sec598_exec` and `sec598_systemd` rules |
| Catalogue | Exactly two predefined benign scenarios: `curl` and `systemd` |
| Execution authority | Explicit analyst `--select` and `--approve` |
| Evidence | SSM execution outcome, relevant audit events and (for systemd) service context |
| Assessment | Pydantic-structured AI conclusions, bounded by observed evidence |
| Cleanup | Remove test artefacts, then attempt per-run Terraform destroy |
| Out of scope | Original exploit, actual malware, credentials, C2, detection analytic, containment/response |

## Scenario 1: benign command/download utility

### Reported behaviour and mapping

Microsoft describes adversaries retrieving content using `wget`/`curl`, including payload delivery and some pipe-to-shell execution.

- ATT&CK candidates: **T1105** (Ingress Tool Transfer) and relevant **T1059.004** (Unix Shell) context.
- Local CTI analysis behaviour **4**, high confidence, matched to `curl`.
- One generated quotation failed the exact source-text check; the separate quoted excerpt "Remote content retrieved with wget or curl and piped to a shell for execution." was source-verified in the local CTI review.

### Implemented analogue

Through SSM, `run_validation.py` executes `/usr/bin/curl` against `https://example.com` with a bounded timeout and writes to a uniquely named file under `/tmp`. The script verifies the file is non-empty, returns a success marker and removes it during cleanup.

It does **not** pipe downloaded content to a shell, fetch an adversary payload, reproduce the Zimbra process parentage or establish malicious intent.

### Expected telemetry and verification

- The remote command invocation reports success and the expected marker.
- `auditd` captures the relevant `execve` event for `/usr/bin/curl`.
- `parse_audit.py` extracts command, executable and execution metadata; `run_validation.py` selects records matching this run ID.
- The structured assessment can conclude execution/telemetry success only where supported by these artefacts.

**Success criteria:** execution marker present; relevant curl audit event selected; AI assessment acknowledges evidence without claiming a detection rule fired.

## Scenario 2: benign systemd service creation/execution

### Reported behaviour and mapping

Microsoft describes a `zimlog.service` service installed/enabled in an observed compromise, including timestamp changes to resemble legitimate services.

- ATT&CK candidate: **T1543.002** (Create or Modify System Process: Systemd Service).
- Local CTI analysis behaviour **11**, high confidence, matched to `systemd`.
- The local CTI review source-verified excerpts describing `systemctl enable` and timestamp modification.

### Implemented analogue

The runner writes a uniquely named unit file under `/etc/systemd/system/`, reloads systemd, enables/starts a harmless one-shot unit and executes `/usr/bin/touch` to create a marker file. `systemctl` output and journal details support the service's configured action. Cleanup disables/stops the unit, deletes the unit and marker, and reloads systemd.

The unit is deliberately benign. It does **not** change timestamps to conceal files, emulate the original `zimlog.service` payload, or prove that persistence survives a reboot.

### Expected telemetry and verification

- `auditd` observes unit-file creation under `sec598_systemd`.
- `auditd` captures the marker-file `touch` execution.
- `systemctl cat/show`, `journalctl` and marker-file checks provide supporting context.
- Deterministic selection requires both the expected unit-creation and command-execution evidence.

**Success criteria:** the unit file and marker are created; service context shows the harmless action; relevant audit events are captured and selected; the assessment does not conflate service-state evidence with an independently tested reboot-persistence mechanism.

## Evidence scoring

Both scenarios feed the same structured assessment:

| Output | Meaning |
| --- | --- |
| `behaviour_observed` | Test behaviour is supported by the supplied evidence |
| `execution_confirmed` | The target action executed |
| `telemetry_confirmed` | Linux host telemetry captured relevant activity |
| `detection_confirmed` | Only true if an actual detection rule/analytic fired and evidence was supplied |

**Expected `detection_confirmed`: false.** This project deliberately does not test detection rules or MDR response.

## Demonstrated local outcomes

In local runs shared on 7 November 2026, each standalone scenario reported: behaviour observed = **True**, execution confirmed = **True**, telemetry confirmed = **True**, detection confirmed = **False**, with teardown status **succeeded**. The integrated CTI run reported both scenarios completed and the disposable environment torn down. Raw evidence is in gitignored `data/runs/` directories, not in this repository.

See [Architecture](architecture.md) for the data flow, [Coin submission draft](coin-submission.md) for the broader rationale and demonstration checklist.

## Deferred candidates (out of v1)

The human baseline identified SNMP-encoded execution, web shells, privilege escalation, credentials, SSH and payload/C2 chains. These remain useful future hypotheses, but were **not** simulated in this project. Expanding them is not necessary to demonstrate the coin objective.
