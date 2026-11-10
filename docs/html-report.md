# SEC598 HTML report

The HTML renderer is an **optional reporting step**. It reads an existing CTI validation run on the Ubuntu VM; it does not re-run CTI analysis, create AWS infrastructure, call OpenAI or alter the original Markdown output.

## Generate the report from the 7 November run

From the repository root, with the project virtual environment active:

~~~bash
cd ~/projects/sec598-coin
source .venv/bin/activate

python -m app.render_cti_html \
  --cti-dir data/runs/cti-20261107t154553z-75a5ff \
  --verified-state-date 2026-11-10
~~~

The optional date records **your separately performed read-only check** that the pipeline's remote Terraform state was empty on 10 November 2026. It is not an AWS check made by the renderer. For another run, omit the date unless you've independently checked its state.

Output: \`data/runs/cti-20261107t154553z-75a5ff/cti-report.html\`.

Open the file in the Ubuntu browser, or copy it to the Windows host for review. It is a single HTML document with embedded CSS and no web dependencies. Use the browser's **Print → Save as PDF** option for a PDF copy if requested.

## What the report contains

1. Executive summary, with a short project outcome.
2. Vision and goals, distinguishing the working proof of concept from the wider ambition.
3. A concise walk-through of the source-specific parser, AI CTI analysis, analyst approval, Terraform, Ansible, basic red/blue tests, teardown and reporting.
4. The **actual** saved curl/systemd verdicts, selected audit events and AI conclusions, with teardown verification noted briefly here. Source excerpts and detailed reasoning are expandable.
5. A short, first-person roadmap: selected-source ingestion, CrewAI orchestration, Atomic Red Team/CALDERA/AI-assisted emulation, richer blue-side telemetry and detection/Sigma validation.

**No IOC-extraction capability is claimed or proposed as a required part of the future platform.**

The standalone HTML is intended for human reading. It does **not** replace the preserved \`source-analysis.json\`, \`assessment.json\`, \`evidence.json\`, raw audit or Terraform logs.

## Verification and sharing

~~~bash
python -m py_compile app/render_cti_html.py
python -m app.render_cti_html --help
ls -lh data/runs/cti-20261107t154553z-75a5ff/cti-report.html
~~~

Check the rendered values against the original saved JSON files and ensure there are no unwanted account identifiers or sensitive report details before sharing. Only the report generator is committed to Git: generated \`data/runs/\` output remains ignored.

The HTML uses existing \`app.cti_engine.build_candidates\` and the existing structured \`ThreatAnalysis\` model. This means it follows the same CTI candidate matching and exact-quote checking as the working CTI controller rather than silently inventing a second set of associations.

## Scope and caveats

- The selected tests demonstrate benign execution and host telemetry. They do not validate a real detection rule or MDR response.
- The report renders **locally saved run evidence**; it does not independently validate evidence or make a new AI assessment.
- Teardown shown as succeeded comes from the pipeline manifest. The optional verified date is explicitly an **operator attestation**.
- The reviewer will need access to the private GitHub repository to follow documentation links.
- If a required run file is missing or the evidence count/assessment disagrees with the manifest, rendering fails rather than filling the gap with fabricated data.
