from pathlib import Path
import json
import html


INPUT_FILE = Path("data/runs/zimbra-cve-2026-73570-analysis.json")
OUTPUT_FILE = Path("data/runs/zimbra-cve-2026-73570-analysis.html")


def main() -> None:
    data = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

    behaviours_html = []

    for behaviour in data["behaviours"]:
        evidence_html = ""

        for evidence in behaviour["evidence"]:
            evidence_html += f"""
            <li>
                <strong>Evidence:</strong>
                {html.escape(evidence["quote"])}
                <br>
                <em>{html.escape(evidence["explanation"])}</em>
            </li>
            """

        behaviours_html.append(
            f"""
            <section class="behaviour">
                <h2>{html.escape(behaviour["behaviour"])}</h2>

                <p>
                    <strong>ATT&amp;CK:</strong>
                    {html.escape(behaviour.get("attack_technique_id") or "No ID")}
                    —
                    {html.escape(behaviour.get("attack_technique_name") or "")}
                </p>

                <p>
                    <strong>Confidence:</strong>
                    {html.escape(behaviour["confidence"])}
                </p>

                <ul>
                    {evidence_html}
                </ul>
            </section>
            """
        )

    uncertainties_html = "".join(
        f"<li>{html.escape(item)}</li>"
        for item in data["uncertainties"]
    )

    affected_html = ", ".join(
        html.escape(item)
        for item in data["affected_technologies"]
    )

    html_report = f"""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>{html.escape(data["report_title"])}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 1100px;
                margin: 40px auto;
                padding: 0 24px;
                line-height: 1.6;
            }}

            .behaviour {{
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
            }}

            h1, h2 {{
                line-height: 1.2;
            }}

            li {{
                margin-bottom: 12px;
            }}

            code {{
                background: #eee;
                padding: 2px 5px;
            }}
        </style>
    </head>

    <body>
        <h1>{html.escape(data["report_title"])}</h1>

        <h2>Summary</h2>
        <p>{html.escape(data["summary"])}</p>

        <h2>Affected technologies</h2>
        <p>{affected_html}</p>

        <h2>Behaviours</h2>
        {"".join(behaviours_html)}

        <h2>Uncertainties</h2>
        <ul>
            {uncertainties_html}
        </ul>
    </body>
    </html>
    """

    OUTPUT_FILE.write_text(html_report, encoding="utf-8")

    print(f"Saved HTML report to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
