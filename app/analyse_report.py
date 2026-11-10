from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from app.schemas.threat_analysis import ThreatAnalysis


REPORT_FILE = Path("data/reports/zimbra-cve-2026-73570.txt")
OUTPUT_FILE = Path("data/runs/zimbra-cve-2026-73570-analysis.json")


def load_report(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main() -> None:
    load_dotenv(".env")

    client = OpenAI()

    report_text = load_report(REPORT_FILE)

    print(f"Loaded report: {len(report_text):,} characters")

    response = client.responses.parse(
        model="gpt-6-luna",
        input=[
            {
                "role": "system",
                "content": (
                    "You are analysing a public threat intelligence report. "
                    "Extract only behaviours supported by the supplied report. "
                    "Do not invent missing details. "
                    "Treat ATT&CK mappings as analytical mappings and preserve "
                    "supporting evidence for each behaviour. "
                    "Use uncertainties for anything the report does not establish clearly."
                ),
            },
            {
                "role": "user",
                "content": report_text,
            },
        ],
        text_format=ThreatAnalysis,
    )

    analysis = response.output_parsed

    if analysis is None:
        raise RuntimeError("Model did not return a parsed ThreatAnalysis result")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT_FILE.write_text(
        analysis.model_dump_json(indent=2),
        encoding="utf-8",
    )

    print(f"Saved analysis to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
