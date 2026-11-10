import json
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from app.schemas.validation_assessment import ValidationAssessment


def load_evidence(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    # Expect three command-line arguments:
    # 1. Evidence JSON file
    # 2. Output JSON file
    # 3. Description of the expected behaviour

    if len(sys.argv) != 4:
        raise SystemExit(
            "Usage: python -m app.assess_validation "
            "<evidence-file> <output-file> <expected-behaviour>"
        )

    evidence_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    expected_behaviour = sys.argv[3]

    # Load the OpenAI API key from our project .env file
    load_dotenv(".env")

    # Load the structured telemetry evidence
    evidence = load_evidence(evidence_path)

    # Initialise the OpenAI client
    client = OpenAI()

    # Build the assessment prompt
    prompt = f"""
You are assessing a security validation test.

Expected behaviour:
{expected_behaviour}

Observed telemetry:
{json.dumps(evidence, indent=2)}

Assess only what the supplied telemetry supports.

Important distinctions:

- behaviour_observed means the supplied evidence supports
  the expected behaviour.

- execution_confirmed means the expected command or action
  is evidenced as having executed.

- telemetry_confirmed means the expected behaviour appeared
  in the supplied telemetry.

- detection_confirmed must only be true if explicit evidence
  shows that a detection rule or analytic fired.

Additional rules:

- Do not infer detection coverage merely because telemetry exists.
- Do not infer successful file writes from process execution alone.
- Do not infer that a systemd service was enabled or remains active
  unless the supplied evidence explicitly demonstrates that state.
- Do not assume separate audit events establish a causal relationship
  unless the evidence supports that relationship.
- Distinguish observed facts from reasonable interpretations.
- Record uncertainty rather than inventing missing evidence.
- Explain which evidence supports each conclusion.
"""

    # Send evidence to the model and enforce our Pydantic schema
    response = client.responses.parse(
        model="gpt-6-luna",
        input=prompt,
        text_format=ValidationAssessment,
    )

    assessment = response.output_parsed

    # Stop if the model returned no valid structured assessment
    if assessment is None:
        raise RuntimeError("Model returned no parsed assessment")

    # Save the assessment as structured JSON
    output_path.write_text(
        assessment.model_dump_json(indent=2),
        encoding="utf-8",
    )

    print(f"Saved assessment to {output_path}")


if __name__ == "__main__":
    main()
