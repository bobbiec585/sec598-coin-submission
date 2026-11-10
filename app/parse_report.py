from pathlib import Path

from bs4 import BeautifulSoup


SOURCE_FILE = Path("data/reports/zimbra-cve-2026-73570.html")
OUTPUT_FILE = Path("data/reports/zimbra-cve-2026-73570.txt")


def load_html(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")

    article = soup.select_one("div.entry-content.wp-block-post-content")

    if article is None:
        raise ValueError("Could not find article content container")

    for tag in article(["script", "style", "noscript"]):
        tag.decompose()

    text = article.get_text("\n")

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    return "\n".join(lines)

def trim_article(text: str) -> str:
    start_marker = "Microsoft Threat Intelligence identified and tracked exploitation of"
    end_marker = "\nLearn More\n"

    start = text.find(start_marker)

    if start == -1:
        raise ValueError("Could not find expected article start marker")

    text = text[start:]

    end = text.find(end_marker)

    if end != -1:
        text = text[:end]

    return text.strip()

def save_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def main() -> None:
    html = load_html(SOURCE_FILE)
    text = extract_text(html)
    text = trim_article(text)
    save_text(OUTPUT_FILE, text)

    print(f"Saved parsed report to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
