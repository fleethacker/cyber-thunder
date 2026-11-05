"""Render the validation matrix and the bounded README status from one evidence inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- validation-status:start -->"
END = "<!-- validation-status:end -->"


def generate(root: Path) -> tuple[str, str]:
    data = json.loads((root / "docs/validation.json").read_text(encoding="utf-8"))
    rows = data["rows"]
    for row in rows:
        evidence = row.get("evidence")
        if row["real_run"] and not (evidence and row.get("date")):
            raise ValueError(f"{row['platform']}: a real run needs dated evidence")
        if evidence and not (root / evidence.split("#", 1)[0]).is_file():
            raise ValueError(f"{row['platform']}: evidence file is missing")
    status = "\n\n".join(r["summary"] for r in rows if r["real_run"] and r.get("summary"))
    status += ("\n\nThese are recorded real-target results, not full benchmark coverage. "
               "Windows/WinRM, Cisco device changes and other platform versions still need real testing. "
               "See the [validation matrix](docs/VALIDATION.md) for evidence and missing run metadata, "
               "and [coverage](docs/COVERAGE.md) for check/fix counts.")
    status = f"{START}\n{status}\n{END}"
    lines = ["# Platform validation", "", f"Evidence reviewed {data['reviewed_on']}. Generated from `validation.json` by `scripts/validation_status.py`.", ""]
    lines += [f"- {note}" for note in data["notes"]]
    lines += ["", "| Platform / version | Real run recorded | Date | Seeded detections | Fix flow | Evidence |",
              "|---|---|---|---|---|---|"]
    for row in rows:
        evidence = row.get("evidence")
        link = f"[{'Run notes' if row['real_run'] else 'Range instructions'}](../{evidence})" if evidence else "No real-run evidence"
        lines.append(f"| {row['platform']} | {'Yes' if row['real_run'] else 'No'} | {row.get('date', '-')} | "
                     f"{row.get('seeds', 'Not measured')} | {row.get('fix_flow', 'Not exercised')} | {link} |")
    lines += ["", "## Provenance and next evidence", "",
              "The exact application commit for each run is **not recorded**. Do not substitute the current branch or a documentation commit for it.", ""]
    lines += [f"- {r['platform']}: write-up commit `{r['evidence_commit']}`."
              for r in rows if r.get("evidence_commit")]
    lines += ["", "For the next run, record application SHA, deployment mode, OS/build, scanner and benchmark versions/profile, "
              "scan ID, seed scope, collection errors, false-positive dispositions, each fix exercised, and sanitized score/audit evidence. "
              "Keep credentials and target secrets out of the evidence files.", "",
              "To refresh this matrix and the README status:", "", "```sh", "python scripts/validation_status.py --write", "```", "",
              "To check both generated sections without changing files:", "", "```sh", "python scripts/validation_status.py --check", "```", ""]
    return "\n".join(lines), status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    matrix, status = generate(ROOT)
    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    if readme.count(START) != 1 or readme.count(END) != 1:
        raise ValueError("README needs exactly one validation-status marker pair")
    start, end = readme.index(START), readme.index(END) + len(END)
    updated = readme[:start] + status + readme[end:]
    path = ROOT / "docs/VALIDATION.md"
    if args.write:
        path.write_text(matrix, encoding="utf-8", newline="\n")
        readme_path.write_text(updated, encoding="utf-8", newline="\n")
    elif args.check:
        if not path.exists() or path.read_text(encoding="utf-8") != matrix or updated != readme:
            print("Validation docs are stale: run python scripts/validation_status.py --write")
            return 1
        print("Validation matrix and README status agree")
    else:
        print(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
