#!/usr/bin/env python3
"""Convert OpenSCAP XCCDF results XML to compact JSON."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def children(element: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [child for child in list(element) if local_name(child.tag) == name]


def first_child(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in list(element):
        if local_name(child.tag) == name:
            return child
    return None


def text_of(element: ElementTree.Element | None) -> str | None:
    if element is None:
        return None
    text = " ".join("".join(element.itertext()).split())
    return text or None


def attr(element: ElementTree.Element | None, key: str) -> str | None:
    if element is None:
        return None
    return element.attrib.get(key)


def non_empty(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, [], {})}


def parse_rule_result(rule: ElementTree.Element) -> dict[str, Any]:
    checks = []
    for check in children(rule, "check"):
        content_refs = []
        for content_ref in children(check, "check-content-ref"):
            content_refs.append(
                non_empty(
                    {
                        "href": content_ref.attrib.get("href"),
                        "name": content_ref.attrib.get("name"),
                    }
                )
            )

        checks.append(
            non_empty(
                {
                    "system": check.attrib.get("system"),
                    "content_refs": content_refs,
                }
            )
        )

    messages = []
    for message in children(rule, "message"):
        messages.append(
            non_empty(
                {
                    "severity": message.attrib.get("severity"),
                    "text": text_of(message),
                }
            )
        )

    return non_empty(
        {
            "idref": rule.attrib.get("idref"),
            "role": rule.attrib.get("role"),
            "severity": rule.attrib.get("severity"),
            "time": rule.attrib.get("time"),
            "weight": rule.attrib.get("weight"),
            "version": text_of(first_child(rule, "version")),
            "result": text_of(first_child(rule, "result")),
            "idents": [
                non_empty({"system": item.attrib.get("system"), "value": text_of(item)})
                for item in children(rule, "ident")
            ],
            "checks": checks,
            "messages": messages,
            "fix": text_of(first_child(rule, "fix")),
        }
    )


def parse_score(score: ElementTree.Element) -> dict[str, Any]:
    return non_empty(
        {
            "system": score.attrib.get("system"),
            "maximum": score.attrib.get("maximum"),
            "value": text_of(score),
        }
    )


def convert(input_path: Path) -> dict[str, Any]:
    tree = ElementTree.parse(input_path)
    root = tree.getroot()

    test_result = None
    for element in root.iter():
        if local_name(element.tag) == "TestResult":
            test_result = element
            break

    if test_result is None:
        raise ValueError("No XCCDF TestResult element found.")

    rule_results = [
        parse_rule_result(rule) for rule in children(test_result, "rule-result")
    ]
    summary = Counter(
        item.get("result", "unknown") for item in rule_results if item.get("result")
    )

    profile = first_child(test_result, "profile")

    return non_empty(
        {
            "source": str(input_path),
            "benchmark": non_empty(
                {
                    "id": root.attrib.get("id"),
                    "resolved": root.attrib.get("resolved"),
                    "style": root.attrib.get("style"),
                    "title": text_of(first_child(root, "title")),
                    "description": text_of(first_child(root, "description")),
                }
            ),
            "test_result": non_empty(
                {
                    "id": test_result.attrib.get("id"),
                    "start_time": test_result.attrib.get("start-time"),
                    "end_time": test_result.attrib.get("end-time"),
                    "version": text_of(first_child(test_result, "version")),
                    "profile": attr(profile, "idref"),
                    "target": [
                        text
                        for text in (
                            text_of(item) for item in children(test_result, "target")
                        )
                        if text
                    ],
                    "target_addresses": [
                        text
                        for text in (
                            text_of(item)
                            for item in children(test_result, "target-address")
                        )
                        if text
                    ],
                    "organizations": [
                        text
                        for text in (
                            text_of(item)
                            for item in children(test_result, "organization")
                        )
                        if text
                    ],
                    "scores": [
                        parse_score(score) for score in children(test_result, "score")
                    ],
                    "summary": dict(sorted(summary.items())),
                    "rule_results": rule_results,
                }
            ),
        }
    )


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("Usage: xccdf-to-json INPUT.xml [OUTPUT.json]", file=sys.stderr)
        return 64

    input_path = Path(sys.argv[1])
    output = convert(input_path)

    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(json.dumps(output, indent=2) + "\n")
    else:
        print(json.dumps(output, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
