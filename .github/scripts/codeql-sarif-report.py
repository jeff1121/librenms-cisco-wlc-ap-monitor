#!/usr/bin/env python3
"""Turn CodeQL SARIF output into a Markdown report and workflow summary."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SEVERITY_ORDER = ("critical", "high", "medium", "low", "note", "unknown")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif_dir", type=Path, help="Directory containing CodeQL SARIF files")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("codeql-report.md"),
        help="Markdown report path",
    )
    parser.add_argument("--repository", default="", help="owner/name for Security tab links")
    parser.add_argument("--sha", default="", help="Commit SHA included in the report")
    parser.add_argument("--query-suite", default="security-and-quality")
    return parser.parse_args()


def load_sarif_files(sarif_dir: Path) -> list[Path]:
    if not sarif_dir.exists():
        return []
    files = sorted({*sarif_dir.rglob("*.sarif"), *sarif_dir.rglob("*.sarif.json")})
    return [path for path in files if path.is_file()]


def as_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def security_severity_label(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


def level_label(level: str | None) -> str:
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "note",
        "none": "note",
    }
    if not level:
        return "unknown"
    return mapping.get(level.lower(), level.lower())


def rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = ((run.get("tool") or {}).get("driver") or {})
    rules = driver.get("rules") or []
    indexed: dict[str, dict[str, Any]] = {}
    for rule in rules:
        rule_id = rule.get("id")
        if rule_id:
            indexed[str(rule_id)] = rule
    extensions = (run.get("tool") or {}).get("extensions") or []
    for extension in extensions:
        for rule in extension.get("rules") or []:
            rule_id = rule.get("id")
            if rule_id and str(rule_id) not in indexed:
                indexed[str(rule_id)] = rule
    return indexed


def result_severity(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    properties = result.get("properties") or {}
    score = as_float(properties.get("security-severity"))
    if score is None and rule:
        score = as_float((rule.get("properties") or {}).get("security-severity"))
    label = security_severity_label(score)
    if label:
        return label

    level = result.get("level")
    if not level and rule:
        level = ((rule.get("defaultConfiguration") or {}).get("level"))
    return level_label(level if isinstance(level, str) else None)


def result_location(result: dict[str, Any]) -> tuple[str, str]:
    locations = result.get("locations") or []
    if not locations:
        return ("", "")
    physical = (locations[0].get("physicalLocation") or {})
    uri = ((physical.get("artifactLocation") or {}).get("uri")) or ""
    region = physical.get("region") or {}
    line = region.get("startLine")
    return (str(uri), str(line) if line is not None else "")


def collect_findings(sarif_files: list[Path]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in sarif_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(
                {
                    "severity": "unknown",
                    "rule": "sarif-parse-error",
                    "message": f"Failed to parse {path.name}: {exc}",
                    "path": str(path),
                    "line": "",
                }
            )
            continue

        for run in payload.get("runs") or []:
            rules = rule_index(run)
            for result in run.get("results") or []:
                rule_id = str(result.get("ruleId") or "unknown-rule")
                rule = rules.get(rule_id)
                message = ((result.get("message") or {}).get("text")) or ""
                file_path, line = result_location(result)
                findings.append(
                    {
                        "severity": result_severity(result, rule),
                        "rule": rule_id,
                        "message": " ".join(str(message).split()),
                        "path": file_path,
                        "line": line,
                    }
                )
    return findings


def md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_report(
    findings: list[dict[str, str]],
    sarif_files: list[Path],
    repository: str,
    sha: str,
    query_suite: str,
) -> str:
    counts = Counter(item["severity"] for item in findings)
    rule_counts = Counter(item["rule"] for item in findings)
    lines = [
        "# CodeQL security scan report",
        "",
        f"- Query suite: `{query_suite}`",
        f"- SARIF files: {len(sarif_files)}",
        f"- Findings: **{len(findings)}**",
    ]
    if sha:
        lines.append(f"- Commit: `{sha}`")
    if repository:
        lines.append(
            f"- Code scanning alerts: https://github.com/{repository}/security/code-scanning"
        )
    lines.extend(["", "## Severity summary", "", "| Severity | Count |", "| --- | ---: |"])
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity} | {counts.get(severity, 0)} |")

    if rule_counts:
        lines.extend(["", "## Rules", "", "| Rule | Count |", "| --- | ---: |"])
        for rule, count in rule_counts.most_common():
            lines.append(f"| `{md_escape(rule)}` | {count} |")

    lines.extend(["", "## Findings"])
    if not findings:
        lines.extend(["", "No CodeQL findings were reported."])
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "",
            "| Severity | Rule | Location | Message |",
            "| --- | --- | --- | --- |",
        ]
    )
    ordered = sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.index(item["severity"])
            if item["severity"] in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
            item["path"],
            item["line"],
            item["rule"],
        ),
    )
    for item in ordered:
        location = item["path"] or "n/a"
        if item["line"]:
            location = f"{location}:{item['line']}"
        message = item["message"] or ""
        if len(message) > 240:
            message = message[:237] + "..."
        lines.append(
            f"| {item['severity']} | `{md_escape(item['rule'])}` | `{md_escape(location)}` | {md_escape(message)} |"
        )
    return "\n".join(lines) + "\n"


def emit_annotations(findings: list[dict[str, str]]) -> None:
    remaining = 20
    for item in findings:
        if remaining <= 0:
            break
        if item["severity"] in {"note", "unknown"}:
            continue
        command = "error" if item["severity"] in {"critical", "high"} else "warning"
        parts = [f"::{command}"]
        metadata: list[str] = []
        if item["path"]:
            metadata.append(f"file={item['path']}")
        if item["line"]:
            metadata.append(f"line={item['line']}")
        metadata.append(f"title=CodeQL {item['rule']}")
        parts.append(" " + ",".join(metadata))
        message = item["message"] or item["rule"]
        print(f"{''.join(parts)}::{message}", file=sys.stderr)
        remaining -= 1


def main() -> int:
    args = parse_args()
    sarif_files = load_sarif_files(args.sarif_dir)
    findings = collect_findings(sarif_files)
    report = render_report(findings, sarif_files, args.repository, args.sha, args.query_suite)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(report, end="")
    emit_annotations(findings)
    if not sarif_files:
        print("No SARIF files were found; the Markdown report still describes an empty scan.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
