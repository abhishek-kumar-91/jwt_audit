from collections import Counter
import html
import json
from pathlib import Path
from typing import Iterable

from rich.console import Console

from .models import AuditResult, Finding


console = Console()


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def print_header(root):
    console.print()
    console.print("JWT-AUDIT | JWT Security Assessment")
    console.print(f"Target: {root}")
    console.print()


def print_discovery(findings):
    discovery = [
        f for f in findings
        if f.rule_id == "DISCOVERY"
    ]

    if not discovery:
        console.print("JWT implementations detected: 0")
        console.print()
        return

    console.print(
        f"JWT implementations detected: {len(discovery)}"
    )

    languages = Counter(
        f.language
        for f in discovery
    )

    libraries = Counter(
        f.library
        for f in discovery
    )

    console.print(
        "Languages: "
        + ", ".join(
            f"{name} ({count})"
            for name, count in languages.items()
        )
    )

    console.print(
        "Libraries: "
        + ", ".join(
            f"{name} ({count})"
            for name, count in libraries.items()
        )
    )

    console.print()


def format_finding(finding):
    location = f"{finding.file}:{finding.line}"

    return (
        f"[{finding.severity}] "
        f"{finding.rule_id} | "
        f"{finding.title} | "
        f"{finding.status} | "
        f"{location}"
    )


def print_priority_section(title, findings):
    if not findings:
        return

    console.print(title)

    for finding in findings:
        console.print(
            format_finding(finding)
        )

        if finding.evidence:
            console.print(
                f"    Evidence: {finding.evidence}"
            )

        if finding.remediation:
            console.print(
                f"    Remediation: {finding.remediation}"
            )

        console.print()


def print_summary(findings):
    security = [
        f for f in findings
        if f.rule_id != "DISCOVERY"
    ]

    status_counts = Counter(
        f.status
        for f in security
    )

    fail_count = status_counts["FAIL"]
    review_count = status_counts["REVIEW"]
    pass_count = status_counts["PASS"]

    high_failures = [
        f for f in security
        if f.status == "FAIL"
        and f.severity in {"CRITICAL", "HIGH"}
    ]

    console.print("SUMMARY")
    console.print(
        f"FAIL: {fail_count} | "
        f"REVIEW: {review_count} | "
        f"PASS: {pass_count}"
    )

    console.print(
        f"High/Critical confirmed findings: "
        f"{len(high_failures)}"
    )

    console.print()


def _as_result(findings, root):
    if isinstance(findings, AuditResult):
        return findings
    from .models import RepositoryInventory
    return AuditResult(
        inventory=RepositoryInventory(root=root),
        findings=list(findings),
    )


def print_results(findings, root):
    result = _as_result(findings, root)
    findings = result.findings
    root = result.inventory.root
    print_header(root)

    inventory = result.inventory
    console.print(f"Files analyzed: {inventory.files_analyzed}")
    console.print("Languages: " + (", ".join(inventory.languages) or "none"))
    console.print("Frameworks: " + (", ".join(inventory.frameworks) or "none"))
    console.print()

    # --------------------------------------------------------
    # Discovery
    # --------------------------------------------------------

    print_discovery(findings)

    security = [
        f for f in findings
        if f.rule_id != "DISCOVERY"
    ]

    if not security:
        console.print("No JWT security checks generated.")
        return

    # --------------------------------------------------------
    # Sort by severity first, then status
    # --------------------------------------------------------

    status_order = {
        "FAIL": 0,
        "REVIEW": 1,
        "PASS": 2,
    }

    security.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            status_order.get(f.status, 99),
            f.file,
            f.line,
        )
    )

    # --------------------------------------------------------
    # Only show actual problems first
    # --------------------------------------------------------

    failures = [
        f for f in security
        if f.status == "FAIL"
    ]

    reviews = [
        f for f in security
        if f.status == "REVIEW"
    ]

    passes = [
        f for f in security
        if f.status == "PASS"
    ]

    print_priority_section(
        "HIGH PRIORITY / SECURITY ISSUES",
        failures,
    )

    print_priority_section(
        "MANUAL REVIEW REQUIRED",
        reviews,
    )

    # --------------------------------------------------------
    # PASS results
    # --------------------------------------------------------

    if passes:
        console.print("PASSED SECURITY CHECKS")

        for finding in passes:
            console.print(
                f"[PASS] {finding.rule_id} | "
                f"{finding.title} | "
                f"{finding.file}:{finding.line}"
            )

        console.print()

    print_summary(findings)


def result_to_dict(result: AuditResult) -> dict:
    return result.to_dict()


def render_json(result: AuditResult) -> str:
    return json.dumps(result_to_dict(result), indent=2, sort_keys=True)


def render_markdown(result: AuditResult) -> str:
    inventory = result.inventory
    security = [finding for finding in result.findings if finding.rule_id != "DISCOVERY"]
    lines = [
        "# JWT Audit Report",
        "",
        f"- Target: `{inventory.root}`",
        f"- Files analyzed: {inventory.files_analyzed}",
        f"- Languages: {', '.join(inventory.languages) or 'none'}",
        f"- Frameworks: {', '.join(inventory.frameworks) or 'none'}",
        f"- JWT-related files: {len(inventory.jwt_related_files)}",
        "",
        "## Architecture Signals",
        "",
    ]
    lines.extend(f"- {signal}" for signal in inventory.architecture_signals or ["No architecture signals detected."])
    lines.extend(["", "## Findings", "", "| Severity | Rule | Status | File | Line | Title |", "|---|---|---|---|---:|---|"])
    for finding in security:
        title = finding.title.replace("|", "\\|")
        lines.append(f"| {finding.severity} | {finding.rule_id} | {finding.status} | `{finding.file}` | {finding.line} | {title} |")
    return "\n".join(lines) + "\n"


def render_html(result: AuditResult) -> str:
    inventory = result.inventory
    rows = []
    for finding in result.findings:
        if finding.rule_id == "DISCOVERY":
            continue
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(value))}</td>"
                for value in (
                    finding.severity,
                    finding.rule_id,
                    finding.status,
                    finding.file,
                    finding.line,
                    finding.title,
                    finding.evidence,
                    finding.remediation,
                )
            )
            + "</tr>"
        )
    return """<!doctype html>
<html><head><meta charset="utf-8"><title>JWT Audit Report</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#18212b}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #ccd3da;padding:.5rem;text-align:left;vertical-align:top}th{background:#edf1f5}.FAIL{color:#a11}.REVIEW{color:#8a5a00}</style>
</head><body>
<h1>JWT Audit Report</h1>
<h2>Repository Information</h2>
<p><strong>Target:</strong> %s<br><strong>Files analyzed:</strong> %s<br><strong>Languages:</strong> %s<br><strong>Frameworks:</strong> %s</p>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Status</th><th>File</th><th>Line</th><th>Title</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>%s</tbody></table>
</body></html>
""" % (
        html.escape(inventory.root),
        inventory.files_analyzed,
        html.escape(", ".join(inventory.languages) or "none"),
        html.escape(", ".join(inventory.frameworks) or "none"),
        "".join(rows),
    )


def write_report(result: AuditResult, output: str, format_name: str) -> None:
    renderers = {
        "json": render_json,
        "markdown": render_markdown,
        "html": render_html,
    }
    Path(output).write_text(renderers[format_name](result), encoding="utf-8")