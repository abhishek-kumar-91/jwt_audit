from collections import Counter

from rich.console import Console


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
    console.print("JWT-AUDIT | Java JWT Security Assessment")
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


def print_results(findings, root):
    print_header(root)

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