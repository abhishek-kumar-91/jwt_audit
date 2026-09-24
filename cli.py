import argparse
import sys

from .scanner import ProjectScanner
from .reporter import print_results, write_report
from . import __version__


def build_parser():

    parser = argparse.ArgumentParser(
        prog="jwt-audit",
        description=(
            "JWT implementation detection and "
            "security auditing tool."
        )
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"JWT-Audit {__version__}"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a source-code project"
    )

    scan_parser.add_argument(
        "path",
        help="Path to the source-code project"
    )

    scan_parser.add_argument(
        "--format",
        choices=("console", "json", "markdown", "html"),
        default="console",
        help="Report format (default: console)",
    )
    scan_parser.add_argument(
        "--output",
        help="Write a machine-readable report to this file",
    )
    scan_parser.add_argument(
        "--severity",
        choices=("critical", "high", "medium", "low", "info"),
        help="Only include findings at or above this severity",
    )
    scan_parser.add_argument(
        "--language",
        help="Only analyze a language, such as Python or JavaScript",
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include all available report details",
    )

    return parser


def main():

    parser = build_parser()

    args = parser.parse_args()

    if args.command != "scan":

        parser.print_help()

        sys.exit(1)

    try:

        scanner = ProjectScanner(
            args.path
        )

        print(
            f"\nScanning: {scanner.root}\n"
        )

        result = scanner.audit()

        if args.language:
            result.findings = [
                finding for finding in result.findings
                if finding.language.lower() == args.language.lower()
            ]

        if args.severity:
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }
            threshold = severity_order[args.severity]
            result.findings = [
                finding for finding in result.findings
                if severity_order.get(finding.severity.lower(), 99) <= threshold
            ]

        if args.format == "console":
            print_results(result, str(scanner.root))
        elif not args.output:
            parser.error("--output is required for non-console formats")
        else:
            write_report(result, args.output, args.format)

    except (
        FileNotFoundError,
        NotADirectoryError
    ) as error:

        print(
            f"Error: {error}",
            file=sys.stderr
        )

        sys.exit(1)

    except KeyboardInterrupt:

        print(
            "\nScan cancelled."
        )

        sys.exit(130)


if __name__ == "__main__":
    main()