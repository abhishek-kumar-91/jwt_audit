import argparse
import sys

from .scanner import ProjectScanner
from .reporter import print_results
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

        findings = scanner.scan()

        print_results(
            findings,
            str(scanner.root)
        )

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