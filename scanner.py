from pathlib import Path

from .detector import analyze_file
from .models import Finding


IGNORED_DIRECTORIES = {
    ".git",
    ".svn",
    ".hg",

    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",

    "__pycache__",

    "target",
    "build",
    "dist",

    ".idea",
    ".vscode",

    "coverage",
}


SUPPORTED_EXTENSIONS = {
    ".py",
    ".java",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
}


class ProjectScanner:

    def __init__(self, root: str):

        self.root = Path(root).resolve()

        if not self.root.exists():
            raise FileNotFoundError(
                f"Project path does not exist: {self.root}"
            )

        if not self.root.is_dir():
            raise NotADirectoryError(
                f"Project path is not a directory: {self.root}"
            )

    def discover_files(self):
        """
        Find source files that we currently support.
        """

        for path in self.root.rglob("*"):

            if not path.is_file():
                continue

            # Ignore unwanted directories.
            if any(
                part in IGNORED_DIRECTORIES
                for part in path.parts
            ):
                continue

            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue

            yield path

    def scan(self) -> list[Finding]:
        """
        Scan every supported source file.
        """

        findings = []

        for path in self.discover_files():

            file_findings = analyze_file(path)

            findings.extend(file_findings)

        return findings