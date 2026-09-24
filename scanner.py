from pathlib import Path
import json
import re

from .detector import analyze_file
from .detector import detect_language
from .models import AuditResult, Finding, RepositoryInventory


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
    ".cache",
    "vendor",
    ".tox",
}


SUPPORTED_EXTENSIONS = {
    ".py",
    ".java",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".cs",
    ".go",
    ".php",
    ".rb",
}


CONFIGURATION_NAMES = {
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "requirements.txt",
    "pyproject.toml",
    "pipfile",
    "composer.json",
    "gemfile",
    "go.mod",
    "application.properties",
    "application.yml",
    "application.yaml",
    "appsettings.json",
    "web.config",
}

CONFIGURATION_SUFFIXES = {".env", ".properties", ".yml", ".yaml", ".toml", ".json", ".xml"}

AUTH_TERMS = re.compile(
    r"\b(jwt|oauth|oidc|bearer|accessToken|refreshToken|idToken|"
    r"authentication|authorization|security|login|logout|claims|session)\b",
    re.IGNORECASE,
)

FRAMEWORK_SIGNATURES = {
    "Spring Boot": ("spring-boot", "SecurityFilterChain", "OncePerRequestFilter"),
    "Express": ("express", "app.use(", "Router("),
    "NestJS": ("@nestjs/", "CanActivate", "AuthGuard"),
    "Django": ("django", "REST_FRAMEWORK", "APIView"),
    "Flask": ("flask", "Flask(", "@app.route"),
    "FastAPI": ("fastapi", "FastAPI(", "Depends("),
    "ASP.NET": ("Microsoft.AspNetCore", "AddAuthentication", "[Authorize]"),
    "Laravel": ("laravel", "Illuminate\\", "Route::"),
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

            if (
                path.suffix.lower() not in SUPPORTED_EXTENSIONS
                and path.name.lower() not in CONFIGURATION_NAMES
                and not path.name.lower().startswith(".env")
                and path.suffix.lower() not in CONFIGURATION_SUFFIXES
            ):
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

    def inventory(self) -> RepositoryInventory:
        """Build a lightweight repository map without executing source code."""
        source_files = []
        configuration_files = []
        languages = set()
        frameworks = set()
        dependencies = set()
        authentication_files = []
        jwt_related_files = []

        for path in self.discover_files():
            relative = str(path.relative_to(self.root))
            language = detect_language(path)
            if language:
                source_files.append(relative)
                languages.add(language)
            else:
                configuration_files.append(relative)

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            if AUTH_TERMS.search(content):
                authentication_files.append(relative)
            if re.search(r"\b(jwt|oauth|oidc|bearer|accessToken|refreshToken)\b", content, re.I):
                jwt_related_files.append(relative)

            for framework, signatures in FRAMEWORK_SIGNATURES.items():
                if any(signature.lower() in content.lower() for signature in signatures):
                    frameworks.add(framework)

            if path.name.lower() == "package.json":
                try:
                    package = json.loads(content)
                    dependencies.update(package.get("dependencies", {}).keys())
                    dependencies.update(package.get("devDependencies", {}).keys())
                except json.JSONDecodeError:
                    pass
            elif path.name.lower() in {"requirements.txt", "go.mod", "gemfile", "composer.json"}:
                for line in content.splitlines():
                    candidate = re.match(r"\s*(?:require\s+)?([A-Za-z0-9_./:@-]+)", line)
                    if candidate and not line.lstrip().startswith(("#", "//")):
                        dependencies.add(candidate.group(1))

        signals = []
        if any("frontend" in file.lower() or "client" in file.lower() for file in authentication_files):
            signals.append("frontend authentication code detected")
        if any("middleware" in file.lower() or "filter" in file.lower() or "guard" in file.lower() for file in authentication_files):
            signals.append("authentication middleware/filter/guard detected")
        if any("refresh" in file.lower() for file in jwt_related_files):
            signals.append("refresh-token flow candidate detected")

        return RepositoryInventory(
            root=str(self.root),
            files_analyzed=len(source_files) + len(configuration_files),
            source_files=sorted(source_files),
            configuration_files=sorted(configuration_files),
            languages=sorted(languages),
            frameworks=sorted(frameworks),
            dependencies=sorted(dependencies),
            authentication_files=sorted(set(authentication_files)),
            jwt_related_files=sorted(set(jwt_related_files)),
            architecture_signals=signals,
        )

    def audit(self) -> AuditResult:
        inventory = self.inventory()
        findings = []
        for path in self.discover_files():
            if detect_language(path):
                findings.extend(analyze_file(path))
        return AuditResult(inventory=inventory, findings=findings)