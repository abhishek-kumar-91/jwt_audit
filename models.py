from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    file: str
    line: int
    language: str
    library: str
    operation: str
    evidence: str
    rule_id: str = "DISCOVERY"
    title: str = "JWT Implementation Detected"
    severity: str = "INFO"
    status: str = "DETECTED"
    confidence: str = "High"

    remediation: str = ""
    category: str = "JWT"
    cwe: str = ""
    owasp: str = ""
    explanation: str = ""
    attack_scenario: str = ""
    data_flow: str = ""
    secure_example: str = ""

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "language": self.language,
            "library": self.library,
            "operation": self.operation,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "category": self.category,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "explanation": self.explanation,
            "attack_scenario": self.attack_scenario,
            "data_flow": self.data_flow,
            "secure_example": self.secure_example,
        }


@dataclass
class RepositoryInventory:
    root: str
    files_analyzed: int = 0
    source_files: list[str] = field(default_factory=list)
    configuration_files: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    authentication_files: list[str] = field(default_factory=list)
    jwt_related_files: list[str] = field(default_factory=list)
    architecture_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_analyzed": self.files_analyzed,
            "source_files": self.source_files,
            "configuration_files": self.configuration_files,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "dependencies": self.dependencies,
            "authentication_files": self.authentication_files,
            "jwt_related_files": self.jwt_related_files,
            "architecture_signals": self.architecture_signals,
        }


@dataclass
class AuditResult:
    inventory: RepositoryInventory
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory": self.inventory.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }


