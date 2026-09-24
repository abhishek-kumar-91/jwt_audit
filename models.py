from dataclasses import dataclass
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
        }


