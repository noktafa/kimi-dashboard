"""
Data models for security findings and scan results.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import json


def _utc_now() -> datetime:
    """Get current UTC time."""
    return datetime.now(timezone.utc)


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    """Confidence levels for findings."""
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


@dataclass
class Finding:
    """Represents a security finding/vulnerability."""
    
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    target: str
    finding_type: str
    
    # Optional fields
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    request: Optional[str] = None
    response: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    timestamp: datetime = field(default_factory=_utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        result = asdict(self)
        result['severity'] = self.severity.value
        result['confidence'] = self.confidence.value
        result['timestamp'] = self.timestamp.isoformat()
        return result
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert finding to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class ScanResult:
    """Aggregated results from a security scan."""
    
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the scan results."""
        self.findings.append(finding)
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_summary(self) -> Dict[str, int]:
        """Get a summary count of findings by severity."""
        summary = {s.value: 0 for s in Severity}
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'findings': [f.to_dict() for f in self.findings],
            'metadata': self.metadata,
            'summary': self.get_summary(),
        }
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert scan result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
