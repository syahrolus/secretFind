"""
Detection engine — applies regex patterns + entropy analysis to text lines.
Returns structured Finding objects.
"""

from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Set

from .patterns import PATTERNS, SecretPattern, FP_PATTERNS
from .entropy import find_high_entropy_strings


@dataclass
class Finding:
    """A single secret finding."""
    pattern_id: str
    pattern_name: str
    severity: str
    confidence: str
    description: str
    tags: List[str]

    # Location
    source: str            # file path, git commit ref, URL, etc.
    line_number: int
    line_content: str      # the raw line (redacted for output)
    secret_value: str      # the matched secret

    # Extra context
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    author: Optional[str] = None
    entropy: Optional[float] = None

    def fingerprint(self) -> str:
        """Stable unique fingerprint for deduplication."""
        key = f"{self.pattern_id}:{self.source}:{self.line_number}:{self.secret_value}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def redacted_value(self, keep: int = 4) -> str:
        """Show only first `keep` chars followed by ****."""
        if len(self.secret_value) <= keep:
            return "****"
        return self.secret_value[:keep] + "****"

    def redacted_line(self) -> str:
        """Line content with secret value partially redacted."""
        if not self.secret_value or self.secret_value not in self.line_content:
            return self.line_content
        redacted = self.secret_value[:4] + "****"
        return self.line_content.replace(self.secret_value, redacted, 1)


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class Detector:
    """
    Combines regex pattern matching and entropy analysis.
    Filters findings by severity, tags, allowlist.
    Deduplicates across a scan session.
    """

    def __init__(
        self,
        use_entropy: bool = True,
        entropy_threshold: float = 4.5,
        severity_filter: Optional[List[str]] = None,
        tags_filter: Optional[List[str]] = None,
        allowlist: Optional[List[str]] = None,
        verbose: bool = False,
    ):
        self.use_entropy = use_entropy
        self.entropy_threshold = entropy_threshold
        self.severity_filter = set(severity_filter) if severity_filter else None
        self.tags_filter = set(t.lower() for t in tags_filter) if tags_filter else None
        self.verbose = verbose

        # Compile allowlist regexes
        self._allowlist: List[re.Pattern] = []
        for pattern in (allowlist or []):
            try:
                self._allowlist.append(re.compile(pattern))
            except re.error:
                pass

        # Compile all detection patterns upfront
        for p in PATTERNS:
            p.compile()

        # Session-level deduplication set
        self._seen_fingerprints: Set[str] = set()

    def reset(self) -> None:
        """Reset deduplication state between scans."""
        self._seen_fingerprints.clear()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_line(
        self,
        line: str,
        source: str,
        line_number: int,
        commit_hash: Optional[str] = None,
        commit_message: Optional[str] = None,
        author: Optional[str] = None,
    ) -> List[Finding]:
        """Scan a single line of text and return all findings."""
        findings: List[Finding] = []

        # --- Regex pattern matching ---
        for pattern in PATTERNS:
            if not self._pattern_passes_filter(pattern):
                continue
            for match in pattern.findall(line):
                secret = match.group(pattern.group) if pattern.group < len(match.groups()) + 1 else match.group(0)
                if not secret:
                    continue
                finding = self._make_finding(
                    pattern=pattern,
                    secret=secret,
                    source=source,
                    line_number=line_number,
                    line_content=line,
                    commit_hash=commit_hash,
                    commit_message=commit_message,
                    author=author,
                )
                if finding:
                    findings.append(finding)

        # --- Entropy-based detection ---
        if self.use_entropy:
            for token, entropy, enc in find_high_entropy_strings(line, self.entropy_threshold):
                finding = self._make_entropy_finding(
                    token=token,
                    entropy=entropy,
                    encoding=enc,
                    source=source,
                    line_number=line_number,
                    line_content=line,
                    commit_hash=commit_hash,
                    commit_message=commit_message,
                    author=author,
                )
                if finding:
                    # Skip if already caught by a regex pattern
                    if not any(token in f.secret_value or f.secret_value in token for f in findings):
                        findings.append(finding)

        return findings

    def scan_text(
        self,
        text: str,
        source: str,
        commit_hash: Optional[str] = None,
        commit_message: Optional[str] = None,
        author: Optional[str] = None,
    ) -> List[Finding]:
        """Scan multi-line text block."""
        findings: List[Finding] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            findings.extend(
                self.scan_line(
                    line=line,
                    source=source,
                    line_number=line_number,
                    commit_hash=commit_hash,
                    commit_message=commit_message,
                    author=author,
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _pattern_passes_filter(self, pattern: SecretPattern) -> bool:
        if self.severity_filter and pattern.severity not in self.severity_filter:
            return False
        if self.tags_filter:
            if not any(t in self.tags_filter for t in pattern.tags):
                return False
        return True

    def _is_false_positive(self, value: str) -> bool:
        if FP_PATTERNS.search(value):
            return True
        for al in self._allowlist:
            if al.search(value):
                return True
        return False

    def _make_finding(
        self,
        pattern: SecretPattern,
        secret: str,
        source: str,
        line_number: int,
        line_content: str,
        commit_hash: Optional[str],
        commit_message: Optional[str],
        author: Optional[str],
    ) -> Optional[Finding]:
        if self._is_false_positive(secret):
            return None

        f = Finding(
            pattern_id=pattern.id,
            pattern_name=pattern.name,
            severity=pattern.severity,
            confidence=pattern.confidence,
            description=pattern.description,
            tags=list(pattern.tags),
            source=source,
            line_number=line_number,
            line_content=line_content.rstrip(),
            secret_value=secret,
            commit_hash=commit_hash,
            commit_message=commit_message,
            author=author,
        )
        fp = f.fingerprint()
        if fp in self._seen_fingerprints:
            return None
        self._seen_fingerprints.add(fp)
        return f

    def _make_entropy_finding(
        self,
        token: str,
        entropy: float,
        encoding: str,
        source: str,
        line_number: int,
        line_content: str,
        commit_hash: Optional[str],
        commit_message: Optional[str],
        author: Optional[str],
    ) -> Optional[Finding]:
        if self._is_false_positive(token):
            return None

        # Severity based on entropy level
        if entropy >= 5.5:
            severity = "HIGH"
        elif entropy >= 5.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if self.severity_filter and severity not in self.severity_filter:
            return None

        f = Finding(
            pattern_id="entropy-high-entropy-string",
            pattern_name="High Entropy String",
            severity=severity,
            confidence="LOW",
            description=(
                f"High-entropy {encoding}-like string detected near a secret keyword "
                f"(entropy={entropy:.2f}). May be an unrecognized secret format."
            ),
            tags=["entropy", "generic"],
            source=source,
            line_number=line_number,
            line_content=line_content.rstrip(),
            secret_value=token,
            commit_hash=commit_hash,
            commit_message=commit_message,
            author=author,
            entropy=entropy,
        )
        fp = f.fingerprint()
        if fp in self._seen_fingerprints:
            return None
        self._seen_fingerprints.add(fp)
        return f
