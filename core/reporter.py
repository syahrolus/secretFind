"""
Output formatters for SecretFind findings.
Supports: table (colored terminal), JSON, SARIF 2.1.0, CSV.
"""

from __future__ import annotations
import json
import csv
import io
import sys
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from .detector import Finding

# ---------------------------------------------------------------------------
# ANSI color codes (no external deps)
# ---------------------------------------------------------------------------
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

_RED    = "\033[91m"
_ORANGE = "\033[33m"
_YELLOW = "\033[93m"
_BLUE   = "\033[94m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_GRAY   = "\033[90m"
_WHITE  = "\033[97m"

SEVERITY_COLORS = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _ORANGE + _BOLD,
    "MEDIUM":   _YELLOW,
    "LOW":      _BLUE,
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}

CONFIDENCE_COLORS = {
    "HIGH":   _GREEN,
    "MEDIUM": _YELLOW,
    "LOW":    _GRAY,
}


class OutputFormat(str, Enum):
    TABLE = "table"
    JSON  = "json"
    SARIF = "sarif"
    CSV   = "csv"


def _c(text: str, color: str, no_color: bool) -> str:
    if no_color:
        return text
    return f"{color}{text}{_RESET}"


class Reporter:
    def __init__(
        self,
        format: OutputFormat = OutputFormat.TABLE,
        output_file: Optional[str] = None,
        no_color: bool = False,
        verbose: bool = False,
    ):
        self.format = format
        self.output_file = output_file
        self.no_color = no_color or (not sys.stdout.isatty() and output_file is None)
        self.verbose = verbose

    def report(self, findings: List[Finding]) -> None:
        if self.format == OutputFormat.TABLE:
            output = self._render_table(findings)
        elif self.format == OutputFormat.JSON:
            output = self._render_json(findings)
        elif self.format == OutputFormat.SARIF:
            output = self._render_sarif(findings)
        elif self.format == OutputFormat.CSV:
            output = self._render_csv(findings)
        else:
            output = self._render_table(findings)

        if self.output_file:
            with open(self.output_file, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"\n[+] Report written to {self.output_file}", file=sys.stderr)
        else:
            print(output)

    # ------------------------------------------------------------------
    # Table renderer
    # ------------------------------------------------------------------

    def _render_table(self, findings: List[Finding]) -> str:
        nc = self.no_color
        lines: List[str] = []

        if not findings:
            lines.append(_c("  No secrets found.", _GREEN + _BOLD, nc))
            return "\n".join(lines)

        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.severity, 9))

        lines.append("")
        lines.append(_c(f"  {'='*70}", _GRAY, nc))
        lines.append(_c(f"  FINDINGS ({len(findings)} total)", _BOLD + _WHITE, nc))
        lines.append(_c(f"  {'='*70}", _GRAY, nc))
        lines.append("")

        for idx, f in enumerate(sorted_findings, start=1):
            sev_color = SEVERITY_COLORS.get(f.severity, _WHITE)
            con_color  = CONFIDENCE_COLORS.get(f.confidence, _GRAY)
            icon = SEVERITY_ICONS.get(f.severity, "?") if not nc else ""

            lines.append(_c(f"  [{idx}] {icon} {f.pattern_name}", sev_color, nc))
            lines.append(_c(f"  {'─'*60}", _GRAY, nc))

            lines.append(
                f"  {'Severity:':<14}{_c(f.severity, sev_color, nc)}"
                f"  {'Confidence:':<14}{_c(f.confidence, con_color, nc)}"
            )
            lines.append(f"  {'Pattern ID:':<14}{_c(f.pattern_id, _CYAN, nc)}")
            lines.append(f"  {'Description:':<14}{f.description}")
            lines.append(f"  {'Tags:':<14}{_c(', '.join(f.tags), _GRAY, nc)}")
            lines.append("")

            # Location
            if f.commit_hash:
                lines.append(f"  {'Commit:':<14}{_c(f.commit_hash[:16], _YELLOW, nc)}")
                if f.author:
                    lines.append(f"  {'Author:':<14}{f.author}")
                if f.commit_message:
                    lines.append(f"  {'Message:':<14}{f.commit_message[:80]}")
            lines.append(f"  {'File:':<14}{_c(f.source, _BLUE, nc)}")
            lines.append(f"  {'Line:':<14}{f.line_number}")
            lines.append("")

            # Code context (redacted)
            line_display = f.redacted_line()
            if len(line_display) > 120:
                line_display = line_display[:120] + "..."
            lines.append(f"  {_c('Context:', _GRAY, nc)}")
            lines.append(f"  {_c('  ' + str(f.line_number).rjust(5) + ' │ ', _GRAY, nc)}{line_display.strip()}")
            lines.append("")

            # Secret value (redacted)
            lines.append(
                f"  {'Secret:':<14}{_c(f.redacted_value(keep=6), sev_color + _BOLD, nc)}"
                + (f"  {_c(f'(entropy: {f.entropy:.2f})', _GRAY, nc)}" if f.entropy else "")
            )
            lines.append(_c(f"  {'─'*60}", _GRAY, nc))
            lines.append("")

        # Summary table
        lines.extend(self._render_summary(findings))
        return "\n".join(lines)

    def _render_summary(self, findings: List[Finding]) -> List[str]:
        nc = self.no_color
        lines: List[str] = []
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        lines.append(_c(f"  {'='*70}", _GRAY, nc))
        lines.append(_c("  SUMMARY", _BOLD + _WHITE, nc))
        lines.append(_c(f"  {'='*70}", _GRAY, nc))
        lines.append(f"  Total findings : {_c(str(len(findings)), _BOLD, nc)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            color = SEVERITY_COLORS.get(sev, _WHITE)
            icon  = SEVERITY_ICONS.get(sev, "") if not nc else ""
            n     = counts.get(sev, 0)
            lines.append(f"  {icon} {sev:<10}: {_c(str(n), color, nc)}")

        # Top sources
        source_counts: Dict[str, int] = {}
        for f in findings:
            source_counts[f.source] = source_counts.get(f.source, 0) + 1
        if source_counts:
            lines.append("")
            lines.append("  Top affected files / locations:")
            for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1])[:5]:
                lines.append(f"    {cnt:>4}  {_c(src, _CYAN, nc)}")

        lines.append(_c(f"  {'='*70}", _GRAY, nc))
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # JSON renderer
    # ------------------------------------------------------------------

    def _render_json(self, findings: List[Finding]) -> str:
        data = {
            "metadata": {
                "tool": "SecretFind",
                "version": "1.0.0",
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "total": len(findings),
            },
            "findings": [self._finding_to_dict(f) for f in findings],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def _finding_to_dict(self, f: Finding) -> Dict[str, Any]:
        return {
            "id": f.fingerprint(),
            "pattern_id": f.pattern_id,
            "pattern_name": f.pattern_name,
            "severity": f.severity,
            "confidence": f.confidence,
            "description": f.description,
            "tags": f.tags,
            "location": {
                "source": f.source,
                "line": f.line_number,
                "commit": f.commit_hash,
                "author": f.author,
                "commit_message": f.commit_message,
            },
            "secret_redacted": f.redacted_value(keep=6),
            "line_redacted": f.redacted_line(),
            "entropy": f.entropy,
        }

    # ------------------------------------------------------------------
    # SARIF 2.1.0 renderer (GitHub Code Scanning compatible)
    # ------------------------------------------------------------------

    def _render_sarif(self, findings: List[Finding]) -> str:
        rules: List[Dict] = []
        rule_ids_seen = set()
        results: List[Dict] = []

        for f in findings:
            if f.pattern_id not in rule_ids_seen:
                rule_ids_seen.add(f.pattern_id)
                rules.append({
                    "id": f.pattern_id,
                    "name": f.pattern_name.replace(" ", ""),
                    "shortDescription": {"text": f.pattern_name},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": {
                            "CRITICAL": "error",
                            "HIGH": "error",
                            "MEDIUM": "warning",
                            "LOW": "note",
                        }.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": f.tags,
                        "precision": f.confidence.lower(),
                    },
                })

            results.append({
                "ruleId": f.pattern_id,
                "level": {
                    "CRITICAL": "error",
                    "HIGH": "error",
                    "MEDIUM": "warning",
                    "LOW": "note",
                }.get(f.severity, "warning"),
                "message": {"text": f"{f.pattern_name}: {f.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.source, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": f.line_number,
                            "snippet": {"text": f.redacted_line()},
                        },
                    }
                }],
                "fingerprints": {"secretfind/v1": f.fingerprint()},
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "secret_redacted": f.redacted_value(keep=4),
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecretFind",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/secretfind",
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # CSV renderer
    # ------------------------------------------------------------------

    def _render_csv(self, findings: List[Finding]) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "id", "severity", "confidence", "pattern_id", "pattern_name",
            "source", "line", "commit", "author", "description", "tags",
            "secret_redacted",
        ])
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id": f.fingerprint(),
                "severity": f.severity,
                "confidence": f.confidence,
                "pattern_id": f.pattern_id,
                "pattern_name": f.pattern_name,
                "source": f.source,
                "line": f.line_number,
                "commit": f.commit_hash or "",
                "author": f.author or "",
                "description": f.description,
                "tags": "|".join(f.tags),
                "secret_redacted": f.redacted_value(keep=6),
            })
        return buf.getvalue()
