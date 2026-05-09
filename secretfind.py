#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   SecretFind v1.0.0  — Powerful Secret Scanner           ║
║   Inspired by TruffleHog, Gitleaks, SecretFinder,        ║
║               GitGuardian & Trivy                        ║
║                                                          ║
║   Modes: file | dir | git | url | stdin                  ║
║   Detects: regex (90+ patterns) + Shannon entropy        ║
║   Output:  table | json | sarif | csv                    ║
╚══════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
from pathlib import Path

# Make 'core' importable regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.scanner import FileScanner, DirectoryScanner, GitScanner, StdinScanner, UrlScanner
from core.reporter import Reporter, OutputFormat
from core.detector import Detector
from core.patterns import PATTERNS

VERSION = "1.0.0"

BANNER = r"""
  ____                    _   _____ _           _
 / ___|  ___  ___ _ __ ___| |_|  ___|(_)_ __   __| |
 \___ \ / _ \/ __| '__/ _ \ __| |_  | | '_ \ / _` |
  ___) |  __/ (__| | |  __/ |_|  _| | | | | | (_| |
 |____/ \___|\___|_|  \___|\__|_|   |_|_| |_|\__,_|

  v{version}  |  90+ patterns  |  Entropy analysis  |  Git history
""".format(version=VERSION)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_allowlist(path: str) -> list:
    try:
        with open(path) as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    except OSError as e:
        print(f"[!] Cannot read allowlist {path}: {e}", file=sys.stderr)
        return []


def _list_patterns(args) -> None:
    """Print all built-in patterns."""
    from core.patterns import PATTERNS
    severity_filter = set(args.severity.upper().split(",")) if args.severity else None
    tag_filter      = set(args.tags.lower().split(","))    if args.tags     else None

    print(f"\n  {'ID':<45} {'SEVERITY':<10} {'CONFIDENCE':<12} TAGS")
    print(f"  {'─'*45} {'─'*10} {'─'*12} {'─'*30}")
    count = 0
    for p in PATTERNS:
        if severity_filter and p.severity not in severity_filter:
            continue
        if tag_filter and not any(t in tag_filter for t in p.tags):
            continue
        tags_str = ", ".join(p.tags[:4])
        print(f"  {p.id:<45} {p.severity:<10} {p.confidence:<12} {tags_str}")
        count += 1
    print(f"\n  {count} patterns listed.\n")


# ---------------------------------------------------------------------------
# CLI build
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretfind",
        description="SecretFind — powerful secret scanner for files, directories, git repos, and URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory recursively
  python secretfind.py scan dir /path/to/project

  # Scan a single file
  python secretfind.py scan file config.env

  # Scan git history (last 200 commits)
  python secretfind.py scan git /path/to/repo --all-commits --depth 200

  # Scan only staged changes (pre-commit hook style)
  python secretfind.py scan git . --staged

  # Scan a JavaScript bundle URL (SecretFinder-style)
  python secretfind.py scan url https://example.com/bundle.js

  # Pipe output of another command
  cat secrets.txt | python secretfind.py scan stdin

  # Output JSON report
  python secretfind.py scan dir . --format json --output report.json

  # Only show CRITICAL and HIGH findings
  python secretfind.py scan dir . --severity CRITICAL,HIGH

  # Scan only AWS/cloud related patterns
  python secretfind.py scan dir . --tags aws,gcp,azure

  # List all built-in patterns
  python secretfind.py patterns

  # Pre-commit hook integration (non-zero exit if secrets found):
  python secretfind.py scan git . --staged --format json --quiet
        """,
    )

    parser.add_argument("--version", action="version", version=f"SecretFind {VERSION}")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    subparsers = parser.add_subparsers(dest="command")

    # ── patterns command ────────────────────────────────────────────────────
    pat_parser = subparsers.add_parser("patterns", help="List all built-in detection patterns")
    pat_parser.add_argument("--severity", help="Filter by severity (e.g. CRITICAL,HIGH)")
    pat_parser.add_argument("--tags", help="Filter by tags (e.g. aws,github)")

    # ── scan command ────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan for secrets")
    scan_sub    = scan_parser.add_subparsers(dest="target")

    # scan dir
    dir_p = scan_sub.add_parser("dir", help="Recursively scan a directory")
    dir_p.add_argument("path", help="Directory to scan")
    dir_p.add_argument("--exclude", "-e", action="append", metavar="GLOB",
                       help="Exclude glob pattern (repeatable)")
    dir_p.add_argument("--threads", "-j", type=int, default=4,
                       help="Parallel threads (default: 4)")

    # scan file
    file_p = scan_sub.add_parser("file", help="Scan a single file")
    file_p.add_argument("path", help="File to scan")

    # scan git
    git_p = scan_sub.add_parser("git", help="Scan git repository history")
    git_p.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")
    git_p.add_argument("--all-commits", action="store_true",
                       help="Scan entire commit history (all branches)")
    git_p.add_argument("--staged", action="store_true",
                       help="Scan staged changes only")
    git_p.add_argument("--diff", action="store_true",
                       help="Scan unstaged working-tree changes")
    git_p.add_argument("--branch", help="Branch to scan (default: all)")
    git_p.add_argument("--depth", type=int, default=100,
                       help="Max commits to inspect (default: 100)")

    # scan url
    url_p = scan_sub.add_parser("url", help="Fetch and scan a URL (JS, HTML, JSON)")
    url_p.add_argument("url", help="URL to fetch and scan")

    # scan stdin
    stdin_p = scan_sub.add_parser("stdin", help="Read from stdin and scan")

    # Common options for all scan modes
    for p in (dir_p, file_p, git_p, url_p, stdin_p):
        p.add_argument(
            "--format", "-f",
            choices=["table", "json", "sarif", "csv"],
            default="table",
            dest="format",
            help="Output format (default: table)",
        )
        p.add_argument("--output", "-o", metavar="FILE",
                       help="Write output to file (default: stdout)")
        p.add_argument(
            "--severity", "-s",
            help="Filter by severity: CRITICAL,HIGH,MEDIUM,LOW (default: all)",
        )
        p.add_argument("--tags", "-t",
                       help="Filter by pattern tags (e.g. aws,stripe,github)")
        p.add_argument("--no-entropy", action="store_true",
                       help="Disable entropy-based detection")
        p.add_argument("--entropy-threshold", type=float, default=4.5, metavar="N",
                       help="Shannon entropy threshold (default: 4.5)")
        p.add_argument("--allowlist", metavar="FILE",
                       help="File with regex patterns to ignore (one per line)")
        p.add_argument("--max-file-size", type=int, default=10, metavar="MB",
                       help="Skip files larger than N MB (default: 10)")
        p.add_argument("--no-color", action="store_true",
                       help="Disable ANSI color output")
        p.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose progress output")
        p.add_argument("--quiet", "-q", action="store_true",
                       help="Suppress all output except findings (machine-readable)")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # Show banner (unless JSON mode, quiet mode, or explicitly suppressed)
    show_banner = (
        not getattr(args, "no_banner", False)
        and not getattr(args, "quiet", False)
        and getattr(args, "format", "table") != "json"
        and getattr(args, "format", "table") != "csv"
        and getattr(args, "format", "table") != "sarif"
    )
    if show_banner:
        print(BANNER, file=sys.stderr)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "patterns":
        _list_patterns(args)
        return 0

    if args.command == "scan":
        if args.target is None:
            parser.parse_args(["scan", "--help"])
            return 1

        # Build severity / tag filters
        severity_filter = None
        if args.severity:
            severity_filter = [s.strip().upper() for s in args.severity.split(",")]

        tags_filter = None
        if args.tags:
            tags_filter = [t.strip().lower() for t in args.tags.split(",")]

        allowlist = []
        if args.allowlist:
            allowlist = _load_allowlist(args.allowlist)

        detector = Detector(
            use_entropy=not args.no_entropy,
            entropy_threshold=args.entropy_threshold,
            severity_filter=severity_filter,
            tags_filter=tags_filter,
            allowlist=allowlist,
            verbose=args.verbose,
        )

        output_fmt = OutputFormat(args.format)
        reporter   = Reporter(
            format=output_fmt,
            output_file=args.output,
            no_color=args.no_color,
            verbose=args.verbose,
        )

        findings = []
        try:
            if args.target == "file":
                scanner  = FileScanner(detector, max_file_size_mb=args.max_file_size)
                findings = scanner.scan(Path(args.path))

            elif args.target == "dir":
                scanner = DirectoryScanner(
                    detector,
                    max_file_size_mb=args.max_file_size,
                    exclude_patterns=args.exclude or [],
                    threads=args.threads,
                    verbose=args.verbose,
                )
                findings = scanner.scan(Path(args.path))

            elif args.target == "git":
                scanner = GitScanner(
                    detector,
                    all_commits=args.all_commits,
                    staged=args.staged,
                    diff_only=args.diff,
                    branch=args.branch,
                    depth=args.depth,
                    verbose=args.verbose,
                )
                findings = scanner.scan(Path(args.path))

            elif args.target == "url":
                scanner  = UrlScanner(detector, verbose=args.verbose)
                findings = scanner.scan(args.url)

            elif args.target == "stdin":
                scanner  = StdinScanner(detector)
                findings = scanner.scan()

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.", file=sys.stderr)
            return 130
        except Exception as exc:
            print(f"\n[!] Fatal error: {exc}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc(file=sys.stderr)
            return 1

        if not args.quiet or args.format != "table":
            reporter.report(findings)

        if findings and args.quiet and args.format == "table":
            # quiet+table: just print count to stderr
            print(f"[!] {len(findings)} secret(s) found.", file=sys.stderr)

        # Non-zero exit code when secrets are found (useful for CI/CD gates)
        return 1 if findings else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
