"""
Scanner implementations:
  FileScanner       — single file
  DirectoryScanner  — recursive directory walk (parallel)
  GitScanner        — git history, staged diff, working-tree diff
  StdinScanner      — pipe / stdin
  UrlScanner        — fetch URL and scan content (JS, HTML, JSON)
"""

from __future__ import annotations
import os
import sys
import subprocess
import urllib.request
import urllib.error
import fnmatch
from pathlib import Path
from typing import List, Iterator, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .detector import Detector, Finding

# ---------------------------------------------------------------------------
# File extension allow / deny lists
# ---------------------------------------------------------------------------
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".img", ".iso",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".class", ".jar", ".war", ".ear",
    ".pyc", ".pyo", ".pyd",
    ".ttf", ".woff", ".woff2", ".eot", ".otf",
    ".db", ".sqlite", ".sqlite3",
    ".lock",  # package lock files have no secrets worth scanning
}

# Default ignore patterns (gitignore-style globs)
DEFAULT_IGNORE_PATTERNS = [
    "*.min.js",
    "*.min.css",
    "node_modules/**",
    ".git/**",
    ".svn/**",
    "vendor/**",
    "dist/**",
    "build/**",
    "__pycache__/**",
    "*.egg-info/**",
    ".venv/**",
    "venv/**",
    ".tox/**",
    "coverage/**",
    ".nyc_output/**",
]

MAX_LINE_LENGTH = 2000  # skip lines longer than this (minified JS etc.)


def _is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        # Heuristic: if >30% of first 8 KB is non-text bytes, treat as binary
        non_text = sum(1 for b in chunk if b < 9 or (b > 13 and b < 32) or b > 126)
        return non_text / max(len(chunk), 1) > 0.30
    except OSError:
        return True


def _matches_any_glob(path_str: str, patterns: List[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(path_str, pat):
            return True
        # Also check each component of the path
        if fnmatch.fnmatch(os.path.basename(path_str), pat.rstrip("/**")):
            return True
    return False


# ---------------------------------------------------------------------------
# FileScanner
# ---------------------------------------------------------------------------

class FileScanner:
    def __init__(self, detector: Detector, max_file_size_mb: int = 10):
        self.detector = detector
        self.max_bytes = max_file_size_mb * 1024 * 1024

    def scan(self, path: Path) -> List[Finding]:
        path = Path(path)
        if not path.is_file():
            print(f"[!] Not a file: {path}", file=sys.stderr)
            return []

        if _is_binary_file(path):
            return []

        try:
            stat = path.stat()
            if stat.st_size > self.max_bytes:
                print(f"[!] Skipping {path} — file too large ({stat.st_size // 1024 // 1024} MB)", file=sys.stderr)
                return []
        except OSError:
            return []

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
            return []

        findings: List[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > MAX_LINE_LENGTH:
                continue
            findings.extend(
                self.detector.scan_line(line=line, source=str(path), line_number=lineno)
            )
        return findings


# ---------------------------------------------------------------------------
# DirectoryScanner
# ---------------------------------------------------------------------------

class DirectoryScanner:
    def __init__(
        self,
        detector: Detector,
        max_file_size_mb: int = 10,
        exclude_patterns: Optional[List[str]] = None,
        threads: int = 4,
        verbose: bool = False,
    ):
        self.detector = detector
        self.file_scanner = FileScanner(detector, max_file_size_mb)
        self.exclude = (exclude_patterns or []) + DEFAULT_IGNORE_PATTERNS
        self.threads = threads
        self.verbose = verbose

    def _collect_files(self, root: Path) -> List[Path]:
        files: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            # Prune ignored directories in-place
            dirnames[:] = [
                d for d in dirnames
                if not _matches_any_glob(os.path.join(rel_dir, d), self.exclude)
                and not d.startswith(".")
            ]
            for fname in filenames:
                rel_path = os.path.join(rel_dir, fname)
                if _matches_any_glob(rel_path, self.exclude):
                    continue
                full = Path(dirpath) / fname
                if not _is_binary_file(full):
                    files.append(full)
        return files

    def scan(self, path: Path) -> List[Finding]:
        path = Path(path)
        if not path.is_dir():
            print(f"[!] Not a directory: {path}", file=sys.stderr)
            return []

        files = self._collect_files(path)
        if self.verbose:
            print(f"[*] Found {len(files)} files to scan", file=sys.stderr)

        all_findings: List[Finding] = []

        def scan_one(f: Path) -> List[Finding]:
            if self.verbose:
                print(f"    Scanning {f}", file=sys.stderr)
            return self.file_scanner.scan(f)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(scan_one, f): f for f in files}
            for future in as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error scanning {futures[future]}: {e}", file=sys.stderr)

        return all_findings


# ---------------------------------------------------------------------------
# GitScanner
# ---------------------------------------------------------------------------

def _run_git(args: List[str], cwd: str) -> str:
    """Run a git command and return stdout. Raises RuntimeError on failure."""
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0 and result.stderr:
        raise RuntimeError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


class GitScanner:
    """
    Scans a git repository for secrets in:
    - All commits (--all-commits)
    - Staged changes (--staged)
    - Unstaged working-tree diff (--diff)
    - Current HEAD content (default, like a file scan of tracked files)
    """

    def __init__(
        self,
        detector: Detector,
        all_commits: bool = False,
        staged: bool = False,
        diff_only: bool = False,
        branch: Optional[str] = None,
        depth: int = 100,
        verbose: bool = False,
    ):
        self.detector = detector
        self.all_commits = all_commits
        self.staged = staged
        self.diff_only = diff_only
        self.branch = branch
        self.depth = depth
        self.verbose = verbose

    def scan(self, path: Path) -> List[Finding]:
        path = Path(path)
        cwd = str(path)

        # Verify it's a git repo
        try:
            _run_git(["rev-parse", "--is-inside-work-tree"], cwd)
        except (RuntimeError, FileNotFoundError):
            print(f"[!] Not a git repository: {path}", file=sys.stderr)
            return []

        findings: List[Finding] = []

        if self.staged:
            print("[*] Scanning staged changes ...", file=sys.stderr)
            findings.extend(self._scan_diff(cwd, ["diff", "--cached"]))

        elif self.diff_only:
            print("[*] Scanning unstaged working tree changes ...", file=sys.stderr)
            findings.extend(self._scan_diff(cwd, ["diff"]))

        elif self.all_commits:
            print("[*] Scanning full git history ...", file=sys.stderr)
            findings.extend(self._scan_history(cwd))

        else:
            # Default: scan last `depth` commits
            print(f"[*] Scanning last {self.depth} commits ...", file=sys.stderr)
            findings.extend(self._scan_history(cwd))

        return findings

    def _scan_diff(self, cwd: str, git_args: List[str]) -> List[Finding]:
        """Scan a git diff output for secrets."""
        try:
            diff = _run_git(git_args + ["--unified=0"], cwd)
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            return []

        return self._parse_diff(diff, source="<staged>")

    def _scan_history(self, cwd: str) -> List[Finding]:
        """Iterate commits and scan their diffs."""
        # Get commit list
        log_args = ["log", "--format=%H|||%ae|||%s", f"-{self.depth}"]
        if self.branch:
            log_args.append(self.branch)
        else:
            log_args.append("--all")

        try:
            log_output = _run_git(log_args, cwd)
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            return []

        commits = []
        for line in log_output.strip().splitlines():
            if "|||" in line:
                parts = line.split("|||", 2)
                if len(parts) == 3:
                    commits.append({"hash": parts[0], "author": parts[1], "message": parts[2]})

        if self.verbose:
            print(f"[*] Processing {len(commits)} commits", file=sys.stderr)

        all_findings: List[Finding] = []
        for commit in commits:
            h = commit["hash"]
            short = h[:12]
            if self.verbose:
                print(f"    [{short}] {commit['message'][:60]}", file=sys.stderr)

            try:
                diff = _run_git(["show", h, "--unified=0", "--format="], cwd)
            except RuntimeError as e:
                if self.verbose:
                    print(f"[!] Cannot show commit {short}: {e}", file=sys.stderr)
                continue

            findings = self._parse_diff(
                diff,
                source=f"git:{short}",
                commit_hash=h,
                commit_message=commit["message"],
                author=commit["author"],
            )
            all_findings.extend(findings)

        return all_findings

    def _parse_diff(
        self,
        diff_text: str,
        source: str,
        commit_hash: Optional[str] = None,
        commit_message: Optional[str] = None,
        author: Optional[str] = None,
    ) -> List[Finding]:
        """Parse unified diff output and scan only added lines (+)."""
        findings: List[Finding] = []
        current_file = source
        line_number = 0
        in_hunk = False

        for raw_line in diff_text.splitlines():
            # Track file being diffed
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:].strip()
                in_hunk = False
                # Skip binary / known uninteresting files
                if _matches_any_glob(current_file, DEFAULT_IGNORE_PATTERNS):
                    current_file = "__skip__"
                continue

            if current_file == "__skip__":
                continue

            # Hunk header: @@ -a,b +c,d @@
            if raw_line.startswith("@@"):
                in_hunk = True
                # Extract new file line start
                import re
                m = re.search(r'\+(\d+)', raw_line)
                line_number = int(m.group(1)) if m else 0
                continue

            if not in_hunk:
                continue

            # Only scan added lines
            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                line_content = raw_line[1:]  # strip the leading '+'
                if len(line_content) <= MAX_LINE_LENGTH:
                    findings.extend(
                        self.detector.scan_line(
                            line=line_content,
                            source=current_file,
                            line_number=line_number,
                            commit_hash=commit_hash,
                            commit_message=commit_message,
                            author=author,
                        )
                    )
                line_number += 1
            elif not raw_line.startswith("-"):
                line_number += 1

        return findings


# ---------------------------------------------------------------------------
# StdinScanner
# ---------------------------------------------------------------------------

class StdinScanner:
    def __init__(self, detector: Detector):
        self.detector = detector

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(sys.stdin, start=1):
            line = line.rstrip("\n")
            if len(line) <= MAX_LINE_LENGTH:
                findings.extend(
                    self.detector.scan_line(line=line, source="<stdin>", line_number=lineno)
                )
        return findings


# ---------------------------------------------------------------------------
# UrlScanner
# ---------------------------------------------------------------------------

class UrlScanner:
    """
    Fetches a URL and scans its content — particularly useful for JS files
    loaded by web apps (inspired by SecretFinder).
    """

    USER_AGENT = "SecretFind/1.0 (+https://github.com/secretfind)"
    TIMEOUT = 15

    def __init__(self, detector: Detector, verbose: bool = False):
        self.detector = detector
        self.verbose = verbose

    def scan(self, url: str) -> List[Finding]:
        print(f"[*] Fetching {url} ...", file=sys.stderr)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": self.USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                raw = resp.read(10 * 1024 * 1024)  # 10 MB max
                try:
                    content = raw.decode("utf-8", errors="replace")
                except Exception:
                    content = raw.decode("latin-1", errors="replace")
        except urllib.error.URLError as e:
            print(f"[!] Failed to fetch {url}: {e}", file=sys.stderr)
            return []

        if self.verbose:
            print(f"[*] Fetched {len(content):,} bytes from {url}", file=sys.stderr)

        return self.detector.scan_text(text=content, source=url)
