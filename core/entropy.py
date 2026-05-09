"""
Shannon entropy analysis for detecting high-entropy strings (likely secrets).
Used in addition to regex patterns to catch unknown/custom secret formats.
"""

from __future__ import annotations
import math
import re
from typing import List, Tuple

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "0123456789abcdefABCDEF"

# Keywords that often appear next to secrets — used to reduce noise
SECRET_KEYWORDS = re.compile(
    r'(?:password|passwd|secret|token|key|api[_\-]?key|auth|credential|cred|'
    r'private|priv|access|bearer|authorization|apikey|clientsecret|client_secret|'
    r'db_pass|database_pass|connection_string)',
    re.IGNORECASE,
)

# Patterns that look like secrets but are actually noise
NOISE_PATTERNS = re.compile(
    r'(?:'
    r'[a-z]{6,}'                          # lowercase-only words
    r'|[A-Z]{6,}'                         # uppercase-only words
    r'|[0-9]{6,}'                         # digit-only strings
    r'|(?:http|www|localhost)'            # URLs
    r'|(?:true|false|null|none|undefined)'
    r'|[./\\]'                             # paths
    r')',
    re.IGNORECASE,
)


def shannon_entropy(data: str, charset: str) -> float:
    """Compute Shannon entropy of `data` restricted to characters in `charset`."""
    filtered = [c for c in data if c in charset]
    if not filtered:
        return 0.0
    length = len(filtered)
    freq: dict[str, int] = {}
    for c in filtered:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def classify_entropy(s: str) -> Tuple[bool, float, str]:
    """
    Return (is_high_entropy, entropy_value, encoding_type).
    Checks both base64 and hex encodings.
    """
    if len(s) < 16:
        return False, 0.0, "none"

    b64_ent = shannon_entropy(s, BASE64_CHARS)
    hex_ent = shannon_entropy(s, HEX_CHARS)

    # High entropy base64-like string
    if b64_ent > 4.5 and len(s) >= 20:
        return True, b64_ent, "base64"

    # High entropy hex string
    if hex_ent > 3.5 and all(c in HEX_CHARS for c in s) and len(s) >= 16:
        return True, hex_ent, "hex"

    return False, max(b64_ent, hex_ent), "none"


# Tokenizer: split a line into candidate tokens
_TOKENIZER = re.compile(r'[A-Za-z0-9+/=_\-]{16,}')


def find_high_entropy_strings(
    line: str,
    threshold: float = 4.5,
    require_keyword_proximity: bool = True,
) -> List[Tuple[str, float, str]]:
    """
    Scan a line for high-entropy substrings.
    Returns list of (token, entropy, encoding).
    When `require_keyword_proximity` is True, only returns tokens near a secret
    keyword (reduces noise dramatically).
    """
    has_keyword = bool(SECRET_KEYWORDS.search(line))
    if require_keyword_proximity and not has_keyword:
        return []

    results: List[Tuple[str, float, str]] = []
    for match in _TOKENIZER.finditer(line):
        token = match.group()
        if NOISE_PATTERNS.fullmatch(token):
            continue
        is_high, ent, enc = classify_entropy(token)
        if is_high and ent >= threshold:
            results.append((token, ent, enc))
    return results
