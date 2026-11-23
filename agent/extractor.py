"""Domain Extraction, Normalization, and Allowlist Filtering Module.

Designed for Cyber Threat Intelligence and Security Machine Learning pipelines.
Ingests raw threat reports, OSINT feeds, and unstructured text, defangs/de-obfuscates
indicators, normalizes FQDN candidates, validates domain syntax, and filters
known trusted domains against local or top-list allowlists (e.g. Tranco / Umbrella).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


# Regex to detect IPv4 addresses (to discard pure IPs from FQDN extraction)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Regex to detect IPv6 addresses (enclosed or plain)
IPV6_REGEX = re.compile(r"^\[?[a-fA-F0-9:]+\]?$")

# Valid FQDN label: 1 to 63 chars, alphanumeric with hyphens, cannot start or end with hyphen
LABEL_REGEX = re.compile(r"^(?!-)[a-z0-9-_]{1,63}(?<!-)$")

# Defang replacement mappings (ordered for safe sequential replacement)
DEFANG_REPLACEMENTS: Sequence[Tuple[re.Pattern, str]] = (
    # Common de-obfuscation for brackets and dots
    (re.compile(r"\[\.\]", re.IGNORECASE), "."),
    (re.compile(r"\(\.\)", re.IGNORECASE), "."),
    (re.compile(r"\{\.\}", re.IGNORECASE), "."),
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\{dot\}", re.IGNORECASE), "."),
    (re.compile(r"\s+dot\s+", re.IGNORECASE), "."),
    # Scheme defangs: hxxp://, hxxps://, meow://, etc.
    (re.compile(r"\bhxxps?://", re.IGNORECASE), ""),
    (re.compile(r"\bhttps?://", re.IGNORECASE), ""),
    (re.compile(r"\bftp://", re.IGNORECASE), ""),
    (re.compile(r"\bsftp://", re.IGNORECASE), ""),
    # Defanged colons/slashes
    (re.compile(r"\[:\]", re.IGNORECASE), ":"),
    (re.compile(r"\[/\]", re.IGNORECASE), "/"),
    (re.compile(r"\[//\]", re.IGNORECASE), "//"),
    (re.compile(r"\(/\)", re.IGNORECASE), "/"),
)

# Broad token pattern extracting candidate URLs or domain-like strings from text
TOKEN_REGEX = re.compile(r"[^\s,;\"'<>\[\]{}|\\]+")


@dataclass(frozen=True)
class FilteredDomain:
    """Represents a domain candidate that was rejected or excluded."""
    domain: str
    reason: str


@dataclass
class ExtractionResult:
    """Structured result returned by the domain extraction and filtering pipeline."""
    passed: List[str] = field(default_factory=list)
    filtered: List[FilteredDomain] = field(default_factory=list)
    total_raw_candidates: int = 0

    @property
    def passed_count(self) -> int:
        return len(self.passed)

    @property
    def filtered_count(self) -> int:
        return len(self.filtered)

    def summary(self) -> Dict[str, int]:
        return {
            "raw_candidates": self.total_raw_candidates,
            "passed": self.passed_count,
            "filtered": self.filtered_count,
        }


def defang_text(text: str) -> str:
    """Replaces common cyber threat defanging patterns into normalized text."""
    if not text:
        return ""
    result = text
    for pattern, replacement in DEFANG_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    return result


def is_valid_fqdn(candidate: str) -> bool:
    """Validates whether a normalized string conforms to standard FQDN syntax.

    Rules applied:
    - Overall length between 3 and 253 characters
    - Must contain at least one dot separating labels
    - Cannot be a pure IPv4 or IPv6 address
    - Each label must be 1-63 characters, alphanumeric or hyphen
    - TLD must not be purely numeric and must be at least 2 characters long
    """
    if not candidate or len(candidate) > 253 or len(candidate) < 3:
        return False

    if "." not in candidate:
        return False

    # Discard IP addresses
    if IPV4_REGEX.match(candidate) or IPV6_REGEX.match(candidate):
        return False

    labels = candidate.split(".")
    if len(labels) < 2:
        return False

    # Validate each label
    for label in labels:
        if not label or len(label) > 63:
            return False
        # Handle Punycode/IDN (xn--) as valid alphanumeric syntax
        if not LABEL_REGEX.match(label):
            return False

    # TLD validation: should not be entirely numeric (excludes IPs like 1.2.3.4)
    tld = labels[-1]
    if tld.isdigit() or len(tld) < 2:
        return False

    return True


def normalize_domain_candidate(raw_candidate: str) -> Optional[str]:
    """Cleans, de-obfuscates, strips protocol/port/path, and standardizes a single domain string.

    Returns:
        The normalized FQDN in lowercase, or None if the candidate cannot form a valid domain.
    """
    if not raw_candidate:
        return None

    # Step 1: Defang brackets and indicators
    cleaned = defang_text(raw_candidate.strip())

    # Step 2: Strip any residual protocol
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", cleaned)

    # Step 3: Strip credentials if present (e.g. user:pass@domain.com)
    if "@" in cleaned:
        cleaned = cleaned.split("@", 1)[1]

    # Step 4: Discard path, query string, and fragments
    cleaned = re.split(r"[/?#]", cleaned, 1)[0]

    # Step 5: Strip port number if present (e.g. evil.com:8080 -> evil.com)
    if ":" in cleaned and not cleaned.startswith("["):
        cleaned = cleaned.split(":", 1)[0]

    # Step 6: Trim whitespace, punctuation, and leading/trailing dots
    cleaned = cleaned.strip(" \t\r\n.,;:!?'\"`()[]{}<>").lower()

    if not cleaned or not is_valid_fqdn(cleaned):
        return None

    return cleaned


class AllowlistFilter:
    """Manages exact and suffix-based matching for trusted domains to prevent false positives."""

    def __init__(
        self,
        allowlist_domains: Optional[Iterable[str]] = None,
        allowlist_files: Optional[Sequence[Path | str]] = None,
    ) -> None:
        self.exact_allowed: Set[str] = set()

        # Load initial in-memory domains if provided
        if allowlist_domains:
            for d in allowlist_domains:
                normalized = self._clean_allow_entry(d)
                if normalized:
                    self.exact_allowed.add(normalized)

        # Load files if provided
        if allowlist_files:
            for path in allowlist_files:
                self.load_from_file(path)

    @staticmethod
    def _clean_allow_entry(entry: str) -> Optional[str]:
        cleaned = entry.strip().lower()
        if not cleaned or cleaned.startswith("#"):
            return None
        # Handle Tranco/Umbrella CSV ranking formats: "1,google.com"
        if "," in cleaned:
            parts = cleaned.split(",")
            # If format is "rank,domain"
            if len(parts) >= 2 and parts[0].strip().isdigit():
                cleaned = parts[1].strip()
            else:
                cleaned = parts[0].strip()
        cleaned = cleaned.strip(". ")
        return cleaned if cleaned else None

    def load_from_file(self, filepath: Path | str) -> int:
        """Loads allowed domains from a text or CSV file. Returns the number of domains added."""
        path = Path(filepath)
        if not path.is_file():
            return 0

        count_added = 0
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    entry = self._clean_allow_entry(line)
                    if entry:
                        self.exact_allowed.add(entry)
                        count_added += 1
        except OSError:
            return 0
        return count_added

    def is_allowed(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Checks if a domain matches the allowlist (exact or parent subdomain match).

        Returns:
            (True, matched_rule) if allowed, (False, None) otherwise.
        """
        target = domain.strip().lower()
        if target in self.exact_allowed:
            return True, target

        # Subdomain matching: e.g. api.google.com -> matches google.com
        parts = target.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.exact_allowed:
                return True, parent

        return False, None


class DomainExtractor:
    """High-level extractor and filter for threat intelligence and machine learning pipelines."""

    def __init__(
        self,
        allowlist: Optional[AllowlistFilter] = None,
        auto_load_data_dir: bool = True,
        data_dir: Optional[Path | str] = None,
    ) -> None:
        self.allowlist = allowlist or AllowlistFilter()

        if auto_load_data_dir:
            base_dir = Path(data_dir) if data_dir else Path(__file__).resolve().parent.parent / "data"
            self._load_default_allowlists(base_dir)

    def _load_default_allowlists(self, data_dir: Path) -> None:
        if not data_dir.is_dir():
            return

        # 1. Custom local allowlist
        local_allow = data_dir / "allowlist.txt"
        if local_allow.is_file():
            self.allowlist.load_from_file(local_allow)

        # 2. Known top-domain list candidates (Tranco / Umbrella / Alexa)
        for pattern in ("*tranco*.csv", "*tranco*.txt", "*top1m*.csv", "*allowlist*.csv"):
            for candidate in data_dir.glob(pattern):
                self.allowlist.load_from_file(candidate)

    def extract_from_text(self, text: str) -> ExtractionResult:
        """Extracts candidate domains from unstructured text, defangs, normalizes,

        and categorizes them against the allowlist.
        Preserves the first-seen ordering of unique domains.
        """
        result = ExtractionResult()
        if not text:
            return result

        # Split text into candidate tokens
        tokens = TOKEN_REGEX.findall(text)
        result.total_raw_candidates = len(tokens)

        seen: Set[str] = set()

        for token in tokens:
            normalized = normalize_domain_candidate(token)
            if not normalized:
                continue

            if normalized in seen:
                continue
            seen.add(normalized)

            # Check allowlist
            is_allow, matched_rule = self.allowlist.is_allowed(normalized)
            if is_allow:
                result.filtered.append(
                    FilteredDomain(
                        domain=normalized,
                        reason=f"allowlisted: matches '{matched_rule}'",
                    )
                )
            else:
                result.passed.append(normalized)

        return result

    def extract_from_list(self, items: Iterable[str]) -> ExtractionResult:
        """Convenience method to process an iterable of domain/URL strings."""
        joined = "\n".join(items)
        return self.extract_from_text(joined)
