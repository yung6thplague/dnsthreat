"""Unit tests for agent/extractor.py domain extraction, normalization, and allowlist filtering."""

import pytest
from pathlib import Path
from agent.extractor import (
    AllowlistFilter,
    DomainExtractor,
    ExtractionResult,
    defang_text,
    is_valid_fqdn,
    normalize_domain_candidate,
)


def test_defang_text():
    """Validates de-obfuscation of defanged threat indicators."""
    assert defang_text("hxxp://evil[.]com/bad") == "evil.com/bad"
    assert defang_text("hxxps://malicious(.)net") == "malicious.net"
    assert defang_text("c2{dot}server{.}org") == "c2.server.org"
    assert defang_text("phishing[dot]top") == "phishing.top"
    assert defang_text("attacker[:]8080[/]path") == "attacker:8080/path"


def test_is_valid_fqdn():
    """Validates FQDN syntax detection and rejection of invalid/IP entries."""
    # Valid domains
    assert is_valid_fqdn("google.com") is True
    assert is_valid_fqdn("sub.domain.co.uk") is True
    assert is_valid_fqdn("c2-beacon-01.xyz") is True
    assert is_valid_fqdn("xn--fsqu00a.xn--4gbrim") is True  # Punycode / IDN

    # Invalid / Discarded entries
    assert is_valid_fqdn("192.168.1.1") is False  # IPv4
    assert is_valid_fqdn("10.0.2.15") is False    # IPv4
    assert is_valid_fqdn("2001:db8::1") is False  # IPv6
    assert is_valid_fqdn("localhost") is False     # Single-label
    assert is_valid_fqdn("justaword") is False    # Single-label
    assert is_valid_fqdn("-invalid.com") is False # Invalid leading hyphen
    assert is_valid_fqdn("invalid-.com") is False # Invalid trailing hyphen
    assert is_valid_fqdn("domain.123") is False   # Numeric TLD
    assert is_valid_fqdn("") is False


def test_normalize_domain_candidate():
    """Tests normalization of paths, ports, schemes, and punctuation."""
    # Scheme, path, port stripping
    assert normalize_domain_candidate("https://evil-c2.com/gate.php?id=1") == "evil-c2.com"
    assert normalize_domain_candidate("hxxp://bad-domain.xyz:8080/download") == "bad-domain.xyz"
    assert normalize_domain_candidate("ftp://user:pass@ftp-drop.net:21/dump") == "ftp-drop.net"

    # Defanged brackets
    assert normalize_domain_candidate("malware[.]traffic[.]org") == "malware.traffic.org"
    assert normalize_domain_candidate("stealer(dot)biz/login") == "stealer.biz"

    # Punctuation and casing
    assert normalize_domain_candidate("  UPPERCASE-MALWARE.COM. ") == "uppercase-malware.com"
    assert normalize_domain_candidate("trailing-dot.com...") == "trailing-dot.com"

    # IPs and garbage
    assert normalize_domain_candidate("192.168.1.50:80/shell") is None
    assert normalize_domain_candidate("not_a_domain") is None
    assert normalize_domain_candidate("http://[2001:db8::1]/path") is None


def test_allowlist_exact_and_subdomain_matching():
    """Tests in-memory and file-based allowlist matching."""
    allow = AllowlistFilter(allowlist_domains=["google.com", "microsoft.com", "gov.pt"])

    # Exact match
    allowed, rule = allow.is_allowed("google.com")
    assert allowed is True
    assert rule == "google.com"

    # Subdomain match
    allowed, rule = allow.is_allowed("mail.google.com")
    assert allowed is True
    assert rule == "google.com"

    allowed, rule = allow.is_allowed("portal.seguranca.gov.pt")
    assert allowed is True
    assert rule == "gov.pt"

    # Non-allowed
    allowed, rule = allow.is_allowed("google.com.evil.com")
    assert allowed is False
    assert rule is None

    allowed, rule = allow.is_allowed("attacker-c2.ru")
    assert allowed is False


def test_allowlist_file_loading(tmp_path: Path):
    """Tests loading allowlists from txt and Tranco-style CSV files."""
    # Text file with comments and whitespace
    txt_file = tmp_path / "custom_allow.txt"
    txt_file.write_text("# Trusted list\ncloudflare.com\n\n  amazon.com \n", encoding="utf-8")

    # CSV file (rank, domain format typical of Tranco / Umbrella)
    csv_file = tmp_path / "tranco_sample.csv"
    csv_file.write_text("1,google.com\n2,facebook.com\n3,apple.com\n", encoding="utf-8")

    filter_engine = AllowlistFilter(allowlist_files=[txt_file, csv_file])

    assert filter_engine.is_allowed("cloudflare.com")[0] is True
    assert filter_engine.is_allowed("s3.amazon.com")[0] is True
    assert filter_engine.is_allowed("apple.com")[0] is True
    assert filter_engine.is_allowed("untrusted-site.xyz")[0] is False


def test_domain_extractor_pipeline():
    """Tests full end-to-end extraction from unstructured threat report text."""
    raw_report = """
    CRITICAL THREAT BULLETIN:
    Observed active command-and-control beaconing to hxxps://c2-darknet[.]top:443/api/v1.
    Additional payload dropped from http://192.168.10.5/trojan.exe and hxxp://bad-payload(dot)xyz/stager.
    Legitimate traffic resolved via https://dns.google.com/resolve and https://update.microsoft.com.
    Secondary fallback observed at c2-darknet[.]top (duplicate) and https://evil-phish.net/login.
    """

    allow = AllowlistFilter(allowlist_domains=["google.com", "microsoft.com"])
    extractor = DomainExtractor(allowlist=allow, auto_load_data_dir=False)

    result = extractor.extract_from_text(raw_report)

    # Domains that should pass (malicious, non-allowlisted, non-IP)
    assert "c2-darknet.top" in result.passed
    assert "bad-payload.xyz" in result.passed
    assert "evil-phish.net" in result.passed

    # Verify duplicate handling (c2-darknet.top should only appear once)
    assert result.passed.count("c2-darknet.top") == 1

    # Verify allowlisted domains are filtered with proper reason
    filtered_domains = {f.domain: f.reason for f in result.filtered}
    assert "dns.google.com" in filtered_domains
    assert "google.com" in filtered_domains["dns.google.com"]
    assert "update.microsoft.com" in filtered_domains

    # Verify IPs were ignored and not passed
    assert "192.168.10.5" not in result.passed


def test_domain_extractor_convenience_list():
    """Tests extraction from an iterable list of candidates."""
    candidates = [
        "hxxp://malware-feed.cc/gate",
        "https://github.com/project",
        "malware-feed.cc",  # duplicate
        "10.0.0.1",         # ip
        "phishing-alert.online",
    ]

    allow = AllowlistFilter(allowlist_domains=["github.com"])
    extractor = DomainExtractor(allowlist=allow, auto_load_data_dir=False)

    res = extractor.extract_from_list(candidates)

    assert res.passed == ["malware-feed.cc", "phishing-alert.online"]
    assert len(res.filtered) == 1
    assert res.filtered[0].domain == "github.com"
