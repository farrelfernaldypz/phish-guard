"""Deterministic, network-free URL feature extraction shared by training and inference.
Includes advanced Shannon Entropy, Homograph/Punycode detection, and Indonesian threat lexicon.
"""
from __future__ import annotations
import ipaddress
import json
import math
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length", "fragment_length",
    "count_dots", "count_hyphens", "count_underscores", "count_digits", "count_special_characters",
    "count_at_symbols", "count_percent_symbols", "count_subdomains", "has_ip_address",
    "has_punycode", "has_port", "uses_https", "has_suspicious_keyword",
    "suspicious_keyword_count", "has_url_shortener", "has_double_slash_redirect_pattern"
]

_INDICATORS_PATH = Path(__file__).resolve().parent.parent / "core" / "indicators.json"

@lru_cache(maxsize=1)
def _load_indicators() -> dict[str, list[str]]:
    try:
        data = json.loads(_INDICATORS_PATH.read_text(encoding="utf-8"))
        return {
            "suspicious_keywords": [str(i).casefold() for i in data.get("suspicious_keywords", [])],
            "url_shorteners": [str(i).casefold() for i in data.get("url_shorteners", [])],
            "suspicious_tlds": [str(i).casefold().lstrip(".") for i in data.get("suspicious_tlds", [])],
            "indonesian_keywords": [str(i).casefold() for i in data.get("indonesian_keywords", [])],
        }
    except (OSError, json.JSONDecodeError):
        return {
            "suspicious_keywords": [],
            "url_shorteners": [],
            "suspicious_tlds": [],
            "indonesian_keywords": []
        }

def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy (bits per char) measuring randomness / DGA characteristics."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)

def _parse_url(value: str):
    raw = value.strip()
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        raw_host = (parsed.hostname or "").rstrip(".").casefold()
        host, port = raw_host.encode("idna").decode("ascii").casefold(), parsed.port
    except (ValueError, UnicodeError):
        parsed, host, port = urlsplit(""), "", None
    return raw, parsed, host, port

def detect_homograph(hostname: str) -> dict[str, any]:
    """Detects internationalized domain spoofing / Punycode / Cyrillic confusable characters."""
    has_punycode = "xn--" in hostname.casefold()
    unicode_host = hostname
    if has_punycode:
        try:
            unicode_host = hostname.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            unicode_host = hostname

    # Check for confusable characters commonly used in phishing (Cyrillic a, c, e, o, p, s, x)
    confusables = set("\u0430\u0441\u0435\u043e\u0440\u0455\u0445\u0456\u0458\u0443")
    found_confusables = [char for char in unicode_host if char in confusables]

    is_homograph = has_punycode or len(found_confusables) > 0
    return {
        "is_homograph": is_homograph,
        "has_punycode": has_punycode,
        "unicode_representation": unicode_host,
        "confusable_chars_detected": found_confusables,
        "message": "Potential IDN homograph / punycode obfuscation detected." if is_homograph else "Standard ASCII authority."
    }

def extract_advanced_heuristics(url: str) -> dict[str, any]:
    """Computes cutting-edge explainable metrics: Entropy, Homograph, Indonesian Lexicon, and TLD Risk."""
    raw, parsed, hostname, _ = _parse_url(str(url))
    lowered = raw.casefold()
    indicators = _load_indicators()

    host_entropy = calculate_shannon_entropy(hostname)
    url_entropy = calculate_shannon_entropy(raw)
    is_dga_entropy = host_entropy > 3.85

    homograph = detect_homograph(hostname)

    # TLD Analysis
    labels = [part for part in hostname.split(".") if part]
    tld = labels[-1] if labels else ""
    is_suspicious_tld = tld in indicators["suspicious_tlds"]

    # Indonesian threat lexicon matches
    matched_id_keywords = [kw for kw in indicators["indonesian_keywords"] if kw in lowered]

    return {
        "shannon_entropy_host": host_entropy,
        "shannon_entropy_url": url_entropy,
        "is_high_entropy_dga": is_dga_entropy,
        "homograph_analysis": homograph,
        "top_level_domain": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "indonesian_keywords_detected": matched_id_keywords,
        "indonesian_threat_count": len(matched_id_keywords),
        "entropy_verdict": "High Randomness (DGA-like)" if is_dga_entropy else "Normal Linguistic Distribution"
    }

def _extract_all_features(url: str) -> dict[str, int]:
    raw, parsed, hostname, port = _parse_url(str(url))
    lowered = raw.casefold()
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = 1
    except ValueError:
        is_ip = 0
    labels = [part for part in hostname.split(".") if part]
    indicators = _load_indicators()
    keyword_count = sum(lowered.count(word) for word in indicators["suspicious_keywords"])
    shortener = int(any(hostname == domain or hostname.endswith("." + domain) for domain in indicators["url_shorteners"]))
    authority = parsed.netloc.rsplit("@", 1)[-1]
    redirect_remainder = raw[raw.find("://") + 3:] if "://" in raw else raw
    uses_https_val = int(parsed.scheme.casefold() == "https" or lowered.startswith("https://"))

    return {
        # Standard 21 features
        "url_length": len(raw),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "fragment_length": len(parsed.fragment),
        "count_dots": raw.count("."),
        "count_hyphens": raw.count("-"),
        "count_underscores": raw.count("_"),
        "count_digits": sum(char.isdigit() for char in raw),
        "count_special_characters": sum(not char.isalnum() for char in raw),
        "count_at_symbols": raw.count("@"),
        "count_percent_symbols": raw.count("%"),
        "count_subdomains": max(0, len(labels) - 2),
        "has_ip_address": is_ip,
        "has_punycode": int("xn--" in hostname or detect_homograph(hostname)["is_homograph"]),
        "has_port": int(port is not None or (":" in authority and not authority.startswith("["))),
        "uses_https": uses_https_val,
        "has_suspicious_keyword": int(keyword_count > 0),
        "suspicious_keyword_count": keyword_count,
        "has_url_shortener": shortener,
        "has_double_slash_redirect_pattern": int("//" in redirect_remainder),

        # 11-feature model compatibility aliases
        "count_dot": raw.count("."),
        "count_hyphen": raw.count("-"),
        "count_at": raw.count("@"),
        "count_question": raw.count("?"),
        "count_equal": raw.count("="),
        "count_slash": raw.count("/"),
        "has_https": uses_https_val,
        "has_ip": is_ip,
        "suspicious_words": keyword_count,

        # 15-feature integrated ML model features
        "shannon_entropy": calculate_shannon_entropy(hostname),
        "has_homograph": int("xn--" in hostname or detect_homograph(hostname)["is_homograph"]),
        "is_suspicious_tld": int((hostname.split(".")[-1] if "." in hostname else "") in indicators["suspicious_tlds"]),
        "indonesian_keywords": sum(lowered.count(kw) for kw in indicators["indonesian_keywords"]),
    }

def extract_features(url: str, feature_names: list[str] | None = None) -> dict[str, int]:
    """Extract numeric features without resolving or fetching the URL."""
    all_features = _extract_all_features(url)
    target_names = feature_names if feature_names is not None else FEATURE_NAMES
    return {name: all_features.get(name, 0) for name in target_names}

def extract_feature_vector(url: str) -> list[int]:
    return list(extract_features(url).values())
