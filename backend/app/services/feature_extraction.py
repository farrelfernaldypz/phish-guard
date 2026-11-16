"""Deterministic, network-free URL feature extraction shared by training and inference."""
from __future__ import annotations
import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

FEATURE_NAMES = ["url_length", "hostname_length", "path_length", "query_length", "fragment_length", "count_dots", "count_hyphens", "count_underscores", "count_digits", "count_special_characters", "count_at_symbols", "count_percent_symbols", "count_subdomains", "has_ip_address", "has_punycode", "has_port", "uses_https", "has_suspicious_keyword", "suspicious_keyword_count", "has_url_shortener", "has_double_slash_redirect_pattern"]
_INDICATORS_PATH = Path(__file__).resolve().parent.parent / "core" / "indicators.json"

@lru_cache(maxsize=1)
def _load_indicators() -> dict[str, list[str]]:
    try:
        data = json.loads(_INDICATORS_PATH.read_text(encoding="utf-8"))
        return {key: [str(item).casefold() for item in data.get(key, [])] for key in ("suspicious_keywords", "url_shorteners")}
    except (OSError, json.JSONDecodeError):
        return {"suspicious_keywords": [], "url_shorteners": []}

def _parse_url(value: str):
    raw = value.strip()
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        raw_host = (parsed.hostname or "").rstrip(".").casefold()
        host, port = raw_host.encode("idna").decode("ascii").casefold(), parsed.port
    except (ValueError, UnicodeError):
        parsed, host, port = urlsplit(""), "", None
    return raw, parsed, host, port

def extract_features(url: str) -> dict[str, int]:
    """Extract numeric features without resolving or fetching the URL."""
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
    return {
        "url_length": len(raw), "hostname_length": len(hostname), "path_length": len(parsed.path),
        "query_length": len(parsed.query), "fragment_length": len(parsed.fragment), "count_dots": raw.count("."),
        "count_hyphens": raw.count("-"), "count_underscores": raw.count("_"),
        "count_digits": sum(char.isdigit() for char in raw), "count_special_characters": sum(not char.isalnum() for char in raw),
        "count_at_symbols": raw.count("@"), "count_percent_symbols": raw.count("%"),
        "count_subdomains": max(0, len(labels) - 2), "has_ip_address": is_ip,
        "has_punycode": int("xn--" in hostname),
        "has_port": int(port is not None or (":" in authority and not authority.startswith("["))),
        "uses_https": int(parsed.scheme.casefold() == "https"),
        "has_suspicious_keyword": int(keyword_count > 0), "suspicious_keyword_count": keyword_count,
        "has_url_shortener": shortener, "has_double_slash_redirect_pattern": int("//" in redirect_remainder),
    }

def extract_feature_vector(url: str) -> list[int]:
    return list(extract_features(url).values())

