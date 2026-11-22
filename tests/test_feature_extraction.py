import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.services.feature_extraction import FEATURE_NAMES, extract_features

def test_normal_url_features():
    features = extract_features("https://example.com/path?q=one#top")
    assert features["uses_https"] == 1
    assert features["hostname_length"] == len("example.com")
    assert features["path_length"] == len("/path")
    assert features["query_length"] == len("q=one")
    assert list(features) == FEATURE_NAMES

def test_multiple_subdomains():
    assert extract_features("a.b.shop.example.com")["count_subdomains"] == 3

def test_ip_address_and_port():
    features = extract_features("http://192.0.2.1:8080/login")
    assert features["has_ip_address"] == 1
    assert features["has_port"] == 1

def test_punycode_and_special_indicators():
    features = extract_features("http://xn--e1afmkfd.example/verify%20account@")
    assert features["has_punycode"] == 1
    assert features["count_at_symbols"] == 1
    assert features["count_percent_symbols"] == 1
    assert features["has_suspicious_keyword"] == 1

def test_unicode_hostname_is_recognized_as_punycode():
    assert extract_features("https://пример.рф/login")["has_punycode"] == 1

def test_url_without_scheme_and_malformed_input_are_safe():
    assert extract_features("example.com/path")["hostname_length"] == len("example.com")
    assert len(extract_features("http://[broken")) == len(FEATURE_NAMES)

def test_shortener_match_is_host_aware():
    assert extract_features("https://bit.ly/abc")["has_url_shortener"] == 1
    assert extract_features("https://notbit.ly.example/path")["has_url_shortener"] == 0

def test_shannon_entropy_calculation():
    from backend.app.services.feature_extraction import calculate_shannon_entropy
    assert calculate_shannon_entropy("") == 0.0
    normal_entropy = calculate_shannon_entropy("google.com")
    dga_entropy = calculate_shannon_entropy("x89f2a93c7z1v4k9.xyz")
    assert dga_entropy > normal_entropy
    assert dga_entropy > 3.8

def test_homograph_and_punycode_detection():
    from backend.app.services.feature_extraction import detect_homograph
    res_normal = detect_homograph("paypal.com")
    assert res_normal["is_homograph"] is False
    res_punycode = detect_homograph("xn--pple-43d.com")
    assert res_punycode["is_homograph"] is True
    assert res_punycode["has_punycode"] is True

def test_indonesian_threat_lexicon_detection():
    from backend.app.services.feature_extraction import extract_advanced_heuristics
    res = extract_advanced_heuristics("http://dana-kaget-bansos-bri.xyz/login")
    assert res["is_suspicious_tld"] is True
    assert "bansos" in res["indonesian_keywords_detected"]
    assert "dana" in res["indonesian_keywords_detected"]
    assert res["indonesian_threat_count"] >= 3

def test_safe_unshortener_service():
    from backend.app.services.unshortener import SafeUnshortener
    unshortener = SafeUnshortener()
    assert unshortener.is_known_shortener("https://s.id/bansos") is True
    assert unshortener.is_known_shortener("https://bit.ly/promo") is True
    assert unshortener.is_known_shortener("https://github.com") is False
    res = unshortener.resolve("https://example.com/normal-path")
    assert res["resolved_url"] == "https://example.com/normal-path"
    assert res["is_shortened_service"] is False


