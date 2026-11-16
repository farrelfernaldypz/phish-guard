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

