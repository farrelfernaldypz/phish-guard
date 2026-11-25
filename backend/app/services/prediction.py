from __future__ import annotations
from pathlib import Path
from typing import Any
import urllib.parse
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
import joblib
import numpy as np
from ..core.config import MODEL_PATH
from .feature_extraction import (
    FEATURE_NAMES,
    extract_features,
    extract_advanced_heuristics,
    extract_v2_tabular_features,
    strip_scheme,
)
from .unshortener import SafeUnshortener

# Comprehensive registry of trusted, reputable, and official institutions
REPUTABLE_ROOT_DOMAINS = {
    # Global Tech & Services
    "google.com", "google.co.id", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "github.com", "microsoft.com", "apple.com", "linkedin.com",
    "wikipedia.org", "amazon.com", "netflix.com", "spotify.com", "stackoverflow.com",
    "medium.com", "reddit.com", "gitlab.com", "whatsapp.com", "telegram.org",
    "zoom.us", "cloudflare.com", "openai.com", "anthropic.com", "kaggle.com",

    # Major Indonesian Media & Portals
    "detik.com", "kompas.com", "tribunnews.com", "liputan6.com", "cnbcindonesia.com",
    "cnnindonesia.com", "tempo.co", "kumparan.com", "idntimes.com", "merdeka.com",
    "antaranews.com", "suara.com", "sindonews.com", "viva.co.id", "kaskus.co.id",

    # Indonesian Universities & Institutions
    "itb.ac.id", "ui.ac.id", "ugm.ac.id", "unair.ac.id", "ipb.ac.id", "undip.ac.id",
    "its.ac.id", "unpad.ac.id", "ub.ac.id", "uns.ac.id", "upi.edu", "binus.ac.id",
    "telkomuniversity.ac.id", "usu.ac.id", "unhas.ac.id", "uny.ac.id",

    # Indonesian Government & Public Services
    "kemdikbud.go.id", "kemkes.go.id", "kemenkeu.go.id", "kominfo.go.id", "pajak.go.id",
    "bssn.go.id", "polri.go.id", "setneg.go.id", "mahkamahagung.go.id", "kemendagri.go.id",
    "bpjs-kesehatan.go.id", "bpjsketenagakerjaan.go.id", "bps.go.id", "bkn.go.id",
}

# Dynamically populate with official domains from Brand Knowledge Base
try:
    from .server_investigator import BRAND_KNOWLEDGE_BASE
    for brand in BRAND_KNOWLEDGE_BASE:
        for domain in brand.get("official_domains", []):
            REPUTABLE_ROOT_DOMAINS.add(domain.lower().rstrip("."))
except Exception:
    pass

def is_reputable_domain(host: str) -> bool:
    """Determine whether host belongs to known reputable, academic, or government entities."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    # Direct match or subdomain of reputable domain
    if h in REPUTABLE_ROOT_DOMAINS:
        return True
    for rep in REPUTABLE_ROOT_DOMAINS:
        if h.endswith("." + rep):
            return True
    # Indonesian academic (.ac.id) and government (.go.id), and global (.edu, .gov)
    if h.endswith(".ac.id") or h.endswith(".go.id") or h.endswith(".edu") or h.endswith(".gov"):
        return True
    return False

def canonicalize_for_model(url: str) -> str:
    """Prepares canonical root domain to evaluate structural legitimacy under PhiUSIIL distribution."""
    parsed = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower().rstrip(".")
    labels = host.split(".")

    # Exclude raw IPv4 addresses from adding www.
    is_ip = len(labels) == 4 and all(p.isdigit() for p in labels)
    canonical_host = host
    if not is_ip and not canonical_host.startswith("www."):
        if len(labels) == 2 or (len(labels) == 3 and labels[-2] in ("co", "ac", "go", "or", "sch", "net", "web")):
            canonical_host = f"www.{canonical_host}"

    new_netloc = canonical_host + (f":{parsed.port}" if parsed.port else "")
    # Evaluate pure root domain without path bias
    return urllib.parse.urlunsplit(("https", new_netloc, "", "", ""))

class ModelNotReadyError(RuntimeError):
    pass

class PredictionService:
    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model_path = model_path
        self.bundle: dict[str, Any] | None = None
        self.load_error: str | None = None
        self.unshortener = SafeUnshortener()
        self.reload()

    def reload(self) -> None:
        self.bundle, self.load_error = None, None
        target_path = self.model_path
        if not target_path.is_file():
            candidates = [
                target_path,
                target_path.parent / "model_phishing_v2.pkl",
                target_path.parent / "phishguard_model.joblib",
                target_path.parent / "model_phishing.pkl",
                target_path.parent / "model_phishing.joblib",
            ]
            found = next((p for p in candidates if p.is_file()), None)
            if not found:
                self.load_error = "Trained model artifact is not available."
                return
            target_path = found

        try:
            loaded = joblib.load(target_path)
            if isinstance(loaded, dict) and {"model", "feature_names"}.issubset(loaded):
                threshold = float(loaded.get("threshold", 0.5))
                algorithm = loaded.get("algorithm", type(loaded["model"]).__name__)
                self.bundle = {
                    "model": loaded["model"],
                    "feature_names": list(loaded["feature_names"]),
                    "threshold": threshold,
                    "algorithm": algorithm,
                    "metadata": loaded.get("metadata", {}),
                    "tfidf_vectorizer": loaded.get("tfidf_vectorizer"),
                    "tfidf_classifier": loaded.get("tfidf_classifier"),
                }
            elif hasattr(loaded, "predict_proba"):
                feature_names = getattr(loaded, "feature_names_in_", None)
                if feature_names is not None:
                    feature_names = list(feature_names)
                else:
                    feature_names = list(FEATURE_NAMES)
                self.bundle = {
                    "model": loaded,
                    "feature_names": feature_names,
                    "threshold": 0.5,
                    "algorithm": type(loaded).__name__,
                    "metadata": {"type": "raw_classifier", "source_file": target_path.name},
                    "tfidf_vectorizer": None,
                    "tfidf_classifier": None,
                }
            else:
                raise ValueError("Invalid model bundle format.")
        except Exception as error:
            self.load_error = f"Model artifact could not be loaded: {type(error).__name__}."

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    def model_info(self) -> dict[str, Any]:
        if not self.bundle:
            return {"status": "not_ready", "model_name": None, "feature_names": FEATURE_NAMES, "metadata": None, "message": self.load_error}
        return {"status": "ready", "model_name": self.bundle.get("algorithm"), "feature_names": self.bundle["feature_names"], "threshold": float(self.bundle["threshold"]), "metadata": self.bundle.get("metadata", {}), "message": None}

    def predict(self, url: str, resolve_redirects: bool = True) -> dict[str, Any]:
        if not self.bundle:
            raise RuntimeError(self.load_error or "Model is unavailable.")

        # Safe Unshortener: resolve redirect hops if the URL is a shortener
        trace = {
            "initial_url": url,
            "resolved_url": url,
            "is_shortened_service": self.unshortener.is_known_shortener(url),
            "redirect_occurred": False,
            "hop_count": 0,
            "redirect_chain": [url]
        }
        target_url = url

        # Resolve redirect hops if needed (shorteners or root redirect)
        if resolve_redirects:
            try:
                resolved_trace = self.unshortener.resolve(url)
                if resolved_trace.get("redirect_occurred"):
                    trace = resolved_trace
                    target_url = resolved_trace["resolved_url"]
            except Exception:
                pass

        parsed = urllib.parse.urlsplit(target_url if "://" in target_url else "https://" + target_url)
        raw_scheme = parsed.scheme.lower() or "https"
        raw_host = (parsed.hostname or "").lower().rstrip(".")

        # 1. Extract accurate features for target URL
        is_v2_bundle = (
            self.bundle.get("tfidf_vectorizer") is not None
            and self.bundle.get("tfidf_classifier") is not None
        )
        canonical_url = canonicalize_for_model(target_url)

        if is_v2_bundle:
            tfidf_vec = self.bundle["tfidf_vectorizer"]
            tfidf_clf = self.bundle["tfidf_classifier"]
            tf_pos_idx = list(tfidf_clf.classes_).index(1)

            raw_v2 = extract_v2_tabular_features(target_url)
            raw_v2["tfidf_char_prob"] = round(
                float(tfidf_clf.predict_proba(tfidf_vec.transform([strip_scheme(target_url)]))[0][tf_pos_idx]),
                4,
            )
            feature_map = {name: raw_v2.get(name, 0) for name in self.bundle["feature_names"]}

            dom_v2 = extract_v2_tabular_features(canonical_url)
            dom_v2["tfidf_char_prob"] = round(
                float(tfidf_clf.predict_proba(tfidf_vec.transform([strip_scheme(canonical_url)]))[0][tf_pos_idx]),
                4,
            )
            domain_feature_map = {name: dom_v2.get(name, 0) for name in self.bundle["feature_names"]}
        else:
            feature_map = extract_features(target_url, self.bundle["feature_names"])
            domain_feature_map = extract_features(canonical_url, self.bundle["feature_names"])

        advanced_heuristics = extract_advanced_heuristics(target_url)

        import pandas as pd
        model = self.bundle["model"]
        positive_index = list(model.classes_).index(1)
        threshold = float(self.bundle["threshold"])

        # Base domain score
        vec_domain = pd.DataFrame([[domain_feature_map[name] for name in self.bundle["feature_names"]]], columns=self.bundle["feature_names"])
        base_domain_score = float(model.predict_proba(vec_domain)[0][positive_index])

        # Full URL raw score
        vec_full = pd.DataFrame([[feature_map[name] for name in self.bundle["feature_names"]]], columns=self.bundle["feature_names"])
        raw_full_score = float(model.predict_proba(vec_full)[0][positive_index])

        # 3. Brand intelligence & official domain verification
        is_official_brand = False
        is_impersonating = False
        try:
            from .server_investigator import ServerInvestigator
            brand_intel = ServerInvestigator().identify_brand(target_url)
            is_official_brand = bool(brand_intel.get("is_official"))
            is_impersonating = bool(brand_intel.get("is_impersonating"))
        except Exception:
            pass

        # 4. Check if domain is reputable or academic/government
        reputable = is_official_brand or is_reputable_domain(raw_host)

        # 5. Detect explicit malicious threat signals
        has_phishing_threat = (
            feature_map.get("suspicious_words", 0) > 0 or
            feature_map.get("indonesian_keywords", 0) > 0 or
            feature_map.get("count_at", 0) > 0 or
            feature_map.get("has_ip", 0) > 0 or
            feature_map.get("has_ip_address", 0) > 0 or
            feature_map.get("typosquat_similarity", 0) >= 0.80 or
            is_impersonating or
            advanced_heuristics.get("is_suspicious_tld", False) or
            advanced_heuristics.get("is_high_entropy_dga", False) or
            advanced_heuristics.get("homograph_analysis", {}).get("is_homograph", False)
        )

        # 6. Post-Processing Calibration & Domain-Decomposed Scoring:
        # Prevents dataset collection artifact where http or paths cause 100% false positive.
        if is_impersonating:
            # Domain is actively spoofing a known brand (e.g. bca-klik.com)
            score = 1.0000
        elif reputable:
            if has_phishing_threat:
                # Reputable site with suspicious tokens (e.g. github.com/user/login-form)
                score = min(0.35, 0.10 + feature_map.get("suspicious_words", 0) * 0.05)
            else:
                score = 0.01 if raw_scheme == "https" else 0.05
        else:
            # Unknown / general web domain
            if base_domain_score >= threshold:
                # The domain structure itself resembles known phishing patterns
                score = max(base_domain_score, raw_full_score)
            else:
                # Domain structure is clean
                if has_phishing_threat:
                    # Explicit credential or phishing tokens present in path/query/heuristics
                    score = max(0.70, raw_full_score)
                else:
                    # Benign unknown domain with standard path
                    score = base_domain_score
                    if raw_scheme == "http":
                        # Insecure unencrypted transport penalty (remains below phishing threshold)
                        score = min(0.35, score + 0.10)

        # Bound score between 0.0 and 1.0
        score = round(float(max(0.0, min(1.0, score))), 4)
        is_phishing = score >= threshold

        # 7. Collect relevant trigger indicators
        relevant = []
        if is_impersonating:
            relevant.append("brand_impersonation_spoofing")
        if feature_map.get("typosquat_similarity", 0) >= 0.75 and not is_official_brand:
            relevant.append("typosquatting_brand_similarity")
        if feature_map.get("has_ip") or feature_map.get("has_ip_address"):
            relevant.append("has_ip_address")
        if feature_map.get("has_punycode"):
            relevant.append("has_punycode")
        if feature_map.get("has_port"):
            relevant.append("has_port")
        if feature_map.get("suspicious_words", 0) > 0:
            relevant.append("suspicious_keywords")
        if feature_map.get("has_url_shortener"):
            relevant.append("has_url_shortener")
        if advanced_heuristics.get("is_high_entropy_dga"):
            relevant.append("high_entropy_dga")
        if advanced_heuristics.get("homograph_analysis", {}).get("is_homograph"):
            relevant.append("homograph_obfuscation")
        if advanced_heuristics.get("is_suspicious_tld"):
            relevant.append("suspicious_tld")
        if advanced_heuristics.get("indonesian_threat_count", 0) > 0:
            relevant.append("indonesian_phishing_tokens")
        if trace.get("redirect_occurred"):
            relevant.append("shortener_redirect_cloaking")
        if raw_scheme == "http":
            relevant.append("unencrypted_http_transport")

        return {
            "url": url,
            "resolved_url": target_url,
            "prediction": int(is_phishing),
            "label": "Phishing" if is_phishing else "Legitimate",
            "model_score": score,
            "threshold": threshold,
            "features": feature_map,
            "advanced_heuristics": advanced_heuristics,
            "redirect_trace": trace,
            "relevant_indicators": relevant,
            "model_name": self.bundle.get("algorithm")
        }
