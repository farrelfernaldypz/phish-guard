"""Safe URL Unshortener & HTTP Redirect Resolver.
Traces redirect chains (bit.ly, s.id, etc.) using HTTP HEAD requests only.
Zero response body downloading to maintain security and prevent malware egress.
"""
from __future__ import annotations
import urllib.request
import urllib.error
import urllib.parse
from typing import Any
from .feature_extraction import _load_indicators

class SafeUnshortener:
    """Safe redirect resolver that traces Location headers via HEAD requests."""

    def __init__(self, max_hops: int = 4, timeout_sec: float = 2.5) -> None:
        self.max_hops = max_hops
        self.timeout_sec = timeout_sec

    def is_known_shortener(self, url: str) -> bool:
        """Determines if the URL domain matches a known shortening service."""
        try:
            parsed = urllib.parse.urlsplit(url if "://" in url else f"//{url}")
            host = (parsed.hostname or "").casefold()
            shorteners = _load_indicators().get("url_shorteners", [])
            return any(host == s or host.endswith("." + s) for s in shorteners)
        except Exception:
            return False

    def resolve(self, initial_url: str) -> dict[str, Any]:
        """Traces the redirect chain safely using HTTP HEAD without body downloads.
        Returns trace metadata including hops, intermediate URLs, and final destination.
        """
        current_url = initial_url.strip()
        if not current_url.startswith("http://") and not current_url.startswith("https://"):
            current_url = "https://" + current_url

        chain: list[str] = [current_url]
        was_shortened = self.is_known_shortener(current_url)

        # Custom HTTP redirect handler that does NOT follow automatically
        # so we can track and record each hop safely
        for _ in range(self.max_hops):
            try:
                parsed = urllib.parse.urlsplit(current_url)
                if parsed.scheme.lower() not in ("http", "https"):
                    break

                req = urllib.request.Request(
                    current_url,
                    headers={
                        "User-Agent": "PhishGuard-SafeRedirectAudit/1.0",
                        "Accept": "*/*"
                    },
                    method="HEAD"
                )

                # Opener that disables automatic redirect following
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(NoRedirectHandler)

                try:
                    with opener.open(req, timeout=self.timeout_sec) as response:
                        # 200 OK or non-redirect status
                        if 300 <= response.status < 400:
                            next_url = response.headers.get("Location")
                            if next_url:
                                next_url = urllib.parse.urljoin(current_url, next_url)
                                if next_url != current_url and next_url not in chain:
                                    chain.append(next_url)
                                    current_url = next_url
                                    continue
                        break
                except urllib.error.HTTPError as error:
                    if 300 <= error.code < 400:
                        next_url = error.headers.get("Location")
                        if next_url:
                            next_url = urllib.parse.urljoin(current_url, next_url)
                            if next_url != current_url and next_url not in chain:
                                chain.append(next_url)
                                current_url = next_url
                                continue
                    break
            except Exception:
                # On network timeout, unreachable host, or DNS failure, fail safely
                break

        final_url = chain[-1]
        has_redirected = len(chain) > 1

        return {
            "initial_url": initial_url,
            "resolved_url": final_url,
            "is_shortened_service": was_shortened or self.is_known_shortener(final_url),
            "redirect_occurred": has_redirected,
            "hop_count": len(chain) - 1,
            "redirect_chain": chain,
        }
