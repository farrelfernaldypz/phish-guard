"""PhishGuard Chat Message URL Extractor.
Extracts HTTP, HTTPS, and naked domains from forwarded chat messages in WhatsApp & Telegram.
"""
from __future__ import annotations
import re
from typing import List

URL_REGEX = re.compile(
    r'(?:https?://)?'                                 # scheme (optional)
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' # subdomains/domain
    r'[a-zA-Z]{2,24}'                                  # TLD
    r'(?::\d{1,5})?'                                   # optional port
    r'(?:/[^\s<>"\',;`\(\)\[\]]*)?',                   # path & query
    re.IGNORECASE
)

def extract_urls(text: str) -> List[str]:
    """Extract and normalize all URLs found in chat text."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    cleaned = []
    seen = set()
    for m in matches:
        m = m.strip(".,;:?!'\"()[]{}")
        # Ignore common non-domain extensions (like file extensions in regular text)
        if "." not in m:
            continue
        # Ensure scheme is present for parsing
        normalized = m if "://" in m else "https://" + m
        if normalized.lower() not in seen:
            seen.add(normalized.lower())
            cleaned.append(normalized)
    return cleaned
