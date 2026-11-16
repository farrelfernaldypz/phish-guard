"""Input normalization and validation. This module never makes network requests."""
from __future__ import annotations
import ipaddress
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
class URLValidationError(ValueError):
    pass

def normalize_url(value: str) -> str:
    if not isinstance(value, str):
        raise URLValidationError("URL must be text.")
    raw = value.strip()
    if not raw:
        raise URLValidationError("Enter a URL to scan.")
    if len(raw) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL must be {MAX_URL_LENGTH} characters or fewer.")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise URLValidationError("URL contains unsupported control characters.")
    try:
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        port = parsed.port
    except ValueError as error:
        raise URLValidationError("URL format is invalid.") from error
    if parsed.scheme.casefold() not in {"http", "https"}:
        raise URLValidationError("Only HTTP and HTTPS URLs are supported.")
    host = parsed.hostname
    if not host or any(char.isspace() for char in host):
        raise URLValidationError("Enter a URL with a valid hostname.")
    if port is not None and not 1 <= port <= 65535:
        raise URLValidationError("Port must be between 1 and 65535.")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise URLValidationError("Hostname is invalid.") from error
    try:
        ipaddress.ip_address(ascii_host.strip("[]"))
    except ValueError:
        labels = ascii_host.rstrip(".").split(".")
        if len(ascii_host) > 253 or any(not item or len(item) > 63 for item in labels):
            raise URLValidationError("Hostname is invalid.")
    if ":" in ascii_host and not ascii_host.startswith("["):
        ascii_host = f"[{ascii_host}]"
    netloc = ascii_host + (f":{port}" if port is not None else "")
    return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path, parsed.query, parsed.fragment))

