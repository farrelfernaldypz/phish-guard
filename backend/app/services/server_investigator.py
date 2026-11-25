"""PhishGuard Deep Server & Infrastructure Forensic Investigator.
Performs safe, non-rendering network and OSINT profiling:
- Safe DNS Resolution & Reverse DNS
- Server Geolocation & ASN/ISP Identification
- Multi-Hop HTTP Redirect Chain Tracing (without downloading payloads)
- Brand Impersonation & Target Institution Identification
- SSL/TLS Certificate Analysis
"""
from __future__ import annotations
import socket
import ssl
import ipaddress
import urllib.parse
from typing import Any
import httpx
from .unshortener import SafeUnshortener

_SYNTHETIC_IP_NETS = (
    ipaddress.ip_network("198.18.0.0/15"),  # RFC 2544 / Fake-IP proxy range
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT / shared address space
)
_DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)


def _is_non_public_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check whether an IP is private, loopback, reserved, or synthetic proxy Fake-IP."""
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or any(ip_obj in net for net in _SYNTHETIC_IP_NETS)
    )


def _extract_ssl_cert_error(err: BaseException) -> ssl.SSLCertVerificationError | None:
    """Walk exception chain to detect wrapped SSLCertVerificationError from httpx/httpcore."""
    cur: BaseException | None = err
    seen: set[int] = set()
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ssl.SSLCertVerificationError):
            return cur
        cur = cur.__cause__ or cur.__context__
    return None


def _format_cert_result(cert: dict[str, Any], hostname: str) -> dict[str, Any]:
    """Normalize peer TLS certificate metadata into a uniform dictionary."""
    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    subject_dict = dict(x[0] for x in cert.get("subject", []))
    return {
        "has_ssl": True,
        "cert_valid": True,
        "probe_status": "ok",
        "status": "Valid TLS Handshake",
        "issuer_org": issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown Issuer")),
        "common_name": subject_dict.get("commonName", hostname),
        "expires_at": cert.get("notAfter"),
    }

BRAND_KNOWLEDGE_BASE = [
    {
        "id": "bca",
        "name": "PT Bank Central Asia Tbk (BCA)",
        "category": "Perbankan Indonesia",
        "official_domains": ["bca.co.id", "klikbca.com", "mybca.bca.co.id"],
        "keywords": ["bca", "klikbca", "mybca", "halobca", "halo-bca", "tariktunaibca"]
    },
    {
        "id": "mandiri",
        "name": "PT Bank Mandiri (Persero) Tbk",
        "category": "Perbankan Indonesia",
        "official_domains": ["bankmandiri.co.id", "livinbymandiri.id", "mandirikartukredit.com"],
        "keywords": ["mandiri", "livin", "livinbymandiri", "kopra"]
    },
    {
        "id": "bri",
        "name": "PT Bank Rakyat Indonesia (Persero) Tbk (BRI)",
        "category": "Perbankan Indonesia",
        "official_domains": ["bri.co.id", "brimo.bri.co.id", "ib.bri.co.id"],
        "keywords": ["bri", "brimo", "bankbri", "ib-bri"]
    },
    {
        "id": "bni",
        "name": "PT Bank Negara Indonesia (Persero) Tbk (BNI)",
        "category": "Perbankan Indonesia",
        "official_domains": ["bni.co.id", "bniexperience.bni.co.id"],
        "keywords": ["bni", "wondr", "bni-mobile", "ibank-bni"]
    },
    {
        "id": "dana",
        "name": "DANA Dompet Digital Indonesia",
        "category": "Dompet Digital (E-Wallet)",
        "official_domains": ["dana.id", "link.dana.id"],
        "keywords": ["dana", "dana-id", "danaindonesia", "dana-kaget", "danakaget"]
    },
    {
        "id": "gopay",
        "name": "GoPay & Gojek Indonesia",
        "category": "Dompet Digital & On-Demand",
        "official_domains": ["gopay.co.id", "gojek.com"],
        "keywords": ["gopay", "go-pay", "gojek", "gopayplus"]
    },
    {
        "id": "ovo",
        "name": "OVO (PT Visionet Internasional)",
        "category": "Dompet Digital (E-Wallet)",
        "official_domains": ["ovo.id"],
        "keywords": ["ovo", "ovo-id", "ovopoint"]
    },
    {
        "id": "shopee",
        "name": "Shopee & ShopeePay Indonesia",
        "category": "E-Commerce & FinTech",
        "official_domains": ["shopee.co.id", "shopeepay.co.id"],
        "keywords": ["shopee", "shopeepay", "spaylater", "shopee-pay"]
    },
    {
        "id": "tokopedia",
        "name": "Tokopedia Indonesia",
        "category": "E-Commerce",
        "official_domains": ["tokopedia.com", "tokopedia.link"],
        "keywords": ["tokopedia", "tokped"]
    },
    {
        "id": "paypal",
        "name": "PayPal Inc.",
        "category": "Pembayaran Digital Global",
        "official_domains": ["paypal.com", "paypal.me"],
        "keywords": ["paypal", "paypal-service", "paypal-verify"]
    },
    {
        "id": "google",
        "name": "Google / Gmail / Google Cloud",
        "category": "Teknologi & Cloud Service",
        "official_domains": ["google.com", "accounts.google.com", "gmail.com"],
        "keywords": ["google", "gmail", "gdrive", "google-security", "google-login"]
    },
    {
        "id": "microsoft",
        "name": "Microsoft / Office 365 / Outlook",
        "category": "Teknologi & Produktivitas",
        "official_domains": ["microsoft.com", "login.microsoftonline.com", "live.com", "office.com"],
        "keywords": ["microsoft", "office365", "outlook", "onedrive", "msft"]
    },
    {
        "id": "apple",
        "name": "Apple Inc. (Apple ID & iCloud)",
        "category": "Ekosistem Teknologi",
        "official_domains": ["apple.com", "icloud.com"],
        "keywords": ["apple", "icloud", "appleid", "find-my-iphone"]
    },
    {
        "id": "netflix",
        "name": "Netflix Inc.",
        "category": "Streaming Video",
        "official_domains": ["netflix.com"],
        "keywords": ["netflix", "netflix-verify", "netflix-billing"]
    },
    {
        "id": "whatsapp",
        "name": "WhatsApp / Meta Platforms",
        "category": "Komunikasi & Pesan",
        "official_domains": ["whatsapp.com", "web.whatsapp.com", "wa.me"],
        "keywords": ["whatsapp", "wa.me", "wa-web", "whatsapp-verification"]
    },
    {
        "id": "telegram",
        "name": "Telegram Messenger",
        "category": "Komunikasi & Pesan",
        "official_domains": ["telegram.org", "t.me"],
        "keywords": ["telegram", "telegram-login", "t.me-secure"]
    },
    {
        "id": "kemensos_pajak",
        "name": "Lembaga Pemerintah (Kemensos / DJP Pajak / BPJS)",
        "category": "Layanan Publik Republik Indonesia",
        "official_domains": ["kemensos.go.id", "pajak.go.id", "bpjs-kesehatan.go.id", "prakerja.go.id"],
        "keywords": ["kemensos", "bansos", "ditjenpajak", "pajak-online", "bpjs-kesehatan", "prakerja"]
    }
]

class ServerInvestigator:
    def __init__(self, timeout_sec: float = 2.5) -> None:
        self.timeout_sec = timeout_sec
        self.unshortener = SafeUnshortener(max_hops=4, timeout_sec=timeout_sec)

    def identify_brand(self, url: str) -> dict[str, Any]:
        """Detects if the URL mimics a recognized enterprise brand."""
        parsed = urllib.parse.urlsplit(url if "://" in url else f"//{url}")
        host = (parsed.hostname or "").lower().rstrip(".")
        path_only = (parsed.path or "").lower()
        target_text = f"{host}{path_only}"

        # Check official domains across all brands before matching keywords
        for entry in BRAND_KNOWLEDGE_BASE:
            is_official = any(host == d or host.endswith("." + d) for d in entry["official_domains"])
            if is_official:
                return {
                    "is_impersonating": False,
                    "is_official": True,
                    "brand": entry["name"],
                    "category": entry["category"],
                    "official_domains": entry["official_domains"],
                    "status": "Terverifikasi Sebagai Domain Resmi",
                    "threat_note": None
                }

        for entry in BRAND_KNOWLEDGE_BASE:
            matched_keywords = [kw for kw in entry["keywords"] if kw in target_text]
            if matched_keywords:
                return {
                    "is_impersonating": True,
                    "is_official": False,
                    "brand": entry["name"],
                    "category": entry["category"],
                    "official_domains": entry["official_domains"],
                    "status": f"Indikasi Penipuan / Pemalsuan Brand ({entry['name']})",
                    "matched_keywords": matched_keywords,
                    "threat_note": f"Domain '{host}' bukan domain resmi milik {entry['name']}, tetapi menggunakan kata kunci pengenal merek untuk memperdaya calon korban."
                }

        return {
            "is_impersonating": False,
            "is_official": False,
            "brand": None,
            "category": "Domain Umum / Tidak Terdaftar dalam Brand Target",
            "official_domains": [],
            "status": "Tidak Ditemukan Indikasi Pencatutan Brand Tertentu",
            "threat_note": None
        }

    def _resolve_doh(self, hostname: str) -> list[str]:
        """Resolve public A/AAAA records via DNS over HTTPS (Cloudflare / Google)."""
        headers = {"Accept": "application/dns-json", "User-Agent": "PhishGuard-ForensicEngine/2.0"}
        try:
            with httpx.Client(timeout=self.timeout_sec) as client:
                for endpoint in _DOH_ENDPOINTS:
                    ips: list[str] = []
                    for rtype in ("A", "AAAA"):
                        try:
                            resp = client.get(endpoint, params={"name": hostname, "type": rtype}, headers=headers)
                            if resp.status_code != 200:
                                continue
                            data = resp.json()
                            if data.get("Status") != 0:
                                continue
                            for ans in data.get("Answer", []):
                                if ans.get("type") not in (1, 28):
                                    continue
                                candidate = str(ans.get("data", "")).strip()
                                try:
                                    ip_obj = ipaddress.ip_address(candidate)
                                    if not _is_non_public_ip(ip_obj) and candidate not in ips:
                                        ips.append(candidate)
                                except ValueError:
                                    continue
                        except Exception:
                            continue
                        if ips and rtype == "A":
                            break
                    if ips:
                        return ips
        except Exception:
            pass
        return []

    def _resolve_ptr_doh(self, ip_str: str) -> str | None:
        """Resolve reverse DNS PTR record via DoH when raw PTR sockets are restricted."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ptr_name = ip_obj.reverse_pointer
            headers = {"Accept": "application/dns-json", "User-Agent": "PhishGuard-ForensicEngine/2.0"}
            with httpx.Client(timeout=self.timeout_sec) as client:
                for endpoint in _DOH_ENDPOINTS:
                    try:
                        resp = client.get(endpoint, params={"name": ptr_name, "type": "PTR"}, headers=headers)
                        if resp.status_code != 200:
                            continue
                        for ans in resp.json().get("Answer", []):
                            if ans.get("type") == 12:
                                return str(ans.get("data", "")).rstrip(".") or None
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    def resolve_dns(self, hostname: str) -> dict[str, Any]:
        """Safely resolve DNS via system DNS with automatic DoH fallback for Fake-IP / restricted hosts."""
        if not hostname:
            return {"status": "error", "error": "Hostname kosong", "ips": []}

        clean_host = hostname.strip().strip("[]").rstrip(".")
        # Handle literal IP hostnames directly
        try:
            lit_ip = ipaddress.ip_address(clean_host)
            is_priv = _is_non_public_ip(lit_ip)
            return {
                "status": "resolved",
                "primary_ip": str(lit_ip),
                "all_ips": [str(lit_ip)],
                "is_private": is_priv,
                "reverse_dns": None,
                "ip_version": f"IPv{lit_ip.version}",
                "dns_source": "literal",
            }
        except ValueError:
            pass

        is_localhost = clean_host.lower() in ("localhost", "localhost.localdomain")
        ips: list[str] = []
        dns_source = "system"
        sys_err: str | None = None

        try:
            addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(dict.fromkeys(info[4][0] for info in addr_info if info and info[4]))
        except socket.gaierror as e:
            sys_err = str(e)
        except Exception as e:
            sys_err = str(e)

        # If system DNS failed or returned synthetic/Fake-IP (e.g. 198.18.x.x), resolve via DoH
        all_non_public = bool(ips) and all(_is_non_public_ip(ipaddress.ip_address(ip)) for ip in ips)
        if not is_localhost and (not ips or all_non_public):
            doh_ips = self._resolve_doh(clean_host)
            if doh_ips:
                ips = doh_ips
                dns_source = "doh"

        if not ips:
            return {
                "status": "unresolved",
                "error": f"Domain gagal di-resolve (NXDOMAIN / DNS Error): {sys_err or 'No records'}",
                "ips": [],
            }

        primary_ip = ips[0]
        ip_obj = ipaddress.ip_address(primary_ip)
        is_private = _is_non_public_ip(ip_obj)

        reverse_host = None
        if not is_private:
            if dns_source == "system":
                try:
                    reverse_host = socket.gethostbyaddr(primary_ip)[0]
                except Exception:
                    reverse_host = self._resolve_ptr_doh(primary_ip)
            else:
                reverse_host = self._resolve_ptr_doh(primary_ip)

        return {
            "status": "resolved",
            "primary_ip": primary_ip,
            "all_ips": ips,
            "is_private": is_private,
            "reverse_dns": reverse_host,
            "ip_version": f"IPv{ip_obj.version}",
            "dns_source": dns_source,
        }

    def query_geoip(self, ip_address: str) -> dict[str, Any]:
        """Queries geolocation and ASN information for a public IP via proxy-aware HTTPS."""
        if not ip_address:
            return {"status": "unavailable", "message": "IP tidak tersedia"}

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if _is_non_public_ip(ip_obj):
                return {
                    "status": "private_network",
                    "country": "Localhost / Jaringan Privat",
                    "country_code": "LOC",
                    "city": "Internal / RFC1918",
                    "isp": "Private Network Intranet",
                    "organization": "Local Loopback",
                    "asn": "Private ASN"
                }
        except ValueError:
            return {"status": "invalid_ip"}

        headers = {"User-Agent": "PhishGuard-ForensicEngine/2.0"}
        try:
            with httpx.Client(timeout=self.timeout_sec) as client:
                # Primary: HTTPS endpoint (works through HTTPS_PROXY)
                try:
                    resp = client.get(f"https://ipwho.is/{ip_address}", headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("success") is True:
                            conn = data.get("connection") or {}
                            asn_num = conn.get("asn")
                            org_name = conn.get("org") or conn.get("isp") or "Unknown"
                            return {
                                "status": "success",
                                "country": data.get("country", "Unknown"),
                                "country_code": data.get("country_code", "??"),
                                "city": data.get("city", "Unknown"),
                                "isp": conn.get("isp") or org_name,
                                "organization": org_name,
                                "asn": f"AS{asn_num} {org_name}".strip() if asn_num else org_name,
                            }
                except Exception:
                    pass

                # Fallback: ip-api JSON via httpx
                try:
                    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,city,isp,org,as,query"
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("status") == "success":
                            return {
                                "status": "success",
                                "country": data.get("country", "Unknown"),
                                "country_code": data.get("countryCode", "??"),
                                "city": data.get("city", "Unknown"),
                                "isp": data.get("isp", "Unknown ISP"),
                                "organization": data.get("org", data.get("isp", "Unknown")),
                                "asn": data.get("as", "Unknown ASN"),
                            }
                except Exception:
                    pass
        except Exception:
            pass

        return {
            "status": "fallback",
            "country": "Tidak Terdeteksi (Air-Gapped / Jaringan Terbatas)",
            "country_code": "N/A",
            "city": "Unknown",
            "isp": "Penyedia Jaringan Tidak Ditemukan",
            "organization": "Unknown Organization",
            "asn": "N/A"
        }

    def inspect_ssl(self, hostname: str, port: int = 443, is_private_ip: bool = False) -> dict[str, Any]:
        """Safely inspect TLS certificate via proxy-aware httpx stream, with direct socket fallback."""
        if not hostname:
            return {"has_ssl": False, "cert_valid": False, "probe_status": "invalid", "status": "No Hostname"}
        if is_private_ip:
            return {
                "has_ssl": None,
                "cert_valid": None,
                "probe_status": "private_or_fake_ip",
                "status": "Probe TLS Dilewati (DNS Mengarah ke IP Privat / Fake-IP Proxy)"
            }

        target_https = f"https://{hostname}" if port == 443 else f"https://{hostname}:{port}"
        try:
            with httpx.Client(timeout=self.timeout_sec, follow_redirects=False) as client:
                with client.stream("HEAD", target_https, headers={"User-Agent": "PhishGuard-TLSProbe/2.0"}) as resp:
                    stream = resp.extensions.get("network_stream")
                    ssl_obj = stream.get_extra_info("ssl_object") if stream else None
                    cert = ssl_obj.getpeercert() if ssl_obj else None
                    if cert:
                        return _format_cert_result(cert, hostname)
        except Exception as err:
            cert_err = _extract_ssl_cert_error(err)
            if cert_err is not None:
                return {
                    "has_ssl": True,
                    "cert_valid": False,
                    "probe_status": "invalid_cert",
                    "status": f"Sertifikat Tidak Valid / Self-Signed: {cert_err.verify_message}"
                }

        # Fallback: direct socket TLS probe (for non-HTTP TLS services or direct hosts)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout_sec) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"has_ssl": False, "cert_valid": False, "probe_status": "empty_cert", "status": "Sertifikat Kosong"}
                    return _format_cert_result(cert, hostname)
        except ssl.SSLCertVerificationError as e:
            return {
                "has_ssl": True,
                "cert_valid": False,
                "probe_status": "invalid_cert",
                "status": f"Sertifikat Tidak Valid / Self-Signed: {e.verify_message}"
            }
        except Exception:
            return {
                "has_ssl": None,
                "cert_valid": None,
                "probe_status": "unreachable",
                "status": "Port 443 Tidak Terjangkau / Dibatasi Firewall Server"
            }

    def investigate(self, url: str) -> dict[str, Any]:
        """Executes full deep forensic investigation."""
        target_url = url.strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url

        # 1. Trace Redirect Hops
        redirect_trace = self.unshortener.resolve(target_url)
        final_destination = redirect_trace.get("resolved_url", target_url)

        # 2. Extract Destination Host
        parsed_final = urllib.parse.urlsplit(final_destination)
        dest_host = parsed_final.hostname or ""

        # 3. DNS & Reverse DNS
        dns_info = self.resolve_dns(dest_host)
        primary_ip = dns_info.get("primary_ip")

        # 4. Geo-IP and Hosting ASN
        geoip_info = self.query_geoip(primary_ip) if primary_ip else self.query_geoip("")

        # 5. Brand Impersonation Intelligence
        brand_info = self.identify_brand(final_destination)
        if not brand_info["is_impersonating"]:
            # Also check initial URL if redirected
            initial_brand = self.identify_brand(target_url)
            if initial_brand["is_impersonating"]:
                brand_info = initial_brand

        # 6. SSL Handshake Probe (if HTTPS)
        ssl_info = self.inspect_ssl(dest_host, is_private_ip=bool(dns_info.get("is_private"))) if parsed_final.scheme == "https" else {
            "has_ssl": False,
            "cert_valid": False,
            "probe_status": "http_plaintext",
            "status": "Insecure Protocol (HTTP Polos Tanpa Enkripsi)"
        }

        # 7. Forensic Threat Diagnosis
        init_host = (urllib.parse.urlsplit(target_url).hostname or "").lower().removeprefix("www.")
        final_host_base = dest_host.lower().removeprefix("www.")
        is_suspicious_redirect = bool(redirect_trace.get("redirect_occurred")) and (
            bool(redirect_trace.get("is_shortened_service")) or (init_host != final_host_base)
        )

        threat_signals = []
        if brand_info["is_impersonating"]:
            threat_signals.append(f"Pencatutan Brand: Meniru {brand_info['brand']}")
        if is_suspicious_redirect:
            threat_signals.append(f"Redirect Cloaking: Disamarkan melalui {redirect_trace.get('hop_count')} lompatan URL")
        if ssl_info.get("has_ssl") is False:
            threat_signals.append("Protokol Tidak Terenkripsi (HTTP Polos)")
        elif ssl_info.get("cert_valid") is False:
            threat_signals.append("Sertifikat SSL/TLS Tidak Valid / Self-Signed")
        if geoip_info.get("country_code") not in ("ID", "??", "LOC", "N/A") and "Indonesia" in brand_info.get("category", ""):
            threat_signals.append(f"Infrastruktur Asing: Brand Indonesia di-hosting di server luar negeri ({geoip_info.get('country')})")

        threat_level = "LOW"
        if len(threat_signals) >= 3 or brand_info["is_impersonating"]:
            threat_level = "CRITICAL"
        elif len(threat_signals) >= 1 or is_suspicious_redirect:
            threat_level = "ELEVATED"

        return {
            "initial_url": url,
            "final_destination": final_destination,
            "destination_host": dest_host,
            "dns": dns_info,
            "geoip": geoip_info,
            "brand_intelligence": brand_info,
            "redirect_trace": redirect_trace,
            "ssl_intelligence": ssl_info,
            "threat_level": threat_level,
            "threat_signals": threat_signals
        }
