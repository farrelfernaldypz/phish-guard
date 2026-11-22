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
import json
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from typing import Any
from .unshortener import SafeUnshortener

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
        host = (parsed.hostname or "").lower()
        full_path = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()
        full_text = f"{host}{full_path}"

        for entry in BRAND_KNOWLEDGE_BASE:
            # Check if domain is genuinely official
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

            # Check if keywords are abused on an unapproved domain
            matched_keywords = [kw for kw in entry["keywords"] if kw in full_text]
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

    def resolve_dns(self, hostname: str) -> dict[str, Any]:
        """Safely performs DNS resolution with strict timeout."""
        if not hostname:
            return {"status": "error", "error": "Hostname kosong", "ips": []}

        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list({info[4][0] for info in addr_info if info and info[4]})
            if not ips:
                return {"status": "unresolved", "error": "Domain tidak merespons IP DNS", "ips": []}

            primary_ip = ips[0]
            ip_obj = ipaddress.ip_address(primary_ip)
            is_private = ip_obj.is_private or ip_obj.is_loopback

            reverse_host = None
            if not is_private:
                try:
                    reverse_host = socket.gethostbyaddr(primary_ip)[0]
                except Exception:
                    reverse_host = None

            return {
                "status": "resolved",
                "primary_ip": primary_ip,
                "all_ips": ips,
                "is_private": is_private,
                "reverse_dns": reverse_host,
                "ip_version": f"IPv{ip_obj.version}"
            }
        except socket.gaierror as e:
            return {"status": "unresolved", "error": f"Domain gagal di-resolve (NXDOMAIN / DNS Error): {e}", "ips": []}
        except Exception as e:
            return {"status": "error", "error": f"Gagal mengecek DNS: {e}", "ips": []}

    def query_geoip(self, ip_address: str) -> dict[str, Any]:
        """Queries geolocation and ASN information for a public IP."""
        if not ip_address:
            return {"status": "unavailable", "message": "IP tidak tersedia"}

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
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

        # Live GeoIP Query via lightweight JSON endpoint
        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,city,isp,org,as,query"
            req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-ForensicEngine/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    return {
                        "status": "success",
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "??"),
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown ISP"),
                        "organization": data.get("org", data.get("isp", "Unknown")),
                        "asn": data.get("as", "Unknown ASN")
                    }
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

    def inspect_ssl(self, hostname: str, port: int = 443) -> dict[str, Any]:
        """Safely inspects SSL/TLS certificate metadata without downloading payload."""
        if not hostname:
            return {"has_ssl": False, "status": "No Hostname"}

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout_sec) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"has_ssl": False, "status": "Sertifikat Kosong"}

                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    not_after = cert.get("notAfter")

                    return {
                        "has_ssl": True,
                        "status": "Valid TLS Handshake",
                        "issuer_org": issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown Issuer")),
                        "common_name": subject_dict.get("commonName", hostname),
                        "expires_at": not_after
                    }
        except ssl.SSLCertVerificationError as e:
            return {"has_ssl": True, "status": f"Sertifikat Tidak Valid / Self-Signed: {e.verify_message}"}
        except Exception:
            return {"has_ssl": False, "status": "Tidak Menggunakan SSL atau Port 443 Tertutup"}

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
        ssl_info = self.inspect_ssl(dest_host) if parsed_final.scheme == "https" else {
            "has_ssl": False,
            "status": "Insecure Protocol (HTTP Polos Tanpa Enkripsi)"
        }

        # 7. Forensic Threat Diagnosis
        threat_signals = []
        if brand_info["is_impersonating"]:
            threat_signals.append(f"Pencatutan Brand: Meniru {brand_info['brand']}")
        if redirect_trace.get("redirect_occurred"):
            threat_signals.append(f"Redirect Cloaking: Disamarkan melalui {redirect_trace.get('hop_count')} lompatan URL")
        if not ssl_info.get("has_ssl"):
            threat_signals.append("Protokol Tidak Terenkripsi (HTTP / Sertifikat Bodong)")
        if geoip_info.get("country_code") not in ("ID", "??", "LOC", "N/A") and "Indonesia" in brand_info.get("category", ""):
            threat_signals.append(f"Infrastruktur Asing: Brand Indonesia di-hosting di server luar negeri ({geoip_info.get('country')})")

        threat_level = "LOW"
        if len(threat_signals) >= 3 or brand_info["is_impersonating"]:
            threat_level = "CRITICAL"
        elif len(threat_signals) >= 1 or redirect_trace.get("redirect_occurred"):
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
