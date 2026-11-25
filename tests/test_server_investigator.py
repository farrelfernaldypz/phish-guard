from backend.app.services.server_investigator import ServerInvestigator

def test_identify_brand_impersonation():
    investigator = ServerInvestigator()
    
    # 1. Fake BCA domain
    res = investigator.identify_brand("http://bca-klik-login-secure.xyz")
    assert res["is_impersonating"] is True
    assert res["is_official"] is False
    assert "BCA" in res["brand"]

    # 2. Legitimate BCA domain
    res_legit = investigator.identify_brand("https://www.klikbca.com")
    assert res_legit["is_impersonating"] is False
    assert res_legit["is_official"] is True

    # 3. Random neutral domain
    res_neutral = investigator.identify_brand("https://example.com")
    assert res_neutral["is_impersonating"] is False
    assert res_neutral["is_official"] is False

    # 4. Official brand querying another brand or UTM tracking param in query must not trigger false spoofing
    res_google_q = investigator.identify_brand("https://www.google.com/search?q=bca")
    assert res_google_q["is_impersonating"] is False
    assert res_google_q["is_official"] is True

    res_utm = investigator.identify_brand("https://www.liputan6.com/tekno/read/5812345/tips?utm_source=whatsapp")
    assert res_utm["is_impersonating"] is False

def test_dns_and_geoip_safe_fallback():
    investigator = ServerInvestigator()
    # Test private IP handling
    geo = investigator.query_geoip("127.0.0.1")
    assert geo["status"] == "private_network"
    assert "Localhost" in geo["country"]

    # Fake-IP / proxy DNS (198.18.0.0/15) must skip TLS probe cleanly without flagging HTTP
    ssl_res = investigator.inspect_ssl("google.com", is_private_ip=True)
    assert ssl_res["has_ssl"] is None
    assert ssl_res["probe_status"] == "private_or_fake_ip"


def test_doh_fallback_when_system_dns_returns_synthetic_fake_ip(monkeypatch):
    import socket
    from backend.app.services import server_investigator as si_mod

    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.7.108", 0))]

    monkeypatch.setattr(si_mod.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(ServerInvestigator, "_resolve_doh", lambda self, host: ["142.251.10.102"])
    monkeypatch.setattr(ServerInvestigator, "_resolve_ptr_doh", lambda self, ip: "lga34s34-in-f14.1e100.net")

    res = ServerInvestigator().resolve_dns("google.com")
    assert res["status"] == "resolved"
    assert res["primary_ip"] == "142.251.10.102"
    assert res["is_private"] is False
    assert res["dns_source"] == "doh"
    assert res["reverse_dns"] == "lga34s34-in-f14.1e100.net"


def test_inspect_ssl_via_httpx_proxy_when_direct_socket_blocked(monkeypatch):
    import socket
    from backend.app.services import server_investigator as si_mod

    def blocked_socket(*args, **kwargs):
        raise OSError("Direct TCP 443 blocked")

    class FakeSslObj:
        def getpeercert(self):
            return {
                "issuer": ((("organizationName", "Google Trust Services"),),),
                "subject": ((("commonName", "*.google.com"),),),
                "notAfter": "Jan 26 08:26:49 2027 GMT",
            }

    class FakeStream:
        def get_extra_info(self, key):
            return FakeSslObj() if key == "ssl_object" else None

    class FakeResp:
        extensions = {"network_stream": FakeStream()}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def stream(self, *args, **kwargs):
            return FakeResp()

    monkeypatch.setattr(si_mod.socket, "create_connection", blocked_socket)
    monkeypatch.setattr(si_mod.httpx, "Client", FakeClient)

    res = ServerInvestigator().inspect_ssl("google.com")
    assert res["has_ssl"] is True
    assert res["cert_valid"] is True
    assert res["issuer_org"] == "Google Trust Services"
    assert res["common_name"] == "*.google.com"


def test_inspect_ssl_detects_wrapped_cert_verification_error(monkeypatch):
    import ssl
    import httpx
    from backend.app.services import server_investigator as si_mod

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def stream(self, *args, **kwargs):
            cert_err = ssl.SSLCertVerificationError("self-signed certificate")
            cert_err.verify_message = "self-signed certificate"
            raise httpx.ConnectError("TLS failed") from cert_err

    monkeypatch.setattr(si_mod.httpx, "Client", FakeClient)

    res = ServerInvestigator().inspect_ssl("bad-cert.example")
    assert res["has_ssl"] is True
    assert res["cert_valid"] is False
    assert res["probe_status"] == "invalid_cert"
