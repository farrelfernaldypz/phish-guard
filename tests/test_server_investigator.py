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

def test_dns_and_geoip_safe_fallback():
    investigator = ServerInvestigator()
    # Test private IP handling
    geo = investigator.query_geoip("127.0.0.1")
    assert geo["status"] == "private_network"
    assert "Localhost" in geo["country"]
