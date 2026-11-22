import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.integrations.url_detector import extract_urls
from backend.app.integrations.message_formatter import format_telegram_alert, format_whatsapp_alert

client = TestClient(app)

def test_extract_urls_from_broadcast_text():
    text = (
        "Selamat! Anda mendapatkan dana bantuan tunai Rp 2.400.000.\n"
        "Segera klaim melalui tautan berikut: http://dana-kaget-bansos-bri.xyz/login\n"
        "Info lebih lanjut kunjungi https://kemkes.go.id atau hubungi kami."
    )
    urls = extract_urls(text)
    assert len(urls) == 2
    assert "http://dana-kaget-bansos-bri.xyz/login" in urls
    assert "https://kemkes.go.id" in urls

def test_extract_urls_empty_and_no_urls():
    assert extract_urls("") == []
    assert extract_urls("Halo selamat pagi kawan-kawan, apa kabar hari ini?") == []

def test_message_formatters_phishing_and_legitimate():
    mock_phish = {
        "url": "http://dana-kaget-bansos-bri.xyz/login",
        "resolved_url": "http://dana-kaget-bansos-bri.xyz/login",
        "prediction": 1,
        "model_score": 0.95,
        "brand_intelligence": {
            "is_impersonating": True,
            "brand": "PT Bank Rakyat Indonesia (BRI)",
            "official_domains": ["bri.co.id"]
        },
        "advanced_heuristics": {
            "is_suspicious_tld": True,
            "indonesian_threat_count": 2,
            "indonesian_keywords_detected": ["dana", "bansos"]
        },
        "redirect_trace": {"redirect_occurred": False}
    }
    tg_alert = format_telegram_alert(mock_phish)
    wa_alert = format_whatsapp_alert(mock_phish)

    assert "PERINGATAN BAHAYA" in tg_alert
    assert "<b>PT Bank Rakyat Indonesia (BRI)</b>" in tg_alert
    assert "PERINGATAN BAHAYA" in wa_alert
    assert "*PT Bank Rakyat Indonesia (BRI)*" in wa_alert

    mock_safe = {
        "url": "https://google.com",
        "resolved_url": "https://google.com",
        "prediction": 0,
        "model_score": 0.01,
        "brand_intelligence": {"is_official": True, "brand": "Google"}
    }
    assert "TERVERIFIKASI AMAN" in format_telegram_alert(mock_safe)
    assert "LINK AMAN" in format_whatsapp_alert(mock_safe)

def test_whatsapp_webhook_handshake_and_scan():
    # 1. Verification Handshake
    res_verify = client.get("/api/webhook/whatsapp?hub.mode=subscribe&hub.verify_token=phishguard_verify_token&hub.challenge=test_challenge_123")
    assert res_verify.status_code == 200
    assert res_verify.text == "test_challenge_123"

    # 2. Incoming WhatsApp message with phishing URL
    payload = {
        "sender": "6281234567890",
        "message": "Segera klaim dana bansos anda di http://dana-kaget-bansos-bri.xyz/login sekarang!"
    }
    res_post = client.post("/api/webhook/whatsapp", json=payload)
    assert res_post.status_code == 200
    data = res_post.json()
    assert data["status"] == "success"
    assert data["scanned_count"] >= 1
    assert "PERINGATAN BAHAYA" in data["reply"]
