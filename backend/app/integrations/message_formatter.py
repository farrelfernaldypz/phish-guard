"""PhishGuard Chat Alert Formatter for WhatsApp and Telegram."""
from __future__ import annotations
from typing import Any, Dict

def format_telegram_alert(result: Dict[str, Any], investigator_report: Dict[str, Any] | None = None) -> str:
    """Format analysis result into rich HTML message for Telegram."""
    is_phishing = result.get("prediction", 0) == 1
    score = float(result.get("model_score", 0.0)) * 100
    url = result.get("url", "")
    resolved_url = result.get("resolved_url", url)
    brand = result.get("brand_intelligence") or {}
    adv = result.get("advanced_heuristics") or {}
    trace = result.get("redirect_trace") or {}

    if is_phishing:
        msg = "🚨 <b>[PERINGATAN BAHAYA: LINK PHISHING]</b> 🚨\n\n"
        msg += f"⚠️ <b>JANGAN KLIK LINK INI!</b> Terdeteksi potensi kejahatan penipuan siber / pencurian data akun.\n\n"
        msg += f"🔗 <b>Target URL:</b> <code>{url}</code>\n"
        if resolved_url != url:
            msg += f"🔀 <b>Tujuan Asli:</b> <code>{resolved_url}</code>\n"
        msg += f"📊 <b>Tingkat Risiko:</b> <b>{score:.1f}% (BAHAYA TINGGI)</b>\n"

        if brand.get("is_impersonating"):
            msg += f"\n🏦 <b>Indikasi Pencatutan Brand:</b>\n"
            msg += f"Tautan ini meniru merek <b>{brand.get('brand')}</b>, padahal alamat situs bukan milik domain resmi!\n"

        msg += "\n📌 <b>Temuan Forensik:</b>\n"
        reasons = []
        if trace.get("redirect_occurred"):
            reasons.append("• Menggunakan pemendek link untuk menyamarkan alamat berbahaya.")
        if adv.get("is_suspicious_tld"):
            reasons.append("• Menggunakan ekstensi domain berisiko tinggi (.xyz/.top/dsb).")
        if adv.get("indonesian_threat_count", 0) > 0:
            tokens = ", ".join(adv.get("indonesian_keywords_detected", []))
            reasons.append(f"• Memuat kata kunci jebakan phishing Indonesia (<i>{tokens}</i>).")
        if adv.get("is_high_entropy_dga"):
            reasons.append("• Karakter nama domain tersusun dari huruf acak (Domain Generation Algorithm).")
        if not reasons:
            reasons.append("• Pola struktur URL sangat mirip dengan ribuan sampel serangan phishing terdata.")
        msg += "\n".join(reasons) + "\n\n"

        msg += "🛡️ <b>Langkah Pencegahan Wajib:</b>\n"
        msg += "1. 🚫 Jangan buka tautan di browser HP / laptop Anda.\n"
        msg += "2. 🔒 Jangan pernah kirimkan password, PIN ATM, atau kode OTP.\n"
        msg += "3. 📵 Hapus pesan ini dan segera blokir nomor pengirimnya.\n"
    else:
        msg = "✅ <b>[STATUS: TERVERIFIKASI AMAN]</b> ✅\n\n"
        msg += f"🔗 <b>Target URL:</b> <code>{url}</code>\n"
        msg += f"📊 <b>Tingkat Risiko:</b> <b>{score:.1f}% (Sangat Rendah)</b>\n"
        if brand.get("is_official"):
            msg += f"🏢 <b>Domain Resmi:</b> Terverifikasi sebagai domain sah <b>{brand.get('brand')}</b>.\n"
        msg += "\n📌 <b>Keterangan:</b>\n"
        msg += "• Struktur URL nominal dan bebas dari parameter manipulasi kredensial.\n"
        msg += "• Tidak terindikasi pemendek link jebakan atau teknik homograf.\n"

    msg += "\n<i>🛡️ Dianalisis secara defensif oleh PhishGuard Machine Learning Engine</i>"
    return msg

def format_whatsapp_alert(result: Dict[str, Any], investigator_report: Dict[str, Any] | None = None) -> str:
    """Format analysis result into WhatsApp markdown format (*bold*, _italic_, ```mono```)."""
    is_phishing = result.get("prediction", 0) == 1
    score = float(result.get("model_score", 0.0)) * 100
    url = result.get("url", "")
    resolved_url = result.get("resolved_url", url)
    brand = result.get("brand_intelligence") or {}
    adv = result.get("advanced_heuristics") or {}
    trace = result.get("redirect_trace") or {}

    if is_phishing:
        msg = "🚨 *[PERINGATAN BAHAYA: LINK PHISHING]* 🚨\n\n"
        msg += "⚠️ *JANGAN KLIK LINK INI!* Terdeteksi indikasi kejahatan penipuan siber / pencurian data akun & rekening.\n\n"
        msg += f"🔗 *Target URL:* ```{url}```\n"
        if resolved_url != url:
            msg += f"🔀 *Tujuan Asli (Unshorten):* ```{resolved_url}```\n"
        msg += f"📊 *Tingkat Risiko:* *{score:.1f}% (BAHAYA)*\n"

        if brand.get("is_impersonating"):
            msg += f"\n🏦 *Indikasi Pencatutan Brand:*\n"
            msg += f"Tautan ini meniru merek *{brand.get('brand')}*, padahal *BUKAN* domain resmi milik instansi tersebut!\n"

        msg += "\n📌 *Temuan Keamanan:*\n"
        reasons = []
        if trace.get("redirect_occurred"):
            reasons.append("- Menggunakan pemendek link untuk menyembunyikan target asli.")
        if adv.get("is_suspicious_tld"):
            reasons.append("- Menggunakan domain berisiko tinggi (.xyz/.top/dsb).")
        if adv.get("indonesian_threat_count", 0) > 0:
            tokens = ", ".join(adv.get("indonesian_keywords_detected", []))
            reasons.append(f"- Memuat kata pancingan penipuan ({tokens}).")
        if adv.get("is_high_entropy_dga"):
            reasons.append("- Domain tersusun dari karakter acak buatan.")
        if not reasons:
            reasons.append("- Pola URL identik dengan database ancaman phishing.")
        msg += "\n".join(reasons) + "\n\n"

        msg += "🛡️ *Langkah Pencegahan:*\n"
        msg += "1. 🚫 Jangan klik tautan ini.\n"
        msg += "2. 🔒 Jangan berikan password, PIN, atau kode OTP kepada siapapun.\n"
        msg += "3. 📵 Hapus pesan dan blokir nomor WhatsApp pengirim.\n"
    else:
        msg = "✅ *[STATUS: LINK AMAN]* ✅\n\n"
        msg += f"🔗 *Target URL:* ```{url}```\n"
        msg += f"📊 *Tingkat Risiko:* *{score:.1f}% (Aman)*\n"
        if brand.get("is_official"):
            msg += f"🏢 *Domain Resmi:* Terverifikasi resmi milik *{brand.get('brand')}*.\n"
        msg += "\n📌 *Keterangan:* Tautan bebas dari pola manipulasi kredensial dan tidak berbahaya.\n"

    msg += "\n_🛡️ PhishGuard Cyber Threat Intelligence_"
    return msg
