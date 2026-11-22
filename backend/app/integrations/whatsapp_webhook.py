"""PhishGuard WhatsApp Webhook Integration.
Compatible with Meta WhatsApp Cloud API and Indonesian Gateway Services (Fonnte, Wablas, Baileys).
"""
from __future__ import annotations
import os
from typing import Any, Dict
from fastapi import APIRouter, Request, Response, HTTPException
import httpx

from .url_detector import extract_urls
from .message_formatter import format_whatsapp_alert
from ..services.prediction import PredictionService
from ..services.server_investigator import ServerInvestigator

router = APIRouter(prefix="/api/webhook/whatsapp", tags=["WhatsApp Integration"])

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "phishguard_verify_token")
WHATSAPP_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
FONNTE_API_TOKEN = os.getenv("FONNTE_API_TOKEN", "")

@router.get("")
def verify_meta_webhook(request: Request):
    """Webhook verification handshake for Meta WhatsApp Cloud API."""
    params = request.query_params
    mode = params.get("hub.mode")
    token = params.get("hub.verify_token")
    challenge = params.get("hub.challenge")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return Response(content=challenge, media_type="text/plain")
    raise HTTPException(status_code=403, detail="Verification token mismatch.")

async def send_meta_whatsapp_message(to_number: str, text: str) -> None:
    """Send message via official Meta WhatsApp Cloud API."""
    if not WHATSAPP_ACCESS_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        return
    url = f"https://graph.facebook.com/v21.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to_number,
        "type": "text",
        "text": {"body": text}
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, headers=headers, timeout=10.0)
    except Exception as e:
        print(f"✗ Gagal mengirim pesan ke Meta WhatsApp API: {e}")

async def send_fonnte_message(target_number: str, message: str) -> None:
    """Send message via Fonnte WhatsApp Gateway (popular in Indonesia)."""
    if not FONNTE_API_TOKEN:
        return
    url = "https://api.fonnte.com/send"
    headers = {"Authorization": FONNTE_API_TOKEN}
    payload = {
        "target": target_number,
        "message": message
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, data=payload, headers=headers, timeout=10.0)
    except Exception as e:
        print(f"✗ Gagal mengirim via Fonnte API: {e}")

@router.post("")
async def handle_whatsapp_incoming(request: Request):
    """Handle incoming message webhook from Meta Cloud API or Indonesian Gateways."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    sender = ""
    incoming_text = ""

    # 1. Meta WhatsApp Cloud API format
    if "entry" in body:
        try:
            entry = body.get("entry", [{}])[0]
            change = entry.get("changes", [{}])[0]
            value = change.get("value", {})
            messages = value.get("messages", [])
            if messages:
                msg = messages[0]
                sender = msg.get("from", "")
                if msg.get("type") == "text":
                    incoming_text = msg.get("text", {}).get("body", "")
        except Exception:
            pass

    # 2. Fonnte / Wablas / Baileys format
    if not incoming_text:
        incoming_text = body.get("message") or body.get("text") or body.get("body") or ""
        sender = body.get("sender") or body.get("phone") or body.get("from") or ""

    if not incoming_text:
        return {"status": "ignored", "reason": "No text content detected."}

    # Extract URLs from message
    urls = extract_urls(incoming_text)
    if not urls:
        reply = (
            "🛡️ *PhishGuard Cyber Security Bot*\n\n"
            "Kirimkan tautan web (URL) mencurigakan atau teruskan pesan broadcast untuk diperiksa status keamanannya."
        )
        if sender:
            await send_meta_whatsapp_message(sender, reply)
            await send_fonnte_message(sender, reply)
        return {"status": "ok", "reply": reply}

    # Run inspection
    service: PredictionService = request.app.state.prediction_service
    investigator: ServerInvestigator = request.app.state.server_investigator

    replies = []
    for u in urls[:3]: # Limit to 3 scans per WhatsApp message
        try:
            result = service.predict(u, resolve_redirects=True)
            result["brand_intelligence"] = investigator.identify_brand(result.get("resolved_url", u))
            alert = format_whatsapp_alert(result)
            replies.append(alert)
        except Exception as e:
            replies.append(f"⚠️ Gagal menganalisis link *{u}*: {e}")

    full_reply = "\n\n---\n\n".join(replies)

    # Send outbound reply if gateway credentials configured
    if sender:
        await send_meta_whatsapp_message(sender, full_reply)
        await send_fonnte_message(sender, full_reply)

    # Return in HTTP response (for gateways that use immediate response webhook)
    return {
        "status": "success",
        "scanned_count": len(urls),
        "sender": sender,
        "reply": full_reply
    }
