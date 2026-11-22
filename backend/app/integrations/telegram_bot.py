"""PhishGuard Telegram Bot Integration.
High-speed autonomous phishing URL inspector for Telegram chats & groups.
"""
from __future__ import annotations
import asyncio
import os
import sys
import argparse
from typing import Any, Dict
import httpx

from ..services.prediction import PredictionService
from ..services.server_investigator import ServerInvestigator
from .url_detector import extract_urls
from .message_formatter import format_telegram_alert

class TelegramPhishGuardBot:
    def __init__(self, token: str) -> None:
        self.token = token.strip()
        self.api_base = f"https://api.telegram.org/bot{self.token}"
        self.prediction_service = PredictionService()
        self.investigator = ServerInvestigator()
        self.bot_info: Dict[str, Any] = {}
        self.is_running = False

    async def initialize(self, client: httpx.AsyncClient) -> bool:
        """Verify bot token and test connection."""
        try:
            resp = await client.get(f"{self.api_base}/getMe", timeout=10.0)
            data = resp.json()
            if data.get("ok"):
                self.bot_info = data.get("result", {})
                username = self.bot_info.get("username", "Unknown")
                print(f"✓ Berhasil terhubung ke Telegram Bot: @{username}")
                # Reset webhook so polling works cleanly
                await client.post(f"{self.api_base}/deleteWebhook", json={"drop_pending_updates": True}, timeout=10.0)
                return True
            else:
                print(f"✗ Gagal inisialisasi bot: {data.get('description')}")
                return False
        except Exception as e:
            print(f"✗ Koneksi ke Telegram API gagal: {e}")
            return False

    async def send_message(self, client: httpx.AsyncClient, chat_id: int | str, text: str, reply_to_message_id: int | None = None) -> None:
        """Send message via Telegram Bot API."""
        payload: Dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_to_message_id:
            payload["reply_to_message_id"] = reply_to_message_id
        try:
            await client.post(f"{self.api_base}/sendMessage", json=payload, timeout=10.0)
        except Exception as e:
            print(f"✗ Gagal mengirim pesan ke chat {chat_id}: {e}")

    async def handle_message(self, client: httpx.AsyncClient, message: Dict[str, Any]) -> None:
        chat = message.get("chat", {})
        chat_id = chat.get("id")
        text = message.get("text", "") or message.get("caption", "")
        message_id = message.get("message_id")

        if not chat_id or not text:
            return

        # Commands
        if text.startswith("/start"):
            welcome = (
                "🛡️ <b>Selamat Datang di PhishGuard Bot!</b>\n\n"
                "Saya adalah asisten cerdas untuk melindungi Anda dari kejahatan <b>URL Phishing, pencurian rekening, dan penipuan siber</b>.\n\n"
                "💡 <b>Cara Menggunakan:</b>\n"
                "1. Teruskan (forward) pesan broadcast atau kirim link mencurigakan ke chat ini.\n"
                "2. Masukkan bot ini ke grup WhatsApp/Telegram Anda untuk memantau link berbahaya otomatis.\n"
                "3. PhishGuard akan langsung menganalisis tautan tersebut dalam hitungan milidetik!\n\n"
                "<i>Kirimkan link apa pun sekarang untuk mencobanya!</i>"
            )
            await self.send_message(client, chat_id, welcome, reply_to_message_id=message_id)
            return

        if text.startswith("/help"):
            help_text = (
                "📖 <b>Panduan PhishGuard Bot:</b>\n\n"
                "• <b>Analisis Tautan:</b> Cukup ketik atau paste tautan apa pun (misal: <code>http://dana-kaget-bansos-bri.xyz/login</code>).\n"
                "• <b>Pesan Forward:</b> Jika menerima broadcast mencurigakan dari grup lain, teruskan pesan tersebut ke sini, bot akan otomatis mengekstrak seluruh link di dalamnya.\n\n"
                "<i>Keamanan Anda adalah prioritas kami.</i>"
            )
            await self.send_message(client, chat_id, help_text, reply_to_message_id=message_id)
            return

        # Extract URLs
        found_urls = extract_urls(text)
        if not found_urls:
            # If in private chat and no URL found, give polite hint
            if chat.get("type") == "private":
                await self.send_message(
                    client, chat_id,
                    "ℹ️ Tidak ditemukan link web (URL) pada pesan Anda. Silakan kirimkan tautan web yang ingin Anda periksa keamanannya.",
                    reply_to_message_id=message_id
                )
            return

        # Scan each detected URL
        for url in found_urls[:5]: # Limit to max 5 URLs per message to avoid spamming
            try:
                # 1. Predict with PhishGuard Machine Learning Engine
                res = self.prediction_service.predict(url, resolve_redirects=True)
                # 2. Attach brand intelligence
                res["brand_intelligence"] = self.investigator.identify_brand(res.get("resolved_url", url))
                # 3. Format into user-friendly security alert
                alert_text = format_telegram_alert(res)
                # 4. Reply
                await self.send_message(client, chat_id, alert_text, reply_to_message_id=message_id)
            except Exception as e:
                err_msg = f"⚠️ Maaf, terjadi kendala saat memeriksa link <code>{url}</code>: {e}"
                await self.send_message(client, chat_id, err_msg, reply_to_message_id=message_id)

    async def run(self) -> None:
        """Run bot with long polling."""
        self.is_running = True
        offset = 0
        async with httpx.AsyncClient() as client:
            ok = await self.initialize(client)
            if not ok:
                return

            print("⚡ Bot siap menerima pesan. Menunggu pesan masuk dari Telegram (Tekan Ctrl+C untuk berhenti)...")
            while self.is_running:
                try:
                    resp = await client.get(
                        f"{self.api_base}/getUpdates",
                        params={"offset": offset, "timeout": 20},
                        timeout=30.0
                    )
                    data = resp.json()
                    if not data.get("ok"):
                        await asyncio.sleep(2)
                        continue

                    updates = data.get("result", [])
                    for update in updates:
                        offset = update["update_id"] + 1
                        msg = update.get("message") or update.get("channel_post")
                        if msg:
                            asyncio.create_task(self.handle_message(client, msg))
                except httpx.ReadTimeout:
                    continue
                except httpx.ConnectError:
                    await asyncio.sleep(5)
                except Exception as e:
                    print(f"⚠️ Error loop: {e}")
                    await asyncio.sleep(2)

def main():
    parser = argparse.ArgumentParser(description="Jalankan PhishGuard Telegram Bot")
    parser.add_argument("--token", default=os.getenv("TELEGRAM_BOT_TOKEN"), help="Token Bot Telegram dari @BotFather")
    args = parser.parse_args()

    token = args.token
    if not token:
        print("=" * 60)
        print("  PANDUAN MENJALANKAN TELEGRAM BOT PHISHGUARD")
        print("=" * 60)
        print("1. Buka Telegram dan cari akun @BotFather.")
        print("2. Kirim perintah /newbot dan ikuti petunjuk hingga mendapat token HTTP API.")
        print("3. Jalankan bot dengan perintah:")
        print("   python -m backend.app.integrations.telegram_bot --token <TOKEN_ANDA>")
        print("   atau simpan di berkas .env: TELEGRAM_BOT_TOKEN=<TOKEN_ANDA>")
        print("=" * 60)
        return

    bot = TelegramPhishGuardBot(token)
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        print("\n✓ Bot Telegram dihentikan dengan aman.")

if __name__ == "__main__":
    main()
