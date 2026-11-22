"""PhishGuard Telegram Bot Launcher.
Usage:
    python run_telegram_bot.py --token <YOUR_TELEGRAM_BOT_TOKEN>
    or set TELEGRAM_BOT_TOKEN in your .env file
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure backend package is in python path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))
load_dotenv(ROOT / ".env")

from app.integrations.telegram_bot import main

if __name__ == "__main__":
    main()
