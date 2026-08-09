#!/usr/bin/env python3
# cli.py
"""Headless-запуск clo без GUI — для cron, ssh и remote-управления.

    python cli.py <module> <target>
    python cli.py username john_doe
    python cli.py github torvalds
    python cli.py telegram @durov

Отчёт (JSON+HTML) кладётся в reports/ автоматически.
"""

import sys

from analyzers.phone import analyze_phone_combo
from analyzers.username import analyze_username_combo
from analyzers.email import analyze_email_leaks
from analyzers.discord import analyze_discord
from analyzers.telegram import analyze_telegram_full
from analyzers.github import analyze_github
from analyzers.ip import analyze_ip_basic, analyze_shodan_smart
from analyzers.domain import analyze_domain
from analyzers.photo import analyze_photo
from analyzers.card import analyze_card
from analyzers.crypto import analyze_crypto
from analyzers.face import analyze_face
from analyzers.investigate import investigate
from core import report

MODULES = {
    "phone": (analyze_phone_combo, "Телефон"),
    "username": (analyze_username_combo, "Username"),
    "email": (analyze_email_leaks, "Email"),
    "discord": (analyze_discord, "Discord"),
    "telegram": (analyze_telegram_full, "Telegram"),
    "github": (analyze_github, "GitHub"),
    "ip": (analyze_ip_basic, "IP"),
    "shodan": (analyze_shodan_smart, "Shodan"),
    "domain": (analyze_domain, "Домен"),
    "photo": (analyze_photo, "Фото"),
    "card": (analyze_card, "Карта"),
    "crypto": (analyze_crypto, "Крипто"),
    "face": (analyze_face, "Реверс-фото"),
}


def main(argv: list[str]) -> int:
    if len(argv) < 2 or (argv[0] not in MODULES and argv[0] != "investigate"):
        print(f"usage: python cli.py <investigate|{'|'.join(MODULES)}> <target>")
        return 2

    # investigate сам управляет отчётами и пишет сводный файл
    if argv[0] == "investigate":
        investigate(argv[1])
        return 0

    func, label = MODULES[argv[0]]
    target = argv[1]
    rep = report.begin(label, target)
    try:
        func(target)
    finally:
        report.finish()
        try:
            json_path, html_path = rep.save()
            print(f"\n[✓] Отчёт: {html_path}\n[✓] JSON:  {json_path}")
        except Exception as exc:
            print(f"\n[!] Отчёт не сохранён: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
