# core/verify.py
"""Проверка валидности email и телефона.

Email: синтаксис + наличие MX/A у домена (DNS over HTTPS, без доп. зависимостей)
+ признаки одноразового/ролевого/бесплатного адреса.
Телефон: вердикт через phonenumbers (offline).
"""

from __future__ import annotations

import re

import phonenumbers
from phonenumbers import geocoder, carrier

from core.utils import logger

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# Наиболее ходовые одноразовые/temp-mail домены. Не исчерпывающе, но ловит
# большинство «10-минутных» ящиков.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "tempmail.com", "throwawaymail.com", "yopmail.com", "getnada.com",
    "trashmail.com", "sharklasers.com", "guerrillamailblock.com", "dispostable.com",
    "maildrop.cc", "mailnesia.com", "fakeinbox.com", "tempinbox.com",
    "mohmal.com", "emailondeck.com", "moakt.com", "tempmailo.com",
    "1secmail.com", "mailpoof.com", "burnermail.io", "temp-mail.io",
    "gmx.us", "spam4.me", "grr.la", "inboxkitten.com", "vjuum.com",
}

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "aol.com", "protonmail.com", "proton.me", "gmx.com",
    "mail.com", "zoho.com", "yandex.ru", "yandex.com", "mail.ru",
    "bk.ru", "inbox.ru", "list.ru", "rambler.ru", "ya.ru",
}

# Локальные части, указывающие на служебный (не личный) ящик.
ROLE_LOCALPARTS = {
    "admin", "administrator", "info", "support", "sales", "contact", "help",
    "no-reply", "noreply", "postmaster", "webmaster", "abuse", "office",
    "hello", "team", "billing", "hr", "jobs", "marketing", "security", "root",
}


def doh(domain: str, rtype: str, session) -> list[str]:
    """DNS over HTTPS: сырые data-строки записей данного типа (A/AAAA/NS/TXT/...)."""
    try:
        r = session.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": rtype},
            timeout=8,
        )
        if r.status_code != 200:
            return []
        return [
            a.get("data", "").strip().strip('"')
            for a in r.json().get("Answer", [])
            if a.get("data")
        ]
    except Exception as exc:
        logger.debug("DoH %s %s: %s", rtype, domain, exc)
        return []


def _doh_lookup(domain: str, rtype: str, session) -> list[str]:
    """DNS over HTTPS через dns.google. Возвращает список ответов данного типа."""
    type_num = {"MX": 15, "A": 1}.get(rtype, 1)
    try:
        r = session.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": rtype},
            timeout=8,
        )
        if r.status_code != 200:
            return []
        data = r.json()
        out = []
        for ans in data.get("Answer", []):
            if ans.get("type") == type_num:
                # MX: "10 mx.example.com." → берём хост
                val = ans.get("data", "").strip().rstrip(".")
                out.append(val.split()[-1] if rtype == "MX" else val)
        return out
    except Exception as exc:
        logger.debug("DoH %s %s: %s", rtype, domain, exc)
        return []


def check_email(email: str, session) -> dict:
    """Полная проверка адреса. session — requests.Session (для DoH)."""
    email = email.strip()
    res = {
        "email": email,
        "syntax_valid": bool(_EMAIL_RE.match(email)),
        "domain": "",
        "local": "",
        "has_mx": False,
        "mx_hosts": [],
        "has_a": False,
        "is_disposable": False,
        "is_role": False,
        "is_free": False,
        "deliverable": False,
    }
    if not res["syntax_valid"]:
        return res

    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    res["local"] = local
    res["domain"] = domain
    res["is_disposable"] = domain in DISPOSABLE_DOMAINS
    res["is_free"] = domain in FREE_PROVIDERS
    res["is_role"] = local.lower() in ROLE_LOCALPARTS

    mx = _doh_lookup(domain, "MX", session)
    res["mx_hosts"] = mx[:5]
    res["has_mx"] = bool(mx)
    if not mx:
        # без MX почта может доставляться на A-запись домена
        a = _doh_lookup(domain, "A", session)
        res["has_a"] = bool(a)

    # доставляемость: синтаксис ок И домен принимает почту (MX или A)
    res["deliverable"] = res["has_mx"] or res["has_a"]
    return res


_LINE_TYPE = {
    0: "стационарный", 1: "мобильный", 2: "стац./моб.", 3: "toll-free",
    4: "premium-rate", 5: "shared-cost", 6: "VoIP", 7: "personal",
    8: "pager", 9: "UAN", 10: "voicemail", 99: "неизвестен",
}


def check_phone(phone: str, default_region: str = "RU") -> dict:
    """Вердикт по номеру через phonenumbers (без сети)."""
    res = {
        "input": phone, "parsed": False, "possible": False, "valid": False,
        "e164": "", "international": "", "region": "", "carrier": "",
        "line_type": "", "country_code": None,
    }
    clean = re.sub(r"[^\d+]", "", phone)
    try:
        parsed = phonenumbers.parse(clean, None if clean.startswith("+") else default_region)
    except phonenumbers.NumberParseException as exc:
        logger.debug("phone parse: %s", exc)
        return res
    res["parsed"] = True
    res["possible"] = phonenumbers.is_possible_number(parsed)
    res["valid"] = phonenumbers.is_valid_number(parsed)
    res["country_code"] = parsed.country_code
    res["e164"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    res["international"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    res["region"] = geocoder.description_for_number(parsed, "ru") or ""
    res["carrier"] = carrier.name_for_number(parsed, "ru") or ""
    res["line_type"] = _LINE_TYPE.get(phonenumbers.number_type(parsed), "неизвестен")
    return res
