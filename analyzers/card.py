# analyzers/card.py
"""BIN-пробив банковской карты через binlist.net (без ключа).

По первым 6-8 цифрам определяет платёжную систему, тип, банк и страну.
Полный номер карты не хранится и никуда не отправляется — берётся только BIN.
"""

from __future__ import annotations

import re

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary
from core.cache import throttle

API = "https://lookup.binlist.net/{}"


def analyze_card(target: str) -> None:
    bin_digits = re.sub(r"\D", "", target)[:8]
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] BIN: {bin_digits}")
    dual_print(f"{'═' * 58}")

    if len(bin_digits) < 6:
        dual_print("  [!] Нужно минимум 6 цифр (BIN).")
        return

    results: dict[str, str] = {}
    session = get_session()
    print_section("binlist.net")
    throttle(API.format(bin_digits[:8]))
    try:
        r = safe_get(
            session, API.format(bin_digits[:8]), timeout=12,
            headers={**session.headers, "Accept-Version": "3"},
        )
    except Exception as e:
        dual_print(f"  [!] binlist: {e}")
        print_summary(results, f"BIN {bin_digits}")
        return
    if r.status_code == 404:
        dual_print("  [–] BIN не найден в базе.")
        print_summary(results, f"BIN {bin_digits}")
        return
    if r.status_code == 429:
        dual_print("  [!] Лимит binlist исчерпан (5 запросов/час). Попробуйте позже.")
        print_summary(results, f"BIN {bin_digits}")
        return
    if r.status_code != 200:
        dual_print(f"  [!] binlist вернул {r.status_code}")
        print_summary(results, f"BIN {bin_digits}")
        return

    d = r.json()
    scheme = d.get("scheme")
    ctype = d.get("type")
    brand = d.get("brand")
    bank = (d.get("bank") or {})
    country = (d.get("country") or {})

    print_field("Платёжная система", scheme)
    print_field("Тип карты", ctype)
    print_field("Бренд", brand)
    if d.get("prepaid") is not None:
        print_field("Предоплаченная", "да" if d["prepaid"] else "нет")
    print_field("Банк", bank.get("name"))
    print_field("Сайт банка", bank.get("url"))
    print_field("Телефон банка", bank.get("phone"))
    flag = country.get("emoji", "")
    if country.get("name"):
        print_field("Страна", f"{country.get('name')} {flag}".strip())
    if country.get("currency"):
        print_field("Валюта", country.get("currency"))

    for k, v in (("Система", scheme), ("Банк", bank.get("name")),
                 ("Страна", country.get("name"))):
        if v:
            results[k] = str(v)
    print_summary(results, f"BIN {bin_digits}")


if __name__ == "__main__":
    import sys
    analyze_card(sys.argv[1] if len(sys.argv) > 1 else "45717360")
