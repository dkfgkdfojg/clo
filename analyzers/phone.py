# analyzers/phone.py
import re
import shutil
import subprocess
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from urllib.parse import quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger
from config import API_KEYS


def analyze_phone_combo(phone_str):
    """
    Комплексный анализ телефонного номера.
    Этапы:
      1. Локальный анализ через библиотеку phonenumbers
      2. Параллельный сбор данных из множества источников:
         - Veriphone.io
         - htmlweb.ru
         - phonenum.org
         - phoneinfo.ru
         - who-called.ru / whoscall
         - Truecaller (web)
         - NumLookup
         - 2ip.ru (телефон)
         - CallApp
         - smsc.ru (HLR-запрос)
         - numverify.com (требует API-ключ)
    """
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] ТЕЛЕФОН: {phone_str}")
    dual_print(f"{'═' * 58}")

    # Очистка номера
    clean = re.sub(r"[^\d+]", "", phone_str)
    num_only = re.sub(r"[^\d]", "", clean)

    # ---------- 1. ЛОКАЛЬНЫЙ АНАЛИЗ (phonenumbers) ----------
    try:
        # Номер в международном формате (+..) парсим как есть; иначе — с регионом
        # по умолчанию RU, чтобы корректно распознать 10-значные и 8-префиксные
        # номера (слепое добавление '+' ломало country code, напр. 8800... -> +8800).
        if clean.startswith("+"):
            parsed = phonenumbers.parse(clean)
        else:
            parsed = phonenumbers.parse(clean, "RU")
        if not phonenumbers.is_valid_number(parsed):
            possible = phonenumbers.is_possible_number(parsed)
            print_section("Валидность")
            print_field("Статус", "✗ НЕДЕЙСТВИТЕЛЬНЫЙ")
            print_field(
                "Возможный по длине",
                "да (номер существует по формату, но не выделен оператору)"
                if possible else "нет (неверная длина/код)",
            )
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            print_field("E164", e164)
            dual_print("  [–] Онлайн-источники пропущены: номер невалиден.")
            return

        region = geocoder.description_for_number(parsed, "ru") or "—"
        oper = carrier.name_for_number(parsed, "ru") or "—"
        tzs = timezone.time_zones_for_number(parsed)
        tz_str = tzs[0] if tzs else "—"
        type_map = {
            0: "Стационарный",
            1: "Мобильный",
            2: "Стац./Мобильный",
            3: "Toll-free",
            4: "Premium-rate",
            5: "Shared-cost",
            6: "VoIP",
            7: "Personal",
            8: "Pager",
            9: "UAN",
            10: "Voicemail",
            99: "Неизвестен",
        }
        line = type_map.get(phonenumbers.number_type(parsed), "Неизвестен")
        intl = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        nat = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        )
        cc = parsed.country_code
        nn = parsed.national_number

        print_section("phonenumbers (локальный анализ)")
        print_field("Статус", "✓ ДЕЙСТВИТЕЛЬНЫЙ")
        print_field("Международный", intl)
        print_field("E164", e164)
        print_field("Национальный", nat)
        print_field("Страна/регион", region)
        print_field("Оператор", oper)
        print_field("Тип линии", line)
        print_field("Часовой пояс", tz_str)
        print_field("WhatsApp", f"https://wa.me/{cc}{nn}")
        print_field("Telegram", f"https://t.me/+{cc}{nn}")
    except Exception as e:
        logger.debug(f"Phone parse error: {e}")
        dual_print(f"  [!] Ошибка: {e}")
        return

    session = get_session()
    results = {}

    # ---------- 2. ФУНКЦИИ-ЗАГРУЗЧИКИ ----------

    # 2.1 Veriphone.io
    def fetch_veriphone():
        try:
            print_section("Veriphone.io")
            r = safe_get(
                session, f"https://veriphone.io/lookup?phone={quote(clean)}", timeout=12
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for row in soup.select("table tr")[:12]:
                    cells = row.find_all(["td", "th"])
                    if len(cells) >= 2:
                        k = cells[0].get_text(strip=True)
                        v = cells[1].get_text(strip=True)
                        if k and v:
                            print_field(k, v)
                            results[k] = v
        except Exception as e:
            logger.debug(f"Veriphone error: {e}")
            dual_print(f"  [!] Veriphone: {e}")

    # 2.2 htmlweb.ru
    def fetch_htmlweb():
        try:
            print_section("htmlweb.ru")
            r = safe_get(
                session,
                f"https://htmlweb.ru/geo/phone.php?phone={num_only}",
                timeout=12,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                table = soup.find("table")
                if table:
                    for row in table.find_all("tr")[:10]:
                        cells = row.find_all(["td", "th"])
                        if len(cells) >= 2:
                            k = cells[0].get_text(strip=True)
                            v = cells[1].get_text(strip=True)
                            if k and v:
                                print_field(k, v)
        except Exception as e:
            logger.debug(f"htmlweb error: {e}")
            dual_print(f"  [!] htmlweb.ru: {e}")

    # 2.3 phonenum.org
    def fetch_phonenum_org():
        try:
            print_section("phonenum.org")
            r = safe_get(
                session, f"https://phonenum.org/phone/{quote(clean)}", timeout=12
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for sel in ["table", ".info-table", ".phone-info"]:
                    el = (
                        soup.find(sel) if isinstance(sel, str) else soup.select_one(sel)
                    )
                    if el:
                        for row in el.find_all("tr")[:10]:
                            cells = row.find_all(["td", "th"])
                            if len(cells) >= 2:
                                k = cells[0].get_text(strip=True)
                                v = cells[1].get_text(strip=True)
                                if k and v:
                                    print_field(k, v)
                        break
        except Exception as e:
            logger.debug(f"phonenum.org error: {e}")
            dual_print(f"  [!] phonenum.org: {e}")

    # 2.4 phoneinfo.ru
    def fetch_phoneinfo_ru():
        try:
            print_section("phoneinfo.ru")
            r = safe_get(session, f"https://phoneinfo.ru/{num_only}", timeout=12)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for row in soup.select(".info-row, .phone-row, tr")[:10]:
                    cells = row.find_all(["td", "th"])
                    if len(cells) >= 2:
                        k = cells[0].get_text(strip=True)
                        v = cells[1].get_text(strip=True)
                        if k and v:
                            print_field(k, v)
        except Exception as e:
            logger.debug(f"phoneinfo.ru error: {e}")
            dual_print(f"  [!] phoneinfo.ru: {e}")

    # 2.5 who-called.ru / whoscall
    def fetch_whois_phone():
        try:
            print_section("who-called.ru / whoscall")
            for url in [
                f"https://who-called.ru/number/{num_only}",
                f"https://www.calleridtest.com/phonebook/{quote(clean)}",
            ]:
                try:
                    r = safe_get(session, url, timeout=10)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        reviews = soup.select(
                            ".review, .comment, .feedback, .review-text"
                        )
                        if reviews:
                            dual_print(f"  Отзывов о номере: {len(reviews)}")
                            for rv in reviews[:3]:
                                txt = rv.get_text(strip=True)[:120]
                                if txt:
                                    dual_print(f"    → {txt}")
                        h1 = soup.find("h1")
                        if h1:
                            dual_print(f"  {h1.get_text(strip=True)[:80]}")
                        break
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"who-called error: {e}")
            dual_print(f"  [!] who-called: {e}")

    # 2.6 Truecaller (web)
    def fetch_truecaller_web():
        try:
            print_section("Truecaller (web)")
            r = safe_get(
                session, f"https://www.truecaller.com/search/ru/{num_only}", timeout=12
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for sel in ["h1.title", ".name", '[class*="name"]', "h2"]:
                    el = soup.select_one(sel)
                    if el and el.get_text(strip=True):
                        print_field("Имя (Truecaller)", el.get_text(strip=True))
                        results["Имя (Truecaller)"] = el.get_text(strip=True)
                        break
        except Exception as e:
            logger.debug(f"Truecaller error: {e}")
            dual_print(f"  [!] Truecaller: {e}")

    # 2.7 NumLookup
    def fetch_numcheck():
        try:
            print_section("NumLookup")
            r = safe_get(
                session,
                f"https://www.numlookup.com/api/query?phone={quote(clean)}",
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    for k, v in data.items():
                        if v:
                            print_field(str(k), str(v))
        except Exception as e:
            logger.debug(f"NumLookup error: {e}")
            dual_print(f"  [!] NumLookup: {e}")

    # 2.8 2ip.ru (телефон)
    def fetch_2ip_phone():
        try:
            print_section("2ip.ru (телефон)")
            r = safe_get(
                session, f"https://2ip.ru/whois-phone/?phone={num_only}", timeout=12
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                table = soup.find("table")
                if table:
                    for row in table.find_all("tr")[:10]:
                        cells = row.find_all(["td", "th"])
                        if len(cells) >= 2:
                            k = cells[0].get_text(strip=True)
                            v = cells[1].get_text(strip=True)
                            if k and v:
                                print_field(k, v)
        except Exception as e:
            logger.debug(f"2ip phone error: {e}")
            dual_print(f"  [!] 2ip phone: {e}")

    # 2.9 CallApp
    def fetch_callapp():
        try:
            print_section("CallerID / getcontact (web)")
            r = safe_get(
                session, f"https://www.callapp.com/phone/{quote(clean)}", timeout=10
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for sel in ["h1", ".name", ".title"]:
                    el = soup.select_one(sel)
                    if el and el.get_text(strip=True):
                        print_field("Имя (CallerID)", el.get_text(strip=True))
                        break
        except Exception as e:
            logger.debug(f"CallApp error: {e}")
            dual_print(f"  [!] CallApp: {e}")

    # 2.10 HLR (smsc.ru) – НОВАЯ ФУНКЦИЯ
    def fetch_hlr():
        """Проверка активности SIM через smsc.ru (бесплатный HLR)."""
        try:
            print_section("HLR (smsc.ru)")
            # Используем публичный метод без ключа (до 5 запросов/день)
            r = safe_get(
                session,
                f"https://smsc.ru/sys/hlr.php?phone={num_only}&fmt=3",
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == 1:
                    print_field("HLR (активен)", "Да")
                    print_field("Оператор (HLR)", data.get("operator"))
                    print_field("Страна (HLR)", data.get("country"))
                    print_field("Код страны (HLR)", data.get("country_code"))
                    results["HLR_активен"] = "Да"
                else:
                    print_field("HLR", "Неактивен или не найден")
                    results["HLR_активен"] = "Нет"
        except Exception as e:
            logger.debug(f"HLR error: {e}")
            dual_print(f"  [!] HLR: {e}")

    # 2.11 NumVerify – НОВАЯ ФУНКЦИЯ (требует API-ключ)
    def fetch_numverify():
        """Проверка через numverify.com (нужен API-ключ, бесплатно 100 запросов/мес)."""
        key = API_KEYS.get("NUMVERIFY")
        if not key:
            return
        try:
            print_section("NumVerify")
            r = safe_get(
                session,
                f"http://api.numverify.com/validate?access_key={key}&number={quote(clean)}",
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("valid"):
                    print_field("NumVerify (валидный)", "Да")
                    print_field("Страна", data.get("country_name"))
                    print_field("Код страны", data.get("country_code"))
                    print_field("Оператор", data.get("carrier"))
                    print_field("Тип линии", data.get("line_type"))
                    results["NumVerify_валидный"] = "Да"
                else:
                    print_field("NumVerify", "Невалидный")
        except Exception as e:
            logger.debug(f"NumVerify error: {e}")
            dual_print(f"  [!] NumVerify: {e}")

    # 2.12 Footprint (PhoneInfoga-стиль): готовые поисковые запросы
    def fetch_footprint():
        print_section("Footprint (поисковые запросы)")
        e = quote(e164)
        n = quote(nat)
        dorks = {
            "Google (точный)": f"https://www.google.com/search?q=%22{e}%22",
            "Google (соцсети)": f"https://www.google.com/search?q=%22{e}%22+OR+%22{n}%22+site:facebook.com+OR+site:vk.com+OR+site:linkedin.com",
            "Объявления": f"https://www.google.com/search?q=%22{n}%22+site:avito.ru+OR+site:youla.ru+OR+site:olx",
            "Утечки/пасты": f"https://www.google.com/search?q=%22{e}%22+site:pastebin.com+OR+site:t.me",
            "WhatsApp": f"https://wa.me/{e164.lstrip('+')}",
            "Telegram": f"https://t.me/+{e164.lstrip('+')}",
        }
        for label, url in dorks.items():
            print_field(label, url)

    # 2.13 ignorant: регистрация номера в соцсетях (если утилита установлена)
    def fetch_ignorant():
        if not shutil.which("ignorant"):
            return
        print_section("ignorant (регистрация в соцсетях)")
        try:
            out = subprocess.run(
                ["ignorant", str(cc), str(nn), "--no-clear", "--no-color", "--only-used"],
                capture_output=True, text=True, timeout=60,
            ).stdout
            used = [ln.strip() for ln in out.splitlines() if "[+]" in ln]
            if used:
                for ln in used[:20]:
                    dual_print(f"    {ln}")
                results["ignorant"] = f"{len(used)} сервисов"
            else:
                dual_print("  Регистраций не обнаружено.")
        except Exception as e:
            logger.debug(f"ignorant error: {e}")
            dual_print(f"  [!] ignorant: {e}")

    # ---------- 3. ПАРАЛЛЕЛЬНЫЙ ЗАПУСК ----------
    print_section("Параллельный сбор данных...")
    funcs = [
        fetch_veriphone,
        fetch_htmlweb,
        fetch_phonenum_org,
        fetch_phoneinfo_ru,
        fetch_whois_phone,
        fetch_truecaller_web,
        fetch_numcheck,
        fetch_2ip_phone,
        fetch_callapp,
        fetch_hlr,  # новая
        fetch_numverify,  # новая (будет пропущена, если нет ключа)
        fetch_footprint,
        fetch_ignorant,
    ]
    with ThreadPoolExecutor(max_workers=len(funcs)) as ex:
        futs = [ex.submit(f) for f in funcs]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"Phone fetch error: {e}")

    # ---------- 4. ИТОГ ----------
    print_summary(results, f"Телефон {clean}")
