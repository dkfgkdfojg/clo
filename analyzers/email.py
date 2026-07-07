# analyzers/email.py
import re
import hashlib
import time
from urllib.parse import quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger
from core.cli_runner import run_external_tool_with_parser
from config import API_KEYS


def analyze_email_leaks(target):
    """
    Анализ email:
      - Gravatar
      - EmailRep.io
      - HaveIBeenPwned
      - LeakPeek
      - Lullar
      - thatsthem
      - Epieos (Selenium)
      - Leak-Lookup
      - IntelX (требует ключ)
      - fth.so
      - CLI: Holehe, Mosint
    """
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] EMAIL: {target}")
    dual_print(f"{'═' * 58}")
    if "@" not in target or "." not in target:
        dual_print("  [!] Некорректный email.")
        return

    session = get_session()
    results = {}

    # ---------- GRAVATAR ----------
    def fetch_gravatar():
        try:
            print_section("Gravatar")
            h = hashlib.md5(target.lower().strip().encode()).hexdigest()
            r = safe_get(session, f"https://www.gravatar.com/{h}.json", timeout=10)
            if r.status_code == 200:
                entry = r.json().get("entry", [{}])[0]
                print_field(
                    "Имя",
                    entry.get("displayName")
                    or entry.get("name", {}).get("formatted", ""),
                )
                print_field("Ник", entry.get("preferredUsername"))
                print_field("Фото", entry.get("thumbnailUrl"))
                print_field("О себе", entry.get("aboutMe"))
                for u in entry.get("urls", [])[:3]:
                    print_field("Ссылка", u.get("value"))
                for acc in entry.get("accounts", [])[:5]:
                    print_field(f"Аккаунт ({acc.get('shortname', '')})", acc.get("url"))
            else:
                dual_print("  [–] Профиль не найден")
        except Exception as e:
            logger.debug(f"Gravatar error: {e}")
            dual_print(f"  [!] Gravatar: {e}")

    # ---------- EMAILREP.IO ----------
    def fetch_emailrep():
        try:
            print_section("EmailRep.io")
            key = API_KEYS.get("EMAILREP", "")
            hdr = {"Key": key} if key else {}
            r = safe_get(
                session,
                f"https://emailrep.io/{quote(target)}",
                timeout=12,
                headers={**session.headers, **hdr},
            )
            if r.status_code == 200:
                data = r.json()
                print_field("Репутация", data.get("reputation"))
                print_field("Профили", ", ".join(data.get("profiles", [])[:8]))
                det = data.get("details", {})
                print_field("Одноразовый", str(det.get("disposable")))
                print_field("Последняя утечка", det.get("last_seen"))
                results["Репутация"] = data.get("reputation", "")
        except Exception as e:
            logger.debug(f"EmailRep error: {e}")
            dual_print(f"  [!] EmailRep: {e}")

    # ---------- HIBP ----------
    def fetch_hibp():
        try:
            print_section("HaveIBeenPwned.com")
            r = safe_get(
                session,
                f"https://haveibeenpwned.com/account/{quote(target)}",
                timeout=15,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                items = soup.select('h4,.pwnedWebsite,[class*="breach"]')
                names = [
                    b.get_text(strip=True) for b in items if b.get_text(strip=True)
                ]
                dual_print(f"  [!] Утечек: {len(names)}")
                for n in names[:15]:
                    dual_print(f"    • {n}")
                results["Утечек (HIBP)"] = str(len(names))
            elif r.status_code == 404:
                dual_print("  [✓] Не найден в утечках")
        except Exception as e:
            logger.debug(f"HIBP error: {e}")
            dual_print(f"  [!] HIBP: {e}")

    # ---------- LEAKPEEK ----------
    def fetch_leakpeek():
        try:
            print_section("LeakPeek.com")
            r = safe_get(
                session,
                f"https://leakpeek.com/search?query={quote(target)}",
                timeout=15,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for ent in soup.select(".result-entry")[:5]:
                    dual_print(f"  {ent.get_text(strip=True)}")
        except Exception as e:
            logger.debug(f"LeakPeek error: {e}")
            dual_print(f"  [!] LeakPeek: {e}")

    # ---------- LULLAR ----------
    def fetch_lullar():
        try:
            print_section("Lullar.com")
            r = safe_get(session, f"https://www.lullar.com/{quote(target)}", timeout=12)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    if any(
                        s in href
                        for s in (
                            "twitter.com",
                            "facebook.com",
                            "linkedin.com",
                            "instagram.com",
                        )
                    ):
                        dual_print(f"  → {href}")
        except Exception as e:
            logger.debug(f"Lullar error: {e}")
            dual_print(f"  [!] Lullar: {e}")

    # ---------- THATSTHEM ----------
    def fetch_thatsthem():
        try:
            print_section("thatsthem.com")
            r = safe_get(
                session, f"https://thatsthem.com/email/{quote(target)}", timeout=12
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for el in soup.select(".ThatsThem-person,.person-card,.person-summary")[
                    :3
                ]:
                    dual_print(f"  {el.get_text(separator=' | ', strip=True)[:120]}")
        except Exception as e:
            logger.debug(f"thatsthem error: {e}")
            dual_print(f"  [!] thatsthem: {e}")

    # ---------- EPIEOS (SELENIUM) ----------
    def fetch_epieos():
        driver = None
        try:
            print_section("Epieos.com")
            from analyzers.username import build_chrome_driver

            driver = build_chrome_driver()
            driver.get(f"https://epieos.com/?q={quote(target)}&type=email")
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                from selenium.webdriver.common.by import By

                WebDriverWait(driver, 20).until(
                    EC.any_of(
                        EC.presence_of_element_located(
                            (By.CSS_SELECTOR, ".result,.account,.service,table")
                        ),
                        EC.presence_of_element_located((By.TAG_NAME, "table")),
                    )
                )
            except Exception:
                time.sleep(10)
            soup = BeautifulSoup(driver.page_source, "html.parser")
            for sel in [".name", ".display-name", "h2", "h3"]:
                el = soup.select_one(sel)
                if el and el.get_text(strip=True):
                    print_field("Имя (Google)", el.get_text(strip=True))
                    break
            services = soup.select('.service,.account-item,li.found,[class*="service"]')
            if services:
                dual_print(f"  Сервисы ({len(services)}):")
                for svc in services[:20]:
                    txt = svc.get_text(strip=True)
                    if txt:
                        dual_print(f"    • {txt}")
            for lnk in soup.find_all(
                "a",
                href=re.compile(
                    r"twitter|facebook|instagram|linkedin|github|youtube", re.I
                ),
            )[:6]:
                print_field("Соцсеть", lnk["href"])
        except Exception as e:
            logger.debug(f"Epieos error: {e}")
            dual_print(f"  [!] Epieos: {e}")
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    # ---------- НОВЫЕ: LEAK-LOOKUP, INTELX, FTH.SO ----------
    def fetch_leak_lookup():
        try:
            print_section("Leak-Lookup.com")
            r = safe_get(
                session,
                f"https://leak-lookup.com/api/search?query={quote(target)}",
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("found"):
                    dual_print(f"  [!] Найден в утечках (Leak-Lookup)")
                    for breach in data.get("breaches", [])[:5]:
                        dual_print(f"    • {breach}")
                    results["Leak-Lookup"] = "Найден"
                else:
                    dual_print("  [–] Не найден в Leak-Lookup")
        except Exception as e:
            logger.debug(f"Leak-Lookup error: {e}")
            dual_print(f"  [!] Leak-Lookup: {e}")

    def fetch_intelx():
        key = API_KEYS.get("INTELX")
        if not key:
            return
        try:
            print_section("IntelX.io")
            headers = {"X-Key": key, "Content-Type": "application/json"}
            payload = {
                "term": target,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": 10,
            }
            r = session.post(
                "https://2.intelx.io/intelligent/search",
                json=payload,
                headers=headers,
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("id"):
                    r2 = session.get(
                        f"https://2.intelx.io/intelligent/search/result?id={data['id']}",
                        headers=headers,
                        timeout=15,
                    )
                    if r2.status_code == 200:
                        result_data = r2.json()
                        records = result_data.get("records", [])
                        if records:
                            dual_print(f"  [!] Найдено {len(records)} записей в IntelX")
                            for rec in records[:5]:
                                dual_print(
                                    f"    • {rec.get('name', '')} - {rec.get('source', '')}"
                                )
                            results["IntelX"] = f"{len(records)} записей"
                        else:
                            dual_print("  [–] IntelX: ничего не найдено")
        except Exception as e:
            logger.debug(f"IntelX error: {e}")
            dual_print(f"  [!] IntelX: {e}")

    def fetch_fthso():
        try:
            print_section("fth.so")
            r = safe_get(
                session, f"https://fth.so/search?q={quote(target)}", timeout=12
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                items = soup.select(".result-item, .search-result, .entry")
                if items:
                    dual_print(f"  Найдено {len(items)} записей:")
                    for item in items[:5]:
                        txt = item.get_text(strip=True)
                        if txt:
                            dual_print(f"    • {txt[:100]}")
                    results["fth.so"] = f"{len(items)} записей"
                else:
                    dual_print("  [–] Ничего не найдено на fth.so")
        except Exception as e:
            logger.debug(f"fth.so error: {e}")
            dual_print(f"  [!] fth.so: {e}")

    # ---------- ПАРАЛЛЕЛЬНЫЙ ЗАПУСК (кроме epieos) ----------
    print_section("Параллельный сбор...")
    with ThreadPoolExecutor(max_workers=8) as executor:
        futs = [
            executor.submit(f)
            for f in (
                fetch_gravatar,
                fetch_emailrep,
                fetch_hibp,
                fetch_leakpeek,
                fetch_lullar,
                fetch_thatsthem,
                fetch_leak_lookup,
                fetch_intelx,
                fetch_fthso,
            )
        ]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"Email fetch error: {e}")

    # epieos запускаем отдельно (Selenium)
    fetch_epieos()

    # ---------- CLI ----------
    print_section("CLI")
    run_external_tool_with_parser("Holehe", ["holehe", target])
    run_external_tool_with_parser("Mosint", ["mosint", target])

    print_summary(results, f"Email {target}")
