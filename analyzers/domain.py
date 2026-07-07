# analyzers/domain.py
import re
from urllib.parse import quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger


def analyze_domain(domain):
    """
    Анализ домена:
      - WHOIS (через whois.domaintools.com)
      - Поддомены (DNSdumpster)
      - SSL-сертификаты (crt.sh)
      - История DNS (SecurityTrails)
    """
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] ДОМЕН: {domain}")
    dual_print(f"{'═' * 58}")

    session = get_session()
    results = {}

    # ---------- 1. WHOIS ----------
    def fetch_whois():
        try:
            print_section("Whois (DomainTools)")
            r = safe_get(session, f"https://whois.domaintools.com/{domain}", timeout=15)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for block in soup.select(".whois-record, .record"):
                    label = block.select_one(".label")
                    value = block.select_one(".value")
                    if label and value:
                        lbl = label.text.strip()
                        val = value.text.strip()
                        if lbl and val:
                            print_field(lbl, val)
                            results[lbl] = val
        except Exception as e:
            logger.debug(f"Whois error: {e}")
            dual_print(f"  [!] Whois: {e}")

    # ---------- 2. DNSDUMPSTER (поддомены) ----------
    def fetch_dnsdumpster():
        try:
            print_section("DNSdumpster")
            r = safe_get(session, f"https://dnsdumpster.com/?q={domain}", timeout=15)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                table = soup.select_one("table#results")
                if table:
                    rows = table.find_all("tr")
                    subdomains = []
                    for row in rows[1:]:
                        cells = row.find_all("td")
                        if len(cells) >= 2:
                            sub = cells[0].text.strip()
                            if sub:
                                subdomains.append(sub)
                    if subdomains:
                        dual_print(f"  Поддомены ({len(subdomains)}):")
                        for sub in subdomains[:20]:
                            dual_print(f"    • {sub}")
                        results["subdomains"] = len(subdomains)
                    else:
                        dual_print("  [–] Поддомены не найдены")
        except Exception as e:
            logger.debug(f"DNSdumpster error: {e}")
            dual_print(f"  [!] DNSdumpster: {e}")

    # ---------- 3. CRT.SH (сертификаты) ----------
    def fetch_crtsh():
        try:
            print_section("crt.sh")
            r = safe_get(session, f"https://crt.sh/?q={domain}", timeout=15)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                table = soup.select_one("table")
                if table:
                    rows = table.find_all("tr")[1:]  # пропускаем заголовок
                    certs = []
                    for row in rows:
                        cells = row.find_all("td")
                        if len(cells) >= 5:
                            name = cells[4].text.strip()
                            if name:
                                certs.append(name)
                    if certs:
                        dual_print(f"  Сертификатов найдено: {len(certs)}")
                        for cert in certs[:10]:
                            dual_print(f"    • {cert}")
                        results["certs"] = len(certs)
                    else:
                        dual_print("  [–] Сертификаты не найдены")
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
            dual_print(f"  [!] crt.sh: {e}")

    # ---------- 4. SECURITYTRAILS (история DNS) ----------
    def fetch_securitytrails():
        try:
            print_section("SecurityTrails")
            r = safe_get(
                session,
                f"https://securitytrails.com/domain/{domain}/history",
                timeout=15,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for record in soup.select(".record, .dns-record"):
                    txt = record.get_text(strip=True)
                    if txt:
                        dual_print(f"  {txt[:120]}")
        except Exception as e:
            logger.debug(f"SecurityTrails error: {e}")
            dual_print(f"  [!] SecurityTrails: {e}")

    # ---------- ПАРАЛЛЕЛЬНЫЙ ЗАПУСК ----------
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = [
            ex.submit(fetch_whois),
            ex.submit(fetch_dnsdumpster),
            ex.submit(fetch_crtsh),
            ex.submit(fetch_securitytrails),
        ]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"Domain fetch error: {e}")

    print_summary(results, f"Домен {domain}")
