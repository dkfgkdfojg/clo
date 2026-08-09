# analyzers/ip.py
import ipaddress
import re
from urllib.parse import quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger
from config import API_KEYS


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def analyze_ip_basic(ip_address_str):
    """
    Базовый анализ IP-адреса с использованием множества бесплатных сервисов:
      - ipwho.is
      - ip-api.com
      - ipinfo.io (с API-ключом)
      - AbuseIPDB
      - 2ip.ua
      - spys.ru
      - iknowwhatyoudownload.com (торренты)
      - bgpview.io (BGP/ASN)
      - proxydocker.com
      - ip2location.com (демо)
      - check-host.net (пинг из разных точек)
    """
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] IP: {ip_address_str}")
    dual_print(f"{'═' * 58}")
    if not validate_ip(ip_address_str):
        dual_print("  [!] Неверный IP.")
        return

    session = get_session()
    results = {}

    # ---------- 1. ipwho.is ----------
    def fetch_ipwho():
        try:
            print_section("ipwho.is")
            r = safe_get(session, f"https://ipwho.is/{ip_address_str}", timeout=12)
            d = r.json()
            if d.get("success"):
                print_field("Страна", f"{d.get('country')} ({d.get('country_code')})")
                print_field("Регион", d.get("region"))
                print_field("Город", d.get("city"))
                print_field("Координаты", f"{d.get('latitude')}, {d.get('longitude')}")
                conn = d.get("connection", {})
                print_field("ASN", str(conn.get("asn", "")))
                print_field("Провайдер", conn.get("isp"))
                sec = d.get("security", {})
                for k in ("vpn", "proxy", "tor", "hosting"):
                    if sec.get(k):
                        print_field(k.upper(), "ДА ⚠")
                results.update(
                    {
                        "Страна": f"{d.get('country')} ({d.get('country_code')})",
                        "Провайдер": conn.get("isp", ""),
                    }
                )
        except Exception as e:
            logger.debug(f"ipwho.is error: {e}")
            dual_print(f"  [!] ipwho.is: {e}")

    # ---------- 2. ip-api.com ----------
    def fetch_ipapi():
        try:
            print_section("ip-api.com")
            fields = (
                "status,message,country,countryCode,region,regionName,city,zip,"
                "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            )
            r = safe_get(
                session,
                f"http://ip-api.com/json/{ip_address_str}?fields={fields}&lang=ru",
                timeout=12,
            )
            d = r.json()
            if d.get("status") == "success":
                print_field("Страна", f"{d.get('country')} ({d.get('countryCode')})")
                print_field("Регион", d.get("regionName"))
                print_field("Город", d.get("city"))
                print_field("Часовой пояс", d.get("timezone"))
                print_field("Провайдер", d.get("isp"))
                print_field("AS", d.get("as"))
                print_field("rDNS", d.get("reverse"))
                for k in ("mobile", "proxy", "hosting"):
                    if d.get(k):
                        print_field(k.upper(), "ДА ⚠")
        except Exception as e:
            logger.debug(f"ip-api error: {e}")
            dual_print(f"  [!] ip-api.com: {e}")

    # ---------- 3. ipinfo.io ----------
    def fetch_ipinfo():
        try:
            print_section("ipinfo.io")
            key = API_KEYS.get("IPINFO", "")
            url = (
                f"https://ipinfo.io/{ip_address_str}?token={key}"
                if key
                else f"https://ipinfo.io/{ip_address_str}/json"
            )
            r = safe_get(session, url, timeout=12)
            d = r.json()
            print_field("Страна", d.get("country"))
            print_field("Регион", d.get("region"))
            print_field("Город", d.get("city"))
            print_field("Провайдер", d.get("org"))
            print_field("Hostname", d.get("hostname"))
            print_field("Timezone", d.get("timezone"))
            abuse = d.get("abuse", {})
            if abuse:
                print_field("Abuse email", abuse.get("email"))
        except Exception as e:
            logger.debug(f"ipinfo error: {e}")
            dual_print(f"  [!] ipinfo.io: {e}")

    # ---------- 4. AbuseIPDB ----------
    def fetch_abuseipdb():
        try:
            print_section("AbuseIPDB")
            r = safe_get(
                session, f"https://www.abuseipdb.com/check/{ip_address_str}", timeout=15
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for sel in [
                    ".abuseScore",
                    '[class*="abuse-score"]',
                    'span[class*="confidence"]',
                    ".progress-bar",
                ]:
                    el = soup.select_one(sel)
                    if el:
                        print_field("Abuse Score", el.get_text(strip=True))
                        results["Abuse Score"] = el.get_text(strip=True)
                        break
                reports = soup.find(string=re.compile(r"reported\s+\d+", re.I))
                if reports:
                    print_field("Жалоб", reports.strip())
        except Exception as e:
            logger.debug(f"AbuseIPDB error: {e}")
            dual_print(f"  [!] AbuseIPDB: {e}")

    # ---------- 5. 2ip.ua ----------
    def fetch_2ip():
        try:
            print_section("2ip.ua")
            r = safe_get(session, f"https://2ip.ua/ru/?ip={ip_address_str}", timeout=12)
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
            logger.debug(f"2ip error: {e}")
            dual_print(f"  [!] 2ip.ua: {e}")

    # ---------- 6. spys.ru ----------
    def fetch_spys():
        try:
            print_section("spys.ru")
            r = safe_get(
                session, f"http://spys.ru/geoip.php?ip={ip_address_str}", timeout=10
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                table = soup.find("table")
                if table:
                    for row in table.find_all("tr"):
                        cols = row.find_all("td")
                        if len(cols) == 2 and cols[0].text.strip():
                            print_field(cols[0].text.strip(), cols[1].text.strip())
        except Exception as e:
            logger.debug(f"spys error: {e}")
            dual_print(f"  [!] spys.ru: {e}")

    # ---------- 7. iknowwhatyoudownload.com ----------
    def fetch_iknow():
        try:
            print_section("iknowwhatyoudownload.com")
            r = safe_get(
                session,
                f"https://iknowwhatyoudownload.com/ru/peer/?ip={ip_address_str}",
                timeout=15,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                table = soup.find("table", class_="table")
                if table:
                    rows = table.find_all("tr")[1:]
                    if rows:
                        dual_print(f"  Загрузки ({min(len(rows), 5)}):")
                        for row in rows[:5]:
                            cols = row.find_all("td")
                            if len(cols) >= 4:
                                dual_print(
                                    f"    - {cols[1].text.strip()} ({cols[3].text.strip()})"
                                )
                        results["Торрент-загрузки"] = str(len(rows))
        except Exception as e:
            logger.debug(f"iknow error: {e}")
            dual_print(f"  [!] iknow: {e}")

    # ---------- 8. bgpview.io ----------
    def fetch_bgpview():
        try:
            print_section("bgpview.io (BGP/ASN)")
            r = safe_get(
                session, f"https://api.bgpview.io/ip/{ip_address_str}", timeout=12
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                pfxs = d.get("prefixes", [])
                if pfxs:
                    p = pfxs[0]
                    print_field("Prefix", p.get("prefix"))
                    asns = p.get("asns", [])
                    if asns:
                        a = asns[0]
                        print_field("ASN", str(a.get("asn", "")))
                        print_field("AS Name", a.get("name"))
                        print_field("Country", a.get("country_code"))
                        results["ASN"] = str(a.get("asn", ""))
        except Exception as e:
            logger.debug(f"bgpview error: {e}")
            dual_print(f"  [!] bgpview.io: {e}")

    # ---------- 9. proxydocker.com ----------
    def fetch_proxydocker():
        try:
            print_section("proxydocker.com")
            r = safe_get(
                session,
                f"https://www.proxydocker.com/en/iplookup/{ip_address_str}",
                timeout=10,
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                table = soup.find("table", class_="table-striped")
                if table:
                    for row in table.find_all("tr"):
                        ths = row.find_all("th")
                        tds = row.find_all("td")
                        if len(ths) == 1 and len(tds) == 1:
                            print_field(ths[0].text.strip(), tds[0].text.strip())
        except Exception as e:
            logger.debug(f"proxydocker error: {e}")
            dual_print(f"  [!] proxydocker: {e}")

    # ---------- 10. ip2location.com (демо) ----------
    def fetch_ip2location():
        try:
            print_section("ip2location.com (demo)")
            r = safe_get(
                session,
                f"https://api.ip2location.com/v2/?ip={ip_address_str}&key=demo",
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                print_field("Страна (IP2L)", data.get("country_name"))
                print_field("Город (IP2L)", data.get("city_name"))
                print_field("Регион (IP2L)", data.get("region_name"))
                print_field("ISP (IP2L)", data.get("isp"))
                results["IP2Location"] = (
                    f"{data.get('country_name')}, {data.get('city_name')}"
                )
        except Exception as e:
            logger.debug(f"IP2Location error: {e}")
            dual_print(f"  [!] IP2Location: {e}")

    # ---------- 11. check-host.net ----------
    def fetch_checkhost():
        try:
            print_section("check-host.net (ping)")
            r = safe_get(
                session,
                f"https://check-host.net/check-ping?host={ip_address_str}",
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                nodes = data.get("nodes", {})
                if nodes:
                    dual_print(f"  Проверено узлов: {len(nodes)}")
                    for node, results_list in list(nodes.items())[:5]:
                        status = results_list[0] if results_list else "нет ответа"
                        dual_print(f"    • {node}: {status}")
        except Exception as e:
            logger.debug(f"Check-Host error: {e}")
            dual_print(f"  [!] Check-Host: {e}")

    def fetch_internetdb():
        """Shodan InternetDB — открытые порты, хосты, теги, CVE. Без ключа."""
        try:
            print_section("Shodan InternetDB")
            r = safe_get(session, f"https://internetdb.shodan.io/{ip_address_str}", timeout=12)
            if r.status_code == 404:
                dual_print("  [–] Нет данных в InternetDB.")
                return
            if r.status_code != 200:
                dual_print(f"  [!] InternetDB: {r.status_code}")
                return
            d = r.json()
            ports = d.get("ports", [])
            if ports:
                print_field("Открытые порты", ", ".join(str(p) for p in ports))
                results["Открытые порты"] = ", ".join(str(p) for p in ports)
            if d.get("hostnames"):
                print_field("Хосты", ", ".join(d["hostnames"]))
            if d.get("tags"):
                print_field("Теги", ", ".join(d["tags"]))
            if d.get("cpes"):
                print_field("CPE (софт)", ", ".join(d["cpes"][:8]))
            vulns = d.get("vulns", [])
            if vulns:
                print_field("Уязвимости (CVE)", ", ".join(vulns[:15]))
                results["CVE"] = ", ".join(vulns[:15])
        except Exception as e:
            logger.debug(f"InternetDB error: {e}")
            dual_print(f"  [!] InternetDB: {e}")

    # ---------- ПАРАЛЛЕЛЬНЫЙ ЗАПУСК ----------
    print_section("Параллельный сбор данных...")
    funcs = [
        fetch_internetdb,
        fetch_ipwho,
        fetch_ipapi,
        fetch_ipinfo,
        fetch_abuseipdb,
        fetch_2ip,
        fetch_spys,
        fetch_iknow,
        fetch_bgpview,
        fetch_proxydocker,
        fetch_ip2location,
        fetch_checkhost,
    ]
    with ThreadPoolExecutor(max_workers=len(funcs)) as ex:
        futs = [ex.submit(f) for f in funcs]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"IP fetch error: {e}")

    print_summary(results, f"IP {ip_address_str}")


def analyze_shodan_smart(target):
    """
    Анализ через Shodan (требуется API-ключ):
      - если передан IP – вызывает analyze_ip_basic и затем Shodan Host
      - если передан домен – собирает поддомены и разрешает их
    """
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] SHODAN: {target}")
    dual_print(f"{'═' * 58}")
    key = API_KEYS.get("SHODAN")
    if not key:
        dual_print("  [!] Нет ключа SHODAN.")
        if validate_ip(target):
            analyze_ip_basic(target)
        return

    session = get_session()

    if validate_ip(target):
        analyze_ip_basic(target)
        try:
            print_section("Shodan Host")
            r = safe_get(
                session,
                f"https://api.shodan.io/shodan/host/{target}?key={key}",
                timeout=20,
            )
            if r.status_code == 200:
                d = r.json()
                print_field("ОС", d.get("os", "—"))
                print_field("Страна", d.get("country_name"))
                print_field("Организация", d.get("org"))
                print_field("ISP", d.get("isp"))
                print_field("Hostnames", ", ".join(d.get("hostnames", [])))
                print_field("Домены", ", ".join(d.get("domains", [])))
                vulns = d.get("vulns", [])
                if vulns:
                    dual_print(f"\n  Уязвимости ({len(vulns)}):")
                    for v in list(vulns)[:10]:
                        dual_print(f"    • {v}")
                ports = d.get("ports", [])
                if ports:
                    dual_print(f"\n  Порты: {', '.join(map(str, sorted(ports)))}")
                for svc in d.get("data", [])[:8]:
                    port = svc.get("port", "?")
                    proto = svc.get("transport", "tcp")
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    banner = (svc.get("data", "") or "").strip()[:80]
                    line = f"    [{port}/{proto}]"
                    if product:
                        line += f" {product}"
                    if version:
                        line += f" {version}"
                    dual_print(line)
                    if banner:
                        dual_print(f"      Баннер: {banner}")
            elif r.status_code == 404:
                dual_print("  [–] IP не в базе Shodan")
        except Exception as e:
            logger.debug(f"Shodan Host error: {e}")
            dual_print(f"  [!] Shodan Host: {e}")
    elif "." in target:
        try:
            print_section("Shodan DNS")
            r = safe_get(
                session,
                f"https://api.shodan.io/dns/domain/{target}?key={key}",
                timeout=20,
            )
            if r.status_code == 200:
                d = r.json()
                subs = d.get("subdomains", [])
                print_field("Субдоменов", str(len(subs)))
                for s in subs[:20]:
                    dual_print(f"    • {s}.{target}")
                r2 = safe_get(
                    session,
                    f"https://api.shodan.io/dns/resolve?hostnames={target}&key={key}",
                    timeout=15,
                )
                if r2.status_code == 200:
                    for host, ip in r2.json().items():
                        print_field(host, ip)
                        analyze_shodan_smart(ip)
        except Exception as e:
            logger.debug(f"Shodan DNS error: {e}")
            dual_print(f"  [!] Shodan DNS: {e}")
