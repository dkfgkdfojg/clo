# analyzers/domain.py
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger
from core.verify import doh
from core.cache import cached_json


def _fetch_rdap(session, domain, results):
    """RDAP — официальная замена WHOIS, отдаёт JSON без ключа и без блокировок."""
    print_section("RDAP (регистрация)")
    d = cached_json(session, f"https://rdap.org/domain/{domain}", ttl=3600, timeout=12)
    if not d:
        dual_print("  [!] RDAP: нет данных.")
        return
    event_names = {
        "registration": "Создан",
        "expiration": "Истекает",
        "last changed": "Изменён",
    }
    for ev in d.get("events", []):
        label = event_names.get(ev.get("eventAction"))
        if label:
            print_field(label, ev.get("eventDate"))
            results[label] = ev.get("eventDate")
    status = d.get("status")
    if status:
        print_field("Статус", ", ".join(status))
    ns = [n.get("ldhName") for n in d.get("nameservers", []) if n.get("ldhName")]
    if ns:
        print_field("NS-серверы", ", ".join(ns))
        results["NS"] = ", ".join(ns)
    for ent in d.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [None, []])[1]
            for item in vcard:
                if item[0] == "fn":
                    print_field("Регистратор", item[3])
                    results["Регистратор"] = item[3]


def _fetch_dns(session, domain, results):
    """A/AAAA/MX/NS/TXT/SOA через DNS over HTTPS."""
    print_section("DNS-записи")
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        recs = doh(domain, rtype, session)
        if recs:
            shown = recs[:6]
            print_field(rtype, "; ".join(shown) + (" …" if len(recs) > 6 else ""))
            if rtype in ("A", "MX"):
                results[rtype] = "; ".join(shown)


def _fetch_crtsh_json(session, domain, results):
    """Сабдомены из Certificate Transparency (crt.sh JSON) — надёжнее HTML-скрейпа."""
    print_section("crt.sh — сабдомены (CT-логи)")
    data = cached_json(session, f"https://crt.sh/?q=%25.{domain}&output=json",
                       ttl=1800, timeout=20)
    if not data:
        dual_print("  [!] crt.sh: нет данных (часто 502 на их стороне).")
        return
    subs = set()
    for row in data:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain) and "@" not in name:
                subs.add(name)
    if subs:
        dual_print(f"  Уникальных поддоменов: {len(subs)}")
        for s in sorted(subs)[:40]:
            dual_print(f"    • {s}")
        results["Поддоменов (CT)"] = len(subs)
    else:
        dual_print("  [–] Ничего не найдено")


def _fetch_extra_subdomains(session, domain, results):
    """Доп. источники сабдоменов: hackertarget + threatminer. Объединяем и дедупим."""
    print_section("Сабдомены (hackertarget + threatminer)")
    subs = set()
    # hackertarget: CSV "host,ip" (free-лимит ~50/день)
    try:
        r = safe_get(session, f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r.status_code == 200 and "API count exceeded" not in r.text:
            for line in r.text.splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith(domain):
                    subs.add(host)
    except Exception as e:
        logger.debug("hackertarget: %s", e)
    # threatminer: JSON
    try:
        r = safe_get(session, f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=15)
        if r.status_code == 200:
            for host in r.json().get("results", []):
                host = str(host).strip().lower()
                if host.endswith(domain):
                    subs.add(host)
    except Exception as e:
        logger.debug("threatminer: %s", e)

    if subs:
        dual_print(f"  Уникальных поддоменов: {len(subs)}")
        for s in sorted(subs)[:40]:
            dual_print(f"    • {s}")
        results["Поддоменов (доп.)"] = len(subs)
    else:
        dual_print("  [–] Ничего не найдено")


def _fetch_urlscan(session, domain, results):
    """urlscan.io — публичные сканы домена: связанные IP, страны, скриншоты."""
    print_section("urlscan.io")
    try:
        r = safe_get(
            session,
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20",
            timeout=15,
        )
    except Exception as e:
        dual_print(f"  [!] urlscan: {e}")
        return
    if r.status_code != 200:
        dual_print(f"  [!] urlscan: {r.status_code}")
        return
    hits = r.json().get("results", [])
    if not hits:
        dual_print("  [–] Сканов нет.")
        return
    dual_print(f"  Найдено сканов: {len(hits)}")
    ips, servers = set(), set()
    for h in hits:
        page = h.get("page", {})
        if page.get("ip"):
            ips.add(page["ip"])
        if page.get("server"):
            servers.add(page["server"])
    if ips:
        print_field("Связанные IP", ", ".join(sorted(ips)[:10]))
        results["IP (urlscan)"] = ", ".join(sorted(ips)[:10])
    if servers:
        print_field("Серверы", ", ".join(sorted(servers)[:6]))
    last = hits[0].get("task", {}).get("url")
    if last:
        print_field("Последний скан", last)


def _fetch_wayback(session, domain, results):
    """Web Archive: сколько снимков и когда домен впервые/последний раз попал в архив."""
    print_section("Wayback Machine")
    try:
        r = safe_get(
            session,
            f"http://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain"
            f"&output=json&fl=timestamp,original&collapse=urlkey&limit=50000",
            timeout=20,
        )
    except Exception as e:
        dual_print(f"  [!] Wayback: {e}")
        return
    if r.status_code != 200:
        dual_print(f"  [!] Wayback: {r.status_code}")
        return
    rows = r.json()
    if len(rows) <= 1:
        dual_print("  [–] Снимков нет.")
        return
    data = rows[1:]  # первая строка — заголовки
    stamps = sorted(row[0] for row in data if row and row[0])

    def _fmt(ts):
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"

    print_field("Уникальных URL в архиве", str(len(data)))
    if stamps:
        print_field("Первый снимок", _fmt(stamps[0]))
        print_field("Последний снимок", _fmt(stamps[-1]))
        results["Архив (URL)"] = str(len(data))


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

    # ---------- ПАРАЛЛЕЛЬНЫЙ ЗАПУСК ----------
    # Надёжные JSON-источники. Старые HTML-скрейперы (DomainTools/DNSdumpster/
    # SecurityTrails/crt.sh-HTML) убраны: они режут ботов и почти всегда пустые.
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = [
            ex.submit(_fetch_rdap, session, domain, results),
            ex.submit(_fetch_dns, session, domain, results),
            ex.submit(_fetch_crtsh_json, session, domain, results),
            ex.submit(_fetch_extra_subdomains, session, domain, results),
            ex.submit(_fetch_urlscan, session, domain, results),
            ex.submit(_fetch_wayback, session, domain, results),
        ]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"Domain fetch error: {e}")

    print_summary(results, f"Домен {domain}")
