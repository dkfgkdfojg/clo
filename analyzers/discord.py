# analyzers/discord.py
"""
Discord ID analysis module.

Features:
  - Snowflake decoding (creation date, worker, process, increment)
  - Profile scanning (discord-sensor.com, discord-tracker.com, discord.id,
    discordlookup.com, discordrep.com, discord.bio)
  - Username history (local tracker + HTML scraping of tracker sites)
  - Server/guild enumeration (disboard.org, top.gg)
  - Data-leak searching (LeakCheck API, Snusbase API)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import API_KEYS
from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger

DISCORD_API = "https://discord.com/api/v10"

# public_flags → бейджи. Основной источник «настоящих» данных об аккаунте.
PUBLIC_FLAGS = {
    1 << 0: "Discord Staff",
    1 << 1: "Partner",
    1 << 2: "HypeSquad Events",
    1 << 3: "Bug Hunter (Level 1)",
    1 << 6: "HypeSquad Bravery",
    1 << 7: "HypeSquad Brilliance",
    1 << 8: "HypeSquad Balance",
    1 << 9: "Early Supporter",
    1 << 14: "Bug Hunter (Level 2)",
    1 << 16: "Verified Bot",
    1 << 17: "Early Verified Bot Developer",
    1 << 18: "Certified Moderator",
    1 << 22: "Active Developer",
}


def _decode_flags(flags: int) -> list[str]:
    return [name for bit, name in PUBLIC_FLAGS.items() if flags & bit]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DISCORD_EPOCH_MS: int = 1420070400000
MAX_THREAD_WORKERS: int = 10
MAX_HISTORY_ENTRIES: int = 20
MAX_SERVER_ENTRIES: int = 10

# Snowflake bit masks
WORKER_ID_MASK: int = 0x3E0000
PROCESS_ID_MASK: int = 0x1F000
INCREMENT_MASK: int = 0xFFF

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class DiscordEndpoints:
    """All remote endpoints used during Discord analysis."""

    sensor: str = "https://discord-sensor.com/members/{user_id}"
    tracker: str = "https://discord-tracker.com/user/{user_id}"
    discord_id: str = "https://discord.id/?id={user_id}"
    discord_lookup: str = "https://discordlookup.com/user/{user_id}"
    discord_rep: str = "https://discordrep.com/u/{user_id}"
    discord_bio: str = "https://discord.bio/user/{user_id}"
    leakcheck: str = "https://leakcheck.net/api/public?check={user_id}"
    snusbase: str = "https://snusbase.com/search"
    disboard: str = "https://disboard.org/profile/{user_id}"
    topgg: str = "https://top.gg/api/bots/{user_id}"

    # Local username-history tracker (optional)
    local_history: str = "http://127.0.0.1:9999/api/history/{user_id}"


# ---------------------------------------------------------------------------
# Snowflake parsing
# ---------------------------------------------------------------------------


@dataclass
class SnowflakeInfo:
    creation_utc: str
    worker_id: int
    process_id: int
    increment: int

    @classmethod
    def from_id(cls, user_id: str) -> SnowflakeInfo | None:
        """Decode a Discord snowflake from its string representation."""
        if not user_id.isdigit():
            return None
        try:
            sf = int(user_id)
            ts = (sf >> 22) + DISCORD_EPOCH_MS
            created = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            worker = (sf & WORKER_ID_MASK) >> 17
            process = (sf & PROCESS_ID_MASK) >> 12
            increment = sf & INCREMENT_MASK
            return cls(
                creation_utc=created.strftime("%Y-%m-%d %H:%M:%S"),
                worker_id=worker,
                process_id=process,
                increment=increment,
            )
        except (ValueError, OverflowError) as exc:
            logger.debug("Snowflake decode error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _try_text(
    soup: BeautifulSoup,
    selectors: list[str] | tuple[str, ...],
    *,
    strip: bool = True,
) -> str | None:
    """Return the text of the first matching CSS selector, or None."""
    for sel in selectors:
        el = soup.select_one(sel)
        if el:
            txt = el.get_text(strip=strip)
            if txt:
                return txt
    return None


def _try_img(
    soup: BeautifulSoup,
    selectors: list[str] | tuple[str, ...],
    attr: str = "src",
) -> str | None:
    """Return the attribute value of the first matching image element."""
    for sel in selectors:
        el = soup.select_one(sel)
        if el and el.get(attr):
            return el[attr]
    return None


# ---------------------------------------------------------------------------
# Username-history scrapers (guaranteed to work — no API keys, just HTML)
# ---------------------------------------------------------------------------


def _scrape_tracker_history(
    session: Any, user_id: str, endpoints: DiscordEndpoints
) -> list[str]:
    """
    Scrape username history from discord-tracker.com via HTML parsing.
    This is the most reliable source — works without any API key.
    """
    names: list[str] = []
    try:
        r = safe_get(session, endpoints.tracker.format(user_id=user_id), timeout=15)
        if r.status_code != 200:
            logger.debug("tracker page returned %s", r.status_code)
            return names

        soup = BeautifulSoup(r.text, "html.parser")

        # Strategy 1: look for structured history containers
        selectors = [
            ".name-history li",
            ".history li",
            ".previous-names li",
            ".name-history span",
            ".history span",
            '[class*="history"] li',
            '[class*="previous"] li',
            "table.name-history td",
            "table.history td",
            ".names-history li",
        ]
        for sel in selectors:
            elements = soup.select(sel)
            if elements:
                for el in elements:
                    txt = el.get_text(strip=True)
                    if txt and txt not in names:
                        names.append(txt)
                if names:
                    break

        # Strategy 2: fallback — scan all text for "→" or "▸" prefixed items
        if not names:
            for el in soup.find_all(["li", "span", "div", "p"]):
                txt = el.get_text(strip=True)
                if txt and (
                    txt.startswith("→") or txt.startswith("▸") or txt.startswith(">")
                ):
                    candidate = txt.lstrip("→▸> ").strip()
                    if candidate and candidate not in names:
                        names.append(candidate)

        # Strategy 3: scan tables that reference "name" / "username"
        if not names:
            for table in soup.find_all("table"):
                for row in table.find_all("tr"):
                    cells = row.find_all("td")
                    if len(cells) >= 1:
                        val = cells[0].get_text(strip=True)
                        if val and val not in names and len(val) > 2:
                            names.append(val)

        logger.debug("scraped %d names from tracker HTML", len(names))
    except Exception as exc:
        logger.debug("tracker HTML scrape error: %s", exc)

    return names


def _scrape_lookup_history(
    session: Any, user_id: str, endpoints: DiscordEndpoints
) -> list[str]:
    """
    Scrape username history from discordlookup.com via HTML parsing.
    """
    names: list[str] = []
    try:
        r = safe_get(
            session, endpoints.discord_lookup.format(user_id=user_id), timeout=12
        )
        if r.status_code != 200:
            return names

        soup = BeautifulSoup(r.text, "html.parser")

        # Look for "Previous Names", "Username History" sections
        for dt in soup.find_all(["dt", "th", "strong", "b"]):
            label = dt.get_text(strip=True)
            if re.search(r"prev|hist|old|past|name", label, re.I):
                dd = dt.find_next_sibling(["dd", "td", "span"])
                if dd:
                    val = dd.get_text(strip=True)
                    if val:
                        # Could be comma-separated or list
                        for part in re.split(r"[,\n;]", val):
                            part = part.strip()
                            if part and part not in names:
                                names.append(part)

        # Generic list scanning
        for el in soup.select("li, [class*='prev'], [class*='hist']"):
            txt = el.get_text(strip=True)
            if txt and txt not in names and len(txt) > 1 and ":" not in txt:
                # Filter out obvious non-usernames
                if not re.match(r"^\d+$", txt) and len(txt) < 50:
                    names.append(txt)

        logger.debug("scraped %d names from lookup HTML", len(names))
    except Exception as exc:
        logger.debug("lookup HTML scrape error: %s", exc)

    return names


def _scrape_sensor_history(
    session: Any, user_id: str, endpoints: DiscordEndpoints
) -> list[str]:
    """
    Scrape username history from discord-sensor.com via HTML parsing.
    """
    names: list[str] = []
    try:
        r = safe_get(session, endpoints.sensor.format(user_id=user_id), timeout=15)
        if r.status_code != 200:
            return names

        soup = BeautifulSoup(r.text, "html.parser")

        selectors = [
            ".name-history li",
            ".prevnames li",
            '[class*="prev"] li',
            '[class*="history"] li',
            ".username-history li",
        ]
        for sel in selectors:
            elements = soup.select(sel)
            if elements:
                for el in elements:
                    txt = el.get_text(strip=True)
                    if txt and txt not in names:
                        names.append(txt)
                if names:
                    break

        logger.debug("scraped %d names from sensor HTML", len(names))
    except Exception as exc:
        logger.debug("sensor HTML scrape error: %s", exc)

    return names


# ---------------------------------------------------------------------------
# Data-source fetchers
# ---------------------------------------------------------------------------


def _print_history_block(
    source_name: str, names: list[str], seen: set[str], limit: int = MAX_HISTORY_ENTRIES
) -> int:
    """Print history entries that are new relative to `seen`.

    Учитывает имена, ещё не встречавшиеся в других источниках (глобальный `seen`),
    дедуплицирует внутри блока и печатает не более `limit` строк.
    Возвращает число новых уникальных имён и обновляет `seen`.
    """
    if not names:
        dual_print(f"  [–] {source_name}: пусто")
        return 0

    # Отбираем только имена, новые относительно seen, с сохранением порядка
    new_names: list[str] = []
    block_seen: set[str] = set()
    for name in names:
        key = name.lower().strip()
        if not key or key in seen or key in block_seen:
            continue
        block_seen.add(key)
        new_names.append(name)

    if not new_names:
        dual_print(f"  [–] {source_name}: нет новых имён")
        return 0

    seen.update(block_seen)

    dual_print(f"  [+] {source_name} (+{len(new_names)}):")
    for name in new_names[:limit]:
        dual_print(f"    → {name}")

    return len(new_names)


def _fetch_sensor(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Retrieve basic profile info from discord-sensor.com."""
    try:
        print_section("discord-sensor.com")
        r = safe_get(session, endpoints.sensor.format(user_id=user_id), timeout=15)
        if r.status_code != 200:
            dual_print(f"  [–] Discord Sensor: {r.status_code}")
            return

        soup = BeautifulSoup(r.text, "html.parser")
        username = _try_text(
            soup, ["h1", "h2", ".username", ".name", '[class*="user"]']
        )
        if username:
            print_field("Username", username)
            results["Username (sensor)"] = username

        avatar = _try_img(
            soup,
            ['img[src*="cdn.discordapp"]', "img.avatar", '[class*="avatar"] img'],
        )
        if avatar:
            print_field("Аватар", avatar)

        for el in soup.find_all(["span", "div", "p"]):
            txt = el.get_text(strip=True)
            if re.match(r"^\d[\d\s,]+$", txt):
                ctx = el.parent.get_text(strip=True) if el.parent else ""
                if 5 < len(ctx) < 80:
                    dual_print(f"    {ctx}")
    except Exception as exc:
        logger.debug("Discord Sensor error: %s", exc)
        dual_print(f"  [!] Discord Sensor: {exc}")


def _fetch_tracker(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Retrieve profile info from discord-tracker.com."""
    try:
        print_section("discord-tracker.com")
        r = safe_get(session, endpoints.tracker.format(user_id=user_id), timeout=15)
        if r.status_code != 200:
            dual_print(f"  [–] discord-tracker: {r.status_code}")
            return

        soup = BeautifulSoup(r.text, "html.parser")
        name = _try_text(soup, ["h1", "h2", "h3", ".username", '[class*="name"]'])
        if name:
            print_field("Имя", name)
            results["Имя (tracker)"] = name

        # Servers
        for ss_path in [
            ".servers li",
            ".guilds li",
            '[class*="server"] li',
            '[class*="guild"] li',
        ]:
            srvs = soup.select(ss_path)
            if srvs:
                entries = [
                    s.get_text(strip=True) for s in srvs if s.get_text(strip=True)
                ]
                if entries:
                    dual_print(f"  Серверы ({len(entries)}):")
                    for entry in entries[:MAX_SERVER_ENTRIES]:
                        dual_print(f"    ◉ {entry}")
                break

        for kw in ("last seen", "последний", "active"):
            el = soup.find(string=re.compile(kw, re.I))
            if el and el.parent:
                print_field("Активность", el.parent.get_text(strip=True)[:80])
                break
    except Exception as exc:
        logger.debug("Discord Tracker error: %s", exc)
        dual_print(f"  [!] discord-tracker: {exc}")


def _fetch_discord_id(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Retrieve username from discord.id."""
    try:
        print_section("discord.id")
        r = safe_get(session, endpoints.discord_id.format(user_id=user_id), timeout=10)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("title")
            if title:
                username = title.text.strip()
                print_field("Username", username)
                results["Username (discord.id)"] = username
    except Exception as exc:
        logger.debug("discord.id error: %s", exc)
        dual_print(f"  [!] discord.id: {exc}")


def _fetch_discord_lookup(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Retrieve detailed infos from discordlookup.com."""
    try:
        print_section("discordlookup.com")
        r = safe_get(
            session, endpoints.discord_lookup.format(user_id=user_id), timeout=12
        )
        if r.status_code != 200:
            return

        soup = BeautifulSoup(r.text, "html.parser")
        for label_el in soup.find_all(["dt", "th", "strong", "b"]):
            val_el = label_el.find_next_sibling(["dd", "td", "span"])
            if label_el.get_text(strip=True) and val_el and val_el.get_text(strip=True):
                lbl = label_el.get_text(strip=True)
                val = val_el.get_text(strip=True)[:80]
                print_field(lbl, val)
                results[lbl] = val
    except Exception as exc:
        logger.debug("discordlookup error: %s", exc)
        dual_print(f"  [!] discordlookup: {exc}")


def _fetch_discord_rep(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Retrieve reputation data from discordrep.com."""
    try:
        print_section("discordrep.com (репутация)")
        r = safe_get(session, endpoints.discord_rep.format(user_id=user_id), timeout=12)
        if r.status_code != 200:
            return

        soup = BeautifulSoup(r.text, "html.parser")
        rep = _try_text(
            soup,
            [".reputation", ".rep-score", ".trust", '[class*="rep"]', "h2", "h3"],
        )
        if rep:
            print_field("Репутация", rep)

        for score_el in soup.select('.score, [class*="score"]')[:3]:
            dual_print(f"    {score_el.get_text(strip=True)}")
    except Exception as exc:
        logger.debug("discordrep error: %s", exc)
        dual_print(f"  [!] discordrep: {exc}")


def _fetch_leaks(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Search for the ID in known breach databases."""
    try:
        print_section("Поиск в утечках")

        r = safe_get(session, endpoints.leakcheck.format(user_id=user_id), timeout=12)
        if r.status_code == 200:
            data: dict = r.json()
            if data.get("found"):
                dual_print("  [!] Найден в утечках LeakCheck!")
                for item in data.get("sources", [])[:5]:
                    dual_print(f"    • {item}")
                results["Утечки (LeakCheck)"] = "Найден"
            else:
                dual_print("  [–] В базе LeakCheck не найден")

        r2 = safe_get(
            session,
            endpoints.snusbase,
            timeout=12,
            headers={"Content-Type": "application/json"},
            json={"term": user_id, "type": "username"},
        )
        if r2 and r2.status_code == 200:
            data2: dict = r2.json()
            if data2.get("results"):
                dual_print("  [!] Найден в базе Snusbase!")
                results["Утечки (Snusbase)"] = "Найден"
    except Exception as exc:
        logger.debug("Leak check error: %s", exc)
        dual_print(f"  [!] Поиск в утечках: {exc}")


def _fetch_server_list(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Try to find what servers/guilds the user is on."""
    try:
        print_section("Серверы / гильдии пользователя")

        r = safe_get(session, endpoints.disboard.format(user_id=user_id), timeout=12)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            servers = soup.select('.server-name, .guild-name, [class*="server"], h3')
            if servers:
                entries = [
                    s.get_text(strip=True) for s in servers if s.get_text(strip=True)
                ]
                dual_print(f"  Серверы (disboard) — {len(entries)}:")
                for entry in entries[:MAX_SERVER_ENTRIES]:
                    dual_print(f"    ◉ {entry}")
            else:
                dual_print("  [–] Серверы не найдены на disboard")

        r2 = safe_get(session, endpoints.topgg.format(user_id=user_id), timeout=10)
        if r2.status_code == 200:
            data: dict = r2.json()
            print_field("Бот (top.gg)", data.get("username", ""))
            print_field("Серверов (бот)", str(data.get("server_count", "")))
            results["Это бот (top.gg)"] = data.get("username", "")
    except Exception as exc:
        logger.debug("Server list error: %s", exc)
        dual_print(f"  [!] Серверы: {exc}")


def _fetch_discord_bio(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """Retrieve bio and social links from discord.bio."""
    try:
        print_section("discord.bio")
        r = safe_get(session, endpoints.discord_bio.format(user_id=user_id), timeout=10)
        if r.status_code != 200:
            return

        soup = BeautifulSoup(r.text, "html.parser")
        bio = soup.select_one(".bio")
        if bio:
            print_field("Bio (discord.bio)", bio.text.strip())
            results["bio"] = bio.text.strip()

        for link in soup.select(".social-links a"):
            href = link.get("href")
            if href:
                print_field("Соцсеть (bio)", href)
    except Exception as exc:
        logger.debug("discord.bio error: %s", exc)
        dual_print(f"  [!] discord.bio: {exc}")


def _fetch_username_history(
    session: Any, user_id: str, endpoints: DiscordEndpoints, results: dict[str, str]
) -> None:
    """
    Collect username history from guaranteed-to-work HTML sources.
    No API keys, no tokens — pure web scraping.
    """
    try:
        print_section("История ников / старые имена")
        seen: set[str] = set()
        total_new = 0

        # ---- SOURCE 1: Local tracker ----
        local_names: list[str] = []
        try:
            r = safe_get(
                session,
                endpoints.local_history.format(user_id=user_id),
                timeout=3,
            )
            if r and r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    local_names = [str(e).strip() for e in data if e]
                elif isinstance(data, dict):
                    # FLEXIBLE: scan for any list-like field
                    for val in data.values():
                        if isinstance(val, list):
                            local_names = [str(v).strip() for v in val if v]
                            break
        except Exception:
            pass

        n = _print_history_block("Локальный трекер", local_names, seen)
        total_new += n

        # ---- SOURCE 2: discord-tracker.com HTML ----
        tracker_names = _scrape_tracker_history(session, user_id, endpoints)
        n = _print_history_block("discord-tracker.com", tracker_names, seen)
        total_new += n

        # ---- SOURCE 3: discordlookup.com HTML ----
        lookup_names = _scrape_lookup_history(session, user_id, endpoints)
        n = _print_history_block("discordlookup.com", lookup_names, seen)
        total_new += n

        # ---- SOURCE 4: discord-sensor.com HTML ----
        sensor_names = _scrape_sensor_history(session, user_id, endpoints)
        n = _print_history_block("discord-sensor.com", sensor_names, seen)
        total_new += n

        # ---- Summary ----
        if total_new > 0:
            results["Ников в истории (уникальных)"] = str(len(seen))
            dual_print(f"\n  {'─' * 40}")
            dual_print(
                f"  ИТОГО: {len(seen)} уникальных имён из {4 if local_names else 3} источников"
            )
        else:
            dual_print("\n  [!] История ников не найдена ни в одном источнике.")

    except Exception as exc:
        logger.debug("Username history error: %s", exc)
        dual_print(f"  [!] История ников: {exc}")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _api_headers() -> dict[str, str] | None:
    token = API_KEYS.get("DISCORD_BOT_TOKEN")
    if not token:
        return None
    return {"Authorization": f"Bot {token}", "User-Agent": "clo-osint/1.0"}


def _avatar_url(uid: str, avatar: str | None) -> str:
    if not avatar:
        return ""
    ext = "gif" if avatar.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/avatars/{uid}/{avatar}.{ext}?size=1024"


def _fetch_official_api(session, user_id: str, results: dict) -> None:
    """GET /users/{id} — реальные данные аккаунта (бейджи, аватар, бот-флаг).

    Требует бот-токен. Без него единственный полностью достоверный источник
    (остальные — скрейперы сторонних сайтов, часто мёртвые)."""
    headers = _api_headers()
    print_section("Discord API (официальный)")
    if headers is None:
        dual_print("  [i] Нет DISCORD_BOT_TOKEN — пропуск. Задай в .env для точных данных.")
        return
    try:
        r = safe_get(session, f"{DISCORD_API}/users/{user_id}", headers=headers, timeout=12)
    except Exception as exc:
        dual_print(f"  [!] API: {exc}")
        return
    if r.status_code == 404:
        dual_print("  [!] Пользователь с таким ID не существует.")
        return
    if r.status_code != 200:
        dual_print(f"  [!] API вернул {r.status_code}")
        return

    d = r.json()
    username = d.get("username", "")
    disc = d.get("discriminator", "0")
    handle = username if disc in ("0", "", None) else f"{username}#{disc}"
    print_field("Username", handle)
    print_field("Global name", d.get("global_name"))
    print_field("ID", d.get("id"))
    print_field("Бот", "да" if d.get("bot") else "нет")
    if d.get("system"):
        print_field("Системный", "да")
    badges = _decode_flags(d.get("public_flags", 0))
    if badges:
        print_field("Бейджи", ", ".join(badges))
        results["Бейджи"] = ", ".join(badges)
    avatar = _avatar_url(user_id, d.get("avatar"))
    if avatar:
        print_field("Аватар", avatar)
    if d.get("banner"):
        ext = "gif" if d["banner"].startswith("a_") else "png"
        print_field("Баннер", f"https://cdn.discordapp.com/banners/{user_id}/{d['banner']}.{ext}?size=1024")
    if d.get("accent_color"):
        print_field("Цвет профиля", f"#{d['accent_color']:06X}")

    results["Username"] = handle
    if d.get("global_name"):
        results["Global name"] = d["global_name"]


def _resolve_invite(session, code: str, results: dict) -> None:
    """GET /invites/{code}?with_counts — данные сервера по инвайту (без токена)."""
    print_section("Инвайт-сервер")
    url = f"{DISCORD_API}/invites/{code}?with_counts=true&with_expiration=true"
    try:
        r = safe_get(session, url, timeout=12)
    except Exception as exc:
        dual_print(f"  [!] invite: {exc}")
        return
    if r.status_code != 200:
        dual_print(f"  [!] Инвайт недействителен ({r.status_code}).")
        return
    d = r.json()
    guild = d.get("guild") or {}
    print_field("Сервер", guild.get("name"))
    print_field("Guild ID", guild.get("id"))
    if guild.get("description"):
        print_field("Описание", guild["description"])
    print_field("Участников", d.get("approximate_member_count"))
    print_field("Онлайн", d.get("approximate_presence_count"))
    ch = d.get("channel") or {}
    print_field("Канал", ch.get("name"))
    inviter = d.get("inviter") or {}
    if inviter:
        print_field("Пригласил", f"{inviter.get('username')} (id {inviter.get('id')})")
    if guild.get("id"):
        results["Guild ID"] = guild["id"]
        _fetch_guild_widget(session, guild["id"], results)


def _fetch_guild_widget(session, guild_id: str, results: dict) -> None:
    """widget.json — доступен, только если владелец включил виджет сервера."""
    try:
        r = safe_get(session, f"{DISCORD_API}/guilds/{guild_id}/widget.json", timeout=10)
    except Exception:
        return
    if r.status_code != 200:
        return
    d = r.json()
    print_section("Widget сервера")
    print_field("Онлайн (widget)", d.get("presence_count"))
    if d.get("instant_invite"):
        print_field("Инвайт", d["instant_invite"])
    members = d.get("members") or []
    if members:
        sample = ", ".join(m.get("username", "?") for m in members[:15])
        print_field("Онлайн-участники", sample)
    channels = d.get("channels") or []
    if channels:
        print_field("Каналов видно", str(len(channels)))


_INVITE_RE = re.compile(r"(?:discord\.gg|discord(?:app)?\.com/invite)/([A-Za-z0-9-]+)", re.I)


def analyze_discord(user_id: str, endpoints: DiscordEndpoints | None = None) -> None:
    """
    Perform a comprehensive analysis of a Discord user ID.

    Parameters
    ----------
    user_id : str
        The Discord snowflake (numeric ID).
    endpoints : DiscordEndpoints, optional
        Override remote-URL configuration (for tests or custom infra).
    """
    user_id = user_id.strip()
    endpoints = endpoints or DiscordEndpoints()
    results: dict[str, str] = {}
    session = get_session()

    # инвайт-ссылка/код вместо ID → разбираем сервер
    inv = _INVITE_RE.search(user_id)
    if inv or (not user_id.isdigit() and re.fullmatch(r"[A-Za-z0-9-]{2,25}", user_id)):
        code = inv.group(1) if inv else user_id
        dual_print(f"\n{'═' * 58}")
        dual_print(f"  [+] DISCORD INVITE: {code}")
        dual_print(f"{'═' * 58}")
        _resolve_invite(session, code, results)
        print_summary(results, f"Discord invite {code}")
        return

    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] DISCORD ID: {user_id}")
    dual_print(f"{'═' * 58}")

    if not user_id.isdigit():
        dual_print("  [!] Введите числовой ID или инвайт (discord.gg/...).")
        return

    # ---------- Snowflake ----------
    print_section("Snowflake — дата создания аккаунта")
    snowflake = SnowflakeInfo.from_id(user_id)
    if snowflake is not None:
        print_field("Создан (UTC)", snowflake.creation_utc)
        print_field("Worker ID", str(snowflake.worker_id))
        print_field("Process ID", str(snowflake.process_id))
        print_field("Increment", str(snowflake.increment))
        results["Создан (UTC)"] = snowflake.creation_utc
    else:
        dual_print("  [!] Не удалось декодировать Snowflake")

    # ---------- Parallel data collection ----------
    print_section("Параллельный сбор данных...")
    tasks: list[Callable[[], None]] = [
        lambda: _fetch_official_api(session, user_id, results),
        lambda: _fetch_sensor(session, user_id, endpoints, results),
        lambda: _fetch_tracker(session, user_id, endpoints, results),
        lambda: _fetch_discord_id(session, user_id, endpoints, results),
        lambda: _fetch_discord_lookup(session, user_id, endpoints, results),
        lambda: _fetch_discord_rep(session, user_id, endpoints, results),
        lambda: _fetch_leaks(session, user_id, endpoints, results),
        lambda: _fetch_username_history(session, user_id, endpoints, results),
        lambda: _fetch_server_list(session, user_id, endpoints, results),
        lambda: _fetch_discord_bio(session, user_id, endpoints, results),
    ]

    with ThreadPoolExecutor(max_workers=MAX_THREAD_WORKERS) as executor:
        futures = [executor.submit(t) for t in tasks]
        for future in as_completed(futures):
            exc = future.exception()
            if exc is not None:
                logger.debug("Discord fetch unhandled error: %s", exc)

    # ---------- Summary ----------
    print_summary(results, f"Discord ID {user_id}")
