# analyzers/username.py (дополнение — заменяет старый _run_cli_tools_parallel)
"""
Username OSINT analysis module.

Features:
  - Multi-source username search across 40+ platforms (pure requests + BS4)
  - Sherlock, Maigret, Blackbird, Holehe, Nexfil, Socialscan (parallel)
  - Namechk, Checkusernames, KnowEm, Usersearch, Social-Searcher, PeekYou
  - Russian platforms: VK, Pikabu, Habr, Drive2, LiveJournal, Yandex, etc.
  - Discord-specific: discord.bio, discord.id, discordlookup, discord-tracker
  - Telegram analysis (t.me + tgstat + tchannels)
  - TikTok analysis (JSON rehydration data)
  - Fully deduplicated output with source tracking
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from bs4 import BeautifulSoup

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger
from core.osint_runner import (
    run_all_username_tools,
    search_username_all,
    print_accounts,
    get_installed_tools,
    FoundAccount,
)
from config import (
    BLACKLIST_SITES,
    ALWAYS_200_SITES,
    ERROR_PATTERNS,
    SEARCH_URL_PATTERNS,
    EXTRA_PLATFORMS,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SCRAPE_WORKERS: int = 15
MAX_FILTER_WORKERS: int = 30
REQUEST_TIMEOUT: int = 12

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class UsernameEndpoints:
    """URL templates for direct username profile lookups."""

    # --- Aggregators ---
    namechk: str = "https://namechk.com/check?q={username}"
    checkusernames: str = "https://checkusernames.com/search?q={username}"
    usersearch: str = "https://www.usersearch.org/search?search={username}"
    social_searcher: str = "https://www.social-searcher.com/search-users/?q={username}"
    peekyou: str = "https://www.peekyou.com/{username}"
    knowem: str = "https://knowem.com/search?s={username}"

    # --- Russian platforms ---
    vk: str = "https://vk.com/{username}"
    pikabu: str = "https://pikabu.ru/@{username}"
    habr: str = "https://habr.com/users/{username}/"
    drive2: str = "https://www.drive2.ru/users/{username}/"
    livejournal: str = "https://{username}.livejournal.com/"
    yandex_music: str = "https://music.yandex.ru/users/{username}/"
    cyberforum: str = "https://www.cyberforum.ru/members/{username}.html"
    yaplakal: str = "https://www.yaplakal.com/profile/{username}"
    pvpru: str = "https://pvpru.com/user/{username}"
    rustats: str = "https://rustats.com/user/{username}"
    dtf: str = "https://dtf.ru/u/{username}"

    # --- Discord ---
    discord_id: str = "https://discord.id/?q={username}"
    discord_bio: str = "https://discord.bio/p/{username}"
    discord_sensor: str = "https://discord-sensor.com/search?q={username}"

    # --- Telegram search ---
    tgstat: str = "https://tgstat.ru/user/{username}"
    tchannels: str = "https://tchannels.me/user/{username}"

    # --- Gaming ---
    steam: str = "https://steamcommunity.com/id/{username}"
    epic: str = "https://www.epicgames.com/id/{username}"
    origin: str = "https://profile.ea.com/{username}"

    # --- Video / Streaming ---
    twitch: str = "https://www.twitch.tv/{username}"
    kick: str = "https://kick.com/{username}"
    rumble: str = "https://rumble.com/user/{username}"
    odysee: str = "https://odysee.com/@{username}"
    vimeo: str = "https://vimeo.com/{username}"
    dailymotion: str = "https://www.dailymotion.com/{username}"
    bitchute: str = "https://www.bitchute.com/channel/{username}"

    # --- Coding ---
    github: str = "https://github.com/{username}"
    gitlab: str = "https://gitlab.com/{username}"
    bitbucket: str = "https://bitbucket.org/{username}"
    replit: str = "https://replit.com/@{username}"
    codepen: str = "https://codepen.io/{username}"
    hackerrank: str = "https://www.hackerrank.com/{username}"
    leetcode: str = "https://leetcode.com/{username}"

    # --- Social ---
    reddit: str = "https://www.reddit.com/user/{username}"
    twitter: str = "https://twitter.com/{username}"
    instagram: str = "https://www.instagram.com/{username}"
    pinterest: str = "https://www.pinterest.com/{username}"
    tumblr: str = "https://{username}.tumblr.com"
    medium: str = "https://medium.com/@{username}"
    devto: str = "https://dev.to/{username}"
    patreon: str = "https://www.patreon.com/{username}"
    substack: str = "https://substack.com/@{username}"
    linktree: str = "https://linktr.ee/{username}"

    # --- Music ---
    soundcloud: str = "https://soundcloud.com/{username}"
    bandcamp: str = "https://{username}.bandcamp.com"
    lastfm: str = "https://www.last.fm/user/{username}"
    spotify: str = "https://open.spotify.com/user/{username}"

    # --- Images / Creative ---
    deviantart: str = "https://www.deviantart.com/{username}"
    flickr: str = "https://www.flickr.com/photos/{username}"
    behance: str = "https://www.behance.net/{username}"
    dribbble: str = "https://dribbble.com/{username}"
    artstation: str = "https://www.artstation.com/{username}"

    # --- Forums / Communities ---
    quora: str = "https://www.quora.com/profile/{username}"
    producthunt: str = "https://www.producthunt.com/@{username}"
    keybase: str = "https://keybase.io/{username}"
    aboutme: str = "https://about.me/{username}"
    angelco: str = "https://angel.co/u/{username}"

    # --- Chat / Messaging ---
    telegram: str = "https://t.me/{username}"
    signal: str = "https://signal.me/{username}"

    # --- Other ---
    pastebin: str = "https://pastebin.com/u/{username}"
    fiverr: str = "https://www.fiverr.com/{username}"
    reverb: str = "https://reverb.com/shop/{username}"
    etsy: str = "https://www.etsy.com/shop/{username}"
    instructables: str = "https://www.instructables.com/member/{username}"
    hackaday: str = "https://hackaday.io/{username}"
    imgur: str = "https://imgur.com/user/{username}"
    giphy: str = "https://giphy.com/{username}"
    chess: str = "https://www.chess.com/member/{username}"
    lichess: str = "https://lichess.org/@/{username}"


# ---------------------------------------------------------------------------
# Error-page detection
# ---------------------------------------------------------------------------


def _is_error_page(html: str, url: str, username: str) -> bool:
    """Check if the HTML indicates a non-profile page."""
    text = html.lower()
    for pat in ERROR_PATTERNS:
        if re.search(pat, text, re.I):
            return True
    try:
        soup = BeautifulSoup(html, "html.parser")
        visible = soup.get_text(strip=True)
        if len(visible) < 100:
            return True
        title = soup.find("title")
        if title:
            t = title.get_text().lower()
            if any(
                w in t
                for w in (
                    "error",
                    "invalid",
                    "not found",
                    "ошибка",
                    "404",
                    "403",
                    "page not",
                )
            ):
                return True
        not_found = [
            r"user not found",
            r"doesn't exist",
            r"no user",
            r"пользователь не найден",
            r"не существует",
            r"page not found",
            r"страница не найдена",
            r"this account doesn",
            r"this profile is private",
            r"profile not found",
            r"no profile",
        ]
        for pat in not_found:
            if re.search(pat, text, re.I):
                return True
    except Exception as exc:
        logger.debug("Error page check failed: %s", exc)
    for pat in SEARCH_URL_PATTERNS:
        if re.search(pat, url):
            return True
    return False


# ---------------------------------------------------------------------------
# Direct URL check
# ---------------------------------------------------------------------------


def _check_single_url(
    site: str, url: str, username: str, session: Any, timeout: int = REQUEST_TIMEOUT
) -> FoundAccount | None:
    """Check one URL for a valid user profile."""
    if any(bad in url.lower() for bad in BLACKLIST_SITES):
        return None
    if any(re.search(pat, url) for pat in SEARCH_URL_PATTERNS):
        return None
    try:
        resp = session.head(url, timeout=timeout, allow_redirects=True)
        final_url = resp.url
        code = resp.status_code
        force_get = any(s in final_url.lower() for s in ALWAYS_200_SITES)
        if code == 200 and not force_get:
            if username.lower() not in final_url.lower() and final_url.rstrip(
                "/"
            ) != url.rstrip("/"):
                gr = safe_get(session, final_url, timeout=timeout)
                if (
                    gr
                    and username.lower() in gr.text.lower()
                    and not _is_error_page(gr.text, final_url, username)
                ):
                    return FoundAccount(
                        site=site, url=final_url, username=username, source="direct"
                    )
                return None
            gr = safe_get(session, final_url, timeout=timeout)
            if (
                gr
                and username.lower() in gr.text.lower()
                and not _is_error_page(gr.text, final_url, username)
            ):
                return FoundAccount(
                    site=site, url=final_url, username=username, source="direct"
                )
            return None
        if code == 200 and force_get:
            gr = safe_get(session, final_url, timeout=timeout)
            if (
                gr
                and username.lower() in gr.text.lower()
                and not _is_error_page(gr.text, final_url, username)
            ):
                return FoundAccount(
                    site=site, url=final_url, username=username, source="direct"
                )
            return None
    except Exception as exc:
        logger.debug("Check %s failed: %s", url, exc)
    return None


# ---------------------------------------------------------------------------
# Aggregator scrapers
# ---------------------------------------------------------------------------


def _scrape_namechk(username: str) -> list[FoundAccount]:
    """Scrape namechk.com JSON API."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://namechk.com/check?q={username}",
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            data: dict = r.json()
            for svc, info in data.items():
                if (
                    isinstance(info, dict)
                    and info.get("available") is False
                    and info.get("url")
                ):
                    results.append(
                        FoundAccount(
                            site=svc,
                            url=info["url"],
                            username=username,
                            source="namechk",
                        )
                    )
    except Exception as exc:
        logger.debug("namechk error: %s", exc)
    return results


def _scrape_checkusernames(username: str) -> list[FoundAccount]:
    """Scrape checkusernames.com HTML."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://checkusernames.com/search?q={username}", timeout=REQUEST_TIMEOUT
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            for row in soup.select(".site-row"):
                sn = row.select_one(".site-name")
                link = row.select_one("a")
                if sn and link and link.get("href"):
                    results.append(
                        FoundAccount(
                            site=sn.text.strip(),
                            url=link["href"],
                            username=username,
                            source="checkusernames",
                        )
                    )
    except Exception as exc:
        logger.debug("checkusernames error: %s", exc)
    return results


def _scrape_knowem(username: str) -> list[FoundAccount]:
    """Scrape knowem.com HTML."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://knowem.com/search?s={username}", timeout=REQUEST_TIMEOUT
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            for item in soup.select(".result-item, .profile-result, [class*='result']"):
                link = item.find("a", href=True)
                if (
                    link
                    and link.get("href")
                    and username.lower() in link["href"].lower()
                ):
                    site_name = item.select_one(".site-name, .platform-name, strong")
                    name = site_name.text.strip() if site_name else link["href"]
                    results.append(
                        FoundAccount(
                            site=name[:40],
                            url=link["href"],
                            username=username,
                            source="knowem",
                        )
                    )
    except Exception as exc:
        logger.debug("knowem error: %s", exc)
    return results


def _scrape_usersearch(username: str) -> list[FoundAccount]:
    """Scrape usersearch.org HTML."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://www.usersearch.org/search?search={quote(username)}",
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            for item in soup.select(".result-item, .media-body, .result"):
                a = item.find("a", href=True)
                if a and username.lower() in a["href"].lower():
                    txt = a.get_text(strip=True) or a["href"]
                    results.append(
                        FoundAccount(
                            site=txt[:40],
                            url=a["href"],
                            username=username,
                            source="usersearch",
                        )
                    )
    except Exception as exc:
        logger.debug("usersearch error: %s", exc)
    return results


def _scrape_social_searcher(username: str) -> list[FoundAccount]:
    """Scrape social-searcher.com HTML."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://www.social-searcher.com/search-users/?q={username}",
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.select('.result a[href*="http"]'):
                href = link.get("href")
                if href and username.lower() in href.lower():
                    results.append(
                        FoundAccount(
                            site=link.text.strip() or href,
                            url=href,
                            username=username,
                            source="social-searcher",
                        )
                    )
    except Exception as exc:
        logger.debug("Social-Searcher error: %s", exc)
    return results


def _scrape_peekyou(username: str) -> list[FoundAccount]:
    """Scrape peekyou.com HTML."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://www.peekyou.com/{username}", timeout=REQUEST_TIMEOUT
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select('a[href*="/"]'):
                href = a.get("href")
                if (
                    href
                    and username.lower() in href.lower()
                    and href.startswith("http")
                ):
                    results.append(
                        FoundAccount(
                            site=a.text.strip() or href,
                            url=href,
                            username=username,
                            source="peekyou",
                        )
                    )
    except Exception as exc:
        logger.debug("PeekYou error: %s", exc)
    return results


# ---------------------------------------------------------------------------
# Discord-specific scrapers
# ---------------------------------------------------------------------------


def _scrape_discord_bio(username: str) -> list[FoundAccount]:
    """Scrape discord.bio for a username."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://discord.bio/p/{username}", timeout=REQUEST_TIMEOUT
        )
        if r.status_code == 200 and not _is_error_page(r.text, r.url, username):
            results.append(
                FoundAccount(
                    site="discord.bio", url=r.url, username=username, source="discord"
                )
            )
            soup = BeautifulSoup(r.text, "html.parser")
            for meta in soup.select('meta[property="og:url"]'):
                content = meta.get("content", "")
                m = re.search(r"/u/(\d+)", content)
                if m:
                    results.append(
                        FoundAccount(
                            site="discord.bio (ID)",
                            url=f"https://discord.bio/user/{m.group(1)}",
                            username=username,
                            source="discord",
                        )
                    )
    except Exception as exc:
        logger.debug("discord.bio error: %s", exc)
    return results


def _scrape_discord_id(username: str) -> list[FoundAccount]:
    """Scrape discord.id search for username."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://discord.id/?q={quote(username)}", timeout=REQUEST_TIMEOUT
        )
        if r.status_code == 200 and username.lower() in r.text.lower():
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.select('a[href*="discord.id"]'):
                href = link.get("href")
                if href and "id=" in href:
                    results.append(
                        FoundAccount(
                            site="discord.id",
                            url=href,
                            username=username,
                            source="discord",
                        )
                    )
    except Exception as exc:
        logger.debug("discord.id search error: %s", exc)
    return results


def _scrape_discord_sensor(username: str) -> list[FoundAccount]:
    """Scrape discord-sensor.com search."""
    results: list[FoundAccount] = []
    try:
        r = get_session().get(
            f"https://discord-sensor.com/search?q={quote(username)}",
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.select('a[href*="/members/"]'):
                href = link.get("href")
                if href and href.startswith("http"):
                    results.append(
                        FoundAccount(
                            site="discord-sensor",
                            url=href,
                            username=username,
                            source="discord",
                        )
                    )
    except Exception as exc:
        logger.debug("discord-sensor search error: %s", exc)
    return results


# ---------------------------------------------------------------------------
# Telegram analysis
# ---------------------------------------------------------------------------


def analyze_telegram(username: str) -> list[FoundAccount]:
    """Analyze Telegram profile."""
    if username.startswith("@"):
        username = username[1:]
    results: list[FoundAccount] = []
    try:
        r = get_session().get(f"https://t.me/{username}", timeout=10)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            body = soup.get_text()
            if "You can contact" not in body and len(body) > 200:
                print_section("Telegram")
                results.append(
                    FoundAccount(
                        site="Telegram",
                        url=f"https://t.me/{username}",
                        username=username,
                        source="telegram",
                    )
                )
                name_tag = soup.find("meta", property="og:title")
                desc_tag = soup.find("meta", property="og:description")
                img_tag = soup.find("meta", property="og:image")
                if name_tag:
                    print_field("Имя", name_tag.get("content", ""))
                if desc_tag:
                    desc = desc_tag.get("content", "")
                    if desc and "You can contact" not in desc:
                        print_field("Bio", desc)
                if img_tag:
                    print_field("Аватар", img_tag.get("content", ""))
                m = re.search(r"([\d\s,]+)\s*(subscribers|подписчик)", body, re.I)
                if m:
                    print_field("Подписчики", m.group(1).strip())
    except Exception as exc:
        logger.debug("Telegram error: %s", exc)
    for url_tpl, name in [
        ("https://tgstat.ru/user/{username}", "TGStat"),
        ("https://tchannels.me/user/{username}", "TChannels"),
    ]:
        try:
            r = get_session().get(url_tpl.format(username=username), timeout=10)
            if r.status_code == 200 and not _is_error_page(r.text, r.url, username):
                results.append(
                    FoundAccount(
                        site=name, url=r.url, username=username, source="telegram"
                    )
                )
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# TikTok analysis
# ---------------------------------------------------------------------------


def analyze_tiktok(username: str) -> list[FoundAccount]:
    """Analyze TikTok profile."""
    if username.startswith("@"):
        username = username[1:]
    try:
        r = get_session(mobile=True).get(
            f"https://www.tiktok.com/@{username}", timeout=12
        )
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        script = soup.find("script", id="__UNIVERSAL_DATA_FOR_REHYDRATION__")
        if script and script.string:
            data = json.loads(script.string)
            try:
                ui = data["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"]
            except (KeyError, TypeError):
                ui = None
            if ui:
                user = ui.get("user", {})
                stats = ui.get("stats", {})
                print_section("TikTok")
                print_field("Ник", user.get("uniqueId"))
                print_field("Отображаемое", user.get("nickname"))
                print_field("Подписчики", f"{stats.get('followerCount', 0):,}")
                print_field("Подписки", f"{stats.get('followingCount', 0):,}")
                print_field("Лайки", f"{stats.get('heartCount', 0):,}")
                print_field("Видео", f"{stats.get('videoCount', 0):,}")
                print_field("Приватный", str(user.get("privateAccount", False)))
                bio = user.get("signature", "")
                if bio:
                    print_field("Bio", bio[:100])
                return [
                    FoundAccount(
                        site="TikTok",
                        url=f"https://www.tiktok.com/@{username}",
                        username=username,
                        source="tiktok",
                    )
                ]
        title = soup.find("meta", property="og:title")
        if title:
            print_section("TikTok (OG)")
            print_field("Заголовок", title.get("content", ""))
            return [
                FoundAccount(
                    site="TikTok",
                    url=f"https://www.tiktok.com/@{username}",
                    username=username,
                    source="tiktok",
                )
            ]
    except Exception as exc:
        logger.debug("TikTok error: %s", exc)
    return []


# ---------------------------------------------------------------------------
# Direct platform checks
# ---------------------------------------------------------------------------


def _check_direct_platforms(username: str) -> list[FoundAccount]:
    """Check all platforms from UsernameEndpoints dataclass directly."""
    endpoints = UsernameEndpoints()
    results: list[FoundAccount] = []
    session = get_session()
    url_dict: dict[str, str] = {}
    for field_name in dir(endpoints):
        if field_name.startswith("_"):
            continue
        url_tpl = getattr(endpoints, field_name)
        if isinstance(url_tpl, str) and "{username}" in url_tpl:
            url_dict[field_name] = url_tpl.format(username=username)

    def _check(name: str, url: str) -> FoundAccount | None:
        return _check_single_url(name, url, username, session)

    with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as executor:
        futures = {
            executor.submit(_check, name, url): name for name, url in url_dict.items()
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as exc:
                logger.debug("Direct check error: %s", exc)
    return results


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _deduplicate(profiles: list[FoundAccount]) -> dict[str, FoundAccount]:
    """Deduplicate profiles by URL."""
    seen_urls: set[str] = set()
    result: dict[str, FoundAccount] = {}
    for p in profiles:
        url_key = p.url.rstrip("/").lower()
        if url_key not in seen_urls:
            seen_urls.add(url_key)
            key = p.site
            if key in result:
                suffix = 1
                while f"{key}_{suffix}" in result:
                    suffix += 1
                key = f"{key}_{suffix}"
            result[key] = p
    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def analyze_username_combo(username: str) -> None:
    """
    Comprehensive username OSINT analysis.

    Pipeline:
      1. CLI OSINT tools (Sherlock, Maigret, Blackbird, etc.)
      2. Aggregator scrapers (namechk, checkusernames, knowem, etc.)
      3. Discord-specific search
      4. Direct platform checks (60+ sites)
      5. Telegram + TikTok deep analysis
      6. Deduplication and summary
    """
    if "@" in username or " " in username:
        dual_print("\n[!] Только никнейм (без @, пробелов).")
        return

    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] USERNAME: {username}")
    dual_print(f"{'═' * 58}")

    all_profiles: list[FoundAccount] = []

    # ---- STAGE 1: CLI OSINT tools (Sherlock, Maigret, etc.) ----
    print_section("ЭТАП 1: CLI-утилиты (Sherlock, Maigret, Blackbird...)")
    installed_tools = get_installed_tools()
    if installed_tools:
        dual_print(f"  Найдено утилит: {', '.join(t.name for t in installed_tools)}")
        cli_results = run_all_username_tools(username, include_extended=True)
        if cli_results:
            all_profiles.extend(cli_results)
            for p in cli_results:
                dual_print(f"  [+] [{p.source}] {p.site}: {p.url}")
        else:
            dual_print("  [–] CLI-утилиты не нашли профилей")
    else:
        dual_print("  [–] CLI-утилиты не установлены")
        dual_print("  [~] Установите: yay -S sherlock-git maigret holehe")
        dual_print("  [~] Или: pip install --user blackbird nexfil socialscan")

    # ---- STAGE 2: Aggregator scrapers (parallel) ----
    print_section("ЭТАП 2: Агрегаторы (параллельно)")
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(_scrape_namechk, username): "namechk",
            executor.submit(_scrape_checkusernames, username): "checkusernames",
            executor.submit(_scrape_knowem, username): "knowem",
            executor.submit(_scrape_usersearch, username): "usersearch",
            executor.submit(_scrape_social_searcher, username): "social-searcher",
            executor.submit(_scrape_peekyou, username): "peekyou",
        }
        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    all_profiles.extend(results)
                    dual_print(f"  [+] {futures[future]}: {len(results)} профилей")
            except Exception as exc:
                logger.debug("Aggregator error: %s", exc)

    # ---- STAGE 3: Discord-specific ----
    print_section("ЭТАП 3: Discord")
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_scrape_discord_bio, username): "discord.bio",
            executor.submit(_scrape_discord_id, username): "discord.id",
            executor.submit(_scrape_discord_sensor, username): "discord-sensor",
        }
        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    all_profiles.extend(results)
                    dual_print(f"  [+] {futures[future]}: {len(results)}")
            except Exception as exc:
                logger.debug("Discord error: %s", exc)

    # ---- STAGE 4: Direct platform checks (60+ sites) ----
    print_section("ЭТАП 4: Прямая проверка платформ (60+)")
    direct_results = _check_direct_platforms(username)
    if direct_results:
        all_profiles.extend(direct_results)
        for p in direct_results:
            dual_print(f"  [+] {p.site}: {p.url}")
    else:
        dual_print("  [–] Прямых профилей не найдено")

    # ---- STAGE 5: Telegram + TikTok ----
    print_section("ЭТАП 5: Telegram / TikTok")
    with ThreadPoolExecutor(max_workers=2) as executor:
        tg_future = executor.submit(analyze_telegram, username)
        tt_future = executor.submit(analyze_tiktok, username)
        tg_results = tg_future.result()
        if tg_results:
            all_profiles.extend(tg_results)
            for p in tg_results:
                dual_print(f"  [+] {p.site}: {p.url}")
        tt_results = tt_future.result()
        if tt_results:
            all_profiles.extend(tt_results)
            for p in tt_results:
                dual_print(f"  [+] {p.site}: {p.url}")

    # ---- STAGE 6: Deduplication and summary ----
    print_section("ЭТАП 6: Дедупликация и результат")
    final = _deduplicate(all_profiles)

    if final:
        dual_print(f"\n  {'─' * 40}")
        dual_print(f"  ВСЕГО НАЙДЕНО: {len(final)} уникальных профилей\n")
        for site, profile in sorted(final.items()):
            dual_print(f"  [{site}] {profile.url}")
    else:
        dual_print("\n  [!] Ни одного профиля не найдено.")

    print_summary(
        {site: p.url for site, p in final.items()},
        f"Username «{username}»",
    )
