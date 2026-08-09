# analyzers/github.py
"""GitHub OSINT.

Через официальный REST API (без ключа — лимит 60 запросов/час; с GITHUB_TOKEN
в .env — 5000/час). Достаёт профиль, топ-репозитории и языки, организации,
публичные SSH/GPG-ключи и — главный трюк — реальные e-mail из коммитов
(GitHub не прячет author email в истории пушей).
"""

from __future__ import annotations

import re
from collections import Counter

from config import API_KEYS
from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger

API = "https://api.github.com"
# служебные адреса, которые не являются реальной почтой человека
_NOREPLY_RE = re.compile(r"noreply|users\.noreply\.github\.com", re.I)


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": "clo-osint/1.0"}
    token = API_KEYS.get("GITHUB_TOKEN")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _extract_login(target: str) -> str:
    t = target.strip().rstrip("/")
    m = re.search(r"github\.com/([^/]+)", t, re.I)
    return (m.group(1) if m else t).lstrip("@")


def analyze_github(target: str) -> None:
    login = _extract_login(target)
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] GITHUB: {login}")
    dual_print(f"{'═' * 58}")

    session = get_session()
    session.headers.update(_headers())
    results: dict[str, str] = {}

    # ---------- Профиль ----------
    print_section("Профиль")
    try:
        r = safe_get(session, f"{API}/users/{login}", timeout=12)
    except Exception as exc:
        dual_print(f"  [!] API: {exc}")
        print_summary(results, f"GitHub {login}")
        return
    if r.status_code == 404:
        dual_print("  [!] Пользователь не найден.")
        print_summary(results, f"GitHub {login}")
        return
    if r.status_code == 403:
        dual_print("  [!] Лимит API исчерпан. Задай GITHUB_TOKEN в .env.")
        print_summary(results, f"GitHub {login}")
        return
    if r.status_code != 200:
        dual_print(f"  [!] API вернул {r.status_code}")
        print_summary(results, f"GitHub {login}")
        return

    u = r.json()
    print_field("Логин", u.get("login"))
    print_field("Имя", u.get("name"))
    print_field("Тип", u.get("type"))
    print_field("Bio", u.get("bio"))
    print_field("Компания", u.get("company"))
    print_field("Локация", u.get("location"))
    print_field("Сайт", u.get("blog"))
    print_field("Публичный email", u.get("email"))
    print_field("Twitter", u.get("twitter_username"))
    print_field("Подписчиков", u.get("followers"))
    print_field("Подписок", u.get("following"))
    print_field("Публичных репо", u.get("public_repos"))
    print_field("Гистов", u.get("public_gists"))
    print_field("Hireable", u.get("hireable"))
    print_field("Создан", u.get("created_at"))
    print_field("Обновлён", u.get("updated_at"))
    for k in ("name", "email", "company", "location"):
        if u.get(k):
            results[k] = str(u[k])

    _fetch_repos(session, login, results)
    _fetch_orgs(session, login, results)
    _fetch_keys(login, session)
    _fetch_commit_emails(session, login, results)

    print_summary(results, f"GitHub {login}")


def _fetch_repos(session, login: str, results: dict) -> None:
    print_section("Репозитории (топ по звёздам)")
    try:
        r = safe_get(
            session,
            f"{API}/users/{login}/repos?per_page=100&sort=pushed",
            timeout=12,
        )
        if r.status_code != 200:
            return
        repos = r.json()
        if not repos:
            dual_print("  Публичных репозиториев нет.")
            return
        langs = Counter(x["language"] for x in repos if x.get("language"))
        if langs:
            top_langs = ", ".join(f"{l} ({n})" for l, n in langs.most_common(6))
            print_field("Языки", top_langs)
            results["Языки"] = top_langs
        total_stars = sum(x.get("stargazers_count", 0) for x in repos)
        print_field("Всего звёзд", str(total_stars))
        for repo in sorted(repos, key=lambda x: x.get("stargazers_count", 0), reverse=True)[:8]:
            stars = repo.get("stargazers_count", 0)
            fork = " (fork)" if repo.get("fork") else ""
            dual_print(
                f"    ★ {stars:<5} {repo.get('name')}{fork} — "
                f"{(repo.get('description') or '')[:60]}"
            )
    except Exception as exc:
        logger.debug("repos: %s", exc)


def _fetch_orgs(session, login: str, results: dict) -> None:
    try:
        r = safe_get(session, f"{API}/users/{login}/orgs", timeout=10)
        if r.status_code != 200:
            return
        orgs = [o.get("login") for o in r.json() if o.get("login")]
        if orgs:
            print_section("Организации")
            print_field("Состоит в", ", ".join(orgs))
            results["Организации"] = ", ".join(orgs)
    except Exception as exc:
        logger.debug("orgs: %s", exc)


def _fetch_keys(login: str, session) -> None:
    """SSH/GPG-ключи доступны по .keys/.gpg без авторизации."""
    print_section("Публичные ключи")
    for label, suffix in (("SSH", "keys"), ("GPG", "gpg")):
        try:
            r = safe_get(session, f"https://github.com/{login}.{suffix}", timeout=10)
            if r.status_code == 200 and r.text.strip():
                count = len([x for x in r.text.splitlines() if x.strip()])
                print_field(f"{label}-ключей", str(count) if suffix == "keys" else "есть")
        except Exception as exc:
            logger.debug("%s keys: %s", label, exc)


def _fetch_commit_emails(session, login: str, results: dict) -> None:
    """Реальные e-mail из публичных push-событий пользователя."""
    print_section("E-mail из коммитов")
    try:
        r = safe_get(session, f"{API}/users/{login}/events/public?per_page=100", timeout=12)
        if r.status_code != 200:
            dual_print("  Событий нет или доступ ограничен.")
            return
        emails: dict[str, str] = {}  # email -> имя автора
        for ev in r.json():
            if ev.get("type") != "PushEvent":
                continue
            for commit in ev.get("payload", {}).get("commits", []):
                author = commit.get("author", {})
                email = author.get("email", "")
                if email and not _NOREPLY_RE.search(email):
                    emails.setdefault(email, author.get("name", ""))
        if emails:
            for email, name in list(emails.items())[:10]:
                print_field(email, name or "—")
            results["Email из коммитов"] = ", ".join(list(emails)[:5])
        else:
            dual_print("  Реальных e-mail в последних коммитах не найдено (или noreply).")
    except Exception as exc:
        logger.debug("commit emails: %s", exc)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_github(sys.argv[1])
    else:
        print("usage: python -m analyzers.github <username|github.com/username>")
