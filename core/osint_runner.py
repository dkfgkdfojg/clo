# core/osint_runner.py
"""
Менеджер OSINT-утилит для Arch Linux.
Запускает Sherlock, Maigret, Blackbird, Holehe и другие инструменты
параллельно, парсит их JSON-вывод и собирает результаты.

Установка на Arch:
  yay -S sherlock-git maigret holehe blackbird-git     (если есть в AUR)
  pip install --user nexfil socialscan                  (PyPI)
  pip install --user blackbird                          (PyPI, либо git clone)
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.utils import dual_print, logger

# ============================================================================
# CONSTANTS
# ============================================================================

MAX_WORKERS: int = 6
CLI_TIMEOUT: int = 45  # seconds per tool

# Прекомпилированные паттерны для разбора текстового вывода CLI-инструментов
# "[+] SiteName: https://url" — общий формат Sherlock/Maigret/Blackbird в text-режиме
_PLUS_LINE_RE = re.compile(r"\[\+\]\s*([^:]+?):\s*(https?://\S+)")
_URL_RE = re.compile(r"https?://[^\s]+")

# ============================================================================
# DATA STRUCTURES
# ============================================================================


@dataclass
class FoundAccount:
    """Represents a discovered account from any OSINT tool."""

    site: str
    url: str
    username: str
    source: str  # which tool found it
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolConfig:
    """Configuration for an external OSINT tool."""

    name: str
    cmd_template: list[str]  # e.g. ["sherlock", "{username}", "--json"]
    parser: Callable[[str, str], list[FoundAccount]]  # parses stdout to accounts
    check_installed: str | None = None  # binary/command to check, e.g. "sherlock"
    pip_package: str | None = None  # pip package name if installable
    timeout: int = CLI_TIMEOUT
    email_only: bool = False  # tool expects an email target, not a username


# ============================================================================
# PARSERS (для каждой утилиты)
# ============================================================================


def _parse_sherlock(stdout: str, username: str) -> list[FoundAccount]:
    """Parse Sherlock JSON output."""
    results: list[FoundAccount] = []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            for site_name, info in data.items():
                if isinstance(info, dict):
                    status = str(info.get("status", "")).lower()
                    url = info.get("url", "")
                    if ("claimed" in status or "found" in status) and url:
                        results.append(
                            FoundAccount(
                                site=site_name,
                                url=url,
                                username=username,
                                source="sherlock",
                            )
                        )
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.debug("Sherlock parse error: %s", exc)
        # Fallback: Sherlock's text mode prints "[+] SiteName: https://url".
        # Recover real site names instead of collapsing to one bogus label.
        for line in stdout.splitlines():
            m = _PLUS_LINE_RE.search(line)
            if m:
                results.append(
                    FoundAccount(
                        site=m.group(1).strip(),
                        url=m.group(2).strip(),
                        username=username,
                        source="sherlock",
                    )
                )
    return results


def _parse_maigret(stdout: str, username: str) -> list[FoundAccount]:
    """Parse Maigret JSON output."""
    results: list[FoundAccount] = []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            # Maigret output format: {"site": {"url": "...", "status": "..."}, ...}
            for site_name, info in data.items():
                if isinstance(info, dict):
                    url = info.get("url", "")
                    status = str(info.get("status", "")).lower()
                    if url and (
                        "claimed" in status or "found" in status or status == "yes"
                    ):
                        results.append(
                            FoundAccount(
                                site=site_name,
                                url=url,
                                username=username,
                                source="maigret",
                            )
                        )
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.debug("Maigret parse error: %s", exc)
        # Fallback: Maigret's --json writes a report FILE, so stdout is text
        # progress ("[+] Site: url"). Without this the strongest tool returned
        # zero results silently.
        for line in stdout.splitlines():
            m = _PLUS_LINE_RE.search(line)
            if m:
                results.append(
                    FoundAccount(
                        site=m.group(1).strip(),
                        url=m.group(2).strip(),
                        username=username,
                        source="maigret",
                    )
                )
    return results


def _parse_blackbird(stdout: str, username: str) -> list[FoundAccount]:
    """Parse Blackbird JSON output."""
    results: list[FoundAccount] = []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            # Blackbird format: {"results": [{"site": "...", "url": "...", ...}], ...}
            entries = data.get("results", data.get("accounts", data.get("data", [])))
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        url = entry.get("url", entry.get("link", ""))
                        site = entry.get("site", entry.get("name", ""))
                        if url:
                            results.append(
                                FoundAccount(
                                    site=site or "blackbird",
                                    url=url,
                                    username=username,
                                    source="blackbird",
                                )
                            )
            elif isinstance(entries, dict):
                for site_name, info in entries.items():
                    if isinstance(info, dict):
                        url = info.get("url", "")
                        if url:
                            results.append(
                                FoundAccount(
                                    site=site_name,
                                    url=url,
                                    username=username,
                                    source="blackbird",
                                )
                            )
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.debug("Blackbird parse error: %s", exc)
        # Fallback: grep lines with URLs
        for line in stdout.splitlines():
            if "http" in line and username.lower() in line.lower():
                m = re.search(r"https?://[^\s]+", line)
                if m:
                    results.append(
                        FoundAccount(
                            site="blackbird",
                            url=m.group(),
                            username=username,
                            source="blackbird",
                        )
                    )
    return results


def _parse_holehe(stdout: str, username: str) -> list[FoundAccount]:
    """Parse Holehe output (email check, returns sites where email is registered)."""
    results: list[FoundAccount] = []
    # Holehe output: "[+] site.com" for registered, "[-] site.com" for not.
    # Only positive ("[+]") lines are real hits.
    for line in stdout.splitlines():
        line_stripped = line.strip()
        if "[+]" not in line_stripped:
            continue
        # Prefer an explicit URL on the line; otherwise reconstruct from domain.
        m = _URL_RE.search(line_stripped)
        if m:
            url = m.group().rstrip(".,;:")
            site = re.sub(r"^https?://(www\.)?", "", url).split("/")[0]
            results.append(
                FoundAccount(site=site, url=url, username=username, source="holehe")
            )
            continue
        for part in line_stripped.split():
            if "." in part and not part.startswith("[") and not part.startswith("http"):
                results.append(
                    FoundAccount(
                        site=part,
                        url=f"https://{part}",
                        username=username,
                        source="holehe",
                    )
                )
                break
    return results


def _parse_nexfil(stdout: str, username: str) -> list[FoundAccount]:
    """Parse Nexfil output."""
    results: list[FoundAccount] = []
    for line in stdout.splitlines():
        # Only positive-hit lines. Without this filter Nexfil's banner/author/
        # repo URLs and progress lines were reported as discovered accounts.
        if "[+]" not in line and "found" not in line.lower():
            continue
        m = _URL_RE.search(line)
        if m:
            url = m.group().rstrip(".,;:")
            site = re.sub(r"^https?://(www\.)?", "", url).split("/")[0]
            results.append(
                FoundAccount(site=site, url=url, username=username, source="nexfil")
            )
    return results


def _parse_socialscan(stdout: str, username: str) -> list[FoundAccount]:
    """Parse Socialscan output.

    Socialscan reports availability: an *unavailable* (taken/claimed) handle
    means the account exists. Matching only "taken"/"claimed" missed the common
    "unavailable" wording and dropped real hits.
    """
    results: list[FoundAccount] = []
    for line in stdout.splitlines():
        low = line.lower()
        if not ("unavailable" in low or "taken" in low or "claimed" in low):
            continue
        if "available" in low and "unavailable" not in low:
            continue  # explicit "Available" — not a hit
        parts = line.split(":", 1)
        site = parts[0].strip()
        if not site:
            continue
        m = _URL_RE.search(line)
        # socialscan doesn't emit URLs; keep a real one only if present.
        url = m.group() if m else f"socialscan://{site}/{username}"
        results.append(
            FoundAccount(site=site, url=url, username=username, source="socialscan")
        )
    return results


def _parse_generic_json(stdout: str, username: str) -> list[FoundAccount]:
    """Generic JSON parser — tries to find account-like entries."""
    results: list[FoundAccount] = []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            # Try common structures
            for key in ("results", "data", "accounts", "sites", "matches", "hits"):
                entries = data.get(key, [])
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            url = entry.get(
                                "url", entry.get("link", entry.get("profile", ""))
                            )
                            if url:
                                site = entry.get(
                                    "site", entry.get("name", entry.get("platform", ""))
                                )
                                results.append(
                                    FoundAccount(
                                        site=site or "unknown",
                                        url=url,
                                        username=username,
                                        source="generic_json",
                                    )
                                )
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    url = entry.get("url", "")
                    if url:
                        site = entry.get("site", entry.get("name", ""))
                        results.append(
                            FoundAccount(
                                site=site or "unknown",
                                url=url,
                                username=username,
                                source="generic_json",
                            )
                        )
    except (json.JSONDecodeError, AttributeError):
        pass
    return results


# ============================================================================
# TOOL CONFIGURATIONS
# ============================================================================

TOOLS: list[ToolConfig] = [
    ToolConfig(
        name="Sherlock",
        cmd_template=["sherlock", "{username}", "--json", "--timeout", "10"],
        parser=_parse_sherlock,
        check_installed="sherlock",
        pip_package="sherlock",
    ),
    ToolConfig(
        name="Maigret",
        cmd_template=[
            "maigret",
            "{username}",
            "--all-sites",
            "--timeout",
            "15",
            "--json",
        ],
        parser=_parse_maigret,
        check_installed="maigret",
        pip_package="maigret",
    ),
    ToolConfig(
        name="Blackbird",
        cmd_template=["blackbird", "-u", "{username}", "-f", "json"],
        parser=_parse_blackbird,
        check_installed="blackbird",
        pip_package="blackbird",
    ),
    ToolConfig(
        name="Holehe",
        cmd_template=["holehe", "{username}", "--only-used"],
        parser=_parse_holehe,
        check_installed="holehe",
        pip_package="holehe",
        email_only=True,  # Holehe проверяет регистрацию EMAIL, не ника
    ),
    ToolConfig(
        name="Nexfil",
        cmd_template=["nexfil", "-u", "{username}"],
        parser=_parse_nexfil,
        check_installed="nexfil",
        pip_package="nexfil",
    ),
    ToolConfig(
        name="Socialscan",
        cmd_template=["socialscan", "{username}"],
        parser=_parse_socialscan,
        check_installed="socialscan",
        pip_package="socialscan",
    ),
]

# Tool configurations for extended tools (installed optionally)
EXTENDED_TOOLS: list[ToolConfig] = [
    ToolConfig(
        name="AliensEye",
        cmd_template=["python3", "-m", "aliens_eye", "-u", "{username}", "-f", "json"],
        parser=_parse_generic_json,
        check_installed=None,
        pip_package=None,
    ),
    ToolConfig(
        name="WhatsMyName-Py",
        cmd_template=["python3", "-m", "whatsmyname", "username", "{username}"],
        parser=_parse_generic_json,
        check_installed=None,
        pip_package=None,
    ),
    ToolConfig(
        name="Osintgram",
        cmd_template=["osintgram", "{username}", "--json"],
        parser=_parse_generic_json,
        check_installed=None,
        pip_package=None,
    ),
]

# Custom user scripts directory
USER_SCRIPTS_DIR = Path.home() / ".config" / "hackerai" / "osint_scripts"


# ============================================================================
# INSTALLATION HELPER
# ============================================================================


def get_install_instructions() -> dict[str, str]:
    """Return installation commands for all tools."""
    return {
        "sherlock": "yay -S sherlock-git  # или: pip install --user sherlock",
        "maigret": "yay -S maigret        # или: pip install --user maigret",
        "blackbird": "pip install --user blackbird  # или git clone + pip install",
        "holehe": "yay -S holehe           # или: pip install --user holehe",
        "nexfil": "pip install --user nexfil",
        "socialscan": "pip install --user socialscan",
    }


def check_tool_installed(tool: ToolConfig) -> bool:
    """Check if a tool is installed on the system.

    * ``check_installed`` set  -> probe that binary via ``which``.
    * ``python3 -m <module>``  -> probe the module via importlib.
    * otherwise                -> probe the first command token via ``which``.

    Раньше инструменты с ``check_installed=None`` (все EXTENDED_TOOLS) всегда
    считались неустановленными и никогда не запускались.
    """
    cmd = tool.cmd_template
    if tool.check_installed:
        return shutil.which(tool.check_installed) is not None
    if not cmd:
        return False
    # python3 -m module  ->  проверяем модуль, а не наличие python
    if cmd[0] in ("python", "python3") and len(cmd) >= 3 and cmd[1] == "-m":
        try:
            return importlib.util.find_spec(cmd[2]) is not None
        except (ImportError, ValueError):
            return False
    return shutil.which(cmd[0]) is not None


def get_installed_tools() -> list[ToolConfig]:
    """Return only the tools that are currently installed."""
    return [t for t in TOOLS if check_tool_installed(t)]


# ============================================================================
# CORE RUNNER
# ============================================================================


def _run_single_tool(tool: ToolConfig, username: str) -> list[FoundAccount]:
    """Run a single OSINT tool and parse its output."""
    if not check_tool_installed(tool):
        logger.debug("Tool '%s' not installed, skipping", tool.name)
        return []

    # Build command
    cmd = [part.replace("{username}", username) for part in tool.cmd_template]

    try:
        dual_print(f"  [→] {tool.name}...", end="")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=tool.timeout,
        )
        if result.returncode != 0:
            logger.debug("%s stderr: %s", tool.name, result.stderr[:200])

        # Try JSON first, fallback to raw stdout
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        accounts = tool.parser(stdout, username)

        # If no results from stdout, try stderr (some tools output to stderr)
        if not accounts and stderr:
            accounts = tool.parser(stderr, username)

        if accounts:
            dual_print(f" {len(accounts)} найдено")
        else:
            dual_print(" нет результатов")

        return accounts

    except subprocess.TimeoutExpired:
        dual_print(f" TIMEOUT ({tool.timeout}s)")
        logger.debug("Tool '%s' timed out after %ds", tool.name, tool.timeout)
        return []
    except FileNotFoundError:
        dual_print(" не найден")
        logger.debug("Tool '%s' binary not found", tool.name)
        return []
    except Exception as exc:
        dual_print(f" ошибка: {exc}")
        logger.debug("Tool '%s' error: %s", tool.name, exc)
        return []


def run_all_username_tools(
    username: str,
    include_extended: bool = False,
    max_workers: int = MAX_WORKERS,
) -> list[FoundAccount]:
    """
    Run all installed OSINT username tools in parallel.

    Args:
        username: Target username to search.
        include_extended: Also run extended/optional tools.
        max_workers: Max parallel tool processes.

    Returns:
        List of FoundAccount with deduplicated results.
    """
    tools = get_installed_tools()
    if include_extended:
        tools.extend([t for t in EXTENDED_TOOLS if check_tool_installed(t)])

    # Holehe и подобные ждут email — на ник (без "@") они бесполезны и только
    # засоряют вывод ошибками. Прогоняем их лишь когда цель похожа на email.
    is_email = "@" in username
    tools = [t for t in tools if is_email or not t.email_only]

    if not tools:
        dual_print("  [!] Ни одна OSINT-утилита не установлена.")
        dual_print("  [!] Установите хотя бы одну:")
        for name, cmd in get_install_instructions().items():
            dual_print(f"      {name}: {cmd}")
        return []

    all_accounts: list[FoundAccount] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_run_single_tool, tool, username): tool.name
            for tool in tools
        }
        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    all_accounts.extend(results)
            except Exception as exc:
                logger.debug("Tool run error: %s", exc)

    return _deduplicate_accounts(all_accounts)


def run_specific_tools(
    username: str,
    tool_names: list[str],
) -> list[FoundAccount]:
    """Run only specific tools by name."""
    all_tools = TOOLS + EXTENDED_TOOLS
    selected = [
        t for t in all_tools if t.name.lower() in [n.lower() for n in tool_names]
    ]
    if not selected:
        dual_print(f"  [!] Указанные утилиты не найдены: {tool_names}")
        return []

    all_accounts: list[FoundAccount] = []
    for tool in selected:
        results = _run_single_tool(tool, username)
        if results:
            all_accounts.extend(results)

    return _deduplicate_accounts(all_accounts)


# ============================================================================
# USER SCRIPTS (кастомные bash/python скрипты)
# ============================================================================


def register_user_script(name: str, command: str) -> Path:
    """Register a custom user script for OSINT scanning.

    Creates a small wrapper script in ~/.config/hackerai/osint_scripts/

    Args:
        name: Name for the script (e.g. "my_scanner")
        command: Command template with {username} placeholder
                 (e.g. "python3 /path/to/tool.py -u {username}")

    Returns:
        Path to the created script file.
    """
    script_path = USER_SCRIPTS_DIR / f"{name}.sh"
    USER_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    # Подставляем {username} как позиционный аргумент $1 — тогда реальное имя
    # приходит при запуске (раньше {username} оставался литералом в теле .sh).
    body = command.replace("{username}", '"$1"')
    script_content = f"""#!/bin/bash
# Auto-generated OSINT script: {name}
# Command: {command}
{body}
"""
    script_path.write_text(script_content)
    script_path.chmod(0o755)
    return script_path


def run_user_script(script_name: str, username: str) -> list[FoundAccount]:
    """Run a registered user script and collect results."""
    script_path = USER_SCRIPTS_DIR / f"{script_name}.sh"
    if not script_path.exists():
        logger.debug("User script '%s' not found at %s", script_name, script_path)
        return []

    cmd = [str(script_path), username]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLI_TIMEOUT,
        )
        stdout = result.stdout or ""
        return _parse_generic_json(stdout, username)
    except Exception as exc:
        logger.debug("User script '%s' error: %s", script_name, exc)
        return []


# ============================================================================
# DEDUPLICATION
# ============================================================================


def _deduplicate_accounts(accounts: list[FoundAccount]) -> list[FoundAccount]:
    """Remove duplicate accounts by URL."""
    seen: set[str] = set()
    result: list[FoundAccount] = []
    for acc in accounts:
        url_key = acc.url.rstrip("/").lower()
        if url_key not in seen:
            seen.add(url_key)
            result.append(acc)
    return result


# ============================================================================
# PRINT HELPERS
# ============================================================================


def print_accounts(accounts: list[FoundAccount], username: str) -> None:
    """Print found accounts in a formatted way."""
    if not accounts:
        dual_print(f"\n  [–] Аккаунтов для '{username}' не найдено.")
        return

    # Group by tool source
    by_source: dict[str, list[FoundAccount]] = {}
    for acc in accounts:
        by_source.setdefault(acc.source, []).append(acc)

    dual_print(f"\n  {'─' * 40}")
    dual_print(f"  НАЙДЕНО ВСЕГО: {len(accounts)} аккаунтов\n")

    for source, accs in sorted(by_source.items()):
        dual_print(f"  [{source.upper()}] ({len(accs)}):")
        for acc in accs[:10]:  # max 10 per source
            dual_print(f"    ◉ {acc.site}: {acc.url}")
        if len(accs) > 10:
            dual_print(f"    ... и ещё {len(accs) - 10}")


# ============================================================================
# HIGH-LEVEL API
# ============================================================================


def search_username_all(username: str) -> dict[str, str]:
    """
    Search username across all available tools and return flat dict.
    This is a drop-in replacement for the old run_external_tool_with_parser calls.

    Returns:
        dict[site_name, url]
    """
    accounts = run_all_username_tools(username, include_extended=True)
    result: dict[str, str] = {}
    for acc in accounts:
        key = f"{acc.source}_{acc.site}"
        if key not in result:
            result[key] = acc.url
    return result


# ============================================================================
# CLI INTERFACE (for testing)
# ============================================================================


if __name__ == "__main__":
    import sys

    username = sys.argv[1] if len(sys.argv) > 1 else input("Username: ")
    accounts = run_all_username_tools(username, include_extended=True)
    print_accounts(accounts, username)
