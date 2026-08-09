# core/browser.py
"""
Браузерные утилиты (Selenium WebDriver).
"""

import os
import re
import shutil
import subprocess

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

from core.http import get_headers
from core.utils import logger


def _find_binary() -> str | None:
    """Системный chromium/chrome. Скачивать ничего не нужно — берём то, что стоит."""
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _major(path: str) -> int | None:
    """Мажорная версия бинарника chromium/chromedriver по `--version`."""
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=8
        ).stdout
        m = re.search(r"(\d+)\.", out)
        return int(m.group(1)) if m else None
    except Exception as exc:
        logger.debug("version %s: %s", path, exc)
        return None


def _make_service(binary: str | None) -> Service:
    """Выбираем chromedriver, чей мажор совпадает с chromium.

    На машине бывает несколько драйверов (напр. свежий /usr/bin и устаревший
    /usr/local/bin, который затеняет его в PATH) — берём подходящий по версии.
    webdriver-manager не трогаем: он тянет драйвер с заблокированного google.
    """
    want = _major(binary) if binary else None
    candidates = [
        os.getenv("CHROMEDRIVER_PATH"),
        shutil.which("chromedriver"),
        "/usr/bin/chromedriver",
        "/usr/local/bin/chromedriver",
    ]
    seen = set()
    fallback = None
    for path in candidates:
        if not path or path in seen or not os.path.exists(path):
            continue
        seen.add(path)
        fallback = fallback or path
        if want is None or _major(path) == want:
            return Service(executable_path=path)
    if fallback:
        return Service(executable_path=fallback)
    return Service()  # selenium 4.8+ сам разрулит драйвер


def build_chrome_driver():
    """Headless-Chromium с отключённой автоматизацией на системных бинарниках."""
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument(f"user-agent={get_headers()['User-Agent']}")

    binary = _find_binary()
    if binary:
        opts.binary_location = binary
    else:
        logger.warning("chromium/chrome не найден в PATH — Selenium может не стартовать")

    driver = webdriver.Chrome(service=_make_service(binary), options=opts)
    driver.execute_script(
        "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    )
    return driver
