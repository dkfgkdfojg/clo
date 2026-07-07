# core/http.py
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .utils import logger


def get_headers(mobile=False):
    if mobile:
        return {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
        }
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }


def get_session(mobile=False, retries=3, backoff=0.5):
    """Возвращает сессию с автоматическими повторными попытками."""
    session = requests.Session()
    session.headers.update(get_headers(mobile))
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def safe_get(session, url, timeout=12, retries=2, **kwargs):
    """
    Выполняет GET с повторными попытками при ошибках сети.
    Перехватывает: Timeout, ConnectionError, HTTPError, TooManyRedirects.
    """
    for attempt in range(retries + 1):
        try:
            return session.get(url, timeout=timeout, **kwargs)
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
            requests.exceptions.TooManyRedirects,
        ) as e:
            if attempt < retries:
                sleep_time = 1.2 * (attempt + 1)
                time.sleep(sleep_time)
                logger.debug(f"Retry {attempt + 1}/{retries} for {url}: {e}")
            else:
                logger.error(f"Failed to fetch {url}: {e}")
                raise
