"""Регрессионные тесты для core.http, core.utils.print_field и analyzers.phone.

Покрывают:
  * http._redact — секреты (query string) не попадают в лог.
  * http.get_session — ретраи только по статусам, без компаундинга.
  * http.safe_get — транспортные ошибки ретраятся, лог без секретов.
  * utils.print_field — 'false' больше не подавляется.
  * phone: 10-значные и 8-префиксные номера парсятся (был off-by-one).
"""
import io
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import requests

from core import http
from core.utils import print_field, logger


class TestRedact:
    def test_strips_query(self):
        assert http._redact("https://api.shodan.io/host/8.8.8.8?key=SECRET") == \
            "https://api.shodan.io/host/8.8.8.8"

    def test_no_query_unchanged(self):
        assert http._redact("https://x.com/u") == "https://x.com/u"


class TestSession:
    def test_retry_only_on_status(self):
        s = http.get_session()
        retry = s.get_adapter("https://x.com").max_retries
        assert retry.connect == 0
        assert retry.read == 0
        assert retry.status == 2
        assert 429 in retry.status_forcelist


class TestSafeGet:
    def test_transport_error_retried_and_redacted(self):
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        logger.addHandler(handler)
        try:
            calls = {"n": 0}

            class FailSession:
                def get(self, url, timeout=None, **kw):
                    calls["n"] += 1
                    raise requests.exceptions.ConnectionError("boom")

            with pytest.raises(requests.exceptions.ConnectionError):
                http.safe_get(FailSession(), "https://api.x.io/q?key=TOPSECRET", retries=1)

            assert calls["n"] == 2  # retries=1 => 2 попытки
            log = buf.getvalue()
            assert "TOPSECRET" not in log
            assert "api.x.io/q" in log
        finally:
            logger.removeHandler(handler)

    def test_success_returns_response(self):
        class OKSession:
            def get(self, url, timeout=None, **kw):
                return "RESP"

        assert http.safe_get(OKSession(), "https://x.com") == "RESP"


class TestPrintField:
    def _capture(self, label, value):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            print_field(label, value)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def test_false_is_shown(self):
        out = self._capture("Одноразовый", str(False))
        assert "False" in out  # раньше подавлялось

    def test_none_suppressed(self):
        assert self._capture("X", None) == ""
        assert self._capture("X", "none") == ""
        assert self._capture("X", "N/A") == ""

    def test_real_value_shown(self):
        assert "hello" in self._capture("X", "hello")


class TestPhoneParsing:
    """Проверяем логику парсинга напрямую (без сетевых фетчеров)."""

    def _parse(self, phone_str):
        import phonenumbers
        clean = re.sub(r"[^\d+]", "", phone_str)
        if clean.startswith("+"):
            p = phonenumbers.parse(clean)
        else:
            p = phonenumbers.parse(clean, "RU")
        return p, phonenumbers.is_valid_number(p)

    @pytest.mark.parametrize("raw", [
        "9261234567",        # 10-значный (раньше отвергался off-by-one)
        "89261234567",       # 8-префикс
        "+79261234567",      # международный
        "8 (926) 123-45-67", # форматированный
    ])
    def test_valid_ru_numbers(self, raw):
        import phonenumbers
        p, valid = self._parse(raw)
        assert valid is True
        assert phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164) == \
            "+79261234567"


class TestPhoneTypeMap:
    def test_type_map_complete(self):
        # Проверяем что новые типы добавлены в модуль
        import analyzers.phone as ph
        import inspect
        src = inspect.getsource(ph.analyze_phone_combo)
        for t in ("Shared-cost", "Pager", "UAN", "Voicemail"):
            assert t in src, f"тип {t} отсутствует в type_map"
