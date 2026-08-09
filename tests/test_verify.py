"""Тесты core.verify без сети (DoH мокаем фейковой сессией)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import verify


class _FakeResp:
    def __init__(self, answer):
        self.status_code = 200
        self._answer = answer

    def json(self):
        return {"Answer": self._answer}


class _FakeSession:
    """Отдаёт заданные MX-ответы, чтобы не ходить в сеть."""

    def __init__(self, mx=None, a=None):
        self.mx = mx or []
        self.a = a or []

    def get(self, url, params=None, timeout=None):
        rtype = (params or {}).get("type")
        if rtype == "MX":
            return _FakeResp([{"type": 15, "data": f"10 {h}."} for h in self.mx])
        return _FakeResp([{"type": 1, "data": ip} for ip in self.a])


class TestCheckEmail:
    def test_bad_syntax(self):
        r = verify.check_email("not-an-email", _FakeSession())
        assert r["syntax_valid"] is False and r["deliverable"] is False

    def test_valid_with_mx(self):
        r = verify.check_email("john@example.com", _FakeSession(mx=["mx.example.com"]))
        assert r["syntax_valid"] and r["has_mx"] and r["deliverable"]
        assert r["mx_hosts"] == ["mx.example.com"]

    def test_no_mx_but_a(self):
        r = verify.check_email("john@example.com", _FakeSession(mx=[], a=["1.2.3.4"]))
        assert r["has_mx"] is False and r["has_a"] and r["deliverable"]

    def test_dead_domain(self):
        r = verify.check_email("john@example.com", _FakeSession())
        assert r["deliverable"] is False

    def test_disposable(self):
        r = verify.check_email("x@mailinator.com", _FakeSession(mx=["m"]))
        assert r["is_disposable"] is True

    def test_role_and_free(self):
        r = verify.check_email("admin@gmail.com", _FakeSession(mx=["m"]))
        assert r["is_role"] is True and r["is_free"] is True


class TestCheckPhone:
    def test_valid_ru(self):
        r = verify.check_phone("+79261234567")
        assert r["valid"] and r["e164"] == "+79261234567" and r["country_code"] == 7

    def test_invalid(self):
        r = verify.check_phone("+7123")
        assert r["valid"] is False

    def test_garbage(self):
        r = verify.check_phone("abcxyz")
        assert r["parsed"] is False and r["valid"] is False

    def test_local_ru(self):
        r = verify.check_phone("89261234567")
        assert r["valid"] and r["country_code"] == 7
