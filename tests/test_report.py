"""Тесты сборщика отчётов: перехват вывода, редакция секретов, JSON/HTML."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import report
from core.utils import print_section, print_field, print_summary, dual_print


def _run_capture():
    """Прогнать типовой вывод анализатора при активном отчёте."""
    rep = report.begin("Test", "target@x")
    print_section("Профиль")
    print_field("Имя", "Alice")
    print_field("Пусто", "")          # не должно попасть
    dual_print("  [!] какая-то заметка")
    print_summary({"k": "v"}, "Итог")
    report.finish()
    return rep


class TestCollection:
    def test_sections_and_fields(self):
        rep = _run_capture()
        d = rep.to_dict()
        prof = [s for s in d["sections"] if s["title"] == "Профиль"][0]
        labels = {f["label"]: f["value"] for f in prof["fields"]}
        assert labels["Имя"] == "Alice"
        assert "Пусто" not in labels          # print_field глотает пустое
        assert any("заметк" in n for n in prof["notes"])

    def test_summary(self):
        rep = _run_capture()
        d = rep.to_dict()
        assert d["summaries"][0]["items"] == {"k": "v"}

    def test_no_double_note_from_field(self):
        """print_field не должен дублироваться ещё и как заметка."""
        rep = _run_capture()
        prof = [s for s in rep.to_dict()["sections"] if s["title"] == "Профиль"][0]
        assert not any("Alice" in n for n in prof["notes"])

    def test_inactive_no_crash(self):
        """Без begin() хелперы просто печатают и не падают."""
        assert report.current() is None
        print_field("x", "y")


class TestRedaction:
    def test_secret_in_url_note(self):
        rep = report.begin("Test", "t")
        dual_print("fetch https://api.site.com/v1?api_key=SUPERSECRET123&x=1")
        report.finish()
        blob = json.dumps(rep.to_dict())
        assert "SUPERSECRET123" not in blob
        assert "***" in blob


class TestSerialization:
    def test_html_and_json(self, tmp_path):
        rep = _run_capture()
        jp, hp = rep.save(tmp_path)
        assert jp.exists() and hp.exists()
        data = json.loads(jp.read_text(encoding="utf-8"))
        assert data["kind"] == "Test" and data["target"] == "target@x"
        html = hp.read_text(encoding="utf-8")
        assert "Alice" in html and "<html" in html.lower()

    def test_html_escapes(self, tmp_path):
        rep = report.begin("Test", "t")
        print_field("xss", "<script>alert(1)</script>")
        report.finish()
        _, hp = rep.save(tmp_path)
        html = hp.read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
