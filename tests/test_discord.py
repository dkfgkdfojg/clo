"""Регрессионные тесты для analyzers.discord.

Покрывают:
  * _print_history_block — исправленный баг дедупликации (печатал имена,
    уже встреченные в других источниках; плюс был мёртвый цикл с pass).
  * SnowflakeInfo.from_id — декодирование Discord snowflake.
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers import discord as d


def _capture(names, seen):
    """Прогнать _print_history_block и вернуть (stdout, возвращённое число)."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        n = d._print_history_block("SRC", names, seen)
    finally:
        sys.stdout = old
    return buf.getvalue(), n


class TestPrintHistoryBlock:
    def test_first_source_prints_all_new(self):
        seen = set()
        out, n = _capture(["alice", "bob"], seen)
        assert n == 2
        assert "alice" in out and "bob" in out
        assert seen == {"alice", "bob"}

    def test_cross_source_dedup(self):
        """Имя из первого источника не должно повторяться во втором."""
        seen = set()
        _capture(["alice", "bob"], seen)
        out, n = _capture(["bob", "carol"], seen)
        assert n == 1                      # только carol — новое
        assert "carol" in out
        assert "bob" not in out            # был баг: bob печатался повторно
        assert "(+1)" in out

    def test_intra_block_dedup(self):
        """Дубли внутри одного источника схлопываются."""
        seen = set()
        out, n = _capture(["sam", "Sam", "SAM"], seen)
        assert n == 1
        assert out.count("→") == 1

    def test_empty_source(self):
        seen = set()
        out, n = _capture([], seen)
        assert n == 0
        assert "пусто" in out

    def test_all_duplicates_reports_no_new(self):
        seen = {"alice"}
        out, n = _capture(["alice"], seen)
        assert n == 0
        assert "нет новых" in out

    def test_limit_respected(self):
        seen = set()
        names = [f"name{i}" for i in range(d.MAX_HISTORY_ENTRIES + 10)]
        out, n = _capture(names, seen)
        assert n == len(names)             # все посчитаны как новые
        assert out.count("→") == d.MAX_HISTORY_ENTRIES  # но напечатано не больше limit


class TestSnowflake:
    def test_known_id(self):
        # Публично известный пример из Discord API docs
        info = d.SnowflakeInfo.from_id("175928847299117063")
        assert info is not None
        assert info.creation_utc.startswith("2016-04-30")
        assert info.worker_id == 1
        assert info.process_id == 0
        assert info.increment == 7

    def test_non_numeric_returns_none(self):
        assert d.SnowflakeInfo.from_id("abc") is None
        assert d.SnowflakeInfo.from_id("") is None
        assert d.SnowflakeInfo.from_id("123abc") is None

    def test_monotonic_dates(self):
        """Больший snowflake => более поздняя дата создания."""
        older = d.SnowflakeInfo.from_id("175928847299117063")
        newer = d.SnowflakeInfo.from_id("900000000000000000")
        assert older.creation_utc < newer.creation_utc
