"""Проверка потокобезопасности вывода GUI.

Смысл: анализаторы печатают из рабочих потоков, а Tk можно трогать только из
главного. Раньше RedirectText.write вставлял текст в виджет прямо из вызвавшего
потока — тесты ниже как раз про то, что теперь этого не происходит.

Если DISPLAY недоступен (сервер, CI), тесты пропускаются: без него Tk не
поднимается, а подменять его целиком ради проверки очереди смысла нет.
"""

import queue
import threading
import time

import pytest

tk = pytest.importorskip("tkinter")

from gui.console.redirect import RedirectText  # noqa: E402


@pytest.fixture
def widget():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("нет графической сессии")
    root.withdraw()
    text = tk.Text(root)
    text.pack()
    yield root, text
    try:
        root.destroy()
    except tk.TclError:
        pass


def test_write_does_not_touch_widget(widget):
    """write() из чужого потока только кладёт в очередь, но не рисует."""
    root, text = widget
    redirect = RedirectText(text, root=root)

    done = threading.Event()

    def worker():
        redirect.write("привет из потока\n")
        done.set()

    threading.Thread(target=worker, daemon=True).start()
    assert done.wait(timeout=5), "поток завис на write()"

    # главный цикл ещё не крутился — в виджете пусто, текст ждёт в очереди
    assert text.get("1.0", tk.END).strip() == ""
    assert not redirect.queue.empty()

    redirect.close()


def test_drain_moves_text_to_widget(widget):
    """После оборота главного цикла текст оказывается в виджете."""
    root, text = widget
    redirect = RedirectText(text, root=root)

    redirect.write("строка один\n")
    redirect.write("строка два\n")

    # даём таймеру after сработать
    deadline = time.time() + 5
    while time.time() < deadline and "строка два" not in text.get("1.0", tk.END):
        root.update()
        time.sleep(0.02)

    content = text.get("1.0", tk.END)
    assert "строка один" in content
    assert "строка два" in content

    redirect.close()


def test_many_threads_do_not_lose_output(widget):
    """Сотня одновременных write() не теряет и не путает строки."""
    root, text = widget
    redirect = RedirectText(text, root=root)

    def worker(n):
        redirect.write(f"поток-{n}\n")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    deadline = time.time() + 10
    while time.time() < deadline:
        root.update()
        if redirect.queue.empty():
            break
        time.sleep(0.02)

    content = text.get("1.0", tk.END)
    missing = [i for i in range(100) if f"поток-{i}" not in content]
    assert not missing, f"потеряны строки: {missing[:10]}"

    redirect.close()


def test_write_after_close_is_silent(widget):
    """Закрыли окно — write() не должен падать."""
    root, text = widget
    redirect = RedirectText(text, root=root)
    redirect.close()

    redirect.write("уже поздно\n")  # не должно бросить
    assert redirect.queue.empty()


def test_links_are_tagged(widget):
    """Разбор ссылок не сломался при переезде на очередь."""
    root, text = widget
    redirect = RedirectText(text, root=root)

    redirect.write("смотри https://example.com/page тут\n")

    deadline = time.time() + 5
    while time.time() < deadline and "example.com" not in text.get("1.0", tk.END):
        root.update()
        time.sleep(0.02)

    assert "link" in text.tag_names()
    assert any(url.startswith("https://example.com")
               for url in text.url_map.values())

    redirect.close()


def test_ansi_escapes_are_stripped(widget):
    """Цветовые коды из консольных утилит не должны попадать в виджет."""
    root, text = widget
    redirect = RedirectText(text, root=root)

    redirect.write("\x1b[31mкрасный\x1b[0m текст\n")

    deadline = time.time() + 5
    while time.time() < deadline and "красный" not in text.get("1.0", tk.END):
        root.update()
        time.sleep(0.02)

    content = text.get("1.0", tk.END)
    assert "красный текст" in content
    assert "\x1b" not in content
    assert "[31m" not in content

    redirect.close()


def test_queue_is_used(widget):
    """Очередь именно queue.Queue — на ней держится потокобезопасность."""
    root, text = widget
    redirect = RedirectText(text, root=root)
    assert isinstance(redirect.queue, queue.Queue)
    redirect.close()
