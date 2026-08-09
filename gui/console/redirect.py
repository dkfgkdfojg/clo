# gui/console/redirect.py
import queue
import re
import tkinter as tk
import webbrowser

# Как часто главный поток забирает накопленный вывод, мс.
DRAIN_INTERVAL_MS = 50
# Предохранитель: за один заход вставляем ограниченное число кусков.
MAX_CHUNKS_PER_DRAIN = 200

# Правила покраски строки по префиксу: (регэксп, тег).
LINE_RULES = [
    (re.compile(r"^\s*\[✓\]|^\s*\[\+\]|^\s*✔"), "ok"),
    (re.compile(r"^\s*\[!\]|^\s*✗| error|ошибка", re.I), "err"),
    (re.compile(r"^\s*▸|^\s*═|^\s*─"), "section"),
    (re.compile(r"^\s*\[[–\-i]\]|^\s*\[i\]"), "muted"),
    (re.compile(r"^\s*•|^\s*→"), "item"),
]


class RedirectText:
    """stdout → tk.Text из фонового потока безопасно: write() кладёт в очередь,
    рисует главный поток по root.after. Строки красятся по префиксу, ссылки
    кликабельны."""

    def __init__(self, text_widget, root=None, autoscroll_var=None):
        self.output = text_widget
        self.root = root or text_widget.winfo_toplevel()
        self.queue: queue.Queue[str] = queue.Queue()
        self._drain_job = None
        self._closed = False
        self._autoscroll = autoscroll_var

        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        self.url_regex = re.compile(r"(https?://[^\s\)]+)")
        self.output.tag_config("link", foreground="#4bd6c0", underline=1)
        self.output.tag_bind("link", "<Enter>", lambda e: self.output.config(cursor="hand2"))
        self.output.tag_bind("link", "<Leave>", lambda e: self.output.config(cursor=""))
        self.output.tag_bind("link", "<Button-1>", self.open_link)
        self.output.tag_raise("link")
        self.output.url_map = {}
        self._buf = ""  # незавершённая строка между чанками

        self._schedule_drain()

    def write(self, string):
        if string and not self._closed:
            self.queue.put(string)

    def flush(self):
        pass

    def _schedule_drain(self):
        if not self._closed:
            self._drain_job = self.root.after(DRAIN_INTERVAL_MS, self._drain)

    def _drain(self):
        chunks = []
        for _ in range(MAX_CHUNKS_PER_DRAIN):
            try:
                chunks.append(self.queue.get_nowait())
            except queue.Empty:
                break
        if chunks:
            try:
                self._insert("".join(chunks))
            except tk.TclError:
                self.close()
                return
        self._schedule_drain()

    def _line_tag(self, line):
        for rx, tag in LINE_RULES:
            if rx.search(line):
                return tag
        return None

    def _insert(self, source):
        clean = self.ansi_escape.sub("", source)
        self._buf += clean
        # рисуем только завершённые строки; хвост без \n держим до следующего чанка
        *lines, self._buf = self._buf.split("\n")

        self.output.config(state=tk.NORMAL)
        for line in lines:
            self._insert_line(line + "\n")
        self.output.config(state=tk.DISABLED)
        if self._autoscroll is None or self._autoscroll.get():
            self.output.see(tk.END)

    def _insert_line(self, line):
        base = self._line_tag(line)
        last = 0
        for m in self.url_regex.finditer(line):
            s, e = m.span()
            self._chunk(line[last:s], base)
            tag = f"url_{abs(hash(m.group(0)))}"
            self.output.url_map[tag] = m.group(0)
            self.output.insert(tk.END, m.group(0), ("link", tag))
            last = e
        self._chunk(line[last:], base)

    def _chunk(self, text, base):
        if not text:
            return
        self.output.insert(tk.END, text, (base,) if base else ())

    def close(self):
        self._closed = True
        if self._drain_job is not None:
            try:
                self.root.after_cancel(self._drain_job)
            except tk.TclError:
                pass
            self._drain_job = None

    def open_link(self, event):
        idx = self.output.index(f"@{event.x},{event.y}")
        for tag in self.output.tag_names(idx):
            if tag.startswith("url_"):
                url = self.output.url_map.get(tag)
                if url:
                    webbrowser.open(url)
