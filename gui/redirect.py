# gui/redirect.py
import queue
import re
import tkinter as tk
import webbrowser

# Как часто главный поток забирает накопленный вывод, мс. 50 мс — вывод выглядит
# мгновенным, но при потоке строк из сканера мы вставляем их пачкой, а не по
# одной, и интерфейс не захлёбывается.
DRAIN_INTERVAL_MS = 50

# Предохранитель от зависания: если анализатор внезапно начнёт сыпать мегабайты,
# за один заход вставляем ограниченное число кусков, остальное подождёт.
MAX_CHUNKS_PER_DRAIN = 200


class RedirectText:
    """
    Перенаправляет stdout/stderr в виджет tk.Text.
    Автоматически делает ссылки кликабельными.

    Tkinter не потокобезопасен: трогать виджеты можно только из того потока,
    где крутится mainloop. Анализаторы же работают в рабочих потоках
    (см. App.run_in_thread) и печатают оттуда, поэтому write() ничего не рисует
    сам — он лишь кладёт текст в очередь. Разбирает её главный поток по таймеру
    root.after, где обращение к виджету законно.
    """

    def __init__(self, text_widget, root=None):
        self.output = text_widget
        # root нужен для after(); если не передали — берём у самого виджета
        self.root = root or text_widget.winfo_toplevel()
        self.queue: queue.Queue[str] = queue.Queue()
        self._drain_job = None
        self._closed = False

        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        self.url_regex = re.compile(r"(https?://[^\s\)]+)")
        self.output.tag_config("link", foreground="#00BFFF", underline=1)
        self.output.tag_bind(
            "link", "<Enter>", lambda e: self.output.config(cursor="hand2")
        )
        self.output.tag_bind("link", "<Leave>", lambda e: self.output.config(cursor=""))
        self.output.tag_bind("link", "<Button-1>", self.open_link)
        self.output.url_map = {}

        self._schedule_drain()

    # ------------------------------------------------------------- вывод
    def write(self, string):
        """Вызывается из любого потока — только кладём в очередь."""
        if string and not self._closed:
            self.queue.put(string)

    def flush(self):
        pass

    # --------------------------------------------------- главный поток
    def _schedule_drain(self):
        if not self._closed:
            self._drain_job = self.root.after(DRAIN_INTERVAL_MS, self._drain)

    def _drain(self):
        """Переносит накопленное из очереди в виджет. Только главный поток."""
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
                # окно уже уничтожено — дальше писать некуда
                self.close()
                return

        self._schedule_drain()

    def _insert(self, clean_source):
        clean = self.ansi_escape.sub("", clean_source)
        self.output.config(state=tk.NORMAL)
        last = 0
        for m in self.url_regex.finditer(clean):
            s, e = m.span()
            url = m.group(0)
            self.output.insert(tk.END, clean[last:s])
            tag = f"url_{abs(hash(url))}"
            self.output.url_map[tag] = url
            self.output.insert(tk.END, url, ("link", tag))
            last = e
        self.output.insert(tk.END, clean[last:])
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def close(self):
        """Останавливает разбор очереди — зовётся при закрытии окна."""
        self._closed = True
        if self._drain_job is not None:
            try:
                self.root.after_cancel(self._drain_job)
            except tk.TclError:
                pass
            self._drain_job = None

    # ------------------------------------------------------------ ссылки
    def open_link(self, event):
        idx = self.output.index(f"@{event.x},{event.y}")
        for tag in self.output.tag_names(idx):
            if tag.startswith("url_"):
                url = self.output.url_map.get(tag)
                if url:
                    webbrowser.open(url)
