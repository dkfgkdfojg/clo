# gui/redirect.py
import tkinter as tk
import re
import webbrowser


class RedirectText:
    """
    Перенаправляет stdout/stderr в виджет tk.Text.
    Автоматически делает ссылки кликабельными.
    """

    def __init__(self, text_widget):
        self.output = text_widget
        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        self.url_regex = re.compile(r"(https?://[^\s\)]+)")
        self.output.tag_config("link", foreground="#00BFFF", underline=1)
        self.output.tag_bind(
            "link", "<Enter>", lambda e: self.output.config(cursor="hand2")
        )
        self.output.tag_bind("link", "<Leave>", lambda e: self.output.config(cursor=""))
        self.output.tag_bind("link", "<Button-1>", self.open_link)
        self.output.url_map = {}

    def open_link(self, event):
        idx = self.output.index(f"@{event.x},{event.y}")
        for tag in self.output.tag_names(idx):
            if tag.startswith("url_"):
                url = self.output.url_map.get(tag)
                if url:
                    webbrowser.open(url)

    def write(self, string):
        clean = self.ansi_escape.sub("", string)
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

    def flush(self):
        pass
