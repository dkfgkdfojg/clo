# gui/console/panel.py
"""Панель консоли: тулбар (копировать/очистить/автопрокрутка), покраска строк,
кликабельные ссылки. Вынесена из app.py в отдельный модуль."""

import tkinter as tk

import customtkinter as ctk

from gui.console.redirect import RedirectText


class ConsolePanel:
    def __init__(self, parent, colors, font_ui, font_mono, root):
        C = self.C = colors
        self.root = root
        self.autoscroll = tk.BooleanVar(value=True)
        self._lines_var = tk.StringVar(value="строк: 0")

        self.frame = ctk.CTkFrame(parent, fg_color=C.CARD, corner_radius=14,
                                  border_width=1, border_color=C.BORDER)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(self.frame, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 0))
        ctk.CTkLabel(bar, text="●  Консоль", text_color=C.MUTED,
                     font=(font_ui, 10, "bold")).pack(side="left")

        ctk.CTkLabel(bar, textvariable=self._lines_var, text_color=C.MUTED2,
                     font=(font_ui, 9)).pack(side="right", padx=(8, 0))
        ctk.CTkButton(bar, text="Очистить", width=72, height=24, corner_radius=7,
                      fg_color=C.SURFACE2, hover_color=C.DANGER, text_color=C.TEXT,
                      font=(font_ui, 10), command=self.clear).pack(side="right", padx=4)
        ctk.CTkButton(bar, text="Копировать", width=84, height=24, corner_radius=7,
                      fg_color=C.SURFACE2, hover_color=C.PRIMARY_SOFT, text_color=C.TEXT,
                      font=(font_ui, 10), command=self.copy).pack(side="right", padx=4)
        ctk.CTkCheckBox(bar, text="автопрокрутка", variable=self.autoscroll,
                        checkbox_width=16, checkbox_height=16, corner_radius=4,
                        fg_color=C.PRIMARY, hover_color=C.PRIMARY_HOVER,
                        text_color=C.MUTED, font=(font_ui, 10)).pack(side="right", padx=(4, 12))

        holder = ctk.CTkFrame(self.frame, fg_color=C.BG, corner_radius=10)
        holder.grid(row=1, column=0, sticky="nsew", padx=14, pady=14)
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)

        sb = ctk.CTkScrollbar(holder, fg_color=C.BG, button_color=C.BORDER,
                              button_hover_color=C.MUTED2)
        sb.grid(row=0, column=1, sticky="ns", pady=10, padx=(0, 8))

        self.text_area = tk.Text(
            holder, bg=C.BG, fg=C.TEXT, insertbackground=C.PRIMARY,
            selectbackground=C.BORDER, font=(font_mono, 11), relief=tk.FLAT,
            padx=14, pady=10, state=tk.DISABLED, wrap=tk.WORD,
            highlightthickness=0, yscrollcommand=sb.set,
        )
        self.text_area.grid(row=0, column=0, sticky="nsew", padx=(2, 0), pady=2)
        sb.configure(command=self.text_area.yview)
        self.text_area.bind("<<Modified>>", self._upd_lines)

        self.text_area.tag_config("ok", foreground=C.SUCCESS)
        self.text_area.tag_config("err", foreground=C.DANGER)
        self.text_area.tag_config("section", foreground=C.PRIMARY)
        self.text_area.tag_config("muted", foreground=C.MUTED)
        self.text_area.tag_config("item", foreground=C.INFO)

        self.redirect = RedirectText(self.text_area, root=root,
                                     autoscroll_var=self.autoscroll)

    def _upd_lines(self, e=None):
        try:
            n = int(self.text_area.index("end-1c").split(".")[0])
            self._lines_var.set(f"строк: {n}")
        except Exception:
            pass
        self.text_area.edit_modified(False)

    def clear(self):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete("1.0", tk.END)
        self.text_area.config(state=tk.DISABLED)

    def copy(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.text_area.get("1.0", tk.END))
        except tk.TclError:
            pass
