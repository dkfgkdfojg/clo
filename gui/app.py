# gui/app.py
"""
Десктоп-интерфейс clo в стиле Recon: боковое меню с секциями и бейджами,
справа карточки активной цели / быстрых действий / статусов модулей и консоль.
"""

import os
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog

import customtkinter as ctk

from analyzers.phone import analyze_phone_combo
from analyzers.username import analyze_username_combo
from analyzers.email import analyze_email_leaks
from analyzers.discord import analyze_discord
from analyzers.ip import analyze_ip_basic, analyze_shodan_smart
from analyzers.photo import analyze_photo
from analyzers.domain import analyze_domain
from analyzers.telegram import analyze_telegram_full
from analyzers.github import analyze_github
from analyzers.investigate import investigate
from core.utils import dual_print
from core import report

from gui.redirect import RedirectText


def pick_font(preferred, fallback):
    try:
        available = set(tkfont.families())
    except Exception:
        return fallback
    for name in preferred:
        if name in available:
            return name
    return fallback


# ---------- Палитра (тёмная, слейт) ----------
class C:
    BG = "#0e1014"
    SURFACE = "#181b21"
    SURFACE2 = "#1e222a"
    CARD = "#181b21"
    BORDER = "#282d37"
    BORDER_SOFT = "#20242c"
    TEXT = "#e7e9ee"
    MUTED = "#7c8593"
    MUTED2 = "#565e6b"

    PRIMARY = "#4bd6c0"          # бирюзовый бренд/акцент
    PRIMARY_HOVER = "#5fe3ce"
    PRIMARY_SOFT = "#2a2f3a"     # фон активного пункта

    SUCCESS = "#43c67a"
    WARNING = "#f0a742"
    DANGER = "#ff5d73"
    INFO = "#56ccf2"


# Ключ API, без которого модуль неполноценен (для карточки статусов).
NEEDS_KEY = {"shodan": "SHODAN"}

# Пример ввода для placeholder (по активному модулю).
EXAMPLES = {
    "username": "john_doe", "email": "john@example.com", "phone": "+79261234567",
    "telegram": "@durov", "discord": "267624335836053506", "github": "torvalds",
    "domain": "example.com", "ip": "8.8.8.8", "shodan": "8.8.8.8",
    "photo": "файл фото…", "investigate": "john@example.com",
}

# Разделы бокового меню: (заголовок, [(key, иконка, подпись, отступ, бейдж)]).
NAV = [
    ("ЛИЧНОСТЬ", [
        ("username", "👤", "Имя пользователя", False, None),
        ("email", "✉️", "Email", False, ("утечки", C.DANGER)),
        ("phone", "📞", "Телефон", False, None),
    ]),
    ("АККАУНТЫ", [
        ("telegram", "✈️", "Телеграмма", False, None),
        ("discord", "💬", "Discord", False, None),
        ("github", "🐙", "GitHub", False, None),
    ]),
    ("ИНФРАСТРУКТУРА", [
        ("domain", "🌐", "Домен", False, None),
        ("ip", "🖥️", "IP-адрес", False, None),
        ("shodan", "🛰️", "IP + Шодан", True, ("API", C.WARNING)),
    ]),
    ("СМИ", [
        ("photo", "🖼️", "Фото", False, None),
    ]),
]

# Нижний блок (действия/навигация): (key, иконка, подпись, бейдж).
BOTTOM = [
    ("investigate", "🔎", "Расследование", None),
    ("history", "🕘", "История запросов", None),
    ("settings", "⚙️", "Настройки и ключи", None),
]

# Все анализ-модули (для статистики статусов).
ALL_MODULES = [k for _, items in NAV for k, *_ in items] + ["investigate"]


ctk.set_appearance_mode("dark")


class OSINTApp:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("Recon — OSINT")
        self.root.geometry("1240x760")
        self.root.minsize(1000, 640)
        self.root.configure(fg_color=C.BG)

        self.font_ui = pick_font(
            ["Inter", "Noto Sans", "Cantarell", "Liberation Sans", "DejaVu Sans"],
            "TkDefaultFont",
        )
        self.font_mono = pick_font(
            ["JetBrains Mono", "JetBrainsMono Nerd Font", "Fira Code", "Hack",
             "DejaVu Sans Mono"],
            "TkFixedFont",
        )

        self.active_key = None
        self._nav_btns = {}
        self._ran = set()            # модули, отработавшие в этой сессии
        self._invest_active = 0      # активных расследований (для бейджа)
        self._pulse_job = None
        self._pulse_on = False
        self._stat_var = tk.StringVar(value="Готов к работе")

        self._build_layout()

        self._orig_stdout = sys.stdout
        self._redirect = RedirectText(self.text_area, root=self.root)
        sys.stdout = self._redirect
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._update_module_stats()
        self._banner()

    def _on_close(self):
        self._stop_pulse()
        if getattr(self, "_redirect", None) is not None:
            self._redirect.close()
        sys.stdout = getattr(self, "_orig_stdout", sys.__stdout__)
        self.root.destroy()

    # ================= LAYOUT =================
    def _build_layout(self):
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self._build_sidebar()

        main = ctk.CTkFrame(self.root, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=(14, 16), pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        self._build_top_cards(main)
        self._build_console(main)

    # ----------------- Sidebar -----------------
    def _build_sidebar(self):
        side = ctk.CTkFrame(self.root, width=272, corner_radius=0, fg_color=C.SURFACE)
        side.grid(row=0, column=0, sticky="nsw")
        side.grid_propagate(False)

        # Лого
        logo = ctk.CTkFrame(side, fg_color="transparent")
        logo.pack(fill="x", padx=20, pady=(20, 14))
        ctk.CTkLabel(logo, text="◎", text_color=C.PRIMARY,
                     font=(self.font_ui, 20, "bold")).pack(side="left")
        ctk.CTkLabel(logo, text="Recon", text_color=C.TEXT,
                     font=(self.font_ui, 16, "bold")).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(logo, text="v0.9", text_color=C.MUTED2,
                     font=(self.font_ui, 10)).pack(side="right")

        # Поиск цели
        search = ctk.CTkFrame(side, fg_color=C.SURFACE2, corner_radius=9,
                              border_width=1, border_color=C.BORDER)
        search.pack(fill="x", padx=16, pady=(0, 6))
        ctk.CTkLabel(search, text="🔍", text_color=C.MUTED,
                     font=(self.font_ui, 12)).pack(side="left", padx=(10, 2))
        self.entry_target = ctk.CTkEntry(
            search, placeholder_text="Введите цель", fg_color="transparent",
            border_width=0, text_color=C.TEXT, placeholder_text_color=C.MUTED2,
            font=(self.font_ui, 12), height=38,
        )
        self.entry_target.pack(side="left", fill="x", expand=True)
        self.entry_target.bind("<Return>", self._on_enter)
        kbd = ctk.CTkLabel(search, text="⌘K", text_color=C.MUTED2,
                           fg_color=C.SURFACE, corner_radius=5,
                           font=(self.font_mono, 9), width=28, height=20)
        kbd.pack(side="right", padx=8)

        # Прокручиваемый список модулей
        nav = ctk.CTkScrollableFrame(side, fg_color="transparent")
        nav.pack(fill="both", expand=True, padx=2, pady=2)

        for title, items in NAV:
            ctk.CTkLabel(nav, text=title, text_color=C.MUTED2,
                         font=(self.font_ui, 9, "bold"), anchor="w").pack(
                fill="x", padx=18, pady=(12, 3))
            for key, icon, label, indent, badge in items:
                self._nav_btns[key] = self._make_nav_item(
                    nav, key, icon, label, indent=indent, badge=badge)

        # Нижний блок
        ctk.CTkFrame(side, fg_color=C.BORDER_SOFT, height=1).pack(
            fill="x", padx=18, pady=(6, 4))
        bottom = ctk.CTkFrame(side, fg_color="transparent")
        bottom.pack(fill="x", padx=0, pady=(0, 12))
        for key, icon, label, badge in BOTTOM:
            self._nav_btns[key] = self._make_nav_item(bottom, key, icon, label, badge=badge)

    def _make_nav_item(self, parent, key, icon, label, indent=False, badge=None):
        cmd = getattr(self, f"run_{key}")
        row = ctk.CTkFrame(parent, fg_color="transparent", corner_radius=8)
        row.pack(fill="x", padx=10, pady=1)

        left_pad = 22 if indent else 6
        ico = ctk.CTkLabel(row, text=icon, text_color=C.MUTED,
                           font=(self.font_ui, 14), width=20)
        ico.pack(side="left", padx=(left_pad, 8), pady=7)
        lbl = ctk.CTkLabel(row, text=label, text_color=C.MUTED, anchor="w",
                           font=(self.font_ui, 12))
        lbl.pack(side="left", fill="x", expand=True)

        badge_lbl = None
        if badge:
            text, color = badge
            badge_lbl = ctk.CTkLabel(row, text=text, text_color=color,
                                     fg_color=C.SURFACE2, corner_radius=6,
                                     font=(self.font_ui, 9, "bold"))
            badge_lbl.pack(side="right", padx=(0, 10))

        entry = {"row": row, "icon": ico, "label": lbl, "badge": badge_lbl}
        for w in (row, ico, lbl) + ((badge_lbl,) if badge_lbl else ()):
            w.bind("<Button-1>", lambda e, k=key, c=cmd: self._activate(k, c))
            w.bind("<Enter>", lambda e, k=key: self._nav_hover(k, True))
            w.bind("<Leave>", lambda e, k=key: self._nav_hover(k, False))
        return entry

    def _nav_hover(self, key, on):
        if key == self.active_key:
            return
        self._nav_btns[key]["row"].configure(fg_color=C.SURFACE2 if on else "transparent")

    def _set_nav_state(self, key, active):
        e = self._nav_btns[key]
        e["row"].configure(fg_color=C.PRIMARY_SOFT if active else "transparent")
        e["icon"].configure(text_color=C.PRIMARY if active else C.MUTED)
        e["label"].configure(text_color=C.TEXT if active else C.MUTED)

    def _activate(self, key, cmd):
        if self.active_key and self.active_key in self._nav_btns:
            self._set_nav_state(self.active_key, False)
        self.active_key = key
        self._set_nav_state(key, True)
        if key in EXAMPLES:
            self.entry_target.configure(placeholder_text=f"напр.: {EXAMPLES[key]}")
        cmd()

    # ----------------- Верхние карточки -----------------
    def _build_top_cards(self, parent):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        wrap.grid_columnconfigure(0, weight=1)

        self._build_target_card(wrap)
        self._build_actions_card(wrap)
        self._build_status_card(wrap)

    def _card(self, parent, title):
        card = ctk.CTkFrame(parent, fg_color=C.CARD, corner_radius=14,
                            border_width=1, border_color=C.BORDER)
        card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(card, text=title, text_color=C.MUTED,
                     font=(self.font_ui, 10, "bold"), anchor="w").pack(
            fill="x", padx=18, pady=(13, 2))
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=18, pady=(2, 15))
        return body

    def _build_target_card(self, parent):
        body = self._card(parent, "Активная цель")
        self._avatar = ctk.CTkLabel(
            body, text="—", text_color=C.TEXT, fg_color=C.PRIMARY_SOFT,
            corner_radius=22, width=44, height=44, font=(self.font_ui, 14, "bold"))
        self._avatar.pack(side="left", padx=(0, 14))
        col = ctk.CTkFrame(body, fg_color="transparent")
        col.pack(side="left", fill="x", expand=True)
        self._target_value_lbl = ctk.CTkLabel(
            col, text="цель не выбрана", text_color=C.TEXT, anchor="w",
            font=(self.font_ui, 15, "bold"))
        self._target_value_lbl.pack(anchor="w")
        self._target_sub_lbl = ctk.CTkLabel(
            col, text="выберите модуль и введите цель", text_color=C.MUTED,
            anchor="w", font=(self.font_ui, 11))
        self._target_sub_lbl.pack(anchor="w")

    def _build_actions_card(self, parent):
        body = self._card(parent, "Быстрые действия")
        actions = (("🔎  В дело", self.run_investigate),
                   ("🏷  Тег", self._tag_target),
                   ("⬇  Экспорт", self.save_report))
        for i in range(len(actions)):
            body.grid_columnconfigure(i, weight=1, uniform="act")
        for i, (text, cmd) in enumerate(actions):
            ctk.CTkButton(
                body, text=text, height=34, corner_radius=9,
                fg_color=C.SURFACE2, hover_color=C.PRIMARY_SOFT, text_color=C.TEXT,
                font=(self.font_ui, 11), command=cmd,
            ).grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))

    def _build_status_card(self, parent):
        body = self._card(parent, "Статусы модулей")
        self._st_labels = {}
        for key, color, text in (("done", C.SUCCESS, "Готово"),
                                 ("key", C.WARNING, "Нужен ключ"),
                                 ("norun", C.MUTED2, "Не запускалось")):
            line = ctk.CTkFrame(body, fg_color="transparent")
            line.pack(fill="x", pady=2)
            ctk.CTkLabel(line, text="●", text_color=color,
                         font=(self.font_ui, 12)).pack(side="left", padx=(0, 8))
            lbl = ctk.CTkLabel(line, text=f"{text} — 0", text_color=C.TEXT,
                               anchor="w", font=(self.font_ui, 12))
            lbl.pack(side="left")
            self._st_labels[key] = (lbl, text)

        sep = ctk.CTkFrame(body, fg_color=C.BORDER_SOFT, height=1)
        sep.pack(fill="x", pady=(8, 8))
        state = ctk.CTkFrame(body, fg_color="transparent")
        state.pack(fill="x")
        self._status_dot = ctk.CTkLabel(state, text="●", text_color=C.SUCCESS,
                                        font=(self.font_ui, 12))
        self._status_dot.pack(side="left", padx=(0, 8))
        self._status_lbl = ctk.CTkLabel(state, text="Готов", text_color=C.TEXT,
                                        anchor="w", font=(self.font_ui, 12, "bold"))
        self._status_lbl.pack(side="left")
        ctk.CTkLabel(state, textvariable=self._stat_var, text_color=C.MUTED2,
                     anchor="e", font=(self.font_mono, 9)).pack(side="right")

    def _update_module_stats(self):
        need = {m for m in ALL_MODULES
                if m in NEEDS_KEY and not _has_key(NEEDS_KEY[m])}
        done = self._ran - need
        norun = set(ALL_MODULES) - done - need
        for key, n in (("done", len(done)), ("key", len(need)), ("norun", len(norun))):
            lbl, text = self._st_labels[key]
            lbl.configure(text=f"{text} — {n}")

    def _tag_target(self):
        t = self.entry_target.get().strip()
        self._status(f"Тег добавлен: {t}" if t else "Введите цель для тега",
                     C.INFO if t else C.WARNING)

    def _set_active_target(self, target, label, matches):
        initials = "".join(ch for ch in target if ch.isalnum())[:2].upper() or "—"
        self._avatar.configure(text=initials)
        self._target_value_lbl.configure(text=target)
        self._target_sub_lbl.configure(text=f"{label} · {matches} совпадений")

    # ----------------- Console -----------------
    def _build_console(self, parent):
        wrap = ctk.CTkFrame(parent, fg_color=C.CARD, corner_radius=14,
                            border_width=1, border_color=C.BORDER)
        wrap.grid(row=1, column=0, sticky="nsew")
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(wrap, fg_color="transparent", height=34)
        bar.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 0))
        ctk.CTkLabel(bar, text="●  Консоль", text_color=C.MUTED,
                     font=(self.font_ui, 10, "bold")).pack(side="left")
        self._lines_var = tk.StringVar(value="строк: 0")
        ctk.CTkLabel(bar, textvariable=self._lines_var, text_color=C.MUTED2,
                     font=(self.font_ui, 9)).pack(side="right")

        holder = ctk.CTkFrame(wrap, fg_color=C.BG, corner_radius=10)
        holder.grid(row=1, column=0, sticky="nsew", padx=16, pady=16)
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)

        sb = ctk.CTkScrollbar(holder, fg_color=C.BG, button_color=C.BORDER,
                              button_hover_color=C.MUTED2)
        sb.grid(row=0, column=1, sticky="ns", pady=10, padx=(0, 8))

        self.text_area = tk.Text(
            holder, bg=C.BG, fg=C.TEXT, insertbackground=C.PRIMARY,
            selectbackground=C.BORDER, font=(self.font_mono, 11), relief=tk.FLAT,
            padx=14, pady=10, state=tk.DISABLED, wrap=tk.WORD,
            highlightthickness=0, yscrollcommand=sb.set,
        )
        self.text_area.grid(row=0, column=0, sticky="nsew", padx=(2, 0), pady=2)
        sb.configure(command=self.text_area.yview)
        self.text_area.bind("<<Modified>>", self._upd_lines)

    def _upd_lines(self, e=None):
        try:
            n = int(self.text_area.index("end-1c").split(".")[0])
            self._lines_var.set(f"строк: {n}")
        except Exception:
            pass
        self.text_area.edit_modified(False)

    def _banner(self):
        print("  Recon · OSINT toolkit\n"
              "  Выберите модуль слева, введите цель и нажмите Enter.\n")

    # ================= ЛОГИКА =================
    def _status(self, text, color=None):
        color = color or C.SUCCESS
        self._status_lbl.configure(text=text)
        self._status_dot.configure(text_color=color)
        if text.lower().startswith("выполня"):
            self._start_pulse(color)
        else:
            self._stop_pulse(color)

    def _start_pulse(self, color):
        self._stop_pulse(color)
        self._pulse_on = True

        def pulse():
            if not self._pulse_on:
                return
            cur = self._status_dot.cget("text_color")
            nxt = C.MUTED2 if cur != C.MUTED2 else color
            self._status_dot.configure(text_color=nxt)
            self._pulse_job = self.root.after(420, pulse)

        pulse()

    def _stop_pulse(self, color=None):
        self._pulse_on = False
        if self._pulse_job:
            try:
                self.root.after_cancel(self._pulse_job)
            except tk.TclError:
                pass
            self._pulse_job = None
        if color is not None:
            try:
                self._status_dot.configure(text_color=color)
            except tk.TclError:
                pass

    def _invest_badge(self, delta):
        self._invest_active = max(0, self._invest_active + delta)
        self._stat_var.set(
            f"расследований активно: {self._invest_active}"
            if self._invest_active else "Готов к работе")

    def save_report(self):
        """Экспорт структурированного отчёта последнего прогона (JSON+HTML)."""
        if self._last_report is not None:
            path = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML", "*.html"), ("JSON", "*.json")],
                title="Экспорт отчёта",
            )
            if not path:
                return
            try:
                directory = os.path.dirname(path) or "."
                json_path, html_path = self._last_report.save(directory)
                dual_print(f"\n[✓] Отчёт: {html_path}\n[✓] JSON:  {json_path}")
            except Exception as e:
                dual_print(f"\n[!] Ошибка: {e}")
            return
        dual_print("\n[!] Нечего экспортировать — сначала запустите модуль.")

    def clear_console(self):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)
        if self.active_key and self.active_key in self._nav_btns:
            self._set_nav_state(self.active_key, False)
            self.active_key = None
        self._avatar.configure(text="—")
        self._target_value_lbl.configure(text="цель не выбрана")
        self._target_sub_lbl.configure(text="выберите модуль и введите цель")
        self._banner()
        self._status("Готов")

    _last_report = None

    def get_target(self):
        t = self.entry_target.get().strip()
        if not t:
            dual_print("\n[!] Введите цель.")
            self._status("Введите цель", C.WARNING)
            return None
        return t

    def _on_enter(self, event=None):
        if not self.active_key:
            self._status("Сначала выберите модуль", C.WARNING)
            return
        run = getattr(self, f"run_{self.active_key}", None)
        if run:
            run()

    def _ui(self, fn):
        try:
            self.root.after(0, fn)
        except (tk.TclError, RuntimeError):
            pass

    def run_in_thread(self, func, arg, label):
        self._status(f"Выполняется: {label}", C.WARNING)
        self._stat_var.set(f"→ {label}: {arg}")

        def wrapper():
            rep = report.begin(label, str(arg))
            try:
                func(arg)
                self._ui(lambda: self._status("Готов"))
            except Exception as e:
                dual_print(f"\n[!] Ошибка: {e}")
                self._ui(lambda: self._status("Ошибка", C.DANGER))
            finally:
                report.finish()
                self._last_report = rep
                matches = _match_count(rep)
                try:
                    _, html_path = rep.save()
                    dual_print(f"\n[✓] Отчёт: {html_path}")
                except Exception as e:
                    dual_print(f"\n[!] Отчёт не сохранён: {e}")
                if self.active_key:
                    self._ran.add(self.active_key)
                self._ui(lambda: self._set_active_target(str(arg), label, matches))
                self._ui(self._update_module_stats)
                self._ui(lambda: self._stat_var.set("Готов к работе"))

        threading.Thread(target=wrapper, daemon=True).start()

    # ---- Модули ----
    def run_phone(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_phone_combo, t, "Телефон")

    def run_username(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_username_combo, t, "Username")

    def run_email(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_email_leaks, t, "Email")

    def run_discord(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_discord, t, "Discord")

    def run_telegram(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_telegram_full, t, "Telegram")

    def run_github(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_github, t, "GitHub")

    def run_ip(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_ip_basic, t, "IP")

    def run_shodan(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_shodan_smart, t, "Shodan")

    def run_photo(self):
        path = filedialog.askopenfilename(
            title="Выберите фотографию",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.gif *.bmp")],
        )
        if path:
            self.run_in_thread(analyze_photo, path, "Фото")

    def run_domain(self):
        t = self.get_target()
        if t:
            self.run_in_thread(analyze_domain, t, "Домен")

    def run_investigate(self):
        """Расследование само пишет сводный отчёт — без обёртки run_in_thread."""
        t = self.get_target()
        if not t:
            return
        self._status("Выполняется: расследование", C.WARNING)
        self._invest_badge(+1)

        def wrapper():
            try:
                investigate(t)
                self._ran.add("investigate")
                self._ui(lambda: self._status("Готов"))
            except Exception as e:
                dual_print(f"\n[!] Ошибка: {e}")
                self._ui(lambda: self._status("Ошибка", C.DANGER))
            finally:
                self._ui(lambda: self._invest_badge(-1))
                self._ui(self._update_module_stats)

        threading.Thread(target=wrapper, daemon=True).start()

    def run_history(self):
        """Пересобрать индекс отчётов и показать список последних."""
        from core.report import build_index, REPORTS_DIR
        idx = build_index()
        dual_print(f"\n[✓] Индекс отчётов: {idx}")
        files = sorted(REPORTS_DIR.glob("*.html"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        dual_print("  Последние отчёты:")
        for f in files[:15]:
            if f.name != "index.html":
                dual_print(f"    • {f.name}")
        self._status("Готов")

    def run_settings(self):
        """Показать статус API-ключей (значения замаскированы)."""
        from config import API_KEYS
        dual_print("\n  API-ключи (.env):")
        for name, val in API_KEYS.items():
            mark = "✓ задан" if val else "— нет"
            dual_print(f"    {name:<20} {mark}")
        dual_print("  Файл: .env (см. .env.example)")
        self._status("Готов")


def _has_key(name):
    from config import API_KEYS
    return bool(API_KEYS.get(name))


def _match_count(rep):
    """Число «совпадений» из сводки отчёта (для карточки активной цели)."""
    try:
        total = sum(len(s.get("items", {})) for s in rep.summaries)
        if total:
            return total
        return sum(len(sec.get("fields", [])) for sec in rep.sections)
    except Exception:
        return 0


if __name__ == "__main__":
    root = ctk.CTk()
    app = OSINTApp(root)
    root.mainloop()
