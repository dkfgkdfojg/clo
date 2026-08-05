# gui/app.py
#
# Установка зависимостей (Arch Linux):
#   sudo pacman -S noto-fonts noto-fonts-emoji ttf-jetbrains-mono ttf-inter
#   pip install customtkinter --break-system-packages
#
# Стиль: тёмный "dashboard" — карточки сверху, боковая навигация, консоль
# со скруглёнными углами. Вдохновлено типичными красивыми GUI-утилитами
# на CustomTkinter (TomSchimansky/CustomTkinter и подобные проекты).

import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog  # для выбора фото

import customtkinter as ctk

# Существующие модули
from analyzers.phone import analyze_phone_combo
from analyzers.username import analyze_username_combo
from analyzers.email import analyze_email_leaks
from analyzers.discord import analyze_discord
from analyzers.ip import analyze_ip_basic, analyze_shodan_smart
from analyzers.photo import analyze_photo  # оставляем
from analyzers.domain import (
    analyze_domain,
)  # если нужен — оставляем, если нет — удалить

# Утилиты для вывода в консоль и логирования
from core.utils import dual_print

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


# ---------- Палитра ----------
class C:
    BG = "#0A0E14"
    SURFACE = "#10141C"
    SURFACE2 = "#161B25"
    CARD = "#141923"
    BORDER = "#232A36"
    BORDER_SOFT = "#1C222D"
    TEXT = "#E7E9ED"
    MUTED = "#76808F"
    MUTED2 = "#4D5563"

    PRIMARY = "#7C5CFC"
    PRIMARY_HOVER = "#8F73FF"
    PRIMARY_SOFT = "#241B3D"

    SUCCESS = "#3DDC97"
    WARNING = "#FFB454"
    DANGER = "#FF5C7A"
    INFO = "#56CCF2"

    # Цвета для оставшихся модулей
    MODULES = {
        "phone": "#FF8C42",
        "username": "#3DDC97",
        "email": "#56CCF2",
        "discord": "#7C8CFF",
        "ip": "#FFB454",
        "shodan": "#FF5C7A",
        "photo": "#FF6B6B",
        "domain": "#6C5CE7",
    }


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class OSINTApp:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("OSINT Tool  •  v3")
        self.root.geometry("1240x760")
        self.root.minsize(980, 640)
        self.root.configure(fg_color=C.BG)

        self.font_ui = pick_font(
            ["Inter", "Noto Sans", "Cantarell", "Liberation Sans", "DejaVu Sans"],
            "TkDefaultFont",
        )
        self.font_mono = pick_font(
            [
                "JetBrains Mono",
                "JetBrainsMono Nerd Font",
                "Fira Code",
                "Hack",
                "DejaVu Sans Mono",
            ],
            "TkFixedFont",
        )

        self._req = 0
        self.active_key = None
        self._pulse_job = None
        self._pulse_on = False

        self._build_layout()

        # stdout подменяем на время жизни окна и обязательно возвращаем в
        # _on_close: без этого после закрытия GUI любой print из консольного
        # режима уходил в уничтоженный виджет и падал с TclError.
        self._orig_stdout = sys.stdout
        self._redirect = RedirectText(self.text_area, root=self.root)
        sys.stdout = self._redirect
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._banner()

    def _on_close(self):
        """Гасим таймеры и возвращаем stdout, потом закрываем окно."""
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
        main.grid(row=0, column=1, sticky="nsew", padx=(0, 18), pady=18)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        self._build_header(main)
        self._build_stat_cards(main)
        self._build_console(main)

    # ----------------- Sidebar -----------------
    def _build_sidebar(self):
        side = ctk.CTkFrame(self.root, width=250, corner_radius=0, fg_color=C.SURFACE)
        side.grid(row=0, column=0, sticky="nsw")
        side.grid_propagate(False)

        logo = ctk.CTkFrame(side, fg_color="transparent")
        logo.pack(fill="x", padx=22, pady=(26, 22))
        ctk.CTkLabel(
            logo, text="⬡", text_color=C.PRIMARY, font=(self.font_mono, 22, "bold")
        ).pack(side="left")
        txtwrap = ctk.CTkFrame(logo, fg_color="transparent")
        txtwrap.pack(side="left", padx=(8, 0))
        ctk.CTkLabel(
            txtwrap,
            text="OSINT TOOL",
            text_color=C.TEXT,
            font=(self.font_ui, 14, "bold"),
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            txtwrap,
            text="версия 3.0",
            text_color=C.MUTED,
            font=(self.font_ui, 10),
            anchor="w",
        ).pack(anchor="w")

        ctk.CTkLabel(
            side,
            text="МОДУЛИ",
            text_color=C.MUTED2,
            font=(self.font_ui, 10, "bold"),
            anchor="w",
        ).pack(fill="x", padx=24, pady=(6, 8))

        self._nav_btns = {}
        # СПИСОК МОДУЛЕЙ (без card, crypto, vehicle, geoint)
        modules = [
            ("phone", "📱", "Анализ телефона", self.run_phone),
            ("username", "👤", "Анализ username", self.run_username),
            ("email", "✉️", "Анализ Email", self.run_email),
            ("discord", "💬", "Discord ID", self.run_discord),
            ("ip", "🌐", "Базовый скан IP", self.run_ip),
            ("shodan", "🔍", "IP + Shodan", self.run_shodan),
            ("photo", "🖼️", "Анализ фото", self.run_photo),
            ("domain", "🌐", "Домен", self.run_domain),  # если оставляете
        ]
        for key, icon, label, cmd in modules:
            self._nav_btns[key] = self._make_nav_button(side, key, icon, label, cmd)

        ctk.CTkFrame(side, fg_color=C.BORDER_SOFT, height=1).pack(
            fill="x", padx=22, pady=18
        )

        self._stat_var = tk.StringVar(value="Готов к работе")
        ctk.CTkLabel(
            side,
            textvariable=self._stat_var,
            text_color=C.MUTED,
            font=(self.font_mono, 10),
            anchor="w",
            justify="left",
            wraplength=200,
        ).pack(fill="x", padx=24)

        footer = ctk.CTkFrame(side, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=22, pady=18)
        ctk.CTkLabel(
            footer, text="⬡ Arch Linux", text_color=C.MUTED2, font=(self.font_mono, 9)
        ).pack(anchor="w")

    def _make_nav_button(self, parent, key, icon, label, cmd):
        accent = C.MODULES[key]
        btn = ctk.CTkButton(
            parent,
            text=f"{icon}   {label}",
            anchor="w",
            corner_radius=10,
            height=42,
            fg_color="transparent",
            hover_color=C.SURFACE2,
            text_color=C.MUTED,
            font=(self.font_ui, 12),
            command=lambda: self._activate(key, cmd),
        )
        btn.pack(fill="x", padx=14, pady=3)
        btn._accent = accent
        return btn

    def _activate(self, key, cmd):
        if self.active_key and self.active_key in self._nav_btns:
            old = self._nav_btns[self.active_key]
            old.configure(fg_color="transparent", text_color=C.MUTED)
        self.active_key = key
        btn = self._nav_btns[key]
        btn.configure(fg_color=C.PRIMARY_SOFT, text_color=C.TEXT)
        cmd()

    # ----------------- Header -----------------
    def _build_header(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        header.grid_columnconfigure(0, weight=1)

        entry_card = ctk.CTkFrame(
            header,
            fg_color=C.CARD,
            corner_radius=12,
            border_width=1,
            border_color=C.BORDER,
        )
        entry_card.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        entry_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            entry_card,
            text="  ЦЕЛЬ",
            text_color=C.MUTED,
            font=(self.font_ui, 10, "bold"),
        ).grid(row=0, column=0, padx=(14, 6))

        self.entry_target = ctk.CTkEntry(
            entry_card,
            placeholder_text="телефон, username, email, IP-адрес...",
            fg_color="transparent",
            border_width=0,
            text_color=C.TEXT,
            placeholder_text_color=C.MUTED2,
            font=(self.font_mono, 13),
            height=44,
        )
        self.entry_target.grid(row=0, column=1, sticky="ew", padx=(0, 14))
        self.entry_target.bind("<Return>", self._on_enter)

        for text, color, hover, cmd in [
            ("💾 Сохранить", C.SURFACE2, C.SUCCESS, self.save_report),
            ("🗑 Очистить", C.SURFACE2, C.DANGER, self.clear_console),
        ]:
            ctk.CTkButton(
                header,
                text=text,
                width=128,
                height=44,
                corner_radius=12,
                fg_color=color,
                hover_color=hover,
                text_color=C.TEXT,
                font=(self.font_ui, 11, "bold"),
                command=cmd,
            ).grid(
                row=0,
                column=len(header.grid_slaves(row=0)) + 1,
                padx=(0, 0) if text.startswith("🗑") else (0, 12),
            )

    def _on_enter(self, event=None):
        if not self.active_key:
            return
        methods = {
            "phone": self.run_phone,
            "username": self.run_username,
            "email": self.run_email,
            "discord": self.run_discord,
            "ip": self.run_ip,
            "shodan": self.run_shodan,
            "photo": self.run_photo,
            "domain": self.run_domain,
        }
        if self.active_key in methods:
            methods[self.active_key]()

    # ----------------- Stat cards -----------------
    def _build_stat_cards(self, parent):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        for i in range(3):
            row.grid_columnconfigure(i, weight=1)

        self.card_status, self._status_dot, self._status_lbl = self._make_status_card(
            row, 0
        )
        self.card_requests, self._req_value_lbl = self._make_simple_card(
            row, 1, "ЗАПРОСОВ ВЫПОЛНЕНО", "0", C.INFO
        )
        self.card_target, self._target_value_lbl = self._make_simple_card(
            row, 2, "ТЕКУЩИЙ МОДУЛЬ", "—", C.PRIMARY
        )

    def _make_simple_card(self, parent, col, title, value, color):
        card = ctk.CTkFrame(
            parent,
            fg_color=C.CARD,
            corner_radius=12,
            border_width=1,
            border_color=C.BORDER,
        )
        card.grid(row=0, column=col, sticky="nsew", padx=6 if col else (0, 6))
        ctk.CTkLabel(
            card, text=title, text_color=C.MUTED, font=(self.font_ui, 9, "bold")
        ).pack(anchor="w", padx=16, pady=(14, 2))
        val = ctk.CTkLabel(
            card, text=value, text_color=color, font=(self.font_mono, 20, "bold")
        )
        val.pack(anchor="w", padx=16, pady=(0, 14))
        return card, val

    def _make_status_card(self, parent, col):
        card = ctk.CTkFrame(
            parent,
            fg_color=C.CARD,
            corner_radius=12,
            border_width=1,
            border_color=C.BORDER,
        )
        card.grid(row=0, column=col, sticky="nsew", padx=(0, 6))
        ctk.CTkLabel(
            card, text="СТАТУС", text_color=C.MUTED, font=(self.font_ui, 9, "bold")
        ).pack(anchor="w", padx=16, pady=(14, 2))
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(anchor="w", padx=16, pady=(0, 14))
        dot = ctk.CTkLabel(
            inner, text="●", text_color=C.SUCCESS, font=(self.font_ui, 14)
        )
        dot.pack(side="left", padx=(0, 8))
        lbl = ctk.CTkLabel(
            inner, text="Готов", text_color=C.TEXT, font=(self.font_mono, 16, "bold")
        )
        lbl.pack(side="left")
        return card, dot, lbl

    # ----------------- Console -----------------
    def _build_console(self, parent):
        wrap = ctk.CTkFrame(
            parent,
            fg_color=C.CARD,
            corner_radius=12,
            border_width=1,
            border_color=C.BORDER,
        )
        wrap.grid(row=2, column=0, sticky="nsew")
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(wrap, fg_color="transparent", height=38)
        bar.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 0))
        ctk.CTkLabel(
            bar, text="●  КОНСОЛЬ", text_color=C.MUTED, font=(self.font_ui, 10, "bold")
        ).pack(side="left")
        self._lines_var = tk.StringVar(value="строк: 0")
        ctk.CTkLabel(
            bar,
            textvariable=self._lines_var,
            text_color=C.MUTED2,
            font=(self.font_ui, 9),
        ).pack(side="right")

        text_holder = ctk.CTkFrame(wrap, fg_color=C.SURFACE, corner_radius=10)
        text_holder.grid(row=1, column=0, sticky="nsew", padx=16, pady=16)
        text_holder.grid_columnconfigure(0, weight=1)
        text_holder.grid_rowconfigure(0, weight=1)

        sb = ctk.CTkScrollbar(
            text_holder,
            fg_color=C.SURFACE,
            button_color=C.BORDER,
            button_hover_color=C.MUTED2,
        )
        sb.grid(row=0, column=1, sticky="ns", pady=10, padx=(0, 8))

        # Реальный tk.Text — нужен для совместимости с RedirectText
        self.text_area = tk.Text(
            text_holder,
            bg=C.SURFACE,
            fg=C.SUCCESS,
            insertbackground=C.PRIMARY,
            selectbackground=C.BORDER,
            font=(self.font_mono, 11),
            relief=tk.FLAT,
            padx=14,
            pady=10,
            state=tk.DISABLED,
            wrap=tk.WORD,
            highlightthickness=0,
            yscrollcommand=sb.set,
        )
        self.text_area.grid(row=0, column=0, sticky="nsew", padx=(2, 0), pady=2)
        sb.configure(command=self.text_area.yview)
        self.text_area.bind("<<Modified>>", self._upd_lines)

        self.text_area.tag_configure("err", foreground=C.DANGER)
        self.text_area.tag_configure("ok", foreground=C.SUCCESS)
        self.text_area.tag_configure("warn", foreground=C.WARNING)

    def _upd_lines(self, e=None):
        try:
            n = int(self.text_area.index("end-1c").split(".")[0])
            self._lines_var.set(f"строк: {n}")
        except Exception:
            pass
        self.text_area.edit_modified(False)

    def _banner(self):
        print(r"""
  ╔══════════════════════════════════════════════════╗
  ║   ___  ____ ___ _   _ _____   v3                  ║
  ║  / _ \/ ___|_ _| \ | |_   _|                      ║
  ║ | | | \___ \| ||  \| | | |                        ║
  ║ | |_| |___) | || |\  | | |                        ║
  ║  \___/|____/___|_| \_| |_|                        ║
  ╚══════════════════════════════════════════════════╝
  Введите цель и выберите модуль.
""")

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
        # color необязателен: при закрытии окна нам нужно только погасить
        # таймер, а перекрашивать уже нечего
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

    def save_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")],
            title="Сохранить отчёт",
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("Лог OSINT Tool\n")
                    self.text_area.config(state=tk.NORMAL)
                    f.write(self.text_area.get("1.0", tk.END))
                    self.text_area.config(state=tk.DISABLED)
                dual_print(f"\n[✓] Лог сохранён: {path}")
            except Exception as e:
                dual_print(f"\n[!] Ошибка: {e}")

    def clear_console(self):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)
        if self.active_key and self.active_key in self._nav_btns:
            self._nav_btns[self.active_key].configure(
                fg_color="transparent", text_color=C.MUTED
            )
            self.active_key = None
        self._target_value_lbl.configure(text="—")
        self._banner()
        self._status("Готов")

    def get_target(self):
        t = self.entry_target.get().strip()
        if not t:
            dual_print("\n[!] Введите цель.")
            return None
        return t

    def run_in_thread(self, func, arg, label):
        self._req += 1
        self._req_value_lbl.configure(text=str(self._req))
        self._target_value_lbl.configure(text=label)
        self._status(f"Выполняется: {label}", C.WARNING)
        self._stat_var.set(f"→ {label}: {arg}")

        def wrapper():
            try:
                func(arg)
                self._ui(lambda: self._status("Готов"))
            except Exception as e:
                # dual_print безопасен: RedirectText кладёт текст в очередь,
                # а рисует его уже главный поток
                dual_print(f"\n[!] Ошибка: {e}")
                self._ui(lambda: self._status("Ошибка", C.DANGER))
            finally:
                self._ui(lambda: self._stat_var.set("Готов к работе"))

        threading.Thread(target=wrapper, daemon=True).start()

    def _ui(self, fn):
        """Выполнить fn в главном потоке. Молчит, если окно уже закрыто.

        Анализатор живёт в фоновом потоке и может завершиться уже после того,
        как пользователь закрыл окно — тогда after() бросает TclError на
        уничтоженном интерпретаторе Tk.
        """
        try:
            self.root.after(0, fn)
        except (tk.TclError, RuntimeError):
            pass

    # ---- Методы для оставшихся модулей ----
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


if __name__ == "__main__":
    root = ctk.CTk()
    app = OSINTApp(root)
    root.mainloop()
