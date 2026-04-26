"""
passit.py — Password Manager
==============================
Dark minimal UI built with Tkinter.
Features: AES-256 encryption, categories, search,
          password generator, strength meter.

Requirements:
    pip install cryptography pillow pyperclip

Files needed in same folder:
    passit.py
    vault.py
    shield.ico        (window icon)
    shield logo.png   (login screen logo)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import re
import random
import string
from vault import Vault

# ── Optional packages ──────────────────────────────────────────────────────
try:
    import pyperclip
    HAS_CLIP = True
except ImportError:
    HAS_CLIP = False

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ── Paths ──────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

VAULT_DIR  = os.path.join(os.environ.get("APPDATA", APP_DIR), "passit")
os.makedirs(VAULT_DIR, exist_ok=True)
VAULT_FILE = os.path.join(VAULT_DIR, "data.vault")
ICON_FILE  = os.path.join(APP_DIR, "shield.ico")
LOGO_FILE  = os.path.join(APP_DIR, "shield logo.png")

# ── Theme ──────────────────────────────────────────────────────────────────
BG       = "#0d1117"
BG2      = "#161b22"
BG3      = "#21262d"
ACCENT   = "#4493f8"
GREEN    = "#3fb950"
RED      = "#f85149"
YELLOW   = "#d29922"
TEXT     = "#e6edf3"
DIM      = "#7d8590"
BORDER   = "#30363d"

F        = ("Consolas", 11)
FB       = ("Consolas", 13, "bold")
FS       = ("Consolas", 9)
FT       = ("Consolas", 8)

CATS = ["general", "passwords", "tokens", "wifi", "credit_cards", "notes", "other"]
CAT_COLORS = {
    "passwords":   "#d29922",
    "tokens":      "#388bfd",
    "wifi":        "#3fb950",
    "credit_cards":"#db61a2",
    "notes":       "#8957e5",
    "other":       "#7d8590",
    "general":     "#7d8590",
}


# ══════════════════════════════════════════════════════════════════════════════
# Reusable widgets
# ══════════════════════════════════════════════════════════════════════════════

class PBtn(tk.Button):
    """Passit styled button."""
    def __init__(self, parent, text, cmd=None, color=None, **kw):
        color = color or ACCENT
        super().__init__(
            parent, text=text, command=cmd,
            bg=color, fg="#fff",
            font=("Consolas", 10, "bold"),
            relief="flat", bd=0,
            padx=16, pady=9,
            cursor="hand2",
            activebackground=color,
            activeforeground="#fff",
            **kw
        )
        self.bind("<Enter>", lambda e: self.config(bg=_lc(color)))
        self.bind("<Leave>", lambda e: self.config(bg=color))


class PEntry(tk.Entry):
    """Passit styled entry field."""
    def __init__(self, parent, show=None, **kw):
        super().__init__(
            parent,
            bg=BG3, fg=TEXT,
            insertbackground=ACCENT,
            relief="flat", bd=0,
            font=F, show=show,
            highlightthickness=1,
            highlightcolor=ACCENT,
            highlightbackground=BORDER,
            **kw
        )


def _lc(c):
    """Lighten a hex color."""
    r, g, b = int(c[1:3],16), int(c[3:5],16), int(c[5:7],16)
    return f"#{min(255,r+22):02x}{min(255,g+22):02x}{min(255,b+22):02x}"


def _sep(parent):
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=20, pady=6)


def _lbl(parent, text, font=FS, fg=DIM, bg=BG, **kw):
    return tk.Label(parent, text=text, font=font, fg=fg, bg=bg, **kw)


def _logo(size=(84, 84)):
    if not HAS_PIL:
        return None
    for p in [LOGO_FILE, ICON_FILE]:
        if os.path.exists(p):
            try:
                img = Image.open(p).convert("RGBA")
                return ImageTk.PhotoImage(img.resize(size, Image.LANCZOS))
            except Exception:
                pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Password utilities
# ══════════════════════════════════════════════════════════════════════════════

def strength(pw: str) -> tuple:
    """Returns (score 0-4, label, color)."""
    s = 0
    if len(pw) >= 8:  s += 1
    if len(pw) >= 12: s += 1
    if re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw): s += 1
    if re.search(r"\d", pw): s += 1
    if re.search(r"[^A-Za-z0-9]", pw): s += 1
    s = min(s, 4)
    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    colors = [RED, RED, YELLOW, GREEN, GREEN]
    return s, labels[s], colors[s]


def generate_password(length=16, upper=True, digits=True, symbols=True) -> str:
    """Generate a secure random password."""
    pool = string.ascii_lowercase
    must = []
    if upper:
        pool += string.ascii_uppercase
        must.append(random.choice(string.ascii_uppercase))
    if digits:
        pool += string.digits
        must.append(random.choice(string.digits))
    if symbols:
        sym = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        pool += sym
        must.append(random.choice(sym))
    rest   = [random.choice(pool) for _ in range(length - len(must))]
    result = must + rest
    random.shuffle(result)
    return "".join(result)


# ══════════════════════════════════════════════════════════════════════════════
# Strength meter widget
# ══════════════════════════════════════════════════════════════════════════════

class StrengthMeter(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG2, **kw)
        row = tk.Frame(self, bg=BG2)
        row.pack(fill="x")
        self._bars = []
        for _ in range(4):
            b = tk.Frame(row, bg=BG3, height=4, width=52)
            b.pack(side="left", padx=2)
            self._bars.append(b)
        self._lbl = tk.Label(self, text="", font=FT, fg=DIM, bg=BG2, anchor="w")
        self._lbl.pack(fill="x", pady=(3, 0))

    def update(self, pw: str):
        if not pw:
            for b in self._bars: b.config(bg=BG3)
            self._lbl.config(text="")
            return
        score, label, color = strength(pw)
        for i, b in enumerate(self._bars):
            b.config(bg=color if i < score else BG3)
        self._lbl.config(text=label, fg=color)


# ══════════════════════════════════════════════════════════════════════════════
# Create Password Screen
# ══════════════════════════════════════════════════════════════════════════════

class CreateScreen(tk.Frame):
    def __init__(self, parent, vault: Vault, on_done):
        super().__init__(parent, bg=BG)
        self.vault   = vault
        self.on_done = on_done
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        c = tk.Frame(self, bg=BG)
        c.grid(row=0, column=0)

        logo = _logo()
        if logo:
            l = tk.Label(c, image=logo, bg=BG)
            l.pack(pady=(0, 14))
            l._i = logo
        else:
            tk.Label(c, text="🔐", font=("Segoe UI Emoji", 48), bg=BG).pack(pady=(0, 14))

        _lbl(c, "Welcome to passit", font=("Consolas", 20, "bold"), fg=ACCENT).pack()
        _lbl(c, "Create a master password to get started.", fg=DIM).pack(pady=(4, 24))

        card = tk.Frame(c, bg=BG2, highlightthickness=1, highlightbackground=BORDER)
        card.pack(ipadx=28, ipady=22, padx=48)

        _lbl(card, "Master Password", bg=BG2).pack(fill="x", padx=8)
        self._p1 = PEntry(card, show="●", width=32)
        self._p1.pack(fill="x", ipady=9, padx=8, pady=(3, 4))
        self._p1.focus()
        self._p1.bind("<KeyRelease>", lambda e: self._meter.update(self._p1.get()))

        self._meter = StrengthMeter(card)
        self._meter.pack(fill="x", padx=8, pady=(0, 12))

        _lbl(card, "Confirm Password", bg=BG2).pack(fill="x", padx=8)
        self._p2 = PEntry(card, show="●", width=32)
        self._p2.pack(fill="x", ipady=9, padx=8, pady=(3, 14))
        self._p2.bind("<Return>", lambda e: self._go())

        sv = tk.BooleanVar()
        tk.Checkbutton(card, text=" Show passwords", variable=sv,
                       command=lambda: [
                           self._p1.config(show="" if sv.get() else "●"),
                           self._p2.config(show="" if sv.get() else "●")],
                       bg=BG2, fg=DIM, selectcolor=BG3,
                       activebackground=BG2, font=FS, bd=0, cursor="hand2"
                       ).pack(pady=(0, 14))

        PBtn(card, "Create Password →", cmd=self._go).pack(fill="x", padx=8)

        self._msg = tk.Label(card, text="", font=FS, bg=BG2, fg=RED)
        self._msg.pack(pady=(8, 0))

    def _go(self):
        p1, p2 = self._p1.get(), self._p2.get()
        if not p1:
            self._msg.config(text="⚠  Password cannot be empty.")
            return
        if len(p1) < 6:
            self._msg.config(text="⚠  At least 6 characters required.")
            return
        if p1 != p2:
            self._msg.config(text="⚠  Passwords do not match.")
            self._p2.delete(0, "end")
            self._p2.focus()
            return
        self.vault.create(p1)
        self._msg.config(text="✓  Vault created!", fg=GREEN)
        self.after(500, lambda: self.on_done(p1))


# ══════════════════════════════════════════════════════════════════════════════
# Login Screen
# ══════════════════════════════════════════════════════════════════════════════

class LoginScreen(tk.Frame):
    def __init__(self, parent, vault: Vault, on_done):
        super().__init__(parent, bg=BG)
        self.vault    = vault
        self.on_done  = on_done
        self.tries    = 0
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        c = tk.Frame(self, bg=BG)
        c.grid(row=0, column=0)

        logo = _logo()
        if logo:
            l = tk.Label(c, image=logo, bg=BG)
            l.pack(pady=(0, 14))
            l._i = logo
        else:
            tk.Label(c, text="🔐", font=("Segoe UI Emoji", 48), bg=BG).pack(pady=(0, 14))

        _lbl(c, "passit", font=("Consolas", 30, "bold"), fg=ACCENT).pack()
        _lbl(c, "Enter your password to unlock", fg=DIM).pack(pady=(4, 26))

        card = tk.Frame(c, bg=BG2, highlightthickness=1, highlightbackground=BORDER)
        card.pack(ipadx=28, ipady=22, padx=48)

        _lbl(card, "Master Password", bg=BG2).pack(fill="x", padx=8)
        self._pw = PEntry(card, show="●", width=30)
        self._pw.pack(fill="x", ipady=9, padx=8, pady=(3, 14))
        self._pw.focus()
        self._pw.bind("<Return>", lambda e: self._go())

        sv = tk.BooleanVar()
        tk.Checkbutton(card, text=" Show password", variable=sv,
                       command=lambda: self._pw.config(show="" if sv.get() else "●"),
                       bg=BG2, fg=DIM, selectcolor=BG3,
                       activebackground=BG2, font=FS, bd=0, cursor="hand2"
                       ).pack(pady=(0, 14))

        PBtn(card, "Unlock →", cmd=self._go).pack(fill="x", padx=8)

        self._msg  = tk.Label(card, text="", font=FS, bg=BG2, fg=RED)
        self._msg.pack(pady=(8, 0))
        self._hint = tk.Label(card, text="3 attempts allowed", font=FT, fg=DIM, bg=BG2)
        self._hint.pack(pady=(4, 0))

    def _go(self):
        pw = self._pw.get()
        if not pw:
            self._msg.config(text="⚠  Enter your password.")
            return
        if self.vault.unlock(pw):
            self.on_done(pw)
        else:
            self.tries += 1
            left = 3 - self.tries
            if left <= 0:
                self._msg.config(text="🚫  Too many attempts. Restart.")
                self._pw.config(state="disabled")
                self._hint.config(text="")
            else:
                self._msg.config(text=f"⚠  Wrong password. {left} attempt(s) left.")
                self._hint.config(text=f"{left} remaining")
            self._pw.delete(0, "end")


# ══════════════════════════════════════════════════════════════════════════════
# Password Generator Dialog
# ══════════════════════════════════════════════════════════════════════════════

class GenDialog(tk.Toplevel):
    def __init__(self, parent, on_use):
        super().__init__(parent)
        self.on_use = on_use
        self.title("Password Generator")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.geometry("400x340")
        self._build()
        self._center(parent)
        self._gen()

    def _center(self, p):
        self.update_idletasks()
        x = p.winfo_rootx() + p.winfo_width()  // 2 - 200
        y = p.winfo_rooty() + p.winfo_height() // 2 - 170
        self.geometry(f"400x340+{x}+{y}")

    def _build(self):
        _lbl(self, "Password Generator", font=FB, fg=ACCENT, bg=BG).pack(
            pady=(18, 4), padx=20, anchor="w")
        _sep(self)

        # Generated password display
        pf = tk.Frame(self, bg=BG3, highlightthickness=1, highlightbackground=BORDER)
        pf.pack(fill="x", padx=20, pady=(4, 12))
        self._result = tk.Label(pf, text="", font=("Consolas", 12, "bold"),
                                fg=GREEN, bg=BG3, wraplength=340)
        self._result.pack(padx=14, pady=12)

        # Strength meter
        self._meter = StrengthMeter(self)
        self._meter.pack(fill="x", padx=20, pady=(0, 10))

        # Options
        of = tk.Frame(self, bg=BG)
        of.pack(fill="x", padx=20)

        # Length
        lf = tk.Frame(of, bg=BG)
        lf.pack(fill="x", pady=4)
        _lbl(lf, "Length:", fg=DIM, bg=BG).pack(side="left")
        self._len = tk.IntVar(value=16)
        tk.Spinbox(lf, from_=8, to=32, textvariable=self._len,
                   width=4, bg=BG3, fg=TEXT, buttonbackground=BG3,
                   relief="flat", font=F).pack(side="left", padx=(8, 0))

        # Checkboxes
        self._upper   = tk.BooleanVar(value=True)
        self._digits  = tk.BooleanVar(value=True)
        self._symbols = tk.BooleanVar(value=True)

        for var, label in [(self._upper, "Uppercase letters"),
                           (self._digits, "Numbers"),
                           (self._symbols, "Symbols  (!@#$%...)")]:
            tk.Checkbutton(of, text=f"  {label}", variable=var,
                           bg=BG, fg=TEXT, selectcolor=BG3,
                           activebackground=BG, font=FS,
                           bd=0, cursor="hand2").pack(anchor="w", pady=2)

        _sep(self)

        bf = tk.Frame(self, bg=BG)
        bf.pack(fill="x", padx=20, pady=8)
        PBtn(bf, "Regenerate", cmd=self._gen, color=BG3).pack(side="left", expand=True, fill="x", padx=(0, 8))
        PBtn(bf, "Use This Password", cmd=self._use, color=ACCENT).pack(side="left", expand=True, fill="x")

    def _gen(self):
        pw = generate_password(
            length=self._len.get(),
            upper=self._upper.get(),
            digits=self._digits.get(),
            symbols=self._symbols.get(),
        )
        self._pw = pw
        self._result.config(text=pw)
        self._meter.update(pw)

    def _use(self):
        self.on_use(self._pw)
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# Add / Edit Secret Dialog
# ══════════════════════════════════════════════════════════════════════════════

class SecretDialog(tk.Toplevel):
    def __init__(self, parent, on_save, prefill=None):
        super().__init__(parent)
        self.on_save = on_save
        self.pre     = prefill or {}
        self.title("Add Secret" if not prefill else "Edit Secret")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.geometry("460x480")
        self._build()
        self._center(parent)

    def _center(self, p):
        self.update_idletasks()
        x = p.winfo_rootx() + p.winfo_width()  // 2 - 230
        y = p.winfo_rooty() + p.winfo_height() // 2 - 240
        self.geometry(f"460x480+{x}+{y}")

    def _build(self):
        _lbl(self, "Add Secret" if not self.pre else "Edit Secret",
             font=FB, fg=ACCENT, bg=BG).pack(pady=(18, 4), padx=20, anchor="w")
        _sep(self)

        # Name
        _lbl(self, "Entry Name  (e.g. gmail, netflix)", bg=BG).pack(fill="x", padx=20)
        self._name = PEntry(self, width=40)
        self._name.pack(fill="x", ipady=9, padx=20, pady=(3, 10))
        self._name.insert(0, self.pre.get("name", ""))
        if self.pre:
            self._name.config(state="disabled")
        else:
            self._name.focus()

        # Category
        _lbl(self, "Category", bg=BG).pack(fill="x", padx=20)
        self._cat = tk.StringVar(value=self.pre.get("category", "general"))
        ttk.Combobox(self, textvariable=self._cat,
                     values=CATS, font=F, state="readonly"
                     ).pack(fill="x", padx=20, ipady=5, pady=(3, 10))

        # Secret
        _lbl(self, "Secret / Password", bg=BG).pack(fill="x", padx=20)
        sf = tk.Frame(self, bg=BG)
        sf.pack(fill="x", padx=20, pady=(3, 2))
        sf.columnconfigure(0, weight=1)
        self._secret = PEntry(sf, show="●")
        self._secret.grid(row=0, column=0, sticky="ew", ipady=9)
        self._secret.bind("<KeyRelease>", lambda e: self._meter.update(self._secret.get()))
        PBtn(sf, "Generate", cmd=self._open_gen, color=BG3).grid(row=0, column=1, padx=(6,0))

        # Strength
        self._meter = StrengthMeter(self)
        self._meter.pack(fill="x", padx=20, pady=(0, 8))

        # Show toggle
        sv = tk.BooleanVar()
        tk.Checkbutton(self, text=" Show secret", variable=sv,
                       command=lambda: self._secret.config(show="" if sv.get() else "●"),
                       bg=BG, fg=DIM, selectcolor=BG3,
                       activebackground=BG, font=FS, bd=0, cursor="hand2"
                       ).pack(anchor="w", padx=20)

        # Note
        _lbl(self, "Note  (optional)", bg=BG).pack(fill="x", padx=20, pady=(8, 0))
        self._note = PEntry(self, width=40)
        self._note.pack(fill="x", ipady=7, padx=20, pady=(3, 4))
        self._note.insert(0, self.pre.get("note", ""))

        self._err = tk.Label(self, text="", font=FS, fg=RED, bg=BG)
        self._err.pack(padx=20, anchor="w")

        _sep(self)
        bf = tk.Frame(self, bg=BG)
        bf.pack(fill="x", padx=20, pady=8)
        PBtn(bf, "Cancel",      cmd=self.destroy, color=BG3).pack(side="left", expand=True, fill="x", padx=(0,8))
        PBtn(bf, "Save Secret", cmd=self._save).pack(side="left", expand=True, fill="x")

    def _open_gen(self):
        GenDialog(self, on_use=lambda pw: (
            self._secret.delete(0, "end"),
            self._secret.insert(0, pw),
            self._meter.update(pw)
        ))

    def _save(self):
        name   = self._name.get().strip()
        secret = self._secret.get().strip()
        note   = self._note.get().strip()
        if not name:
            self._err.config(text="⚠  Name cannot be empty.")
            return
        if not secret:
            self._err.config(text="⚠  Secret cannot be empty.")
            return
        self.on_save(name, secret, self._cat.get(), note)
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# Dashboard
# ══════════════════════════════════════════════════════════════════════════════

class Dashboard(tk.Frame):
    def __init__(self, parent, vault: Vault, on_lock):
        super().__init__(parent, bg=BG)
        self.vault   = vault
        self.on_lock = on_lock
        self.sel_cat = "All"
        self._build()
        self._refresh()

    def _build(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        # ── Topbar ────────────────────────────────────────────────────────
        top = tk.Frame(self, bg=BG2, height=52)
        top.grid(row=0, column=0, columnspan=2, sticky="ew")
        top.grid_propagate(False)

        sm = _logo((26, 26))
        if sm:
            l = tk.Label(top, image=sm, bg=BG2)
            l.pack(side="left", padx=(12, 4), pady=10)
            l._i = sm

        tk.Label(top, text="passit", font=("Consolas", 13, "bold"),
                 fg=ACCENT, bg=BG2).pack(side="left", padx=(4, 0))

        PBtn(top, "+ Add",  cmd=self._add,  color=ACCENT).pack(side="right", padx=10, pady=8)
        PBtn(top, "Lock",   cmd=self._lock, color=BG3).pack(side="right",   padx=4,  pady=8)

        # ── Sidebar ───────────────────────────────────────────────────────
        side = tk.Frame(self, bg=BG2, width=164)
        side.grid(row=1, column=0, sticky="ns", padx=(0,1))
        side.grid_propagate(False)

        _lbl(side, "CATEGORIES", font=("Consolas", 8, "bold"),
             fg=DIM, bg=BG2).pack(anchor="w", padx=14, pady=(14, 6))

        self._cbs = {}
        icons = {"All":"◈","general":"◉","passwords":"🔑","tokens":"⚡",
                 "wifi":"📶","credit_cards":"💳","notes":"📝","other":"•"}
        for cat in ["All"] + CATS:
            b = tk.Button(side,
                text=f"  {icons.get(cat,'•')}  {cat}",
                anchor="w", font=("Consolas", 10),
                bg=BG2, fg=TEXT, relief="flat", bd=0,
                activebackground=BG3, cursor="hand2",
                command=lambda x=cat: self._filt(x))
            b.pack(fill="x", padx=6, ipady=6)
            self._cbs[cat] = b
        self._hi("All")

        # ── Main ─────────────────────────────────────────────────────────
        main = tk.Frame(self, bg=BG)
        main.grid(row=1, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        # Search bar
        sf = tk.Frame(main, bg=BG, pady=10)
        sf.grid(row=0, column=0, sticky="ew", padx=14)
        sf.columnconfigure(0, weight=1)
        self._q = tk.StringVar()
        self._q.trace("w", lambda *a: self._refresh())
        PEntry(sf, textvariable=self._q).grid(row=0, column=0, sticky="ew", ipady=8)
        _lbl(sf, "Search...", fg=DIM, bg=BG).grid(row=0, column=1, padx=(8, 0))

        # Entry list
        lf = tk.Frame(main, bg=BG)
        lf.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        lf.columnconfigure(0, weight=1)
        lf.rowconfigure(0, weight=1)

        self.cv  = tk.Canvas(lf, bg=BG, highlightthickness=0)
        sb       = ttk.Scrollbar(lf, orient="vertical", command=self.cv.yview)
        self.lf2 = tk.Frame(self.cv, bg=BG)
        self.lf2.bind("<Configure>", lambda e: self.cv.configure(
            scrollregion=self.cv.bbox("all")))
        self.cv.create_window((0, 0), window=self.lf2, anchor="nw")
        self.cv.configure(yscrollcommand=sb.set)
        self.cv.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        self.cv.bind_all("<MouseWheel>", lambda e: self.cv.yview_scroll(
            -1 * (e.delta // 120), "units"))

    def _hi(self, sel):
        for c, b in self._cbs.items():
            b.config(bg=BG3 if c == sel else BG2,
                     fg=ACCENT if c == sel else TEXT)

    def _filt(self, cat):
        self.sel_cat = cat
        self._hi(cat)
        self._refresh()

    def _refresh(self):
        for w in self.lf2.winfo_children():
            w.destroy()
        q    = self._q.get().lower() if hasattr(self, "_q") else ""
        rows = [e for e in self.vault.entries()
                if (self.sel_cat == "All" or e["category"] == self.sel_cat)
                and (not q or q in e["name"].lower() or q in e["category"].lower())]
        if not rows:
            _lbl(self.lf2,
                 "No entries yet. Click  + Add  to start.",
                 fg=DIM, bg=BG).pack(pady=50)
            return
        for r in rows:
            self._card(r)

    def _card(self, entry):
        color = CAT_COLORS.get(entry["category"], DIM)
        card  = tk.Frame(self.lf2, bg=BG2,
                         highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill="x", pady=4)
        inner = tk.Frame(card, bg=BG2)
        inner.pack(fill="x", padx=12, pady=9)

        # Left side
        left = tk.Frame(inner, bg=BG2)
        left.pack(side="left", fill="x", expand=True)
        tk.Frame(left, bg=color, width=3).pack(side="left", fill="y", padx=(0, 10))
        info = tk.Frame(left, bg=BG2)
        info.pack(side="left")
        tk.Label(info, text=entry["name"],
                 font=("Consolas", 11, "bold"), fg=TEXT, bg=BG2).pack(anchor="w")
        sub = entry["note"] if entry["note"] else entry["category"]
        tk.Label(info, text=sub, font=FT, fg=color, bg=BG2).pack(anchor="w")

        # Right side — action buttons
        right = tk.Frame(inner, bg=BG2)
        right.pack(side="right")
        n = entry["name"]
        PBtn(right, "View", cmd=lambda x=n: self._view(x),                           color=BG3).pack(side="left", padx=2)
        if HAS_CLIP:
            PBtn(right, "Copy", cmd=lambda x=n: self._copy(x),                       color=BG3).pack(side="left", padx=2)
        PBtn(right, "Edit", cmd=lambda x=n, c=entry["category"]: self._edit(x, c),  color=BG3).pack(side="left", padx=2)
        PBtn(right, "✕",   cmd=lambda x=n: self._del(x),                            color=RED ).pack(side="left", padx=2)

        for w in [card, inner, left, info, right]:
            w.bind("<Enter>", lambda e, c=card: c.config(bg="#1c2128"))
            w.bind("<Leave>", lambda e, c=card: c.config(bg=BG2))

    # ── Actions ────────────────────────────────────────────────────────────
    def _view(self, name):
        entry = self.vault.get(name)
        if not entry:
            return
        win = tk.Toplevel(self)
        win.title(f"Secret — {name}")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.grab_set()
        win.geometry("420x250")
        win.update_idletasks()
        x = self.winfo_rootx() + self.winfo_width()  // 2 - 210
        y = self.winfo_rooty() + self.winfo_height() // 2 - 125
        win.geometry(f"420x250+{x}+{y}")

        _lbl(win, f"  {name}", font=FB, fg=ACCENT, bg=BG).pack(
            pady=(18, 4), padx=20, anchor="w")
        if entry["note"]:
            _lbl(win, f"  {entry['note']}", fg=DIM, bg=BG).pack(padx=20, anchor="w")

        box = tk.Frame(win, bg=BG3, highlightthickness=1, highlightbackground=BORDER)
        box.pack(padx=20, pady=10, fill="x")
        tk.Label(box, text=entry["secret"], font=("Consolas", 12),
                 fg=GREEN, bg=BG3, wraplength=360,
                 justify="left").pack(padx=14, pady=12, anchor="w")

        bf = tk.Frame(win, bg=BG)
        bf.pack(padx=20, pady=(0, 18), fill="x")
        if HAS_CLIP:
            PBtn(bf, "Copy to Clipboard",
                 cmd=lambda: (pyperclip.copy(entry["secret"]), win.destroy()),
                 color=ACCENT).pack(side="left", expand=True, fill="x", padx=(0, 8))
        PBtn(bf, "Close", cmd=win.destroy, color=BG3).pack(
            side="left", expand=True, fill="x")

    def _copy(self, name):
        e = self.vault.get(name)
        if e:
            pyperclip.copy(e["secret"])
            self._toast(f"'{name}' copied!")

    def _add(self):
        SecretDialog(self, on_save=self._save)

    def _edit(self, name, cat):
        e = self.vault.get(name)
        SecretDialog(self, on_save=self._save,
                     prefill={"name": name, "category": cat,
                              "note": e["note"] if e else ""})

    def _save(self, name, secret, cat, note):
        self.vault.add(name, secret, cat, note)
        self._refresh()
        self._toast(f"'{name}' saved!")

    def _del(self, name):
        if messagebox.askyesno("Delete",
                f"Delete '{name}'?\nThis cannot be undone.", parent=self):
            self.vault.delete(name)
            self._refresh()

    def _lock(self):
        self.vault.lock()
        self.on_lock()

    def _toast(self, msg):
        t = tk.Label(self, text=f"  ✓  {msg}  ",
                     font=FS, bg=GREEN, fg="#000", relief="flat")
        t.place(relx=1.0, rely=1.0, anchor="se", x=-18, y=-18)
        self.after(2200, t.destroy)


# ══════════════════════════════════════════════════════════════════════════════
# App
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("passit")
        self.geometry("960x640")
        self.minsize(800, 520)
        self.configure(bg=BG)

        # Icon
        if os.path.exists(ICON_FILE):
            try:
                self.iconbitmap(ICON_FILE)
            except Exception:
                pass

        # Combobox style
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TCombobox",
                    fieldbackground=BG3, background=BG3,
                    foreground=TEXT, selectbackground=BG3,
                    selectforeground=TEXT)

        self.vault = Vault(VAULT_FILE)
        self._route()

    def _route(self):
        self._clear()
        if not self.vault.exists:
            CreateScreen(self, self.vault,
                on_done=self._open).pack(fill="both", expand=True)
        else:
            LoginScreen(self, self.vault,
                on_done=self._open).pack(fill="both", expand=True)

    def _open(self, _pw):
        self._clear()
        Dashboard(self, self.vault,
            on_lock=self._route).pack(fill="both", expand=True)

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()


if __name__ == "__main__":
    App().mainloop()
