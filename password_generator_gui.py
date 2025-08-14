import os
HISTORY_FILE = "password_history.txt"
import math
import string
import tkinter as tk
from tkinter import ttk, messagebox

from secrets import choice
from random import SystemRandom

_sysrand = SystemRandom()

AMBIGUOUS = set("Il1O0|`'\";:,./\\")
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?~"

def build_charsets(include_lower, include_upper, include_digits, include_symbols, exclude_ambiguous, custom_symbols=None):
    lowers = set(string.ascii_lowercase) if include_lower else set()
    uppers = set(string.ascii_uppercase) if include_upper else set()
    digits = set(string.digits) if include_digits else set()
    symbols = set((custom_symbols or DEFAULT_SYMBOLS)) if include_symbols else set()

    if exclude_ambiguous:
        lowers -= AMBIGUOUS
        uppers -= AMBIGUOUS
        digits -= AMBIGUOUS
        symbols -= AMBIGUOUS

    #sorted lists
    return {
        "lower": sorted(lowers),
        "upper": sorted(uppers),
        "digit": sorted(digits),
        "symbol": sorted(symbols),
    }


def estimate_entropy(length, pool_size):
    if pool_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(pool_size)


def classify_char(c):
    if c.islower():
        return "lower"
    if c.isupper():
        return "upper"
    if c.isdigit():
        return "digit"
    return "symbol"


def violates_repeats(pw, max_repeat=2):
    if max_repeat < 1:
        return False
    run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i-1]:
            run += 1
            if run > max_repeat:
                return True
        else:
            run = 1
    return False


def violates_sequences(pw, seq_len=3):
    if seq_len <= 2:
        return False
    def is_seq(a, b):
        return (a.isalpha() and b.isalpha()) or (a.isdigit() and b.isdigit())

    asc = 1
    desc = 1
    for i in range(1, len(pw)):
        if is_seq(pw[i-1], pw[i]) and (ord(pw[i]) - ord(pw[i-1]) == 1):
            asc += 1
            desc = 1
        elif is_seq(pw[i-1], pw[i]) and (ord(pw[i-1]) - ord(pw[i]) == 1):
            desc += 1
            asc = 1
        else:
            asc = desc = 1
        if asc >= seq_len or desc >= seq_len:
            return True
    return False


def generate_password(length, charsets, require_each=True, avoid_repeats=True, avoid_sequences=True, max_attempts=500):
    pools = [v for v in charsets.values() if v]
    if not pools:
        raise ValueError("No character sets selected.")
    pool = [c for v in pools for c in v]
    if not pool:
        raise ValueError("Selected character sets are empty.")

    if require_each and length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)} when requiring at least one of each selected type.")

    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        pw_chars = []

        if require_each:
            for subset in pools:
                pw_chars.append(choice(subset))

        while len(pw_chars) < length:
            pw_chars.append(choice(pool))

        _sysrand.shuffle(pw_chars)
        pw = "".join(pw_chars)

        if avoid_repeats and violates_repeats(pw):
            continue
        if avoid_sequences and violates_sequences(pw):
            continue

        return pw

    raise RuntimeError("Could not generate a password satisfying the rules; try relaxing constraints or increasing length.")


class StrengthMeter(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.var = tk.DoubleVar(value=0.0)
        self.progress = ttk.Progressbar(self, orient="horizontal", length=220, mode="determinate", maximum=100, variable=self.var)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.label = ttk.Label(self, text="Strength: N/A")
        self.label.grid(row=0, column=1, padx=(8,0))

        self.columnconfigure(0, weight=1)

    def update_strength(self, entropy_bits):
        # Map entropy to 0-100 scale with simple thresholds
        # < 40 weak, 40-70 medium, > 70 strong
        score = max(0.0, min(100.0, (entropy_bits / 80.0) * 100.0))
        self.var.set(score)
        if entropy_bits < 40:
            text = f"Weak ({entropy_bits:.1f} bits)"
        elif entropy_bits < 70:
            text = f"Okay ({entropy_bits:.1f} bits)"
        else:
            text = f"Strong ({entropy_bits:.1f} bits)"
        self.label.config(text=f"Strength: {text}")


class App(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=12)
        self.master = master
        master.title("Password Generator")
        master.geometry("720x480")
        master.minsize(640, 420)

        #controls
        self.length_var = tk.IntVar(value=16)

        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=True)

        self.exclude_ambig_var = tk.BooleanVar(value=True)
        self.require_each_var = tk.BooleanVar(value=True)
        self.avoid_repeats_var = tk.BooleanVar(value=True)
        self.avoid_sequences_var = tk.BooleanVar(value=True)

        self.custom_symbols_var = tk.StringVar(value=DEFAULT_SYMBOLS)

        self.password_var = tk.StringVar(value="")
        self.show_var = tk.BooleanVar(value=False)

        #layout
        self._build_layout()
        self._bind_events()
        self._update_entropy_label()
        self._load_history_from_file()
    
    def _load_history_from_file(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip()]
                for pw in reversed(lines[-100:]):
                    self.history.insert(0, pw)
            except Exception as e:
                messagebox.showerror("History Load Error", f"Could not load history file:\n{e}")

    def _save_password_to_file(self, pw):
        try:
            with open(HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(pw + "\n")
        except Exception as e:
            messagebox.showerror("History Save Error", f"Could not save to history file:\n{e}")


    def _build_layout(self):
        #(options)
        options = ttk.LabelFrame(self, text="Options")
        options.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ttk.Label(options, text="Length:").grid(row=0, column=0, sticky="w")
        self.length_spin = ttk.Spinbox(options, from_=4, to=128, textvariable=self.length_var, width=6)
        self.length_spin.grid(row=0, column=1, sticky="w")

        # Character sets
        cs = ttk.LabelFrame(options, text="Character sets")
        cs.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8,0))

        ttk.Checkbutton(cs, text="Lowercase (a-z)", variable=self.lower_var, command=self._update_entropy_label).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(cs, text="Uppercase (A-Z)", variable=self.upper_var, command=self._update_entropy_label).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(cs, text="Digits (0-9)", variable=self.digit_var, command=self._update_entropy_label).grid(row=2, column=0, sticky="w")
        ttk.Checkbutton(cs, text="Symbols", variable=self.symbol_var, command=self._update_entropy_label).grid(row=3, column=0, sticky="w")

        ttk.Label(cs, text="Symbols used:").grid(row=3, column=1, sticky="e", padx=(10,2))
        self.symbols_entry = ttk.Entry(cs, textvariable=self.custom_symbols_var, width=28)
        self.symbols_entry.grid(row=3, column=2, sticky="ew", padx=(0,2))

        ttk.Checkbutton(options, text="Exclude ambiguous characters (Il1O0|`'\";:,./\\)", variable=self.exclude_ambig_var, command=self._update_entropy_label).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8,0))

        rules = ttk.LabelFrame(options, text="Rules")
        rules.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8,0))

        ttk.Checkbutton(rules, text="Require at least one of each selected type", variable=self.require_each_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(rules, text="Avoid repeated chars (no 3+ in a row)", variable=self.avoid_repeats_var).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(rules, text="Avoid sequences (abc, 123, cba, 321)", variable=self.avoid_sequences_var).grid(row=2, column=0, sticky="w")

        strength_box = ttk.LabelFrame(self, text="Strength")
        strength_box.grid(row=1, column=0, sticky="ew", padx=(0,10), pady=(10,0))
        self.entropy_label = ttk.Label(strength_box, text="Entropy: 0.0 bits (pool: 0)")
        self.entropy_label.grid(row=0, column=0, sticky="w", pady=(2,6))
        self.meter = StrengthMeter(strength_box)
        self.meter.grid(row=1, column=0, sticky="ew", pady=(0,4))

        out = ttk.LabelFrame(self, text="Password")
        out.grid(row=0, column=1, rowspan=2, sticky="nsew")

        self.password_entry = ttk.Entry(out, textvariable=self.password_var, font=("Consolas", 14))
        self.password_entry.grid(row=0, column=0, columnspan=4, sticky="ew", padx=6, pady=(8,2))

        ttk.Checkbutton(out, text="Show", variable=self.show_var, command=self._toggle_show).grid(row=1, column=0, sticky="w", padx=6)

        gen_btn = ttk.Button(out, text="Generate", command=self.on_generate)
        gen_btn.grid(row=1, column=1, sticky="ew", padx=6)

        copy_btn = ttk.Button(out, text="Copy", command=self.on_copy)
        copy_btn.grid(row=1, column=2, sticky="ew", padx=6)

        gen_copy_btn = ttk.Button(out, text="Generate & Copy", command=self.on_generate_copy)
        gen_copy_btn.grid(row=1, column=3, sticky="ew", padx=6)

        hist = ttk.LabelFrame(self, text="History (double-click to copy)")
        hist.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(10,0))

        self.history = tk.Listbox(hist, height=6, font=("Consolas", 11))
        self.history.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(hist, orient="vertical", command=self.history.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.history.configure(yscrollcommand=scroll.set)

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        options.columnconfigure(1, weight=1)
        cs.columnconfigure(2, weight=1)
        out.columnconfigure(0, weight=1)
        out.columnconfigure(1, weight=0)
        out.columnconfigure(2, weight=0)
        out.columnconfigure(3, weight=0)
        hist.columnconfigure(0, weight=1)

        self.grid(sticky="nsew")
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        self._toggle_show()

    def _bind_events(self):
        for var in (self.length_var, self.lower_var, self.upper_var, self.digit_var, self.symbol_var, self.exclude_ambig_var):
            if isinstance(var, tk.Variable):
                var.trace_add("write", lambda *args: self._update_entropy_label())
        self.custom_symbols_var.trace_add("write", lambda *args: self._update_entropy_label())
        self.history.bind("<Double-Button-1>", self.on_history_copy)

    def _toggle_show(self):
        self.password_entry.config(show="" if self.show_var.get() else "•")

    def _get_charsets(self):
        return build_charsets(
            self.lower_var.get(),
            self.upper_var.get(),
            self.digit_var.get(),
            self.symbol_var.get(),
            self.exclude_ambig_var.get(),
            self.custom_symbols_var.get() if self.symbol_var.get() else None
        )

    def _update_entropy_label(self):
        cs = self._get_charsets()
        pool_size = sum(len(v) for v in cs.values())
        length = int(self.length_var.get())
        bits = estimate_entropy(length, pool_size)
        self.entropy_label.config(text=f"Entropy: {bits:.1f} bits (pool: {pool_size})")
        self.meter.update_strength(bits)

    def on_generate(self):
        try:
            cs = self._get_charsets()
            length = int(self.length_var.get())
            pw = generate_password(
                length,
                cs,
                require_each=self.require_each_var.get(),
                avoid_repeats=self.avoid_repeats_var.get(),
                avoid_sequences=self.avoid_sequences_var.get()
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        self.password_var.set(pw)
        self._add_to_history(pw)

    def on_copy(self):
        pw = self.password_var.get()
        if not pw:
            messagebox.showinfo("Copy", "No password to copy.")
            return
        self._copy_to_clipboard(pw)

    def on_generate_copy(self):
        self.on_generate()
        pw = self.password_var.get()
        if pw:
            self._copy_to_clipboard(pw)

    def _copy_to_clipboard(self, text):
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            self.master.update()
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Clipboard Error", str(e))

    def _add_to_history(self, pw):
        self.history.insert(0, pw)
        self._save_password_to_file(pw)
        if self.history.size() > 100:
            self.history.delete(100, tk.END)

    def on_history_copy(self, event):
        sel = self.history.curselection()
        if not sel:
            return
        pw = self.history.get(sel[0])
        self.password_var.set(pw)
        self._copy_to_clipboard(pw)


def main():
    root = tk.Tk()
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
