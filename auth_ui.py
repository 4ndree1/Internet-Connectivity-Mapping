"""
Login / Registration page for NetHealer, shown before the network
selection page. Kept in its own module so ui.py only needs a tiny hook.
"""

import os
import sys

import customtkinter as ctk
from PIL import Image

import auth_store

_MAX_FAILS = 5
_LOCKOUT_MS = 10_000


def _resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


class AuthPage(ctk.CTkFrame):
    """on_success(username) is called once the user logs in or registers."""

    def __init__(self, master, on_success):
        super().__init__(master, fg_color="#121212")
        self._on_success = on_success
        self._mode = "login" if auth_store.has_any_users() else "register"
        self._fails = 0
        self._locked = False

        # Header: logo + title (same look as the network selection page)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(pady=(50, 15))
        try:
            img = Image.open(_resource_path("assets/logo.png"))
            logo = ctk.CTkImage(light_image=img, dark_image=img, size=(90, 90))
            lbl = ctk.CTkLabel(header, image=logo, text="")
            lbl.image = logo
            lbl.pack(side="left", padx=(0, 20))
        except Exception:
            pass
        ctk.CTkLabel(
            header, text="INTERNET CONNECTIVITY MAPPING",
            font=("Arial Black", 30), text_color="#FFFFFF"
        ).pack(side="left")

        # Centered card
        center = ctk.CTkFrame(self, fg_color="transparent")
        center.pack(expand=True)
        card = ctk.CTkFrame(
            center, fg_color="#1A1A1A", border_color="#333333",
            border_width=2, corner_radius=10
        )
        card.pack()
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(padx=40, pady=30)

        self._title = ctk.CTkLabel(
            body, text="", font=("Arial Black", 18), text_color="#007AFF")
        self._title.pack(pady=(0, 4))
        self._subtitle = ctk.CTkLabel(
            body, text="", font=("Courier New", 12), text_color="#888888")
        self._subtitle.pack(pady=(0, 18))

        self._username_frame, self._username = self._field(body, "USERNAME")
        self._password_frame, self._password = self._field(body, "PASSWORD", show="•")
        self._confirm_frame, self._confirm = self._field(body, "CONFIRM PASSWORD", show="•")

        self._show_pw = ctk.BooleanVar(value=False)
        self._show_cb = ctk.CTkCheckBox(
            body, text="Show password", variable=self._show_pw,
            command=self._toggle_password,
            fg_color="#007AFF", hover_color="#0055CC", border_color="#444444",
            font=("Courier New", 11), text_color="#AAAAAA")
        self._show_cb.pack(anchor="w", pady=(0, 8))

        self._message = ctk.CTkLabel(
            body, text="", font=("Courier New", 11),
            text_color="#FF3333", wraplength=320, justify="left")
        self._message.pack(pady=(0, 8))

        self._submit = ctk.CTkButton(
            body, text="", width=320, height=44,
            fg_color="#007AFF", hover_color="#0055CC",
            font=("Arial Black", 13), command=self._submit_clicked)
        self._submit.pack(pady=(0, 12))

        for w in (self._username, self._password, self._confirm):
            w.bind("<Return>", lambda e: self._submit_clicked())

        self._apply_mode()
        self._username.focus_set()

    # ---- helpers -------------------------------------------------------
    def _field(self, parent, label, show=""):
        """A label on top with an entry box under it. Returns (frame, entry);
        the frame is what gets shown/hidden so the label moves with the box."""
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(pady=6)
        ctk.CTkLabel(
            frame, text=label, anchor="w",
            font=("Courier New", 12, "bold"), text_color="#AAAAAA"
        ).pack(fill="x", pady=(0, 3))
        e = ctk.CTkEntry(
            frame, width=320, height=40, show=show,
            fg_color="#121212", border_color="#333333",
            text_color="white", font=("Courier New", 13))
        e.pack()
        return frame, e

    def _toggle_password(self):
        ch = "" if self._show_pw.get() else "•"
        self._password.configure(show=ch)
        self._confirm.configure(show=ch)

    def _set_message(self, text, ok=False):
        self._message.configure(text=text,
                                text_color="#00CC66" if ok else "#FF3333")

    def _apply_mode(self):
        self._set_message("")
        if self._mode == "login":
            self._title.configure(text="LOG IN")
            self._subtitle.configure(text="Sign in to continue")
            self._confirm_frame.pack_forget()
            self._submit.configure(text="LOG IN")
        else:
            # First run only: no account exists yet. This creates the one
            # and only account; registration is closed after that.
            self._title.configure(text="CREATE ADMIN ACCOUNT")
            self._subtitle.configure(text="First-time setup")
            self._confirm_frame.pack(after=self._password_frame, pady=6)
            self._submit.configure(text="CREATE ACCOUNT")
        self._password.delete(0, "end")
        self._confirm.delete(0, "end")

    # ---- actions -------------------------------------------------------
    def _submit_clicked(self):
        if self._locked:
            return
        username = self._username.get()
        password = self._password.get()

        if self._mode == "register":
            ok, msg = auth_store.register(username, password, self._confirm.get())
            if not ok:
                self._set_message(msg)
                return
            self._finish(username.strip())
            return

        user = auth_store.verify(username, password)
        if user is None:
            self._fails += 1
            self._password.delete(0, "end")
            if self._fails >= _MAX_FAILS:
                self._lock_out()
            else:
                self._set_message("Incorrect username or password.")
            return
        self._finish(user)

    def _lock_out(self):
        self._locked = True
        self._submit.configure(state="disabled")
        self._set_message(
            f"Too many failed attempts. Try again in {_LOCKOUT_MS // 1000} seconds.")
        self.after(_LOCKOUT_MS, self._unlock)

    def _unlock(self):
        self._locked = False
        self._fails = 0
        if self.winfo_exists():
            self._submit.configure(state="normal")
            self._set_message("")

    def _finish(self, username):
        self._on_success(username)