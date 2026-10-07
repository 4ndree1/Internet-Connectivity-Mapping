import customtkinter as ctk

# Lock the UI to a fixed 1.0 scale everywhere, instead of trusting
# customtkinter's automatic DPI-awareness detection. Left on, that
# detection reads each OS's own display-scaling setting (Windows'
# 100/125/150% scaling, macOS Retina, Linux font-DPI settings) and
# silently multiplies every widget's size by that factor — so the exact
# same code can lay out at a different actual size on another desktop.
# Fixing scaling to 1.0 here means every column width, button size, and
# row height below renders at the literal pixel values we specify, on
# any machine this app is installed on. Must run before any CTk window
# is created, so it's placed immediately after the import.
ctk.deactivate_automatic_dpi_awareness()
ctk.set_widget_scaling(1.0)
ctk.set_window_scaling(1.0)
from tkinter import messagebox, filedialog
import tkinter as tk
import tkinter.font as tkfont
import math
import re
import threading
import time
import zlib
from datetime import datetime, timedelta
import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)
from PIL import Image
from engine import NetHealerEngine
from group_engine import GroupEngine
import group_store
from models import STATUS_COLORS
from auth_ui import AuthPage
import report_builder




def resource_path(relative_path):
   """Get absolute path to a resource — works in dev and in a PyInstaller --onefile exe."""
   base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
   return os.path.join(base_path, relative_path)




def _summarize_troubleshoot_lines(lines):
   """Reduce one device's already-filtered troubleshoot lines down to the
   counts the Troubleshoot page's summary bar shows: how many offline
   incidents were auto-detected, how many of those the engine recovered
   on its own, and how many are still unresolved.

   `lines` is the same list _extract_device_logs()/the periodic refresh
   already produce — one device's lines only, prompt prefix stripped.
   Kept as a plain module-level function (not a method) so both the
   Troubleshoot page's own show_device_log() and the separate periodic
   refresh_auto_troubleshoot_log() poll can call it and always agree on
   the numbers.
   """
   incidents = 0
   recovered = 0
   unresolved = 0
   for line in lines:
       upper = line.upper()
       if "OFFLINE DEVICE DETECTED" in upper:
           incidents += 1
       elif "RECOVERED" in upper:
           recovered += 1
       elif "UNRESOLVED" in upper:
           unresolved += 1
   return {"incidents": incidents, "recovered": recovered, "unresolved": unresolved}


def _format_troubleshoot_summary(device, lines):
   """Build the one-line summary text shown under the troubleshoot log
   for the currently selected device. `device` supplies live health
   fields (status/fail_count/unstable_count/last_check) that the log
   text itself doesn't carry; `lines` supplies the incident counts."""
   if device is None:
       return "Select a device to see a summary."

   counts = _summarize_troubleshoot_lines(lines)
   return (
       f"STATUS: {device.status}    "
       f"INCIDENTS: {counts['incidents']}    "
       f"AUTO-RECOVERED: {counts['recovered']}    "
       f"UNRESOLVED: {counts['unresolved']}    "
       f"FAIL COUNT: {getattr(device, 'fail_count', 0)}    "
       f"LAST CHECK: {getattr(device, 'last_check', '--:--:--')}"
   )




# Dashboard table columns: (header text, base/minimum pixel width).
# DIAGNOSE is handled separately below since it's a button, not a stretchy
# text column. Both the header row and the device rows read from this same
# list (and from the stretched widths computed off of it) so they can never
# drift out of alignment with each other.
DASHBOARD_COLUMNS = [
    ("DEVICE", 155),
    ("IP ADDRESS", 128),
    ("MAC ADDRESS", 162),
    ("LATENCY", 84),
    ("JITTER", 80),
    ("PACKET LOSS", 94),
    ("NETWORK SPEED", 111),
    ("STATUS", 94),
]
DASHBOARD_DIAGNOSE_WIDTH = 80
DASHBOARD_DIAGNOSE_GAP = 15
DASHBOARD_COL_PADX = 10
# The header row (cols_frame) never has a scrollbar, but the row list
# below it (list_canvas) grows one whenever there are enough devices to
# need vertical scrolling — which narrows that canvas without narrowing
# the header. If column widths are stretched to fit the header's (wider)
# width, rows can end up wider than the actual visible row canvas once
# the scrollbar appears, pushing the DIAGNOSE button off the right edge
# with no horizontal scroll to reach it. Reserving this space up front
# keeps columns narrow enough to fit either way.
DASHBOARD_SCROLLBAR_RESERVE = 18
# Column widths stretch to fill leftover panel space, but with no cap
# that blows up on wide windows/screens — huge gaps open up between
# columns and the row can end up wider than the window itself, pushing
# STATUS/DIAGNOSE off the right edge entirely. Capping how far columns
# are allowed to grow keeps spacing reasonable while still letting the
# table reach most of the way across a wide panel instead of leaving a
# large blank strip on the right.
DASHBOARD_MAX_SCALE = 1.0

# Time-range options for the History Log's per-device filter, letting the
# user narrow a device's saved history down to just its recent activity
# (e.g. "what happened in the last 15 minutes") instead of always showing
# its complete saved history. "ALL TIME" has no entry in the minutes map
# below — that absence IS the "no cutoff" case, checked for explicitly
# wherever this is used.
HISTORY_TIME_FILTERS = [
    "ALL TIME",
    "LAST 15 MIN",
    "LAST 1 HOUR",
    "LAST 6 HOURS",
    "LAST 24 HOURS",
]
HISTORY_TIME_FILTER_MINUTES = {
    "LAST 15 MIN": 15,
    "LAST 1 HOUR": 60,
    "LAST 6 HOURS": 360,
    "LAST 24 HOURS": 1440,
}


class _StyledDropdown(ctk.CTkFrame):
    """Drop-in replacement for CTkOptionMenu with a popup list we can
    actually theme.

    CTkOptionMenu's dropdown is a real tkinter.Menu (a native OS menu).
    On macOS, Tk's native menu widget ignores custom bg/fg colors
    entirely — customtkinter's own DropdownMenu._configure_menu_for_platforms
    skips setting them on darwin — so no dropdown_fg_color/dropdown_text_color
    combination can ever restyle it there. This widget instead builds the
    open list out of plain CTkButtons inside a borderless CTkToplevel
    positioned under the button, so it renders identically (and matches
    the app's theme) on every platform.

    Supports the same .pack()/.configure(values=...)/.set()/.get()/
    command= surface the rest of the app already uses.
    """

    def __init__(self, master, values, width=220, height=32,
                 fg_color="#1E1E1E", text_color="#DDDDDD",
                 hover_color="#262626", border_color="#444444",
                 dropdown_fg_color="#1A1A1A", dropdown_hover_color="#262626",
                 dropdown_text_color="#007AFF", font=("Courier New", 11, "bold"),
                 dropdown_font=("Courier New", 12, "bold"),
                 command=None, max_visible_rows=None):
        super().__init__(master, fg_color="transparent")
        self._values = list(values) if values else []
        self._command = command
        # Per-instance override for how many rows show before the list
        # scrolls. None (the default) keeps the class-wide MAX_VISIBLE_ROWS
        # behavior every other dropdown already uses. A caller can pass a
        # bigger number (e.g. len(values)) to always show every option
        # with no scrollbar at all for that one dropdown, without changing
        # behavior for any other dropdown built from this same class.
        self._max_visible_rows = max_visible_rows if max_visible_rows is not None else self.MAX_VISIBLE_ROWS
        self._fg_color = fg_color
        self._hover_color = hover_color
        self._border_color = border_color
        self._dropdown_fg_color = dropdown_fg_color
        self._dropdown_hover_color = dropdown_hover_color
        self._dropdown_text_color = dropdown_text_color
        self._font = font
        self._dropdown_font = dropdown_font
        self._popup = None

        # The full, untruncated value currently selected. The LABEL widget
        # may display a shortened/ellipsized version of this (see
        # _truncate_for), but get()/the command callback always hand back
        # this exact string — code elsewhere (e.g. matching a panel to a
        # dropdown selection by comparing labels) depends on getting back
        # exactly what was passed in, not a display-shortened copy of it.
        self._current_value = self._values[0] if self._values else ""

        # Reserved horizontal space around the text in each context, i.e.
        # everything in the row that ISN'T the label: padding, the arrow
        # glyph, borders. Used both to size the capsule/popup to fit the
        # longest label and to know how much room actual label text has
        # to work with when deciding whether it needs truncating.
        self._CLOSED_CHROME = 54   # left padx(10) + arrow(~14) + arrow padx(10) + inner inset(4) + buffer
        self._ROW_CHROME = 32      # border_spacing(20) + canvas_inset(8) + content border(4)
        self._ROW_CHROME_SCROLL = self._ROW_CHROME + 18  # + room for the scrollbar

        # Width is no longer just whatever fixed pixel value the caller
        # passed in — it's computed from the longest label so nothing the
        # popup or the closed button show ever gets clipped, capped at
        # MAX_WIDTH so a single very long label can't blow the dropdown up
        # to an unreasonable size (that case falls back to ellipsis
        # truncation instead).
        self._min_width = width
        self._computed_width = self._compute_width()

        # Built as a bordered capsule containing a label (left, expands)
        # and a separate arrow label (right, fixed) — NOT an arrow overlaid
        # on top of button text, which was clipping/overlapping long labels
        # like "NETWORK 1  -  192.168.0.0/24". pack_propagate(False) keeps
        # the capsule's overall size fixed regardless of content.
        #
        # The border is NOT drawn via CTkFrame's own border_width — that
        # path has a real CustomTkinter bug where one edge of a rounded,
        # fixed-width frame's border can fail to render (usually the last
        # side drawn), no matter how thick the border is set. Instead the
        # border is faked the same reliable way the dropdown popup's border
        # is: self._capsule is filled entirely with border_color, and an
        # inner frame inset by a couple pixels on every side shows the real
        # background — that inset sliver of the outer frame IS the border,
        # and since it's just two solid rounded rectangles instead of a
        # native border draw, it can't drop a side.
        self._capsule = ctk.CTkFrame(
            self, width=self._computed_width, height=height, corner_radius=8,
            fg_color=border_color
        )
        self._capsule.pack_propagate(False)
        self._capsule.pack()

        self._inner = ctk.CTkFrame(
            self._capsule, corner_radius=6, fg_color=fg_color
        )
        self._inner.pack(fill="both", expand=True, padx=2, pady=2)

        self._label = ctk.CTkLabel(
            self._inner, text=self._display_text(self._current_value, self._font, self._CLOSED_CHROME),
            font=font, text_color=text_color, anchor="w"
        )
        self._label.pack(side="left", fill="both", expand=True, padx=(10, 0))

        self._arrow = ctk.CTkLabel(
            self._inner, text="▼", font=("Arial", 13), text_color=text_color
        )
        self._arrow.pack(side="right", padx=(0, 10))

        # CTk widgets are composites — a CTkLabel/CTkFrame is really an
        # outer Frame with an inner canvas + tk.Label doing the actual
        # drawing, and mouse clicks/Enter/Leave land on whichever of those
        # inner widgets is directly under the cursor, not necessarily on
        # the CTkFrame/CTkLabel object itself. Binding only on
        # self._inner/self._label/self._arrow would silently miss most
        # mouse activity, so bind recursively onto every descendant instead.
        self._bind_hover_recursive(
            self._inner, self._inner, self._fg_color, self._hover_color,
            on_click=lambda e: self._toggle()
        )

    def _bind_hover_recursive(self, widget, target, normal_color, hover_color, on_click=None):
        """Recolors `target` between normal_color/hover_color on mouse
        Enter/Leave, bound onto `widget` AND every one of its descendants
        (composite CTk widgets draw with inner canvases/labels that
        actually receive the mouse events, so binding only on the
        top-level widget misses most hover/click activity)."""
        widget.bind("<Enter>", lambda e: target.configure(fg_color=hover_color))
        widget.bind("<Leave>", lambda e: target.configure(fg_color=normal_color))
        if on_click is not None:
            widget.bind("<Button-1>", on_click)
        for child in widget.winfo_children():
            self._bind_hover_recursive(child, target, normal_color, hover_color, on_click)

    def _toggle(self):
        if self._popup is not None and self._popup.winfo_exists():
            self._close()
        else:
            self._open()

    # ── sizing / truncation helpers ─────────────────────────────────
    # These exist so labels never get silently clipped by their container:
    # the dropdown sizes itself to fit the longest value (up to a sane
    # cap), and only falls back to an ellipsis if a label is so long that
    # even the capped width can't hold it.
    MAX_WIDTH = 420

    def _text_px(self, text, font_spec):
        try:
            weight = font_spec[2] if len(font_spec) > 2 else "normal"
            return tkfont.Font(family=font_spec[0], size=font_spec[1], weight=weight).measure(text)
        except Exception:
            # Fallback if font measurement isn't available yet (e.g. no
            # Tk root ready) — rough monospace-ish estimate is enough to
            # keep sizing sane, it doesn't need to be pixel-perfect.
            return len(text) * (font_spec[1] if len(font_spec) > 1 else 11)

    def _compute_width(self):
        """Width needed to fit the longest current value without
        clipping, clamped between the caller's minimum and MAX_WIDTH."""
        if not self._values:
            return self._min_width
        widest = max(self._text_px(v, self._dropdown_font) for v in self._values)
        needed = widest + max(self._CLOSED_CHROME, self._ROW_CHROME_SCROLL)
        return max(self._min_width, min(needed, self.MAX_WIDTH))

    def _display_text(self, text, font_spec, chrome, extra_reserved=0):
        """Returns `text` as-is if it fits in the current computed width
        minus `chrome`/`extra_reserved`, otherwise an ellipsized version
        that does. This only ever changes what's DRAWN — callers keep
        using the full original string for comparisons/callbacks."""
        if not text:
            return text
        max_px = self._computed_width - chrome - extra_reserved
        if self._text_px(text, font_spec) <= max_px:
            return text
        trimmed = text
        while trimmed and self._text_px(trimmed + "…", font_spec) > max_px:
            trimmed = trimmed[:-1]
        return (trimmed + "…") if trimmed else "…"

    def _resize_capsule(self):
        self._capsule.configure(width=self._computed_width)
        self._label.configure(
            text=self._display_text(self._current_value, self._font, self._CLOSED_CHROME)
        )

    # Rows shown before the list scrolls instead of growing further.
    # Set to 2 so that the scrollbar kicks in as soon as there are 3 or
    # more networks (needs_scroll below is len(values) > MAX_VISIBLE_ROWS).
    MAX_VISIBLE_ROWS = 2

    def _open(self):
        if not self._values:
            return
        self._capsule.update_idletasks()
        x = self._capsule.winfo_rootx()
        y = self._capsule.winfo_rooty() + self._capsule.winfo_height()
        w = self._capsule.winfo_width()
        row_h = 30
        visible_rows = min(len(self._values), self._max_visible_rows)
        needs_scroll = len(self._values) > self._max_visible_rows

        # A real Tk window (the popup Toplevel) is always a square
        # rectangle — no styling trick makes ITS outer edge round. Every
        # attempt to fake the border as a visible sliver of the Toplevel's
        # own background (solid border color, then near-black) just moved
        # where that square edge showed up. The actual fix: stop trying to
        # round the Toplevel at all. Match the ADD NETWORK dialog's own
        # popup card, which already does this correctly elsewhere in this
        # file — near-black Toplevel background so its square edges
        # disappear into the app, with a single CTkFrame that has its OWN
        # native rounded border filling the window completely. Only that
        # frame needs to be round; the window underneath just needs to be
        # invisible.
        canvas_inset = 4

        popup = ctk.CTkToplevel(self)
        popup.overrideredirect(True)
        popup.attributes("-topmost", True)
        popup.configure(fg_color="#0a0a0a")

        border_width = 2
        total_h = row_h * visible_rows + canvas_inset * 2 + border_width * 2
        popup.geometry(f"{w}x{total_h}+{x}+{y}")

        content_frame = ctk.CTkFrame(
            popup, fg_color=self._dropdown_fg_color, corner_radius=6,
            border_width=border_width, border_color=self._border_color
        )
        content_frame.pack(fill="both", expand=True)

        # canvas_inset keeps the plain tk.Canvas (no rounding support of
        # its own) from filling content_frame edge-to-edge and painting
        # squarely over the rounded corners content_frame is drawing.
        #
        # The scrollbar (when needed) is created and packed BEFORE the
        # canvas, and the canvas is packed after it. Tk's pack geometry
        # manager hands out space in the order .pack() is called: a
        # side="left", fill="both", expand=True widget packed first claims
        # the whole remaining cavity immediately, so anything packed after
        # it (like a side="right" scrollbar) is squeezed into zero width
        # and never actually appears — even though the widget exists and
        # needs_scroll is True. Packing the scrollbar first reserves its
        # strip on the right before the canvas is allowed to expand into
        # the rest.
        canvas = tk.Canvas(content_frame, bg=self._dropdown_fg_color, highlightthickness=0)

        if needs_scroll:
            scrollbar = ctk.CTkScrollbar(
                content_frame, button_color="#555555", button_hover_color="#888888",
                command=canvas.yview
            )
            scrollbar.pack(side="right", fill="y")
            canvas.configure(yscrollcommand=scrollbar.set)

            def _on_mousewheel(e):
                # Windows reports multiples of 120; macOS reports small
                # values (+-1, +-2...), which int(-e.delta / 120) rounds
                # to 0 — so the wheel would do nothing there.
                if abs(e.delta) >= 120:
                    steps = int(-1 * (e.delta / 120))
                else:
                    steps = -1 if e.delta > 0 else 1
                canvas.yview_scroll(steps, "units")
            # Bound to the POPUP, not bind_all: bind_all registers on Tk's
            # global "all" bindtag, so every widget in the whole app -
            # including the IP search entry - starts routing mousewheel
            # events through this closure. _close() only destroys the
            # popup; it never undoes a bind_all, so the global hook stays
            # registered afterward and points at a now-destroyed canvas.
            # The next mousewheel event anywhere (e.g. hovering the search
            # bar) hits that dead reference, throws, and disrupts focus/
            # event handling right after a dropdown toggle. Binding to the
            # popup instead scopes the handler to this window only, and it
            # is discarded automatically when the popup is destroyed.
            popup.bind("<MouseWheel>", _on_mousewheel)

        canvas.pack(side="left", fill="both", expand=True, padx=canvas_inset, pady=canvas_inset)

        rows_frame = tk.Frame(canvas, bg=self._dropdown_fg_color)
        rows_window = canvas.create_window((0, 0), window=rows_frame, anchor="nw")

        row_chrome = self._ROW_CHROME_SCROLL if needs_scroll else self._ROW_CHROME
        for value in self._values:
            ctk.CTkButton(
                rows_frame,
                text=self._display_text(value, self._dropdown_font, row_chrome),
                anchor="w", height=row_h, corner_radius=0,
                fg_color="transparent", hover_color=self._dropdown_hover_color,
                text_color=self._dropdown_text_color, font=self._dropdown_font,
                border_spacing=10,
                # `value` (not the possibly-shortened display text) is what
                # gets selected/returned, so truncation never changes what
                # the rest of the app sees.
                command=lambda v=value: self._select(v)
            ).pack(fill="x")

        # The popup height above assumes every row is exactly row_h tall,
        # but each row is a CTkButton with border_spacing=10, so its real
        # height is (text height + 20) — noticeably taller than 30 on
        # some systems. That mismatch is what clipped the last row(s)
        # even though there was no scrollbar. Measure the rows' REAL
        # height now that they exist and size the popup from that, so
        # the same rule always applies: up to max_visible_rows rows show
        # in full, and only beyond that does the list scroll.
        try:
            rows_frame.update_idletasks()
            try:
                _scale = self._get_widget_scaling() or 1.0
            except Exception:
                _scale = 1.0
            real_row_h = rows_frame.winfo_reqheight() / max(1, len(self._values)) / _scale
            if real_row_h > row_h:
                total_h = int(round(real_row_h * visible_rows)) + canvas_inset * 2 + border_width * 2
                popup.geometry(f"{w}x{total_h}+{x}+{y}")
        except Exception:
            pass

        def _sync_canvas_width(event):
            canvas.itemconfig(rows_window, width=event.width)
        canvas.bind("<Configure>", _sync_canvas_width)

        def _sync_scrollregion(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        rows_frame.bind("<Configure>", _sync_scrollregion)

        def _on_popup_focus_out(e):
            # Dragging the scrollbar thumb (or otherwise clicking a child
            # widget inside this SAME popup) can shift Tk's internal focus
            # target onto that child, which fires <FocusOut> on the popup
            # exactly like a genuine click-away would. Closing/destroying
            # the popup right then — mid scrollbar-drag — left the
            # scrollbar's own press/drag bindings pointed at a widget that
            # no longer existed, which is what made every click afterward
            # (including on the closed-state capsule button, e.g. "ALL
            # TIME ▲") fail to re-toggle the dropdown. Only treat this as
            # a real click-away, and actually close the popup, when focus
            # has landed somewhere OUTSIDE the popup's own widget tree.
            new_focus = popup.focus_get()
            if new_focus is not None and str(new_focus).startswith(str(popup)):
                return
            self._close()
        popup.bind("<FocusOut>", _on_popup_focus_out)
        # winfo_exists() guard: this runs 10ms later on a timer, so if the
        # user picks a row (or clicks away) fast enough, the popup can
        # already be destroyed by the time this fires. Calling
        # focus_force on a dead Toplevel throws, and an uncaught error
        # here can leave the OS/window-manager's focus handoff in a
        # half-finished state - which is what made the IP search entry
        # (or any widget) briefly stop accepting keystrokes right after
        # toggling the dropdown.
        popup.after(10, lambda: popup.focus_force() if popup.winfo_exists() else None)
        self._popup = popup
        self._arrow.configure(text="▲")

    def _close(self):
        if self._popup is not None and self._popup.winfo_exists():
            self._popup.destroy()
        self._popup = None
        self._arrow.configure(text="▼")
        # Explicitly hand focus back to the main window. The popup was an
        # overrideredirect Toplevel that force-grabbed focus on open;
        # simply destroying it doesn't reliably return focus to anything,
        # so without this, whatever the user clicks/types next (e.g. the
        # IP search box) can go nowhere until an extra click re-establishes
        # focus.
        self.winfo_toplevel().focus_force()

    def _select(self, value):
        self.set(value)
        self._close()
        if self._command is not None:
            self._command(self._current_value)

    def set(self, value):
        # Store the real value; only the on-screen label may be shortened.
        self._current_value = value
        self._label.configure(text=self._display_text(value, self._font, self._CLOSED_CHROME))

    def get(self):
        return self._current_value

    def configure(self, **kwargs):
        if "values" in kwargs:
            self._values = list(kwargs.pop("values"))
            # New values can change what the longest label is, so re-fit
            # the capsule/popup width and re-truncate the visible label
            # instead of leaving sizing stuck at whatever it was before.
            self._computed_width = self._compute_width()
            self._resize_capsule()
        if kwargs:
            super().configure(**kwargs)


class NetHealerUI(ctk.CTk):
   def __init__(self):
       super().__init__()


       self.title("Network Mapping System")
       self.geometry("1500x1050")
       ctk.set_appearance_mode("dark")
       self.configure(fg_color="#121212")

       # Windows-only fix for whole-window flicker on every periodic
       # refresh (_refresh_all_stats runs every 2s and touches many
       # widgets/canvases at once). By default Tk windows on Windows are
       # painted directly via GDI, not DWM-composited/double-buffered, so
       # updating several widgets in one pass visibly flashes as each one
       # repaints in turn. Setting the window alpha to just under 1.0
       # forces Windows to hand the window to DWM instead, which
       # double-buffers the whole frame — the window looks 100% opaque
       # (the difference is imperceptible) but the flicker goes away.
       # Scoped to Windows only since "-alpha" means true transparency on
       # other platforms, which isn't what we want there.
       if sys.platform.startswith("win"):
           self.attributes("-alpha", 0.99)


       self._panels = {}
       self._radar_ring_state = {}
       self._monitored = set()
       self._network_selector = None
       self._add_network_button = None
       self._main_scroll_outer = None  # the dashboard's scroll area, hidden/shown when navigating to a full page (radar/history)
       self._current_page = None       # the currently-open full page frame (radar or history), or None if on the dashboard
       self._current_network_label = None
       self._refresh_job = None        # after() id of the 2s stats loop, so logout can cancel it
       # Network numbers are assigned dynamically from the numbers currently
       # in use. This means removing NETWORK 2 and adding another network
       # reuses NETWORK 2 instead of incorrectly creating NETWORK 4.


       # --- STATUS BAR --- (hidden until main UI loads)
       self.status_bar = ctk.CTkLabel(
           self, text="SYSTEM INITIALIZING...",
           fg_color="#808080", text_color="black",
           font=("Arial Black", 10), height=35
       )
       # Not packed yet — shown only after network selection


       self._show_auth_page()


   # SMART SCROLLABLE FRAME (scrollbar only when needed)
   def _make_smart_scroll(self, parent, height=None, bg="#121212"):
       """Returns (outer_frame, inner_frame). Scrollbar only appears when content overflows."""
       outer = tk.Frame(parent, bg=bg)


       canvas = tk.Canvas(outer, bg=bg, highlightthickness=0)
       if height:
           canvas.configure(height=height)
       canvas.pack(side="left", fill="both", expand=True)


       scrollbar = ctk.CTkScrollbar(outer, button_color="#555555", button_hover_color="#888888")
       scrollbar.configure(command=canvas.yview)
       canvas.configure(yscrollcommand=scrollbar.set)


       inner = tk.Frame(canvas, bg=bg)
       inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")


       def _update_scrollbar():
           canvas.configure(scrollregion=canvas.bbox("all"))
           if inner.winfo_reqheight() > canvas.winfo_height():
               scrollbar.pack(side="right", fill="y")
           else:
               scrollbar.pack_forget()


       def on_configure(e):
           outer.after(10, _update_scrollbar)


       def on_canvas_resize(e):
           canvas.itemconfig(inner_id, width=e.width)


       inner.bind("<Configure>", on_configure)
       canvas.bind("<Configure>", on_canvas_resize)


       def on_mousewheel(e):
           canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
       canvas.bind_all("<MouseWheel>", on_mousewheel)


       return outer, inner, canvas, scrollbar


   def _hide_radar_header_controls(self):
       """Hide the network selector and Add Network controls while Radar is open."""
       frame = getattr(self, "_header_controls_frame", None)
       if frame is not None and frame.winfo_exists():
           frame.pack_forget()
           self.header_frame.update_idletasks()


   def _restore_radar_header_controls(self):
       """Restore the network selector and Add Network controls after Radar closes."""
       frame = getattr(self, "_header_controls_frame", None)
       if frame is not None and frame.winfo_exists():
           frame.pack(side="right")
           self.header_frame.update_idletasks()


   # IN-WINDOW PAGE NAVIGATION (used by network radar / history log)
   def _show_full_page(self, build_fn, on_back=None):
       """Shows a full-size 'page' overlaid directly on top of the main
       dashboard, with a back button pinned at the top — used so the
       network radar and history log feel like navigating within the app
       instead of spawning a separate OS window. build_fn(page) fills in
       the page's own content below the back button; on_back(), if given,
       runs right before the page is torn down (for cleanup).

       This overlays the page rather than pack_forget()-ing the dashboard
       and re-pack()-ing it on the way back. Re-inserting a large widget
       tree (every device row, across every network) into the pack layout
       forces Tk to recompute geometry for all of it before it can paint,
       which showed up as a blank flash when returning to the dashboard.
       Since the dashboard is never unmapped here, going back is just
       destroying the overlay — nothing underneath needs to be redone."""
       if self._current_page is not None and self._current_page.winfo_exists():
           self._current_page.destroy()

       page = ctk.CTkFrame(self, fg_color="#121212")
       if self._main_scroll_outer is not None:
           page.place(in_=self._main_scroll_outer, relx=0, rely=0, relwidth=1, relheight=1)
       else:
           page.pack(fill="both", expand=True, padx=20, pady=(0, 10))
       self._current_page = page

       def _go_back():
           if on_back is not None:
               on_back()
           if self._current_page is page:
               self._current_page = None
           page.destroy()

       back_row = ctk.CTkFrame(page, fg_color="transparent")
       back_row.pack(fill="x", pady=(10, 8))
       ctk.CTkButton(
           back_row, text="← BACK TO DASHBOARD", width=200, height=32,
           fg_color="#1E1E1E", border_color="#007AFF", border_width=1,
           text_color="#007AFF", hover_color="#262626", font=("Arial Bold", 11),
           command=_go_back
       ).pack(side="left")

       build_fn(page)
       return page


   def _logout_confirm(self):
       self._show_confirm_popup(
           title="LOG OUT?",
           message=(
               f"Log out of {self.current_user or 'this account'}?\n\n"
               "Monitoring will stop for every network and group, and "
               "you will return to the login page."
           ),
           on_confirm=self._logout,
           confirm_text="YES, LOG OUT",
           cancel_text="CANCEL",
           danger=True,
       )

   def _logout(self):
       """Tears down the whole dashboard session (engines, panels, popups,
       timers) and returns to the login page. Logging in again goes
       through network selection like a fresh launch."""
       # 1) stop the 2s UI refresh loop
       if self._refresh_job is not None:
           try:
               self.after_cancel(self._refresh_job)
           except Exception:
               pass
           self._refresh_job = None

       # 2) close every open popup window (device popups, radar, etc.)
       for w in list(self.winfo_children()):
           if isinstance(w, tk.Toplevel):
               try:
                   w.destroy()
               except Exception:
                   pass

       # 3) stop monitoring. NetHealerEngine.stop() also stops its groups
       #    and flushes bandwidth/history to disk.
       for panel in list(self._panels.values()):
           eng = panel["engine"]
           if getattr(eng, "is_group", False):
               continue
           try:
               eng.stop()
           except Exception:
               pass

       # 4) remove the dashboard widgets
       if self._current_page is not None and self._current_page.winfo_exists():
           self._current_page.destroy()
       for name in ("header_frame", "_main_scroll_outer"):
           w = getattr(self, name, None)
           if w is not None and w.winfo_exists():
               w.destroy()
       self.status_bar.pack_forget()
       self.status_bar.configure(text="SYSTEM INITIALIZING...",
                                 fg_color="#808080", text_color="black")
       # the dashboard canvas bound the mouse wheel globally; that canvas
       # no longer exists, so drop the binding (the next dashboard re-adds it)
       try:
           self.unbind_all("<MouseWheel>")
       except Exception:
           pass

       # 5) reset UI state
       self._panels.clear()
       self._radar_ring_state.clear()
       self._monitored.clear()
       self.header_frame = None
       self._header_controls_frame = None
       self._network_selector = None
       self._add_network_button = None
       self._main_scroll_outer = None
       self._current_page = None
       self._current_network_label = None

       # 6) back to login
       self._show_auth_page()


   # STARTUP SELECTION SCREEN
   def _show_auth_page(self):
       """Login / registration page shown first; on success it is removed
       and the normal network selection page takes over."""
       self.current_user = None

       def _on_auth_success(username):
           self.current_user = username
           page.destroy()
           self._show_network_selection()

       page = AuthPage(self, _on_auth_success)
       page.pack(fill="both", expand=True)


   def _show_network_selection(self):
       self._selection_frame = ctk.CTkFrame(self, fg_color="#121212")
       self._selection_frame.pack(fill="both", expand=True)


       # Header row — logo on the left, title/subtitle stacked to its right
       header = ctk.CTkFrame(self._selection_frame, fg_color="transparent")
       header.pack(pady=(50, 15))


       try:
           logo_img = Image.open(resource_path("assets/logo.png"))
           logo_ctk = ctk.CTkImage(light_image=logo_img, dark_image=logo_img, size=(90, 90))
           logo_label = ctk.CTkLabel(header, image=logo_ctk, text="")
           logo_label.image = logo_ctk  # keep a reference so it isn't garbage collected
           logo_label.pack(side="left", padx=(0, 20))
       except Exception:
           pass  # if the logo is missing, just skip it silently


       text_col = ctk.CTkFrame(header, fg_color="transparent")
       text_col.pack(side="left")


       # Title
       ctk.CTkLabel(
           text_col,
           text="INTERNET CONNECTIVITY MAPPING",
           font=("Arial Black", 30), text_color="#FFFFFF"
       ).pack(anchor="w")


       # detect_networks() runs several subprocess calls (ipconfig/ip addr/
       # netstat, occasionally with multi-second timeouts on macOS) — doing
       # that synchronously here, before the frame we just packed ever gets
       # a chance to paint, made the very first screen appear frozen/blank
       # for a moment on launch. Show a lightweight placeholder immediately
       # and run detection on a background thread instead; the real
       # content swaps in via self.after(0, ...) once it's ready.
       loading_label = ctk.CTkLabel(
           self._selection_frame,
           text="DETECTING NETWORK INTERFACES...",
           font=("Courier New", 13, "bold"), text_color="#888888"
       )
       loading_label.pack(pady=30)

       def _detect_and_populate():
           networks = NetHealerEngine.detect_networks()
           if not self.winfo_exists() or not self._selection_frame.winfo_exists():
               return
           self.after(0, lambda: self._populate_network_selection(networks, loading_label))

       threading.Thread(target=_detect_and_populate, daemon=True).start()


   def _populate_network_selection(self, networks, loading_label):
       if loading_label is not None and loading_label.winfo_exists():
           loading_label.destroy()

       if not networks:
           ctk.CTkLabel(
               self._selection_frame,
               text="No network interfaces detected.",
               font=("Courier New", 12), text_color="#FF3333"
           ).pack(pady=10)
           ctk.CTkButton(
               self._selection_frame,
               text="RETRY",
               width=200, height=42,
               fg_color="#1E1E1E", border_color="#007AFF", border_width=1,
               text_color="#007AFF", hover_color="#262626",
               font=("Arial Black", 11),
               command=lambda: [self._selection_frame.destroy(), self._show_network_selection()]
           ).pack(pady=10)
           return


       selected = {}


       def start():
           chosen = [ip for ip, var in selected.items() if var.get()]
           if not chosen:
               messagebox.showwarning("No Network Selected", "Please select at least one network.")
               return
           self._fade_transition(chosen)


       def _fade_out(chosen, step=0):
           # Overlay a black cover frame that grows in opacity
           if step == 0:
               self._cover = tk.Frame(self, bg="black")
               self._cover.place(relx=0, rely=0, relwidth=1, relheight=1)
               self._cover.lift()
           alpha = round(step * 0.07, 2)
           if alpha >= 1.0:
               self._selection_frame.destroy()
               self._build_main_ui(chosen)
               _fade_in()
           else:
               self._cover.configure(bg=_blend_black(alpha))
               self.after(20, lambda: _fade_out(chosen, step + 1))


       def _fade_in(step=15):
           alpha = round(step * 0.07, 2)
           if alpha <= 0:
               self._cover.destroy()
           else:
               self._cover.configure(bg=_blend_black(min(alpha, 1.0)))
               self.after(20, lambda: _fade_in(step - 1))


       def _blend_black(alpha):
           # Interpolate from #121212 (bg) to #000000 based on alpha
           v = int(0x12 * (1 - alpha))
           return f"#{v:02x}{v:02x}{v:02x}"


       self._fade_transition = lambda chosen: _fade_out(chosen)


       # START button always visible at bottom
       ctk.CTkButton(
           self._selection_frame,
           text="START MONITORING",
           width=400, height=46,
           fg_color="#007AFF", hover_color="#0055CC",
           font=("Arial Black", 13),
           command=start
       ).pack(side="bottom", pady=(10, 30))


       # Heading + cards grouped together and centered as one unit in the
       # remaining space, so the heading sits directly above the cards
       # instead of being pinned near the top with a gap before them.
       selection_group = ctk.CTkFrame(self._selection_frame, fg_color="transparent")
       selection_group.pack(expand=True)

       ctk.CTkLabel(
           selection_group,
           text="SELECT THE NETWORK(S) YOU WANT TO MONITOR",
           font=("Courier New", 16, "bold"), text_color="#AAAAAA"
       ).pack(pady=(0, 20))

       cards_outer = ctk.CTkFrame(selection_group, fg_color="transparent")
       cards_outer.pack()


       cards_frame = ctk.CTkFrame(cards_outer, fg_color="transparent")
       cards_frame.pack()


       for i, base_ip in enumerate(networks):
           var = ctk.BooleanVar(value=True)
           selected[base_ip] = var


           card = ctk.CTkFrame(
               cards_frame,
               fg_color="#1A1A1A", border_color="#333333",
               border_width=2, corner_radius=10
           )
           card.pack(side="left", padx=10)


           inner = ctk.CTkFrame(card, fg_color="transparent")
           inner.pack(padx=16, pady=12)


           ctk.CTkCheckBox(
               inner, text="", variable=var, width=20,
               fg_color="#007AFF", hover_color="#0055CC", border_color="#444444"
           ).pack(side="left", padx=(0, 10))


           info = ctk.CTkFrame(inner, fg_color="transparent")
           info.pack(side="left")


           ctk.CTkLabel(info, text=f"NETWORK {i+1}", font=("Arial Black", 12), text_color="#007AFF", anchor="w").pack(anchor="w")
           ctk.CTkLabel(info, text=f"{base_ip}.0/24", font=("Courier New", 15, "bold"), text_color="white", anchor="w").pack(anchor="w")
           ctk.CTkLabel(info, text=f"{base_ip}.1 - {base_ip}.254", font=("Courier New", 11), text_color="#777777", anchor="w").pack(anchor="w")


   def _build_main_ui(self, chosen_networks):


       # Show status bar now that we are in the main UI
       self.status_bar.pack(fill="x", side="bottom")


       # --- HEADER ---
       self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
       self.header_frame.pack(fill="x", padx=30, pady=(20, 10))


       ctk.CTkLabel(
           self.header_frame,
           text="INTERNET CONNECTIVITY MAPPING",
           font=("Arial Black", 24), text_color="white"
       ).pack(side="left")


       self._header_controls_frame = ctk.CTkFrame(
           self.header_frame, fg_color="transparent"
       )
       self._header_controls_frame.pack(side="right")

       # Header controls use GRID instead of pack(side="right") so all three
       # controls are guaranteed to remain visible together. The custom
       # dropdown can grow wider than its minimum width, so mixing it with
       # multiple right-packed buttons could make the Remove button disappear
       # on some window sizes.
       self._header_controls_frame.grid_columnconfigure(0, weight=0)
       self._header_controls_frame.grid_columnconfigure(1, weight=0)
       self._header_controls_frame.grid_columnconfigure(2, weight=0)

       self._network_selector = _StyledDropdown(
           self._header_controls_frame, values=["NETWORK 1"], width=250, height=32,
           fg_color="#1E1E1E", text_color="#AAAAAA", border_color="#AAAAAA",
           hover_color="#262626", font=("Courier New", 11, "bold"),
           dropdown_fg_color="#1A1A1A", dropdown_hover_color="#262626",
           dropdown_text_color="#AAAAAA", dropdown_font=("Courier New", 12, "bold"),
           command=self._on_network_selected,
           # This list now holds networks AND groups (e.g. "GROUP: 1 -
           # NETWORK 1"), so it can grow past the 5-network cap that
           # detect_networks() applies on its own. Show up to 5 rows
           # as-is; from the 6th entry onward the popup stays 5 rows
           # tall and a scrollbar appears (see _StyledDropdown._open,
           # needs_scroll = len(values) > max_visible_rows).
           max_visible_rows=5
       )
       self._network_selector.grid(row=0, column=0, padx=(0, 10), pady=0)

       self._add_network_button = ctk.CTkButton(
           self._header_controls_frame,
           text="+ ADD NETWORK",
           width=140, height=32,
           fg_color="#1E1E1E", border_color="#007AFF", border_width=1,
           text_color="#007AFF", hover_color="#262626",
           command=self._add_network_popup
       )
       self._add_network_button.grid(row=0, column=1, padx=(0, 8), pady=0)

       self._remove_network_button = ctk.CTkButton(
           self._header_controls_frame,
           text="- REMOVE NETWORK",
           width=165, height=32,
           fg_color="#1E1E1E", border_color="#FF3333", border_width=1,
           text_color="#FF3333", hover_color="#2A1414",
           command=self._remove_network_confirm
       )
       self._remove_network_button.grid(row=0, column=2, padx=(0, 8), pady=0)

       self._header_controls_frame.grid_columnconfigure(3, weight=0)
       self._header_controls_frame.grid_columnconfigure(4, weight=0)
       ctk.CTkButton(
           self._header_controls_frame,
           text="MANAGE GROUPS",
           width=140, height=32,
           fg_color="#1E1E1E", border_color="#B266FF", border_width=1,
           text_color="#B266FF", hover_color="#221A2E",
           command=self._open_manage_groups_popup
       ).grid(row=0, column=3, padx=(0, 8), pady=0)
       ctk.CTkButton(
           self._header_controls_frame,
           text="LOGOUT",
           width=140, height=32,
           fg_color="#1E1E1E", border_color="#FF3333", border_width=1,
           text_color="#FF3333", hover_color="#2A1414",
           command=self._logout_confirm
       ).grid(row=0, column=4, padx=0, pady=0)


       # --- MAIN SMART SCROLLABLE AREA ---
       scroll_outer, self._scroll_inner, _sc, _sb = self._make_smart_scroll(self, bg="#121212")
       scroll_outer.pack(fill="both", expand=True, padx=20, pady=(0, 10))
       self._main_scroll_outer = scroll_outer


       # Build dashboards
       for i, base_ip in enumerate(chosen_networks):
           network_number = self._next_network_number()
           label = f"NETWORK {network_number}   -   {base_ip}.0/24"
           engine = NetHealerEngine(self, base_ip=base_ip, label=label)
           self._monitored.add(base_ip)
           self._build_dashboard(engine, is_first=(i == 0))

       self._update_remove_network_button()


       self._refresh_job = self.after(1000, self._refresh_all_stats)


   # ADD NETWORK POPUP
   def _add_network_popup(self):
       all_networks = NetHealerEngine.detect_networks()
       available = [n for n in all_networks if n not in self._monitored]

       dialog = ctk.CTkToplevel(self)
       dialog.overrideredirect(True)
       dialog.attributes("-topmost", True)
       dialog.configure(fg_color="#0a0a0a")
       dialog.grab_set()

       def _close_dialog():
           dialog.grab_release()
           dialog.destroy()
           try:
               self.focus_force()
           except Exception:
               pass

       dialog.bind("<Escape>", lambda e: _close_dialog())
       self._center_popup(dialog, 440, 380)

       card = ctk.CTkFrame(
           dialog,
           fg_color="#121212",
           border_width=1,
           border_color="#007AFF",
           corner_radius=10
       )
       card.pack(fill="both", expand=True)

       ctk.CTkLabel(
           card,
           text="ADD NETWORK",
           font=("Arial Black", 14),
           text_color="white"
       ).pack(anchor="w", padx=18, pady=(16, 0))

       ctk.CTkLabel(
           card,
           text="Select a network to add",
           font=("Courier New", 11),
           text_color="#666666"
       ).pack(pady=(2, 15))

       if not available:
           ctk.CTkLabel(
               card,
               text="All connected networks are already being monitored.",
               font=("Courier New", 11),
               text_color="#555555",
               wraplength=360
           ).pack(pady=30, padx=20)

           ctk.CTkButton(
               card,
               text="CLOSE",
               width=320,
               height=38,
               fg_color="#1E1E1E",
               border_color="#444444",
               border_width=1,
               text_color="#888888",
               hover_color="#262626",
               command=_close_dialog
           ).pack(pady=10)

           return

       selected = [None]
       net_buttons = []

       cards_frame = ctk.CTkFrame(
           card,
           fg_color="transparent"
       )
       cards_frame.pack(fill="x", padx=20)

       for i, net in enumerate(available):
           def select(n=net, idx=i):
               selected[0] = n

               for b in net_buttons:
                   b.configure(
                       fg_color="#1E1E1E",
                       border_color="#333333",
                       text_color="#888888"
                   )

               net_buttons[idx].configure(
                   fg_color="#0a1e3a",
                   border_color="#007AFF",
                   text_color="white"
               )

               add_btn.configure(state="normal")

           btn = ctk.CTkButton(
               cards_frame,
               text=f"  {net}.0/24",
               anchor="w",
               font=("Courier New", 13, "bold"),
               fg_color="#1E1E1E",
               border_color="#333333",
               border_width=2,
               hover_color="#262626",
               text_color="#888888",
               height=48,
               command=select
           )

           btn.pack(fill="x", pady=5)
           net_buttons.append(btn)

       def confirm():
           net = selected[0]

           if not net:
               return

           dialog.grab_release()
           dialog.destroy()
           try:
               self.focus_force()
           except Exception:
               pass

           # Reuse the lowest available NETWORK number. For example, if
           # NETWORK 2 was removed while NETWORK 1 and NETWORK 3 remain,
           # adding a new network creates NETWORK 2 instead of NETWORK 4.
           network_number = self._next_network_number()
           label = f"NETWORK {network_number}   -   {net}.0/24"

           engine = NetHealerEngine(
               self,
               base_ip=net,
               label=label
           )

           self._monitored.add(net)
           self._build_dashboard(engine, is_first=False)
           self._on_network_selected(label)

           if self._network_selector is not None:
               self._network_selector.set(label)
           self._update_remove_network_button()

       add_btn = ctk.CTkButton(
           card,
           text="ADD NETWORK",
           width=400,
           height=40,
           fg_color="#007AFF",
           hover_color="#0055CC",
           font=("Arial Black", 11),
           state="disabled",
           command=confirm
       )
       add_btn.pack(pady=(15, 10))

       ctk.CTkButton(
           card,
           text="CLOSE",
           width=400,
           height=38,
           fg_color="#1E1E1E",
           border_color="#444444",
           border_width=1,
           text_color="#AAAAAA",
           hover_color="#262626",
           font=("Arial Black", 11),
           command=_close_dialog
       ).pack(pady=(0, 18))


   # REMOVE NETWORK
   def _update_remove_network_button(self):
       """Keep Remove Network visible on the main screen. The last
       remaining network cannot be removed, but the button stays visible
       so the control is always easy to find."""
       button = getattr(self, "_remove_network_button", None)
       if button is None or not button.winfo_exists():
           return
       button.configure(state="normal", text_color="#FF3333")

   def _remove_network_confirm(self):
       """Ask for confirmation before removing the currently selected
       network from the main dashboard."""
       selected = next((p["engine"] for p in self._panels.values()
                        if p["engine"].label == self._current_network_label), None)
       if selected is not None and getattr(selected, "is_group", False):
           self._delete_group_confirm(selected)
           return
       network_panels = [p for p in self._panels.values()
                         if not getattr(p["engine"], "is_group", False)]
       if len(network_panels) <= 1:
           self._show_confirm_popup(
               title="CANNOT REMOVE NETWORK",
               message=(
                   "At least one network must remain monitored.\n\n"
                   "Add another network first if you want to remove the current one."
               ),
               on_confirm=lambda: None,
               confirm_text="OK",
               danger=False,
               single_button=True,
           )
           return

       label = self._current_network_label
       panel = None

       if label:
           for candidate in self._panels.values():
               if candidate["engine"].label == label:
                   panel = candidate
                   break

       if panel is None:
           panel = next(iter(network_panels), None)

       if panel is None:
           return

       engine = panel["engine"]
       network_label = engine.label

       self._show_confirm_popup(
           title="REMOVE NETWORK?",
           message=(
               f"Remove {network_label} from the dashboard?\n\n"
               "Monitoring for this network will stop and its dashboard "
               "will be removed from the main screen."
           ),
           on_confirm=lambda e=engine: self._remove_network(e),
           confirm_text="YES, REMOVE IT",
           cancel_text="CANCEL",
           danger=True,
       )

   def _remove_network(self, engine):
       """Remove one monitored network, clean up its dashboard state,
       update the selector, and switch to another remaining network."""
       panel = self._panels.get(id(engine))
       if panel is None:
           return

       # A network's groups live and die with it (their saved definitions
       # are kept, so they come back if the network is added again).
       for g in list(getattr(engine, "groups", {}).values()):
           self._destroy_group_panel(g, delete_saved=False)

       # Close any radar popup associated with this network. Full-page radar
       # and history are normally inaccessible because header controls are
       # hidden there, but cleaning these references makes removal safe.
       radar_popup = getattr(self, "_radar_popup", None)
       if radar_popup is not None and radar_popup.winfo_exists():
           radar_popup.destroy()

       radar_win = panel.get("radar_window")
       if radar_win is not None and radar_win.winfo_exists():
           radar_win.destroy()

       history_win = panel.get("history_window")
       if history_win is not None and history_win.winfo_exists():
           history_win.destroy()

       # Ask the engine to stop background monitoring when the engine class
       # provides one of the common lifecycle methods. This is deliberately
       # defensive so the UI remains compatible with engine.py versions
       # that expose a different shutdown method.
       stopped = False
       for method_name in ("stop", "shutdown", "close", "destroy"):
           method = getattr(engine, method_name, None)
           if callable(method):
               try:
                   method()
                   stopped = True
                   break
               except TypeError:
                   # Some implementations may require an argument; do not
                   # break removal just because that optional cleanup call
                   # is not compatible.
                   continue
               except Exception:
                   continue

       # Remove the dashboard widgets and all UI references.
       box = panel.get("content_box")
       if box is not None and box.winfo_exists():
           box.destroy()

       self._panels.pop(id(engine), None)
       self._monitored.discard(getattr(engine, "base_ip", None))

       # Fallback for engine implementations that store the base network
       # under a different attribute. The dashboard label always contains
       # the network CIDR, so this also keeps _monitored accurate.
       if not stopped:
           base_ip = getattr(engine, "base_ip", None)
           if base_ip is None:
               try:
                   base_ip = engine.label.split("-", 1)[1].strip().split(".", 3)[0] + "." + engine.label.split("-", 1)[1].strip().split(".", 3)[1] + "." + engine.label.split("-", 1)[1].strip().split(".", 3)[2]
               except Exception:
                   base_ip = None
           if base_ip:
               self._monitored.discard(base_ip)

       # Remove stale radar ring state for devices from this engine.
       try:
           with engine.lock:
               device_keys = {(d.mac or d.ip).strip().lower().replace("-", ":") for d in engine.devices}
           for key in device_keys:
               self._radar_ring_state.pop(key, None)
       except Exception:
           pass

       remaining = list(self._panels.values())
       if remaining:
           next_label = remaining[0]["engine"].label
           self._current_network_label = next_label
           self._on_network_selected(next_label)
           self._refresh_network_selector(select_label=next_label)
       else:
           self._current_network_label = None

       self._update_remove_network_button()


   # ─────────────────────────────────────────────
   # DEVICE GROUPS
   # A group is a hand-picked set of devices from ONE network with its own
   # dashboard (see group_engine.GroupEngine). The dashboard itself is the
   # SAME _build_dashboard/refresh_panel code the networks use — a group
   # just plugs in as another "engine" — so radar, history, troubleshoot,
   # bandwidth and diagnostics all work per group with no second copy.
   # ─────────────────────────────────────────────
   def _network_engines(self):
       """Only the real network engines (no groups), in the order added."""
       return [p["engine"] for p in self._panels.values()
               if not getattr(p["engine"], "is_group", False)]

   def _restore_groups_for(self, engine):
       """Rebuilds the saved groups of one network. Called once per
       network, after its network_key has settled (see
       NetHealerEngine._identity_event)."""
       try:
           records = group_store.load_groups(
               engine.network_key, getattr(engine, "base_ip", None))
       except Exception:
           records = []
       for rec in records:
           if not rec.get("id") or rec["id"] in engine.groups:
               continue
           try:
               self._create_group_panel(engine, rec)
           except Exception:
               continue

   def _create_group_panel(self, parent, record):
       group = GroupEngine(self, parent, record)
       parent.register_group(group)
       self._build_dashboard(group, is_first=False)
       self._refresh_network_selector()
       self.request_panel_refresh(group)
       return group

   def _destroy_group_panel(self, group, delete_saved=True):
       """Tears down one group's dashboard and stops it. Its devices go
       back to being monitored normally. The radar ring state is
       keyed by MAC and shared with the parent network's radar, so it is
       intentionally left alone here."""
       panel = self._panels.get(id(group))
       if panel is not None:
           for key in ("radar_window", "history_window", "troubleshoot_window"):
               win = panel.get(key)
               if win is not None and win.winfo_exists():
                   win.destroy()
           box = panel.get("content_box")
           if box is not None and box.winfo_exists():
               box.destroy()
           self._panels.pop(id(group), None)
       try:
           group.parent.unregister_group(group.group_id)
       except Exception:
           pass
       try:
           group.stop()
       except Exception:
           pass
       if delete_saved:
           group_store.delete_group(group.parent.network_key, group.group_id)

   def _delete_group(self, group):
       parent = group.parent
       label = group.label
       self._destroy_group_panel(group, delete_saved=True)
       if self._current_network_label == label:
           self._on_network_selected(parent.label)
       self._refresh_network_selector(select_label=self._current_network_label)

   def _delete_group_confirm(self, group):
       self._show_confirm_popup(
           title="DELETE GROUP?",
           message=(
               f"Delete {group.label}?\n\n"
               "Its devices stay on the network dashboard and keep being "
               "monitored. Only the group and its own dashboard, history "
               "view and bandwidth totals are removed."
           ),
           on_confirm=lambda g=group: self._delete_group(g),
           confirm_text="YES, DELETE IT",
           cancel_text="CANCEL",
           danger=True,
       )

   def _sync_group_header(self, panel, group):
       """Keeps a group dashboard's title in step with the group's real
       name (e.g. after a rename)."""
       if not panel:
           return
       title = panel.get("title_lbl")
       if title is not None and title.winfo_exists() and title.cget("text") != group.label:
           title.configure(text=group.label)

   def _open_manage_groups_popup(self):
       networks = self._network_engines()
       if not networks:
           return

       current = next((p["engine"] for p in self._panels.values()
                       if p["engine"].label == self._current_network_label), None)
       if current is not None and getattr(current, "is_group", False):
           current = current.parent
       if current is None:
           current = networks[0]

       state = {"net": current, "gid": None, "rows": {}, "macs": set(), "filter": ""}

       dialog = ctk.CTkToplevel(self)
       dialog.overrideredirect(True)
       dialog.attributes("-topmost", True)
       dialog.configure(fg_color="#0a0a0a")
       dialog.grab_set()

       def _close_dialog():
           try:
               dialog.grab_release()
           except Exception:
               pass
           dialog.destroy()
           try:
               self.focus_force()
           except Exception:
               pass

       dialog.bind("<Escape>", lambda e: _close_dialog())
       self._center_popup(dialog, 920, 660)

       card = ctk.CTkFrame(dialog, fg_color="#121212", border_width=1,
                           border_color="#007AFF", corner_radius=10)
       card.pack(fill="both", expand=True)

       ctk.CTkLabel(card, text="MANAGE GROUPS", font=("Arial Black", 14),
                    text_color="white").pack(anchor="w", padx=18, pady=(16, 0))
       ctk.CTkLabel(
           card,
           text="Group devices of one network by hand. Each group gets its own dashboard. Changes save instantly.",
           font=("Courier New", 11), text_color="#666666"
       ).pack(anchor="w", padx=18, pady=(2, 10))

       # ---- network picker ------------------------------------------
       net_row = ctk.CTkFrame(card, fg_color="transparent")
       net_row.pack(fill="x", padx=18, pady=(0, 10))
       ctk.CTkLabel(net_row, text="NETWORK", font=("Courier New", 12, "bold"),
                    text_color="#AAAAAA").pack(side="left", padx=(0, 10))
       net_labels = [n.label for n in networks]
       net_menu = ctk.CTkOptionMenu(
           net_row, values=net_labels, width=320, height=30,
           fg_color="#1E1E1E", button_color="#262626", button_hover_color="#333333",
           dropdown_fg_color="#1A1A1A", dropdown_hover_color="#262626",
           text_color="#AAAAAA", dropdown_text_color="#AAAAAA",
           font=("Courier New", 11, "bold"), dropdown_font=("Courier New", 11, "bold"),
           command=lambda lbl: _on_network(lbl))
       net_menu.set(current.label)
       net_menu.pack(side="left")

       # ---- footer: message + CLOSE ----------------------------------
       # Packed with side="bottom" BEFORE the body so the CLOSE button
       # always keeps its own space and can never be clipped off the
       # bottom of the dialog when the body's contents are tall.
       ctk.CTkButton(
           card, text="CLOSE", width=140, height=34, fg_color="#1E1E1E",
           border_color="#444444", border_width=1, text_color="#888888",
           hover_color="#262626", command=_close_dialog
       ).pack(side="bottom", anchor="e", padx=18, pady=(4, 14))
       msg_lbl = ctk.CTkLabel(card, text="", font=("Courier New", 11),
                              text_color="#FF3333", anchor="w")
       msg_lbl.pack(side="bottom", fill="x", padx=18)

       # ---- body: groups (left) | devices (right) ---------------------
       body = ctk.CTkFrame(card, fg_color="transparent")
       body.pack(fill="both", expand=True, padx=18, pady=(0, 6))
       body.grid_columnconfigure(0, weight=0)
       body.grid_columnconfigure(1, weight=1)
       body.grid_rowconfigure(0, weight=1)

       left = ctk.CTkFrame(body, fg_color="#1A1A1A", border_width=1,
                           border_color="#333333", corner_radius=8, width=290)
       left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
       left.grid_propagate(False)
       ctk.CTkLabel(left, text="GROUPS", font=("Arial Black", 11),
                    text_color="#666666").pack(anchor="w", padx=12, pady=(10, 4))
       group_list = ctk.CTkScrollableFrame(left, fg_color="#1A1A1A", height=260)
       group_list.pack(fill="both", expand=True, padx=6)

       name_entry = ctk.CTkEntry(
           left, placeholder_text="Group name...", height=32,
           fg_color="#121212", border_color="#333333", text_color="white",
           font=("Courier New", 12))
       name_entry.pack(fill="x", padx=12, pady=(8, 6))
       btn_row = ctk.CTkFrame(left, fg_color="transparent")
       btn_row.pack(fill="x", padx=12, pady=(0, 12))
       for c in range(3):
           btn_row.grid_columnconfigure(c, weight=1, uniform="grpbtn")

       right = ctk.CTkFrame(body, fg_color="#1A1A1A", border_width=1,
                            border_color="#333333", corner_radius=8)
       right.grid(row=0, column=1, sticky="nsew")
       dev_title = ctk.CTkLabel(right, text="DEVICES", font=("Arial Black", 11),
                                text_color="#666666")
       dev_title.pack(anchor="w", padx=12, pady=(10, 4))
       # (No textvariable on purpose: customtkinter hides the placeholder
       # text whenever one is attached.)
       filter_entry = ctk.CTkEntry(
           right, placeholder_text="Filter by IP or name...",
           height=30, fg_color="#121212", border_color="#333333",
           text_color="white", font=("Courier New", 12))
       filter_entry.pack(fill="x", padx=12, pady=(0, 6))
       dev_list = ctk.CTkScrollableFrame(right, fg_color="#1A1A1A")
       dev_list.pack(fill="both", expand=True, padx=6, pady=(0, 8))
       empty_lbl = ctk.CTkLabel(
           dev_list, text="No free devices.\nAll devices are already\nin other groups.",
           font=("Courier New", 11), text_color="#555555", justify="left")


       # ---- helpers ------------------------------------------------------
       def _say(text, ok=False):
           msg_lbl.configure(text=text, text_color="#00CC66" if ok else "#FF3333")

       def _net_groups():
           return sorted(state["net"].groups.values(), key=lambda g: g.name.lower())

       def _selected_group():
           return state["net"].groups.get(state["gid"])

       def _ip_key(dev):
           try:
               return tuple(int(x) for x in dev.ip.split("."))
           except Exception:
               return (999, 999, 999, 999)

       def _refresh_group_list():
           for w in group_list.winfo_children():
               w.destroy()
           groups = _net_groups()
           if not groups:
               ctk.CTkLabel(group_list, text="No groups yet.\nType a name below\nand press CREATE.",
                            font=("Courier New", 11), text_color="#555555",
                            justify="left").pack(anchor="w", padx=8, pady=10)
           for g in groups:
               selected = (g.group_id == state["gid"])
               ctk.CTkButton(
                   group_list, text=f"{g.name}  ({len(g.members())})",
                   anchor="w", height=32,
                   fg_color="#007AFF" if selected else "#222222",
                   hover_color="#0055CC" if selected else "#2C2C2C",
                   text_color="white", font=("Courier New", 12, "bold"),
                   command=lambda gid=g.group_id: _select(gid)
               ).pack(fill="x", pady=2)
           g = _selected_group()
           dev_title.configure(
               text=f"DEVICES  —  tick to put in: {g.name}" if g else
               "DEVICES  —  select or create a group first")

       def _apply_filter():
           for r in state["rows"].values():
               r["frame"].pack_forget()
           empty_lbl.pack_forget()
           ft = filter_entry.get().strip().lower()
           order = sorted(state["rows"].values(), key=lambda r: r["sort"])
           shown = 0
           for r in order:
               # A device already assigned to ANOTHER group is hidden, so
               # each device can only be picked from where it is free.
               if r.get("hidden"):
                   continue
               if not ft or ft in r["ip"].lower() or ft in r["name"].lower():
                   r["frame"].pack(fill="x", pady=1)
                   shown += 1
           if not shown and state["rows"] and not ft:
               empty_lbl.pack(anchor="w", padx=8, pady=10)

       def _build_rows():
           for r in state["rows"].values():
               r["frame"].destroy()
           state["rows"] = {}
           net = state["net"]
           with net.lock:
               devs = list(net.devices)
           for d in devs:
               mac = group_store.normalize_mac(d.mac)
               if not mac or mac in state["rows"]:
                   continue
               var = ctk.BooleanVar(value=False)
               fr = ctk.CTkFrame(dev_list, fg_color="transparent")
               cb = ctk.CTkCheckBox(
                   fr, text=f"{d.ip}   {d.name}", variable=var, width=420,
                   fg_color="#007AFF", hover_color="#0055CC", border_color="#444444",
                   font=("Courier New", 12), text_color="#DDDDDD",
                   command=lambda m=mac, v=var: _on_toggle(m, v))
               cb.pack(side="left", padx=6, pady=3)
               state["rows"][mac] = {
                   "frame": fr, "var": var, "cb": cb, "hidden": False,
                   "ip": d.ip, "name": d.name, "sort": _ip_key(d),
               }
           state["macs"] = set(state["rows"])
           _apply_filter()

       def _sync_rows():
           net = state["net"]
           with net.lock:
               live = {group_store.normalize_mac(d.mac): d for d in net.devices if d.mac}
           if set(live) != state["macs"]:
               _build_rows()
           group = _selected_group()
           members = group.members() if group else set()
           visibility_changed = False
           for mac, r in state["rows"].items():
               d = live.get(mac)
               if d is not None and d.name != r["name"]:
                   r["name"] = d.name
                   r["cb"].configure(text=f"{r['ip']}   {d.name}")
               r["var"].set(mac in members)
               r["cb"].configure(state="normal" if group else "disabled")
               other = net._mac_group.get(mac)
               hide = other is not None and other is not group
               if hide != r["hidden"]:
                   r["hidden"] = hide
                   visibility_changed = True
           if visibility_changed:
               _apply_filter()

       def _select(gid):
           state["gid"] = gid
           _say("")
           _refresh_group_list()
           _sync_rows()

       def _on_network(label):
           for n in _network_list():
               if n.label == label:
                   state["net"] = n
                   break
           state["gid"] = None
           _say("")
           _build_rows()
           _refresh_group_list()
           _sync_rows()

       def _network_list():
           return self._network_engines()

       def _on_toggle(mac, var):
           net = state["net"]
           group = _selected_group()
           if group is None:
               var.set(False)
               return
           if var.get():
               # A device belongs to at most one group. Devices of other
               # groups are hidden from this list, so this loop is only a
               # safety net.
               for other in list(net.groups.values()):
                   if other is not group and mac in other.members():
                       other.set_members(other.members() - {mac})
                       other._persist()
               group.set_members(group.members() | {mac})
           else:
               group.set_members(group.members() - {mac})
           group._persist()
           self.request_panel_refresh(net)   # also refreshes every group panel
           _refresh_group_list()
           _sync_rows()

       def _validate_name(name, exclude=None):
           name = name.strip()
           if not name:
               return "Enter a group name first."
           if len(name) > group_store.MAX_NAME_LEN:
               return f"Group name can be at most {group_store.MAX_NAME_LEN} characters."
           for g in state["net"].groups.values():
               if g is not exclude and g.name.lower() == name.lower():
                   return "A group with that name already exists on this network."
           return None

       def _create():
           name = name_entry.get()
           err = _validate_name(name)
           if err:
               _say(err)
               return
           net = state["net"]
           record = {
               "id": group_store.new_group_id(), "name": name.strip(), "macs": [],
               "created": datetime.now().isoformat(timespec="seconds"),
               "history_cleared_at": None,
           }
           group_store.save_group(net.network_key, record)
           g = self._create_group_panel(net, record)
           name_entry.delete(0, "end")
           state["gid"] = g.group_id
           _say(f"Group '{g.name}' created. Tick the devices to add.", ok=True)
           _refresh_group_list()
           _sync_rows()

       def _rename():
           g = _selected_group()
           if g is None:
               _say("Select a group to rename first.")
               return
           name = name_entry.get()
           err = _validate_name(name, exclude=g)
           if err:
               _say(err)
               return
           old_label = g.label
           g.rename(name.strip())
           if self._current_network_label == old_label:
               self._current_network_label = g.label
           self._refresh_network_selector(select_label=self._current_network_label)
           name_entry.delete(0, "end")
           _say("Group renamed.", ok=True)
           _refresh_group_list()

       def _delete():
           g = _selected_group()
           if g is None:
               _say("Select a group to delete first.")
               return

           def _do():
               self._delete_group(g)
               state["gid"] = None
               _say("Group deleted.", ok=True)
               _refresh_group_list()
               _sync_rows()

           self._show_confirm_popup(
               title="DELETE GROUP?",
               message=(f"Delete group '{g.name}'?\n\nIts devices stay on the network "
                        "dashboard and keep being monitored."),
               on_confirm=_do, confirm_text="YES, DELETE IT", cancel_text="CANCEL",
               danger=True, parent=dialog)

       for col, (txt, cmd, color, hov) in enumerate((
               ("CREATE", _create, "#007AFF", "#0055CC"),
               ("RENAME", _rename, "#333333", "#444444"),
               ("DELETE", _delete, "#992222", "#CC2222"))):
           ctk.CTkButton(btn_row, text=txt, height=30, fg_color=color, hover_color=hov,
                         font=("Arial Black", 10), command=cmd
                         ).grid(row=0, column=col, sticky="ew", padx=2)

       filter_entry.bind("<KeyRelease>", lambda e: _apply_filter())

       def _poll():
           if not dialog.winfo_exists():
               return
           try:
               _refresh_group_list_if_changed()
               _sync_rows()
           except Exception:
               pass
           dialog.after(3000, _poll)

       def _refresh_group_list_if_changed():
           sig = tuple((g.group_id, g.name, len(g.members())) for g in _net_groups())
           if sig != state.get("_sig"):
               state["_sig"] = sig
               _refresh_group_list()

       _build_rows()
       _refresh_group_list()
       _sync_rows()
       dialog.after(3000, _poll)

   def _center_popup(self, win, w, h, parent=None):
       """Positions a borderless popup centered over `parent` (defaults to
       the main window). Passing the popup that triggered this dialog as
       `parent` keeps a confirmation feeling attached to the window the
       user was actually looking at, instead of jumping back to the
       center of the main dashboard behind it."""
       anchor = parent if parent is not None and parent.winfo_exists() else self
       anchor.update_idletasks()
       x = anchor.winfo_x() + (anchor.winfo_width() - w) // 2
       y = anchor.winfo_y() + (anchor.winfo_height() - h) // 2
       win.geometry(f"{w}x{h}+{max(x, 0)}+{max(y, 0)}")


   # CONFIRM POPUP — themed replacement for tk's native messagebox, so
   # destructive confirmations (clear history, etc.) look like part of the
   # app instead of a jarring light-mode OS dialog. Same borderless
   # CTkToplevel + centered-card pattern as _add_network_popup, just built
   # generically so any yes/no confirmation can reuse it.
   def _show_confirm_popup(self, title, message, on_confirm,
                            confirm_text="YES, CONTINUE", cancel_text="CANCEL",
                            danger=True, single_button=False, parent=None):
       accent = "#FF3333" if danger else "#007AFF"
       accent_hover = "#CC2222" if danger else "#0055CC"

       owner = parent if parent is not None and parent.winfo_exists() else self

       # If `owner` is itself an always-on-top window (e.g. the Bandwidth
       # popup), a second always-on-top dialog can still end up stacked
       # BEHIND it on some platforms, since nothing distinguishes one
       # "topmost" window from another. transient() would normally solve
       # this, but combined with the overrideredirect(True) borderless
       # style used here, transient() is known to hang/crash the window
       # manager on some platforms (macOS in particular). Instead,
       # temporarily drop `owner`'s own topmost flag for as long as this
       # dialog is open — with only one topmost window left, there's no
       # ambiguity about which one shows on top, and it's restored the
       # moment the dialog closes.
       owner_was_topmost = False
       if owner is not self:
           try:
               owner_was_topmost = bool(owner.attributes("-topmost"))
               if owner_was_topmost:
                   owner.attributes("-topmost", False)
           except Exception:
               owner_was_topmost = False

       def _restore_owner_topmost():
           if owner_was_topmost:
               try:
                   if owner.winfo_exists():
                       owner.attributes("-topmost", True)
               except Exception:
                   pass

       dialog = ctk.CTkToplevel(owner)
       dialog.overrideredirect(True)
       dialog.attributes("-topmost", True)
       dialog.configure(fg_color="#0a0a0a")
       self._center_popup(dialog, 420, 260, parent=parent)
       dialog.lift()
       dialog.grab_set()
       dialog.focus_force()

       card = ctk.CTkFrame(dialog, fg_color="#121212", border_width=2,
                            border_color=accent, corner_radius=10)
       card.pack(fill="both", expand=True)

       ctk.CTkLabel(
           card, text=title, font=("Arial Black", 14), text_color=accent
       ).pack(anchor="w", padx=20, pady=(20, 6))

       ctk.CTkLabel(
           card, text=message, font=("Courier New", 12), text_color="#999999",
           wraplength=370, justify="left", anchor="w"
       ).pack(anchor="w", padx=20, fill="x")

       btn_row = ctk.CTkFrame(card, fg_color="transparent")
       btn_row.pack(side="bottom", fill="x", padx=20, pady=(10, 20))

       def _reclaim_focus():
           # dialog.focus_force() above pulls OS-level keyboard focus onto
           # this overrideredirect (no window-manager) Toplevel. Destroying
           # it does NOT reliably hand that keyboard focus back to `owner`
           # on its own — on some platforms it's left pointing at nothing,
           # so any Entry in the app (e.g. History Log's IP ADDRESS search
           # box) can be clicked/highlighted but won't accept typed input
           # until some other window happens to take and release focus.
           # Forcing focus back onto owner right after destroy fixes that.
           try:
               if owner.winfo_exists():
                   owner.focus_force()
           except Exception:
               pass

       def _cancel():
           dialog.grab_release()
           dialog.destroy()
           _restore_owner_topmost()
           _reclaim_focus()

       def _confirm():
           dialog.grab_release()
           dialog.destroy()
           _restore_owner_topmost()
           _reclaim_focus()
           on_confirm()

       dialog.bind("<Escape>", lambda e: _cancel())

       if single_button:
           # Purely informational dialog (nothing to choose between) — one
           # centered acknowledgement button instead of a confirm/cancel
           # pair that implies a decision the person doesn't actually have
           # to make here.
           ctk.CTkButton(
               btn_row, text=confirm_text, width=190, height=36,
               fg_color=accent, hover_color=accent_hover, text_color="white",
               font=("Arial Black", 11), command=_confirm
           ).pack(side="top", anchor="center")
           return

       ctk.CTkButton(
           btn_row, text=cancel_text, width=150, height=36,
           fg_color="#1E1E1E", border_color="#444444", border_width=1,
           text_color="#AAAAAA", hover_color="#262626",
           font=("Arial Bold", 11), command=_cancel
       ).pack(side="left")

       ctk.CTkButton(
           btn_row, text=confirm_text, width=190, height=36,
           fg_color=accent, hover_color=accent_hover, text_color="white",
           font=("Arial Black", 11), command=_confirm
       ).pack(side="right")


   # BUILD DASHBOARD
   def _build_dashboard(self, engine, is_first=False):


       content_box = ctk.CTkFrame(
           self._scroll_inner,
           fg_color="#1A1A1A", border_color="#333333",
           border_width=2, corner_radius=15
       )
       if is_first:
           content_box.pack(fill="x", padx=0, pady=(0, 20))
           self._current_network_label = engine.label


       def _add_ranking_button(parent):
           """VIEW RANKING — same look as the + ADD NETWORK button, pinned
           to the right corner of the panel's title row."""
           ctk.CTkButton(
               parent, text="VIEW RANKING", width=140, height=32,
               fg_color="#1E1E1E", border_color="#007AFF", border_width=1,
               text_color="#007AFF", hover_color="#262626",
               command=self._open_usage_ranking_page
           ).pack(side="right")

       def _add_report_button(parent):
           """NETWORK REPORT — sits just left of VIEW RANKING (packed after
           it, since both pack to the right). Works for a network or a
           group: the report is built from whatever devices that engine
           holds."""
           ctk.CTkButton(
               parent, text="GROUP REPORT" if getattr(engine, "is_group", False) else "NETWORK REPORT",
               width=150, height=32,
               fg_color="#1E1E1E", border_color="#007AFF", border_width=1,
               text_color="#007AFF", hover_color="#262626",
               command=lambda e=engine: self._open_network_report(e)
           ).pack(side="right", padx=(0, 8))

       group_widgets = {}
       if getattr(engine, "is_group", False):
           group_head = ctk.CTkFrame(content_box, fg_color="transparent")
           group_head.pack(fill="x", padx=20, pady=(15, 0))
           title_lbl = ctk.CTkLabel(
               group_head, text=engine.label,
               font=("Arial Black", 12), text_color="#B266FF")
           title_lbl.pack(side="left")
           _add_ranking_button(group_head)
           _add_report_button(group_head)
           group_widgets = {
               "group_head": group_head, "title_lbl": title_lbl,
           }
       else:
           net_head = ctk.CTkFrame(content_box, fg_color="transparent")
           net_head.pack(fill="x", padx=20, pady=(15, 0))
           ctk.CTkLabel(
               net_head, text=engine.label,
               font=("Arial Black", 12), text_color="#007AFF"
           ).pack(side="left")
           _add_ranking_button(net_head)
           _add_report_button(net_head)


       # Topology + history + troubleshoot log — side by side in one row to
       # save vertical space, instead of each being a full-width row
       # stacked on top of the other.
       actions_row = ctk.CTkFrame(content_box, fg_color="transparent")
       actions_row.pack(fill="x", padx=20, pady=(10, 5))
       actions_row.grid_columnconfigure(0, weight=1, uniform="actions")
       actions_row.grid_columnconfigure(1, weight=1, uniform="actions")
       actions_row.grid_columnconfigure(2, weight=1, uniform="actions")

       # Topology — opens in its own window (see _open_radar_window)
       toggle_btn = ctk.CTkButton(
           actions_row, text="NETWORK RADAR",
           fg_color="#222222", border_width=1, border_color="#444444",
       )
       toggle_btn.configure(command=lambda e=engine: self._open_radar_window(e))
       toggle_btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))


       history_btn = ctk.CTkButton(
           actions_row, text="HISTORY LOG",
           fg_color="#222222", border_width=1, border_color="#444444",
       )
       history_btn.configure(command=lambda e=engine: self._open_history_window(e))
       history_btn.grid(row=0, column=1, sticky="ew", padx=(5, 5))


       # Troubleshoot log — now its own window too (see
       # _open_troubleshoot_window), matching Radar and History Log
       # instead of being an always-visible panel on the dashboard.
       troubleshoot_btn = ctk.CTkButton(
           actions_row, text="TROUBLESHOOT LOG",
           fg_color="#222222", border_width=1, border_color="#444444",
       )
       troubleshoot_btn.configure(command=lambda e=engine: self._open_troubleshoot_window(e))
       troubleshoot_btn.grid(row=0, column=2, sticky="ew", padx=(5, 0))


       # Hidden by default — refresh_panel shows this when the engine
       # detects most/all devices degrading at the same moment, which
       # points to an upstream/router issue rather than each device
       # having its own separate problem.
       network_wide_banner = ctk.CTkLabel(
           content_box, text="", font=("Courier New", 13, "bold"),
           text_color="#FF8800", anchor="w", justify="left", wraplength=900
       )


       # --- FULL WIDTH COLUMN ---
       left_col = ctk.CTkFrame(content_box, fg_color="transparent")
       left_col.pack(fill="both", expand=True, padx=10, pady=(5, 5))


       # Summary cards + gateway
       summary_frame = ctk.CTkFrame(left_col, fg_color="transparent")
       summary_frame.pack(fill="x", padx=10, pady=(5, 2))


       # Clicking ONLINE/UNSTABLE/IDLE/OFFLINE filters the dashboard table
       # below down to just that status — mirrors how the radar's filter
       # chips narrow what's drawn on the radar, but applied to the table
       # instead. `status=None` (used for CONNECTED) keeps that card
       # inert; clicking the currently-active card again turns the
       # filter back off. `dashboard_filter_cards` is filled in below so
       # _style_dashboard_filter_cards can highlight whichever is active.
       dashboard_filter_cards = {}

       def make_card(title, color, status=None):
           f = ctk.CTkFrame(summary_frame, fg_color="transparent", corner_radius=8)
           f.pack(side="left", padx=(0, 35))
           title_lbl = ctk.CTkLabel(f, text=title, font=("Arial Black", 10), text_color="#666666")
           title_lbl.pack(anchor="w", padx=8, pady=(4, 0))
           val = ctk.CTkLabel(f, text="0", font=("Courier New", 28, "bold"), text_color=color)
           val.pack(anchor="w", padx=8, pady=(0, 4))
           if status is not None:
               def _on_click(_event=None, s=status):
                   self._toggle_dashboard_filter(engine, s)
               for widget in (f, title_lbl, val):
                   widget.configure(cursor="hand2")
                   widget.bind("<Button-1>", _on_click)
               dashboard_filter_cards[status] = f
           return val


       total_lbl    = make_card("CONNECTED", "#007AFF")
       online_lbl   = make_card("ONLINE",    STATUS_COLORS["Online"], status="Online")
       unstable_lbl = make_card("UNSTABLE",  STATUS_COLORS["Unstable"], status="Unstable")
       idle_lbl     = make_card("IDLE",      STATUS_COLORS["Idle"], status="Idle")
       offline_lbl  = make_card("OFFLINE",   STATUS_COLORS["Offline"], status="Offline")


       gateway_lbl = ctk.CTkLabel(
           summary_frame, text=f"WIFI GATEWAY: {engine.gateway_ip}",
           font=("Courier New", 12, "bold"), text_color="#888888"
       )
       gateway_lbl.pack(side="left", padx=(20, 0), anchor="s", pady=(0, 6))


       # IP search — filters ONLY this network's own device list (built
       # from this engine's `current_devices`, never anyone else's), so
       # even when two separate networks share overlapping/duplicate IP
       # ranges (very common with default 192.168.0.x/1.x routers), typing
       # an IP here can never pull in or highlight a same-IP device that
       # actually lives on a different network's panel. Placed on the
       # right side of the summary row, in the empty space next to the
       # gateway label.
       search_var = ctk.StringVar(value="")
       search_entry = ctk.CTkEntry(
           summary_frame, textvariable=search_var,
           placeholder_text="Search by IP address...",
           width=220, height=30,
           fg_color="#1E1E1E", border_color="#444444", border_width=1,
           text_color="#DDDDDD", font=("Courier New", 12)
       )
       search_entry.pack(side="right", anchor="s", pady=(0, 6))

       # Packed AFTER the entry on purpose: with side="right", each new
       # widget lands just to the LEFT of whatever's already claimed the
       # right edge, so packing this label second is what puts it directly
       # to the left of the search box (not the other way around).
       search_label = ctk.CTkLabel(
           summary_frame, text="IP ADDRESS", font=("Arial Bold", 10),
           text_color="#666666"
       )
       search_label.pack(side="right", anchor="s", pady=(0, 10), padx=(0, 8))


       # Dashboard table
       ctk.CTkLabel(left_col, text="MAPPING DASHBOARD", font=("Arial Black", 11), text_color="#666666").pack(anchor="w", padx=10)


       cols_frame = ctk.CTkFrame(left_col, fg_color="transparent")
       cols_frame.pack(fill="x", padx=10, pady=(5, 5))
       # NOTE: no fill="x"/expand=True on these labels. expand=True splits
       # leftover space EQUALLY across widgets regardless of their `width=`,
       # which is what caused the header/row misalignment previously. Instead
       # we compute exact pixel widths ourselves (see _stretch_dashboard_columns)
       # and apply the SAME numbers to the header and every device row, so they
       # can grow to fill the panel without ever drifting apart.
       header_labels = []
       for text, width in DASHBOARD_COLUMNS:
           lbl = ctk.CTkLabel(cols_frame, text=text, font=("Arial Bold", 10), text_color="#444444", width=width, anchor="w")
           lbl.pack(side="left", padx=(0, DASHBOARD_COL_PADX))
           header_labels.append(lbl)
       ctk.CTkLabel(cols_frame, text="DIAGNOSE", font=("Arial Bold", 10), text_color="#444444", width=DASHBOARD_DIAGNOSE_WIDTH, anchor="w").pack(side="left", padx=(DASHBOARD_DIAGNOSE_GAP, DASHBOARD_COL_PADX))


       list_outer, list_inner, list_canvas, list_scrollbar = self._make_smart_scroll(left_col, height=480, bg="#1A1A1A")
       list_outer.pack(fill="x", padx=10, pady=(0, 10))

       # Shown instead of the (empty) table when the ONLINE/UNSTABLE/IDLE/
       # OFFLINE status filter and/or the IP search leave zero rows.
       empty_state_lbl = ctk.CTkLabel(
           left_col, text="", font=("Courier New", 13), text_color="#555555"
       )


       panel = {
           "engine": engine,
           "content_box": content_box,
           "network_wide_banner": network_wide_banner,
           "network_wide_banner_anchor": left_col,
           "radar_window": None,
           "history_window": None,
           "history_body": None,
           "history_canvas": None,
           "history_scrollbar": None,
           "history_search_var": None,
           "history_device_buttons": {},
           "history_selected_device": None,
           "_history_sig": None,
           "troubleshoot_window": None,
           "troubleshoot_log": None,
           "troubleshoot_search_var": None,
           "radar_canvas": None,
           "radar_toggle_btn": toggle_btn,
           "history_toggle_btn": history_btn,
           "troubleshoot_toggle_btn": troubleshoot_btn,
           "radar_filters": {"Online": True, "Unstable": True, "Idle": True, "Offline": True},
           "radar_filter_cards": {},
           "radar_total_lbl": None,
           "radar_online_lbl": None,
           "radar_unstable_lbl": None,
           "radar_idle_lbl": None,
           "radar_offline_lbl": None,
           # Dashboard-table status filter (separate from the radar's own
           # filters above) — None means "show every status". Set to one
           # of "Online"/"Unstable"/"Idle"/"Offline" by clicking that
           # status's summary card; clicking the same card again clears it.
           "dashboard_filter": None,
           "dashboard_filter_cards": dashboard_filter_cards,
           "empty_state_lbl": empty_state_lbl,
           "radar_spike_banner": None,
           "radar_spike_banner_anchor": None,
           "total_lbl": total_lbl,
           "online_lbl": online_lbl,
           "unstable_lbl": unstable_lbl,
           "idle_lbl": idle_lbl,
           "offline_lbl": offline_lbl,
           "gateway_lbl": gateway_lbl,
           "list_inner": list_inner,
           "list_canvas": list_canvas,
           "list_scrollbar": list_scrollbar,
           "cols_frame": cols_frame,
           "header_labels": header_labels,
           "col_widths": [w for _, w in DASHBOARD_COLUMNS],
           # mac -> {"row": frame, "labels": [CTkLabel,...], "button": CTkButton}
           # Lets refresh_panel update existing widgets in place instead of
           # destroying and recreating the whole device list every refresh.
           "row_widgets": {},
           "_row_order": [],
           "_refresh_pending": False,
           # IP search box state — one StringVar per panel/engine, so each
           # network's filter text lives in its own dict entry and is only
           # ever read against that same engine's device list in
           # refresh_panel. Two networks can be showing/searching the exact
           # same IP at the same time with zero chance of cross-talk.
           "search_var": search_var,
       }
       panel.update(group_widgets)
       self._panels[id(engine)] = panel
       engine._panel_ref = panel


       def _on_search_change(*_args, p=panel):
           self.refresh_panel(p["engine"])
       search_var.trace_add("write", _on_search_change)

       # Stretch the text columns to fill any leftover width whenever the
       # panel is resized, and once shortly after creation (the very first
       # <Configure> event can fire before the frame has its real width).
       # Dynamic stretch-to-fill used to resize these columns based on
       # each panel's measured width, but a panel only gets laid out by
       # Tk once it's actually visible — a freshly-added network's panel
       # is built while still hidden behind whichever network is
       # currently shown, so its very first measurement could land on a
       # different value than an already-visible network got, and the
       # two would never match up again afterward. Using the same fixed
       # base widths (DASHBOARD_COLUMNS) for every panel, always, removes
       # that mismatch entirely: every network's table looks identical
       # regardless of when it was created or shown.


       if is_first:
           self.engine = engine
           self.content_box = content_box
           self.summary_frame = summary_frame
           self.total_lbl = total_lbl
           self.online_lbl = online_lbl
           self.unstable_lbl = unstable_lbl
           self.idle_lbl = idle_lbl
           self.offline_lbl = offline_lbl
           self.gateway_lbl = gateway_lbl
           self.list_inner = list_inner

       self._refresh_network_selector(select_label=engine.label if is_first else None)

   def _next_network_number(self):
       """Return the lowest unused NETWORK number.

       Network labels are intentionally based on the networks that are
       currently being monitored rather than on a permanent incrementing
       counter. This keeps the labels compact and sequential when a network
       is removed and later added again.
       """
       used_numbers = set()

       for panel in self._panels.values():
           engine = panel.get("engine")
           if engine is None:
               continue

           label = getattr(engine, "label", "")
           if not label.startswith("NETWORK "):
               continue

           # Expected format: NETWORK <number>   -   <network>.0/24
           number_part = label[len("NETWORK "):].split("-", 1)[0].strip()
           if number_part.isdigit():
               used_numbers.add(int(number_part))

       number = 1
       while number in used_numbers:
           number += 1

       return number


   def _refresh_network_selector(self, select_label=None):
       """Keeps the CHOOSE NETWORK dropdown's options in sync with every
       network that's actually been added, in the order they were added."""
       if self._network_selector is None:
           return
       labels = [p["engine"].label for p in self._panels.values()]
       if not labels:
           return
       self._network_selector.configure(values=labels)
       if select_label and select_label in labels:
           self._network_selector.set(select_label)
       elif self._current_network_label in labels:
           self._network_selector.set(self._current_network_label)
       else:
           self._network_selector.set(labels[0])

   def _on_network_selected(self, label):
       """Only the chosen network's panel is shown — every other network
       keeps monitoring/updating in the background, it's just hidden,
       so switching back to it shows current data immediately instead of
       needing to re-scan."""
       for panel in self._panels.values():
           box = panel.get("content_box")
           if box is None:
               continue
           if panel["engine"].label == label:
               box.pack(fill="x", padx=0, pady=(0, 20))
           else:
               box.pack_forget()
       self._current_network_label = label
       remove_btn = getattr(self, "_remove_network_button", None)
       if remove_btn is not None and remove_btn.winfo_exists():
           sel = next((p["engine"] for p in self._panels.values()
                       if p["engine"].label == label), None)
           remove_btn.configure(
               text="- DELETE GROUP" if getattr(sel, "is_group", False) else "- REMOVE NETWORK")


   # ─────────────────────────────────────────────
   # NETWORK RADAR
   # ─────────────────────────────────────────────
   def _radar_geometry(self, canvas):
       canvas.update_idletasks()
       width = canvas.winfo_width()
       height = canvas.winfo_height()
       if width < 50: width = 700
       if height < 50: height = 700
       cx, cy = width / 2, height / 2
       # Keep a safe margin on every side so the full radar remains visible
       # inside the black panel instead of being clipped at the bottom.
       # Widened from 80 -> 130 to leave enough room for the dedicated
       # INACCESSIBLE/OUT-OF-RANGE band (radius+95, see _draw_radar) plus
       # an offline device's blip and ".xxx" IP label sitting inside it —
       # with the old 80px margin, offline devices (radius+45) landed
       # INSIDE the Idle zone ring (radius+46) instead of past it.
       radius = min(width, height) / 2 - 130
       return width, height, cx, cy, radius


   def _radar_device_position(self, dev, cx, cy, radius):
       """Every device gets a stable angle derived from its MAC/IP so it
       always shows up in the same spot on the radar between redraws —
       like a fixed location — instead of jumping around each refresh.


       Distance from center reflects latency using the same real-world
       bands used to judge "how far/weak is this link": under ~15ms sits
       at the first ring, 15-40ms the second, 40-100ms the third, 100ms+
       the outer edge, and offline devices sit further out still, in the
       inaccessible / out-of-range band.


       Two layers keep a stationary device from visibly moving:
       1. Hysteresis — each boundary needs to be cleared by a real margin,
          not just nudged across, before a ring change is even considered.
       2. Debounce — a ring change also has to show up on 2 consecutive
          refreshes before it's actually applied. This is the fix for a
          single missed ping (very common, briefly reports "Offline")
          instantly snapping the blip to the outer ring and back — that
          used to bypass hysteresis completely. Now a transient blip like
          that never gets applied at all, only a sustained change does."""
       # Normalized so the same physical device always hashes to the same
       # angle — different discovery paths in the engine (ARP scan vs DHCP
       # sniffing) can report the same MAC with different casing or
       # separators (AA:BB:.. vs aa-bb-..), which would otherwise hash to
       # a completely different angle and make the device appear to move.
       key = (dev.mac or dev.ip).strip().lower().replace("-", ":")
       angle_deg = (zlib.crc32(key.encode()) % 360)
       angle = math.radians(angle_deg)


       # Offline devices have no live latency reading to rank against the
       # ring thresholds, and there's nothing to debounce/hysteresis for a
       # device that's simply gone — so they skip the ring system entirely
       # and sit at a fixed spot out in the dedicated INACCESSIBLE / OUT OF
       # RANGE band drawn in _draw_radar (radius+46 to radius+95) — clearly
       # past the Idle ring (radius+46), not overlapping/inside it like
       # before. Same stable angle as always, so a device that drops
       # offline reappears in the same place if/when it comes back.
       if dev.status == "Offline":
           r = radius + 70
           x = cx + r * math.cos(angle)
           y = cy + r * math.sin(angle)
           return x, y, angle_deg


       # Idle devices get their own dedicated ring — a fixed radius just
       # past the outer latency ring, distinct from both the latency-band
       # rings (they're not being judged on latency right now, there's no
       # reading to judge) and the Offline band further out still (ARP
       # confirms they're likely still connected, just not confirmed).
       if dev.status == "Idle":
           r = radius + 20
           x = cx + r * math.cos(angle)
           y = cy + r * math.sin(angle)
           return x, y, angle_deg


       try:
           lat_ms = float(str(dev.latency).replace("ms", "").strip())
       except (ValueError, TypeError):
           lat_ms = None
       if lat_ms is None:
           lat_ms = 9999  # treated as "far beyond the outer threshold", same pipeline as any other reading


       thresholds = [15, 40, 100]
       margins    = [4, 10, 25]


       state = self._radar_ring_state.get(key)
       if state is None:
           ring = 0
           for i, t in enumerate(thresholds):
               if lat_ms > t:
                   ring = i + 1
           self._radar_ring_state[key] = {"ring": ring, "pending": None, "count": 0}
       else:
           committed = state["ring"]
           target = committed
           while target < 3 and lat_ms > thresholds[target] + margins[target]:
               target += 1
           while target > 0 and lat_ms < thresholds[target - 1] - margins[target - 1]:
               target -= 1


           if target == committed:
               state["pending"] = None
               state["count"] = 0
           elif state["pending"] == target:
               state["count"] += 1
               if state["count"] >= 2:
                   state["ring"] = target
                   state["pending"] = None
                   state["count"] = 0
           else:
               state["pending"] = target
               state["count"] = 1
           ring = state["ring"]


       dist_ratio = [0.15, 0.40, 0.65, 0.90][ring]
       r = radius * dist_ratio
       x = cx + r * math.cos(angle)
       y = cy + r * math.sin(angle)
       return x, y, angle_deg


   def _draw_radar(self, canvas, engine):
       canvas._radar_blips = []  # (x, y, device) hitboxes for right-click lookups
       width, height, cx, cy, radius = self._radar_geometry(canvas)

       # The background (zones, range rings, crosshair, center dot, legend)
       # never changes between refreshes — it's ~30 canvas items that don't
       # depend on any device data at all. Doing canvas.delete("all") and
       # redrawing every single one of them on every ~2s refresh (and on
       # every resize tick) meant the whole canvas went blank for a moment
       # and repainted from scratch each time — that blank-then-repaint is
       # exactly what reads as screen "flicker", and it got more noticeable
       # the more devices/blips there were to redraw on top of it. It's now
       # drawn once per canvas size and left alone; only the per-device
       # blips below (the part that actually changes cycle to cycle) get
       # cleared and redrawn each time.
       cached_size = getattr(canvas, "_radar_static_size", None)
       if cached_size != (width, height):
           canvas.delete("static")
           self._draw_radar_static(canvas, width, height, cx, cy, radius)
           canvas._radar_static_size = (width, height)
       canvas.delete("blips")

       panel = self._panels.get(id(engine), {})
       filters = panel.get("radar_filters", {"Online": True, "Unstable": True, "Idle": True, "Offline": True})


       spike_banner = panel.get("radar_spike_banner")
       spike_anchor = panel.get("radar_spike_banner_anchor")
       if spike_banner is not None and spike_banner.winfo_exists():
           if getattr(engine, "network_wide_issue", False):
               since = getattr(engine, "network_wide_since", None)
               since_txt = f" (since {since})" if since else ""
               spike_banner.configure(
                   text=f"NETWORK-WIDE LATENCY SPIKE{since_txt} — positions below may be "
                        f"temporarily skewed by an upstream/router issue, not the devices themselves."
               )
               if spike_anchor is not None and spike_anchor.winfo_exists():
                   spike_banner.pack(anchor="w", padx=16, pady=(0, 4), before=spike_anchor)
               else:
                   spike_banner.pack(anchor="w", padx=16, pady=(0, 4))
           else:
               spike_banner.pack_forget()


       devices = [d for d in engine.devices if filters.get(d.status, True)]

       radar_search_var = panel.get("radar_search_var")
       radar_search_text = (
           radar_search_var.get().strip().lower()
           if radar_search_var is not None else ""
       )

       if radar_search_text:
           devices = [
               d for d in devices
               if radar_search_text in d.ip.lower()
           ]

       if not devices:
           if not engine.devices:
               msg = " -  SCANNING NETWORK  - "
           elif radar_search_text:
               msg = " -  NO DEVICES MATCH IP ADDRESS  - "
           elif not any(filters.values()):
               msg = " -  ALL FILTERS OFF  - "
           else:
               msg = " -  NO DEVICES MATCH FILTER  - "
           canvas.create_text(cx, cy + radius + 20, text=msg,
                               fill="#999999", font=("Courier New", 16), tags=("blips",))
       else:
           for dev in devices:
               x, y, _ = self._radar_device_position(dev, cx, cy, radius)
               canvas._radar_blips.append((x, y, dev))
               # Same palette as the dashboard (Offline sits out in the
               # inaccessible band, and is also the fallback color).
               blip_color = STATUS_COLORS.get(dev.status, STATUS_COLORS["Offline"])


               if dev.status == "Offline":
                   dash = (1, 3)
               elif dev.status == "Idle":
                   dash = (4, 3)
               else:
                   dash = (2, 5)
               canvas.create_line(cx, cy, x, y, fill=blip_color, width=1, dash=dash, stipple="gray50", tags=("blips",))
               canvas.create_oval(x-9, y-9, x+9, y+9, outline=blip_color, width=1, tags=("blips",))
               canvas.create_oval(x-4, y-4, x+4, y+4, fill=blip_color, outline="", tags=("blips",))

               # IP label under the blip (last octet only — the /24 prefix
               # is already shown in the page header, so repeating it per
               # blip would just be noise). Full name is still available
               # via the click popup, _show_radar_device_popup.
               last_part = dev.ip.split('.')[-1]
               canvas.create_text(x, y+20, text=f".{last_part}", fill="#BBBBBB", font=("Courier New", 12, "bold"), tags=("blips",))


   def _draw_radar_static(self, canvas, width, height, cx, cy, radius):
       """Draws everything on the radar that never changes cycle to cycle:
       zone shading, range rings, crosshair, center dot, and the legend.
       Called once per canvas size (see _draw_radar) instead of on every
       refresh, so these ~30 items stop being deleted and recreated every
       ~2s — that was the actual source of the visible screen flicker on
       this page, independent of how many devices were being monitored.
       Every item here is tagged "static" so a size change can clear
       exactly this layer without touching the live device blips.
       """
       # ── SIGNAL ZONE BACKDROP ────────────────────────────────
       # Purely cosmetic territory shading — communicates "how good does
       # a link at this range tend to be" at a glance. It mirrors the
       # same quarter-radius bands the (unchanged) positioning algorithm
       # already uses, it just paints them instead of leaving them blank.
       #   inaccessible  -> everywhere outside the outer ring (out of range)
       #   red zone      -> outer quarter   (100ms+ territory)
       #   orange zone   -> third quarter   (<100ms territory)
       #   green zone    -> inner half      (<40ms territory)
       # Base fill matches the app's standard page background ("#121212",
       # same as the full-page frame this canvas sits in and other
       # windows throughout the app) rather than a canvas-specific black,
       # so the empty margin beyond the INACCESSIBLE ring blends with the
       # rest of the system instead of looking like its own darker patch.
       tag = ("static",)
       canvas.create_rectangle(0, 0, width, height, fill="#121212", outline="", tags=tag)


       zone_red    = radius            # 4/4
       zone_orange = radius * 3 / 4    # 3/4
       zone_green  = radius * 2 / 4    # 2/4 (inner half)
       zone_idle   = radius + 46       # just past the outer latency ring — thicker band than the others
       zone_inaccessible = radius + 95 # outermost band — where Offline devices actually sit (radius+70),
                                        # clearly past the Idle ring instead of landing inside it


       # Inaccessible zone drawn first (outermost of all), then Idle,
       # then red/orange/green — each nests inside the one before it,
       # same layering trick used throughout. Dim brownish tint of the
       # same "#4A3232" used for both this ring's outline and its legend
       # swatch below.
       canvas.create_oval(cx-zone_inaccessible, cy-zone_inaccessible, cx+zone_inaccessible, cy+zone_inaccessible,
                           fill="#2a1c1c", outline="#4A3232", width=2, stipple="gray25", tags=tag)
       canvas.create_oval(cx-zone_idle, cy-zone_idle, cx+zone_idle, cy+zone_idle,
                           fill="#0c1c2a", outline="#66AAFF", width=2, stipple="gray25", tags=tag)
       canvas.create_oval(cx-zone_red, cy-zone_red, cx+zone_red, cy+zone_red,
                           fill="#2a0e0e", outline="#FF3333", width=1, stipple="gray25", tags=tag)
       canvas.create_oval(cx-zone_orange, cy-zone_orange, cx+zone_orange, cy+zone_orange,
                           fill="#2a1c08", outline="#FF8800", width=1, stipple="gray25", tags=tag)
       canvas.create_oval(cx-zone_green, cy-zone_green, cx+zone_green, cy+zone_green,
                           fill="#0c2414", outline="#00CC66", width=1, stipple="gray25", tags=tag)


       # Range rings (quarter markers) on top of the zone shading
       for i in range(1, 5):
           r = radius * i / 4
           canvas.create_oval(cx-r, cy-r, cx+r, cy+r, outline="#233323", width=1, tags=tag)


       # Idle ring boundary — the outline is already drawn above as part
       # of the filled zone. No in-radar text label here; "IDLE ZONE" is
       # named in the legend below instead, so all the meaning-of-a-band
       # text lives in one place.


       # Crosshair
       canvas.create_line(cx-radius, cy, cx+radius, cy, fill="#233323", width=1, tags=tag)
       canvas.create_line(cx, cy-radius, cx, cy+radius, fill="#233323", width=1, tags=tag)


       # No in-radar range labels (<15ms/<40ms/<100ms/100ms+) or
       # "INACCESSIBLE / OUT OF RANGE" callout — that text now lives on
       # the zone legend below instead, so the radar face itself stays
       # clean and only the legend explains what each band/color means.


       # Center = this machine / gateway — circle indicator, no text label.
       canvas.create_oval(cx-16, cy-16, cx+16, cy+16, fill="#0a1f0a", outline="#00CC66", width=2, tags=tag)


       # ── LEGEND ───────────────────────────────────────────────
       # Moved off the bottom strip (which overlapped the circle once the
       # latency ranges were folded into the labels, making them too wide
       # for one line under a full-width radar) and onto the left margin
       # instead — the empty space between the canvas edge and the circle
       # (cx - radius) that isn't used for anything else. Each entry is
       # still a horizontal row (swatch + text side by side), just
       # stacked vertically down that margin instead of side by side
       # along the bottom, so nothing overlaps the circle regardless of
       # label length.
       # Group 1: what the colored territory bands mean, with the
       # latency range each one covers.
       # Group 2: what a device blip's own color means — offline devices
       # show up out in the inaccessible band, dimmed gray.
       zone_legend = [
           ("#00CC66", "GREEN ZONE (<40ms)"),
           ("#FF8800", "ORANGE ZONE (<100ms)"),
           ("#FF3333", "RED ZONE (100ms+)"),
           ("#66AAFF", "IDLE ZONE (idle devices)"),
           ("#4A3232", "INACCESSIBLE / OUT OF RANGE"),
       ]
       device_legend = [
           (STATUS_COLORS["Online"], "ONLINE DEVICE"),
           (STATUS_COLORS["Unstable"], "UNSTABLE DEVICE"),
           (STATUS_COLORS["Idle"], "IDLE DEVICE"),
           (STATUS_COLORS["Offline"], "OFFLINE DEVICE"),
       ]

       legend_x = 14
       ly = 30
       row_step = 26
       canvas.create_text(legend_x, ly, text="ZONES", fill="#888888",
                           font=("Courier New", 11, "bold"), anchor="w", tags=tag)
       ly += row_step
       for color, label in zone_legend:
           canvas.create_rectangle(legend_x, ly-8, legend_x+17, ly+8, fill=color, outline="", tags=tag)
           canvas.create_text(legend_x+26, ly, text=label, fill="#DDDDDD",
                               font=("Courier New", 12, "bold"), anchor="w", tags=tag)
           ly += row_step

       ly += 14  # gap between the zone group and the device group
       canvas.create_text(legend_x, ly, text="STATUS", fill="#888888",
                           font=("Courier New", 11, "bold"), anchor="w", tags=tag)
       ly += row_step
       for color, label in device_legend:
           canvas.create_oval(legend_x, ly-7, legend_x+15, ly+8, fill=color, outline="", tags=tag)
           canvas.create_text(legend_x+24, ly, text=label, fill="#DDDDDD",
                               font=("Courier New", 12), anchor="w", tags=tag)
           ly += row_step


   def _open_radar_window(self, engine):
       """Opens the network radar as an in-app page — replacing the main
       dashboard until the person clicks back — instead of spawning a
       separate OS window."""
       panel = self._panels.get(id(engine))
       if not panel:
           return

       self._hide_radar_header_controls()

       def _cleanup():
           self._restore_radar_header_controls()
           panel["radar_window"] = None
           panel["radar_canvas"] = None
           panel["radar_filter_cards"] = {}
           panel["radar_total_lbl"] = None
           panel["radar_online_lbl"] = None
           panel["radar_unstable_lbl"] = None
           panel["radar_idle_lbl"] = None
           panel["radar_offline_lbl"] = None
           panel["radar_spike_banner"] = None
           panel["radar_spike_banner_anchor"] = None
           panel["radar_search_var"] = None

       def _build(page):
           header_row = ctk.CTkFrame(page, fg_color="transparent")
           header_row.pack(fill="x", padx=2, pady=(0, 4))

           ctk.CTkLabel(
               header_row, text=f"NETWORK RADAR — {engine.label}",
               font=("Arial Black", 13), text_color="#007AFF"
           ).pack(side="left")

           radar_search_var = ctk.StringVar(value="")

           radar_search_entry = ctk.CTkEntry(
               header_row,
               textvariable=radar_search_var,
               placeholder_text="Search by IP address...",
               width=220,
               height=30,
               fg_color="#1E1E1E",
               border_color="#444444",
               border_width=1,
               text_color="#DDDDDD",
               font=("Courier New", 12)
           )
           radar_search_entry.pack(side="right", pady=(0, 2))

           ctk.CTkLabel(
               header_row,
               text="IP ADDRESS",
               font=("Arial Bold", 10),
               text_color="#666666"
           ).pack(side="right", padx=(0, 8), pady=(0, 2))

           panel["radar_search_var"] = radar_search_var

           def _on_radar_search(*_):
               radar_canvas = panel.get("radar_canvas")
               radar_win = panel.get("radar_window")
               if radar_canvas is not None and radar_win is not None and radar_win.winfo_exists():
                   self._draw_radar(radar_canvas, engine)

           radar_search_var.trace_add("write", _on_radar_search)

           # Device counts + status filter cards — same visual style as
           # the dashboard's CONNECTED/ONLINE/UNSTABLE/IDLE/OFFLINE cards,
           # replacing the old button-style filter chips. Clicking a
           # status card filters the radar to only that status; clicking
           # the currently-solo-active card again shows every status
           # again (see _apply_solo_filter_toggle / _toggle_radar_filter).
           stats_row = ctk.CTkFrame(page, fg_color="transparent")
           stats_row.pack(fill="x", padx=2, pady=(0, 10))

           radar_filter_cards = {}

           def make_radar_card(title, color, status=None):
               f = ctk.CTkFrame(stats_row, fg_color="transparent", corner_radius=8)
               f.pack(side="left", padx=(0, 35))
               title_lbl = ctk.CTkLabel(f, text=title, font=("Arial Black", 10), text_color="#666666")
               title_lbl.pack(anchor="w", padx=8, pady=(4, 0))
               val = ctk.CTkLabel(f, text="0", font=("Courier New", 28, "bold"), text_color=color)
               val.pack(anchor="w", padx=8, pady=(0, 4))
               if status is not None:
                   def _on_click(_event=None, s=status):
                       self._toggle_radar_filter(engine, s)
                   for widget in (f, title_lbl, val):
                       widget.configure(cursor="hand2")
                       widget.bind("<Button-1>", _on_click)
                   radar_filter_cards[status] = f
               return val

           radar_total_lbl    = make_radar_card("CONNECTED", "#007AFF")
           radar_online_lbl   = make_radar_card("ONLINE",    STATUS_COLORS["Online"], status="Online")
           radar_unstable_lbl = make_radar_card("UNSTABLE",  STATUS_COLORS["Unstable"], status="Unstable")
           radar_idle_lbl     = make_radar_card("IDLE",      STATUS_COLORS["Idle"], status="Idle")
           radar_offline_lbl  = make_radar_card("OFFLINE",   STATUS_COLORS["Offline"], status="Offline")

           panel["radar_filter_cards"] = radar_filter_cards
           panel["radar_total_lbl"]    = radar_total_lbl
           panel["radar_online_lbl"]   = radar_online_lbl
           panel["radar_unstable_lbl"] = radar_unstable_lbl
           panel["radar_idle_lbl"]     = radar_idle_lbl
           panel["radar_offline_lbl"]  = radar_offline_lbl
           self._style_radar_filter_cards(panel)

           # Populate with current counts right away instead of waiting
           # for the next 2s tick of _refresh_all_stats.
           with engine.lock:
               _total    = len(engine.devices)
               _online   = len([d for d in engine.devices if d.status == "Online"])
               _unstable = len([d for d in engine.devices if d.status == "Unstable"])
               _idle     = len([d for d in engine.devices if d.status == "Idle"])
               _offline  = len([d for d in engine.devices if d.status == "Offline"])
           radar_total_lbl.configure(text=str(_total))
           radar_online_lbl.configure(text=str(_online))
           radar_unstable_lbl.configure(text=str(_unstable))
           radar_idle_lbl.configure(text=str(_idle))
           radar_offline_lbl.configure(text=str(_offline))


           radar_spike_banner = ctk.CTkLabel(
               page, text="", font=("Courier New", 12, "bold"),
               text_color="#FF8800", anchor="w", justify="left", wraplength=760
           )
           panel["radar_spike_banner"] = radar_spike_banner


           # Removed the old "Click a device to diagnose it" hint.

           radar_canvas = ctk.CTkCanvas(
               page,
               bg="#121212",
               highlightthickness=0
           )
           radar_canvas.pack(
               fill="both",
               expand=True,
               padx=0,
               pady=0
           )
           radar_canvas._radar_blips = []
           _on_radar_ctx = lambda ev, c=radar_canvas, e=engine: self._on_radar_right_click(ev, c, e)
           radar_canvas.bind("<Button-3>", _on_radar_ctx)          # Windows / Linux right-click
           radar_canvas.bind("<Button-2>", _on_radar_ctx)          # macOS trackpad secondary click
           radar_canvas.bind("<Control-Button-1>", _on_radar_ctx)  # macOS Ctrl+click fallback
           radar_canvas.bind("<Button-1>", _on_radar_ctx)          # plain left-click fallback (touch/remote)


           panel["radar_canvas"] = radar_canvas


           resize_job = [None]
           def _on_resize(event, c=radar_canvas, e=engine):
               if resize_job[0] is not None:
                   self.after_cancel(resize_job[0])
               resize_job[0] = self.after(120, lambda: self._draw_radar(c, e))
           radar_canvas.bind("<Configure>", _on_resize)


           self.after(80, lambda: self._draw_radar(radar_canvas, engine))


       page = self._show_full_page(_build, on_back=_cleanup)
       panel["radar_window"] = page


   def _apply_solo_filter_toggle(self, filters, status):
       """Shared single-select logic for the Radar and History Log filter
       chips: clicking a status shows ONLY that status (every other chip
       turns off); clicking the currently-sole-active chip again resets
       every chip back on, showing everything again. Mutates `filters`
       (a {status: bool} dict) in place."""
       is_solo_active = filters.get(status, False) and sum(1 for v in filters.values() if v) == 1
       if is_solo_active:
           for k in filters:
               filters[k] = True
       else:
           for k in filters:
               filters[k] = (k == status)


   def _toggle_radar_filter(self, engine, status):
       """Clicking a status card shows ONLY that status on the radar;
       clicking the same (sole-active) card again shows every status
       again — see _apply_solo_filter_toggle. Restyles the cards and
       redraws the canvas."""
       panel = self._panels.get(id(engine))
       if not panel:
           return
       filters = panel.get("radar_filters")
       if filters is None:
           return
       self._apply_solo_filter_toggle(filters, status)
       self._style_radar_filter_cards(panel)


       radar_win = panel.get("radar_window")
       radar_canvas = panel.get("radar_canvas")
       if radar_win is not None and radar_canvas is not None and radar_win.winfo_exists():
           self._draw_radar(radar_canvas, engine)


   def _toggle_dashboard_filter(self, engine, status):
       """Clicking ONLINE/UNSTABLE/IDLE/OFFLINE on the dashboard narrows
       the MAPPING DASHBOARD table to just that status — clicking the
       same one again (or the active card once more) turns it back off
       and shows every device again. Independent of the radar's own
       filter chips, which only affect the radar drawing."""
       panel = self._panels.get(id(engine))
       if not panel:
           return
       current = panel.get("dashboard_filter")
       panel["dashboard_filter"] = None if current == status else status
       self._style_dashboard_filter_cards(panel)
       self.refresh_panel(engine)


   def _style_dashboard_filter_cards(self, panel):
       """Highlights whichever status card is currently filtering the
       dashboard table (if any) so it's clear what's active."""
       cards = panel.get("dashboard_filter_cards") or {}
       active = panel.get("dashboard_filter")
       for status, frame in cards.items():
           if not frame.winfo_exists():
               continue
           if status == active:
               frame.configure(fg_color="#2A2A2A", border_width=1, border_color="#555555")
           else:
               frame.configure(fg_color="transparent", border_width=0)


   def _open_history_window(self, engine):
       """Opens the History Log as an in-app page laid out exactly like
       Troubleshoot: a DEVICES list on the left (searchable by IP/name/
       MAC), and on the right the flagged Unstable/Idle/Offline history
       for whichever single device is currently selected — never a
       timeline mixing multiple devices together. Same page pattern as
       _open_radar_window / _open_troubleshoot_window.

       While History Log is open, the network selector and + ADD NETWORK
       controls in the main header are hidden so the history page has the
       same clean full-page presentation as Network Radar. They are restored
       automatically when the user returns to the dashboard."""
       panel = self._panels.get(id(engine))
       if not panel:
           return

       # History is a full-page view, so hide the dashboard-only network
       # selector and Add Network controls while it is open.
       self._hide_radar_header_controls()

       selected_device = [None]

       def _cleanup():
           # Restore the dashboard header controls when leaving History Log.
           self._restore_radar_header_controls()
           panel["history_window"] = None
           panel["history_body"] = None
           panel["history_canvas"] = None
           panel["history_scrollbar"] = None
           panel["history_search_var"] = None
           panel["history_summary_label"] = None
           panel["history_device_buttons"] = {}
           panel["history_selected_device"] = None
           panel["history_time_filter"] = None
           selected_device[0] = None


       def _build(page):
           title_row = ctk.CTkFrame(page, fg_color="transparent")
           title_row.pack(fill="x", padx=2, pady=(0, 8))
           ctk.CTkLabel(
               title_row, text=f"HISTORY LOG — {engine.label}",
               font=("Arial Black", 14), text_color="#007AFF"
           ).pack(side="left", anchor="w")

           def _do_clear():
               engine.clear_history()
               refresh_device_buttons()
               panel["_history_sig"] = None
               body = panel.get("history_body")
               body_canvas = panel.get("history_canvas")
               body_scrollbar = panel.get("history_scrollbar")
               if body is not None:
                   self._draw_history_log(page, body, body_canvas, body_scrollbar, engine, panel)

           def _clear_history():
               self._show_confirm_popup(
                   title="CLEAR HISTORY?",
                   message=("This permanently deletes the saved history log for "
                             "this network, including entries saved from earlier "
                             "sessions. This can't be undone."),
                   on_confirm=_do_clear,
                   confirm_text="YES, CLEAR IT",
                   cancel_text="CANCEL",
                   danger=True,
               )

           ctk.CTkButton(
               title_row, text="CLEAR HISTORY", width=140, height=28,
               fg_color="#1E1E1E", border_color="#FF3333", border_width=1,
               text_color="#FF3333", hover_color="#2A1414",
               font=("Arial Bold", 11), command=_clear_history
           ).pack(side="right", anchor="n")


           # IP/name/MAC search bar — same component used on the Dashboard
           # and Network Radar (StringVar + CTkEntry, "IP ADDRESS" label to
           # its left), reused here to filter the DEVICES list on the left,
           # same as Troubleshoot's search does.
           search_row = ctk.CTkFrame(page, fg_color="transparent")
           search_row.pack(fill="x", padx=2, pady=(0, 8))

           history_search_var = ctk.StringVar(value="")
           history_search_entry = ctk.CTkEntry(
               search_row,
               textvariable=history_search_var,
               placeholder_text="Search by IP address...",
               width=220,
               height=30,
               fg_color="#1E1E1E",
               border_color="#444444",
               border_width=1,
               text_color="#DDDDDD",
               font=("Courier New", 12)
           )
           history_search_entry.pack(side="right", pady=(0, 2))

           ctk.CTkLabel(
               search_row,
               text="IP ADDRESS",
               font=("Arial Bold", 10),
               text_color="#666666"
           ).pack(side="right", padx=(0, 8), pady=(0, 2))

           panel["history_search_var"] = history_search_var

           # Time-range filter — narrows the selected device's history
           # down to entries from the last N minutes/hours. Selecting a
           # value stores it on the panel and forces a redraw; the actual
           # filtering happens in _draw_history_log so it stays in sync
           # with the signature-based skip-redraw logic already there.
           panel["history_time_filter"] = HISTORY_TIME_FILTERS[0]

           def _on_time_filter_selected(choice):
               panel["history_time_filter"] = choice
               panel["_history_sig"] = None  # force a redraw with the new filter
               body = panel.get("history_body")
               body_canvas = panel.get("history_canvas")
               body_scrollbar = panel.get("history_scrollbar")
               if body is not None:
                   self._draw_history_log(page, body, body_canvas, body_scrollbar, engine, panel)

           history_time_dropdown = _StyledDropdown(
               search_row, values=HISTORY_TIME_FILTERS, width=160, height=30,
               fg_color="#1E1E1E", text_color="#DDDDDD", border_color="#444444",
               hover_color="#262626", font=("Courier New", 11, "bold"),
               dropdown_fg_color="#1A1A1A", dropdown_hover_color="#262626",
               dropdown_text_color="#007AFF", dropdown_font=("Courier New", 12, "bold"),
               command=_on_time_filter_selected,
               # All 5 options shown at once, no scrollbar — sidesteps the
               # scrollbar/FocusOut interaction entirely for this dropdown.
               max_visible_rows=len(HISTORY_TIME_FILTERS)
           )
           history_time_dropdown.pack(side="right", padx=(0, 20), pady=(0, 2))

           ctk.CTkLabel(
               search_row,
               text="TIME RANGE",
               font=("Arial Bold", 10),
               text_color="#666666"
           ).pack(side="right", padx=(0, 8), pady=(0, 2))

           content = ctk.CTkFrame(page, fg_color="transparent")
           content.pack(fill="both", expand=True)

           device_frame = ctk.CTkFrame(
               content,
               fg_color="#141414",
               border_color="#252525",
               border_width=1,
               corner_radius=4,
               width=280
           )
           device_frame.pack(side="left", fill="y", padx=(0, 8))
           device_frame.pack_propagate(False)

           ctk.CTkLabel(
               device_frame,
               text="DEVICES",
               font=("Arial Black", 11),
               text_color="#777777"
           ).pack(anchor="w", padx=12, pady=(10, 8))

           device_scroll = ctk.CTkScrollableFrame(
               device_frame,
               fg_color="transparent"
           )
           device_scroll.pack(fill="both", expand=True, padx=6, pady=(0, 6))

           log_frame = ctk.CTkFrame(
               content,
               fg_color="#1A1A1A",
               border_color="#252525",
               border_width=1,
               corner_radius=4
           )
           log_frame.pack(side="left", fill="both", expand=True)

           selected_label = ctk.CTkLabel(
               log_frame,
               text="SELECT A DEVICE",
               font=("Arial Black", 13),
               text_color="#007AFF"
           )
           selected_label.pack(anchor="w", padx=12, pady=(10, 4))

           selected_info = ctk.CTkLabel(
               log_frame,
               text="Click a device on the left to view only its status history.",
               font=("Courier New", 11),
               text_color="#666666",
               anchor="w"
           )
           selected_info.pack(anchor="w", padx=12, pady=(0, 8))

           # History status-filter buttons removed. The History Log now
           # keeps the device search bar and shows the selected device's
           # complete status history without filtering buttons.

           body_outer, body, body_canvas, body_scrollbar = self._make_smart_scroll(log_frame, bg="#0d0d0d")
           body_outer.pack(fill="both", expand=True, padx=8, pady=(0, 6))

           # Compact status summary shown below the history timeline.
           history_summary = ctk.CTkFrame(
               log_frame, fg_color="#151515", border_color="#252525",
               border_width=1, corner_radius=5, height=54
           )
           history_summary.pack(fill="x", padx=8, pady=(0, 8))
           history_summary.pack_propagate(False)

           history_summary_title = ctk.CTkLabel(
               history_summary, text="SUMMARY",
               font=("Arial Black", 10), text_color="#777777"
           )
           history_summary_title.pack(side="left", padx=(12, 8))

           history_summary_values = ctk.CTkFrame(history_summary, fg_color="transparent")
           history_summary_values.pack(side="left", fill="x", expand=True, padx=(0, 12))

           history_summary_labels = {}
           summary_colors = {
               "TOTAL": "#AAAAAA",
               "ONLINE": STATUS_COLORS["Online"],
               "UNSTABLE": STATUS_COLORS["Unstable"],
               "IDLE": STATUS_COLORS["Idle"],
               "OFFLINE": STATUS_COLORS["Offline"],
           }
           for key in ("TOTAL", "ONLINE", "UNSTABLE", "IDLE", "OFFLINE"):
               lbl = ctk.CTkLabel(
                   history_summary_values,
                   text=f"{key}: 0",
                   font=("Courier New", 11, "bold"),
                   text_color=summary_colors[key],
                   anchor="w"
               )
               lbl.pack(side="left", padx=(0, 18))
               history_summary_labels[key] = lbl

           panel["history_summary_values"] = history_summary_values
           panel["history_summary_labels"] = history_summary_labels
           panel["history_body"] = body
           panel["history_canvas"] = body_canvas
           panel["history_scrollbar"] = body_scrollbar
           panel["history_device_buttons"] = {}
           panel["history_selected_device"] = None

           def show_device_history(device):
               """Select one device and render only its own status history."""
               selected_device[0] = device
               panel["history_selected_device"] = device
               panel["_history_sig"] = None  # force a redraw for the new device

               selected_label.configure(text=f"{device.name} — {device.ip}")
               selected_info.configure(text=f"MAC ADDRESS: {device.mac}")

               self._draw_history_log(page, body, body_canvas, body_scrollbar, engine, panel)

               for mac, button in panel["history_device_buttons"].items():
                   if button.winfo_exists():
                       is_selected = str(mac) == str(device.mac)
                       button.configure(
                           fg_color="#2A2A2A" if is_selected else "#1E1E1E",
                           border_color="#007AFF" if is_selected else "#444444",
                           text_color="#007AFF" if is_selected else "#AAAAAA"
                       )

           def refresh_device_buttons(*_):
               for widget in device_scroll.winfo_children():
                   widget.destroy()

               panel["history_device_buttons"] = {}

               query = history_search_var.get().strip().lower()
               devices = list(getattr(engine, "devices", []))

               if query:
                   devices = [
                       device for device in devices
                       if query in str(device.ip).lower()
                       or query in str(device.name).lower()
                       or query in str(device.mac).lower()
                   ]

               if not devices:
                   ctk.CTkLabel(
                       device_scroll,
                       text="NO DEVICES FOUND",
                       font=("Courier New", 11),
                       text_color="#555555"
                   ).pack(anchor="w", padx=8, pady=12)
                   return

               for device in devices:
                   # Do not capture a precomputed history list in the
                   # callback — it reads the correct device-specific
                   # records fresh at click time via show_device_history.
                   button = ctk.CTkButton(
                       device_scroll,
                       text=f"{device.name}\n{device.ip}",
                       height=52,
                       fg_color="#1E1E1E",
                       border_color="#444444",
                       border_width=1,
                       text_color="#AAAAAA",
                       hover_color="#262626",
                       font=("Courier New", 11, "bold"),
                       anchor="w",
                       command=lambda selected=device: show_device_history(selected)
                   )
                   button.pack(fill="x", padx=2, pady=4)
                   panel["history_device_buttons"][device.mac] = button

               # Restore the selected device's highlight after a search
               # refresh, but never copy its history to another device.
               if selected_device[0] is not None:
                   selected_mac = str(getattr(selected_device[0], "mac", ""))
                   for mac, button in panel["history_device_buttons"].items():
                       if str(mac) == selected_mac:
                           button.configure(
                               fg_color="#2A2A2A",
                               border_color="#007AFF",
                               text_color="#007AFF"
                           )

           history_search_var.trace_add("write", refresh_device_buttons)
           refresh_device_buttons()

           # No device selected yet — draw the placeholder state.
           self._draw_history_log(page, body, body_canvas, body_scrollbar, engine, panel)


       page = self._show_full_page(_build, on_back=_cleanup)
       panel["history_window"] = page


   def _draw_history_log(self, win, body, body_canvas, body_scrollbar, engine, panel=None):
       """Renders the status history for whichever single device is
       currently selected in the History Log's DEVICES list (see
       _open_history_window) — never more than one device's entries at
       once, same rule the Troubleshoot Log page follows."""
       if not win.winfo_exists():
           return

       # Time-range filter selected in the search row (see
       # _open_history_window) — "ALL TIME" (or nothing selected yet)
       # means no cutoff at all, same as before this filter existed.
       time_filter = panel.get("history_time_filter") if panel is not None else None
       minutes = HISTORY_TIME_FILTER_MINUTES.get(time_filter) if time_filter else None

       # This page only redraws when its signature (below) changes, so a
       # relative window like "LAST 15 MIN" needs something in that
       # signature that changes on its own as time passes — otherwise an
       # entry that has just aged out of the window would keep showing
       # until some unrelated change (a new entry, a filter switch)
       # happened to force a redraw. Rounding "now" down to the minute
       # gives that: this page is already re-checked every 2s by
       # _refresh_all_stats, so the window's edge gets re-evaluated at
       # worst a minute late, at the cost of at most one extra redraw a
       # minute — not on every single 2s poll like a live time display
       # would need. "ALL TIME" has no window to age out of, so it keeps
       # skipping redraws entirely, same as before this filter existed.
       time_bucket = datetime.now().strftime("%Y-%m-%d %H:%M") if minutes is not None else None
       filters_sig = (time_filter, time_bucket)
       selected = panel.get("history_selected_device") if panel is not None else None

       def _refresh_scroll():
           body.update_idletasks()
           body_canvas.configure(scrollregion=body_canvas.bbox("all"))
           if body.winfo_reqheight() > body_canvas.winfo_height():
               body_scrollbar.pack(side="right", fill="y")
           else:
               body_scrollbar.pack_forget()

       if selected is None:
           signature = ("__none__", filters_sig)
           if panel is not None and panel.get("_history_sig") == signature:
               return
           if panel is not None:
               panel["_history_sig"] = signature
           for widget in body.winfo_children():
               widget.destroy()
           ctk.CTkLabel(
               body, text="Select a device on the left to view its status history.",
               font=("Courier New", 13), text_color="#555555", justify="left"
           ).pack(anchor="w", padx=14, pady=14)
           summary_labels = panel.get("history_summary_labels", {}) if panel is not None else {}
           for key, label in summary_labels.items():
               if label.winfo_exists():
                   label.configure(text=f"{key}: 0")
           win.after(30, _refresh_scroll)
           return

       # Re-resolve the selection against the engine's live device list by
       # MAC (rather than trusting the possibly-stale object reference),
       # so a background rescan swapping the underlying NetworkDevice
       # object never leaves this page displaying a frozen copy.
       live = next((d for d in engine.devices if d.mac == selected.mac), selected)

       all_entries = list(reversed(getattr(live, "status_history", [])))

       # Apply the selected time-range cutoff, if any (minutes was
       # already resolved from time_filter above, alongside filters_sig).
       # Entries are stored newest-first (all_entries above is already
       # reversed), each with a "%Y-%m-%d %H:%M:%S" ts (see engine.py's
       # status_history writer), so parsing and comparing against now()
       # minus the chosen window keeps only entries from that recent
       # window. A ts that fails to parse (shouldn't happen, but corrupt/
       # old data is possible) is dropped from a filtered view rather
       # than crashing the page.
       if minutes is None:
           entries = all_entries
       else:
           cutoff = datetime.now() - timedelta(minutes=minutes)
           entries = []
           for entry in all_entries:
               try:
                   ts_dt = datetime.strptime(entry.get("ts", ""), "%Y-%m-%d %H:%M:%S")
               except (TypeError, ValueError):
                   continue
               if ts_dt >= cutoff:
                   entries.append(entry)

       # Skip the rebuild entirely unless this device's timeline or the
       # active filters actually changed since last draw — same
       # performance rule the old merged-timeline draw used, so offline
       # transitions on OTHER devices don't force a redraw here.
       signature = (
           str(live.mac), len(all_entries),
           all_entries[0]["ts"] if all_entries else None,
           filters_sig,
       )
       if panel is not None and panel.get("_history_sig") == signature:
           return
       if panel is not None:
           panel["_history_sig"] = signature

       for widget in body.winfo_children():
           widget.destroy()


       status_colors = dict(STATUS_COLORS)

       # Summary counts reflect whatever's actually on screen: the
       # selected device's complete history when no time filter is
       # active, or just the entries inside the chosen window once one
       # is — so TOTAL here always matches the number of rows shown below.
       status_counts = {"Online": 0, "Unstable": 0, "Idle": 0, "Offline": 0}
       for entry in entries:
           status = str(entry.get("status", "")).title()
           if status in status_counts:
               status_counts[status] += 1
       summary_labels = panel.get("history_summary_labels", {}) if panel is not None else {}
       summary_values = {
           "TOTAL": len(entries),
           "ONLINE": status_counts["Online"],
           "UNSTABLE": status_counts["Unstable"],
           "IDLE": status_counts["Idle"],
           "OFFLINE": status_counts["Offline"],
       }
       for key, value in summary_values.items():
           label = summary_labels.get(key)
           if label is not None and label.winfo_exists():
               label.configure(text=f"{key}: {value}")


       if not all_entries:
           ctk.CTkLabel(
               body,
               text=f"No flagged status changes yet for {live.name}, it has\nstayed Online since it was first seen.",
               font=("Courier New", 13), text_color="#555555", justify="left"
           ).pack(anchor="w", padx=14, pady=14)
       elif not entries:
           ctk.CTkLabel(
               body, text="No history entries match the active filters above.",
               font=("Courier New", 13), text_color="#555555", justify="left"
           ).pack(anchor="w", padx=14, pady=14)
       else:
           for entry in entries:
               color = status_colors.get(entry["status"], "#AAAAAA")
               row = ctk.CTkFrame(body, fg_color="#151515", corner_radius=6)
               row.pack(fill="x", padx=4, pady=3)
               ctk.CTkLabel(
                   row, text=f"{entry['ts']}    {entry['status'].upper()}",
                   font=("Courier New", 13, "bold"), text_color=color, anchor="w"
               ).pack(anchor="w", padx=10, pady=(8, 1))
               ctk.CTkLabel(
                   row,
                   text=(f"latency: {entry['latency']}   jitter: {entry['jitter']}   "
                         f"loss: {entry['packet_loss']}   speed: {entry['network_speed']}"),
                   font=("Courier New", 12), text_color="#777777", anchor="w"
               ).pack(anchor="w", padx=10, pady=(0, 8))


       win.after(30, _refresh_scroll)


   def _open_troubleshoot_window(self, engine):
       """Open the Troubleshoot page with strictly device-specific output.

       The selected device is used as the source of truth every time the
       output is opened.  The log is never stored in a button callback,
       preventing one device's output from appearing under another device.
       """

       panel = self._panels.get(id(engine))
       if not panel:
           return

       self._hide_radar_header_controls()

       selected_device = [None]

       def _cleanup():
           self._restore_radar_header_controls()
           panel["troubleshoot_window"] = None
           panel["troubleshoot_log"] = None
           panel["troubleshoot_summary_label"] = None
           panel["troubleshoot_search_var"] = None
           panel["troubleshoot_device_buttons"] = {}
           panel["troubleshoot_selected_device"] = None
           selected_device[0] = None

       def _snapshot_logs():
           """Read this network's automatic logs safely."""
           try:
               with engine.lock:
                   return list(getattr(engine, "auto_troubleshoot_logs", []))
           except Exception:
               return list(getattr(engine, "auto_troubleshoot_logs", []))

       def _extract_device_logs(device):
           """Return only records belonging to the requested device IP.

           A new device sequence begins only when a line explicitly names
           another device.  Progress/fix lines are assigned to the most
           recently named device.  The result is rebuilt on every click,
           so callbacks cannot retain stale output from another device.
           """
           if device is None:
               return []

           target_ip = str(getattr(device, "ip", "")).strip()
           if not target_ip:
               return []

           lines_for_device = []
           active_ip = None

           marker_pattern = re.compile(
               r"(?:OFFLINE DEVICE DETECTED|AUTO-TROUBLESHOOT STARTED FOR|"
               r"RECOVERED|UNRESOLVED):?.*?\(([^()]+)\)",
               re.IGNORECASE,
           )

           for raw in _snapshot_logs():
               line = str(raw).strip()
               if not line:
                   continue

               # Remove the visual prompt only for matching; preserve the
               # original text when displaying the record.
               clean_line = line[2:].lstrip() if line.startswith("> ") else line

               match = marker_pattern.search(clean_line)
               if match:
                   active_ip = match.group(1).strip()

                   if active_ip == target_ip:
                       lines_for_device.append(clean_line)
                   continue

               # A repair/progress line belongs to the currently active
               # device sequence, never to every device.
               if active_ip == target_ip:
                   lines_for_device.append(clean_line)

           return lines_for_device

       def _build(page):
           title_row = ctk.CTkFrame(page, fg_color="transparent")
           title_row.pack(fill="x", padx=2, pady=(0, 8))

           ctk.CTkLabel(
               title_row,
               text=f"TROUBLESHOOT LOG — {engine.label}",
               font=("Arial Black", 14),
               text_color="#007AFF"
           ).pack(side="left", anchor="w")

           search_row = ctk.CTkFrame(page, fg_color="transparent")
           search_row.pack(fill="x", padx=2, pady=(0, 8))

           troubleshoot_search_var = ctk.StringVar(value="")
           troubleshoot_search_entry = ctk.CTkEntry(
               search_row,
               textvariable=troubleshoot_search_var,
               placeholder_text="Search by IP address...",
               width=220,
               height=30,
               fg_color="#1E1E1E",
               border_color="#444444",
               border_width=1,
               text_color="#DDDDDD",
               font=("Courier New", 12)
           )
           troubleshoot_search_entry.pack(side="right", pady=(0, 2))

           ctk.CTkLabel(
               search_row,
               text="IP ADDRESS",
               font=("Arial Bold", 10),
               text_color="#666666"
           ).pack(side="right", padx=(0, 8), pady=(0, 2))

           panel["troubleshoot_search_var"] = troubleshoot_search_var

           content = ctk.CTkFrame(page, fg_color="transparent")
           content.pack(fill="both", expand=True)

           device_frame = ctk.CTkFrame(
               content,
               fg_color="#141414",
               border_color="#252525",
               border_width=1,
               corner_radius=4,
               width=280
           )
           device_frame.pack(side="left", fill="y", padx=(0, 8))
           device_frame.pack_propagate(False)

           ctk.CTkLabel(
               device_frame,
               text="DEVICES",
               font=("Arial Black", 11),
               text_color="#777777"
           ).pack(anchor="w", padx=12, pady=(10, 8))

           device_scroll = ctk.CTkScrollableFrame(
               device_frame,
               fg_color="transparent"
           )
           device_scroll.pack(fill="both", expand=True, padx=6, pady=(0, 6))

           log_frame = ctk.CTkFrame(
               content,
               fg_color="#1A1A1A",
               border_color="#252525",
               border_width=1,
               corner_radius=4
           )
           log_frame.pack(side="left", fill="both", expand=True)

           selected_label = ctk.CTkLabel(
               log_frame,
               text="SELECT A DEVICE",
               font=("Arial Black", 13),
               text_color="#007AFF"
           )
           selected_label.pack(anchor="w", padx=12, pady=(10, 4))

           selected_info = ctk.CTkLabel(
               log_frame,
               text="Click a device on the left to view only its troubleshooting log.",
               font=("Courier New", 11),
               text_color="#666666",
               anchor="w"
           )
           selected_info.pack(anchor="w", padx=12, pady=(0, 8))

           # Packed with side="bottom" and BEFORE the log textbox below,
           # so it claims its own row at the bottom of log_frame first;
           # the log (packed after, with fill="both"/expand=True) then
           # only fills whatever vertical space is left above it, instead
           # of swallowing the whole frame and leaving no room for this.
           summary_frame = ctk.CTkFrame(
               log_frame,
               fg_color="#141414",
               border_color="#252525",
               border_width=1,
               corner_radius=4
           )
           summary_frame.pack(side="bottom", fill="x", padx=8, pady=(0, 8))

           ctk.CTkLabel(
               summary_frame,
               text="TROUBLESHOOT SUMMARY",
               font=("Arial Black", 10),
               text_color="#777777"
           ).pack(anchor="w", padx=10, pady=(8, 2))

           troubleshoot_summary_label = ctk.CTkLabel(
               summary_frame,
               text=_format_troubleshoot_summary(None, []),
               font=("Courier New", 12),
               text_color="#AAAAAA",
               anchor="w",
               justify="left",
               wraplength=0
           )
           troubleshoot_summary_label.pack(anchor="w", padx=10, pady=(0, 10), fill="x")
           panel["troubleshoot_summary_label"] = troubleshoot_summary_label

           troubleshoot_log = ctk.CTkTextbox(
               log_frame,
               fg_color="#1A1A1A",
               text_color="#666666",
               border_width=0,
               corner_radius=0,
               font=("Courier New", 15),
               wrap="word",
               activate_scrollbars=True
           )
           troubleshoot_log.pack(fill="both", expand=True, padx=8, pady=(0, 8))
           troubleshoot_log.configure(state="disabled")
           panel["troubleshoot_log"] = troubleshoot_log
           panel["troubleshoot_selected_device"] = None
           panel["troubleshoot_device_buttons"] = {}

           def show_device_log(device):
               """Render a fresh, IP-filtered log for this exact device."""
               selected_device[0] = device
               panel["troubleshoot_selected_device"] = device
               lines = _extract_device_logs(device)

               selected_label.configure(
                   text=f"{device.name} — {device.ip}"
               )
               selected_info.configure(
                   text=f"MAC ADDRESS: {device.mac}"
               )

               troubleshoot_log.configure(state="normal")
               troubleshoot_log.delete("1.0", "end")

               if lines:
                   troubleshoot_log.insert(
                       "end",
                       "\n".join(lines) + "\n"
                   )
               else:
                   troubleshoot_log.insert(
                       "end",
                       "> No automatic troubleshooting log for this device yet.\n"
                   )

               troubleshoot_log.configure(state="disabled")
               troubleshoot_log.see("end")

               troubleshoot_summary_label.configure(
                   text=_format_troubleshoot_summary(device, lines)
               )

               for mac, button in panel["troubleshoot_device_buttons"].items():
                   if button.winfo_exists():
                       is_selected = str(mac) == str(device.mac)
                       button.configure(
                           fg_color="#2A2A2A" if is_selected else "#1E1E1E",
                           border_color="#007AFF" if is_selected else "#444444",
                           text_color="#007AFF" if is_selected else "#AAAAAA"
                       )

           def refresh_device_buttons(*_):
               for widget in device_scroll.winfo_children():
                   widget.destroy()

               panel["troubleshoot_device_buttons"] = {}

               query = troubleshoot_search_var.get().strip().lower()
               devices = list(getattr(engine, "devices", []))

               if query:
                   devices = [
                       device for device in devices
                       if query in str(device.ip).lower()
                       or query in str(device.name).lower()
                       or query in str(device.mac).lower()
                   ]

               if not devices:
                   ctk.CTkLabel(
                       device_scroll,
                       text="NO DEVICES FOUND",
                       font=("Courier New", 11),
                       text_color="#555555"
                   ).pack(anchor="w", padx=8, pady=12)
                   return

               for device in devices:
                   # Do not capture a precomputed log list in the callback.
                   # The callback receives only the device and reads the
                   # correct IP-specific records when clicked.
                   button = ctk.CTkButton(
                       device_scroll,
                       text=f"{device.name}\n{device.ip}",
                       height=52,
                       fg_color="#1E1E1E",
                       border_color="#444444",
                       border_width=1,
                       text_color="#AAAAAA",
                       hover_color="#262626",
                       font=("Courier New", 11, "bold"),
                       anchor="w",
                       command=lambda selected=device: show_device_log(selected)
                   )
                   button.pack(fill="x", padx=2, pady=4)
                   panel["troubleshoot_device_buttons"][device.mac] = button

               # Restore the selected device's highlight after a search
               # refresh, but never copy its output to another device.
               if selected_device[0] is not None:
                   selected_mac = str(getattr(selected_device[0], "mac", ""))
                   for mac, button in panel["troubleshoot_device_buttons"].items():
                       if str(mac) == selected_mac:
                           button.configure(
                               fg_color="#2A2A2A",
                               border_color="#007AFF",
                               text_color="#007AFF"
                           )

           troubleshoot_search_var.trace_add("write", refresh_device_buttons)
           refresh_device_buttons()

       page = self._show_full_page(_build, on_back=_cleanup)
       panel["troubleshoot_window"] = page

   def _style_radar_filter_cards(self, panel):
       """Highlights whichever status card is currently the sole active
       radar filter (if any), same highlight style as
       _style_dashboard_filter_cards. When every status is on (no
       filter applied) none of the cards are highlighted."""
       cards = panel.get("radar_filter_cards") or {}
       filters = panel.get("radar_filters", {})
       is_solo = sum(1 for v in filters.values() if v) == 1
       for status, frame in cards.items():
           if not frame.winfo_exists():
               continue
           if is_solo and filters.get(status):
               frame.configure(fg_color="#2A2A2A", border_width=1, border_color="#555555")
           else:
               frame.configure(fg_color="transparent", border_width=0)


   def _on_radar_right_click(self, event, canvas, engine):
       """Hit-tests the click against the blips drawn in the last redraw
       and, if one's close enough, opens a small themed device popup."""
       blips = getattr(canvas, "_radar_blips", [])
       nearest, nearest_dist = None, 14  # px hit radius
       for x, y, dev in blips:
           d = ((event.x - x) ** 2 + (event.y - y) ** 2) ** 0.5
           if d <= nearest_dist:
               nearest, nearest_dist = dev, d


       existing = getattr(self, "_radar_popup", None)
       if existing is not None and existing.winfo_exists():
           existing.destroy()
       if nearest is None:
           return


       self._show_radar_device_popup(event.x_root, event.y_root, engine, nearest)


   def _show_radar_device_popup(self, x_root, y_root, engine, device):
       """A small borderless popup styled to match the rest of the app
       (dark card, blue accent border, same fonts/button style as the
       DIAGNOSE button and diagnostic dialog) instead of a native OS menu."""
       popup = ctk.CTkToplevel(self)
       popup.overrideredirect(True)
       popup.attributes("-topmost", True)
       popup.configure(fg_color="#0a0a0a")


       card = ctk.CTkFrame(popup, fg_color="#141414", border_width=1,
                            border_color="#007AFF", corner_radius=8)
       card.pack(fill="both", expand=True)


       ctk.CTkLabel(
           card, text=device.name, font=("Courier New", 12, "bold"), text_color="#AAAAAA"
       ).pack(anchor="w", padx=14, pady=(12, 0))
       ctk.CTkLabel(
           card, text=device.ip, font=("Courier New", 11), text_color="#666666"
       ).pack(anchor="w", padx=14, pady=(0, 10))


       ctk.CTkFrame(card, fg_color="#2A2A2A", height=1).pack(fill="x", padx=14)


       def _diagnose():
           popup.destroy()
           self._show_device_diagnostic(engine, device)


       ctk.CTkButton(
           card, text="DIAGNOSE DEVICE", width=240, height=32,
           fg_color="#1E1E1E", border_color="#007AFF", border_width=1,
           text_color="#007AFF", hover_color="#262626",
           font=("Arial Black", 10), command=_diagnose
       ).pack(fill="x", padx=14, pady=(10, 14))


       popup.update_idletasks()
       w, h = popup.winfo_reqwidth(), popup.winfo_reqheight()
       popup.geometry(f"{w}x{h}+{x_root}+{y_root}")


       self._radar_popup = popup
       popup.after(50, popup.focus_force)
       popup.bind("<FocusOut>", lambda e: popup.winfo_exists() and popup.destroy())
       popup.bind("<Escape>", lambda e: popup.destroy())


   # ─────────────────────────────────────────────
   # ENGINE CALLBACKS
   # ─────────────────────────────────────────────
   def _stretch_dashboard_columns(self, panel, avail_width):
       """Grow the 8 text columns (DEVICE..STATUS) to fill any leftover
       horizontal space in the panel, so the table reaches the right edge
       instead of leaving it blank. DIAGNOSE stays a fixed-width button.

       Both the header labels and every device row are re-widthed off the
       SAME computed list (panel["col_widths"]), which is what keeps them
       lined up under each other no matter how much the window stretches.
       """
       if avail_width <= 1:
           return  # not laid out yet

       base_total = sum(w for _, w in DASHBOARD_COLUMNS)
       n = len(DASHBOARD_COLUMNS)
       reserved = DASHBOARD_DIAGNOSE_WIDTH + DASHBOARD_DIAGNOSE_GAP + DASHBOARD_COL_PADX * (n + 1) + DASHBOARD_SCROLLBAR_RESERVE
       usable = max(avail_width - reserved, base_total)
       scale = min(usable / base_total, DASHBOARD_MAX_SCALE)
       new_widths = [int(round(w * scale)) for _, w in DASHBOARD_COLUMNS]

       if new_widths == panel.get("col_widths"):
           return  # no change, skip the rebuild

       panel["col_widths"] = new_widths
       for lbl, w in zip(panel["header_labels"], new_widths):
           lbl.configure(width=w)

       engine = panel.get("engine")
       if engine is not None:
           self.refresh_panel(engine)

   def request_panel_refresh(self, engine):
       """Coalesces bursts of refresh requests into one actual redraw.
       Background threads (health checks, discovery, name resolution —
       across up to 5 networks at once) can each fire a refresh request
       within milliseconds of each other; without this, every single one
       triggers its own full rebuild of the device list, which is what
       causes the UI to freeze then catch up in a backlog. Must be called
       from the main thread (callers already wrap this in
       `self.ui.after(0, ...)`), since it touches Tkinter state directly."""
       for _g in list(getattr(engine, "groups", {}).values()):
           self.request_panel_refresh(_g)
       panel = self._panels.get(id(engine))
       if not panel:
           # Panel not built yet (e.g. very first devices arriving before
           # the dashboard exists) — nothing to coalesce against yet.
           self.refresh_panel(engine)
           return
       if panel.get("_refresh_pending"):
           return
       panel["_refresh_pending"] = True
       def _do():
           panel["_refresh_pending"] = False
           self.refresh_panel(engine)
       # 200ms window: fast enough that live stats still feel responsive,
       # wide enough to absorb a burst of same-instant refresh requests
       # (e.g. 50 devices resolving names back-to-back) into a single redraw.
       self.after(200, _do)


   def refresh_panel(self, engine):
       panel = self._panels.get(id(engine))
       if not panel: return


       banner = panel.get("network_wide_banner")
       anchor = panel.get("network_wide_banner_anchor")
       if banner is not None and banner.winfo_exists():
           if getattr(engine, "network_wide_issue", False):
               since = getattr(engine, "network_wide_since", None)
               since_txt = f" (since {since})" if since else ""
               banner.configure(
                   text=f"NETWORK-WIDE LATENCY SPIKE{since_txt} — most devices are degraded "
                        f"at once. Likely the router or this host's own connection, not these "
                        f"devices individually. Readings may be temporarily less accurate."
               )
               if anchor is not None and anchor.winfo_exists():
                   banner.pack(fill="x", padx=20, pady=(0, 8), before=anchor)
               else:
                   banner.pack(fill="x", padx=20, pady=(0, 8))
           else:
               banner.pack_forget()


       list_inner  = panel["list_inner"]
       list_canvas = panel["list_canvas"]
       list_sb     = panel["list_scrollbar"]


       col_widths = panel.get("col_widths") or [w for _, w in DASHBOARD_COLUMNS]
       row_widgets = panel["row_widgets"]

       with engine.lock:
           current_devices = list(engine.devices)

       current_macs = {dev.mac for dev in current_devices}

       # Drop rows for devices that no longer exist (e.g. left the network).
       # This is the only case that still needs real widget destruction —
       # everything still present just gets updated/repositioned below.
       for mac in list(row_widgets.keys()):
           if mac not in current_macs:
               row_widgets[mac]["row"].destroy()
               del row_widgets[mac]

       # IP search filter. `current_devices` above is already scoped to
       # THIS engine/network only (engine.devices, taken under engine.lock),
       # so matching is inherently per-network — a query that matches an IP
       # on one network can never surface a device that merely happens to
       # share that same IP on a different network's panel/engine.
       search_var = panel.get("search_var")
       filter_text = search_var.get().strip().lower() if search_var is not None else ""
       if filter_text:
           visible_devices = [d for d in current_devices if filter_text in d.ip.lower()]
       else:
           visible_devices = current_devices

       # Status filter — set by clicking ONLINE/UNSTABLE/IDLE/OFFLINE above
       # the table. Combines with the IP search (both narrow the same
       # list), same as the radar's own filter + search combo.
       status_filter = panel.get("dashboard_filter")
       if status_filter:
           visible_devices = [d for d in visible_devices if d.status == status_filter]

       empty_state_lbl = panel.get("empty_state_lbl")
       if empty_state_lbl is not None and empty_state_lbl.winfo_exists():
           if current_devices and not visible_devices:
               if status_filter and filter_text:
                   msg = f" -  NO {status_filter.upper()} DEVICES MATCH \"{filter_text}\"  - "
               elif status_filter:
                   msg = f" -  NO {status_filter.upper()} DEVICES  - "
               else:
                   msg = " -  NO DEVICES MATCH IP ADDRESS  - "
               empty_state_lbl.configure(text=msg)
               empty_state_lbl.pack(anchor="w", padx=10, pady=(0, 10))
           else:
               empty_state_lbl.pack_forget()

       for dev in current_devices:
           values = [
               (dev.name,                             ("Courier New", 13, "bold")),
               (dev.ip,                                ("Courier New", 13)),
               (dev.mac,                                ("Courier New", 12)),
               (getattr(dev, "latency",       "--"),   ("Courier New", 12)),
               (getattr(dev, "jitter",        "--"),   ("Courier New", 12)),
               (getattr(dev, "packet_loss",   "--"),   ("Courier New", 12)),
               (getattr(dev, "network_speed", "--"),   ("Courier New", 12)),
               (dev.status,                             ("Courier New", 13)),
           ]

           entry = row_widgets.get(dev.mac)
           if entry is None:
               # New device — create its row's widgets once. These persist
               # across every future refresh; we never destroy them again
               # unless the device itself disappears (see above).
               row = ctk.CTkFrame(list_inner, fg_color="transparent")
               labels = []
               for col_i, ((text, font), width) in enumerate(zip(values, col_widths)):
                   lbl = ctk.CTkLabel(row, text=text, width=width, anchor="w", font=font, text_color=dev.color)
                   lbl.pack(side="left", padx=(0, DASHBOARD_COL_PADX))
                   if col_i == 0:
                       # DEVICE name column doubles as the entry point for
                       # its own Bandwidth popup — click the name to see
                       # this device's consumption alongside the whole
                       # network's total.
                       lbl.configure(cursor="hand2")
                       lbl.bind("<Button-1>", lambda _e, e=engine, d=dev: self._show_device_bandwidth_popup(e, d))
                   labels.append(lbl)
               button = ctk.CTkButton(
                   row, text="DIAGNOSE", width=DASHBOARD_DIAGNOSE_WIDTH, height=24,
                   fg_color="#1E1E1E", border_color="#007AFF", border_width=1,
                   text_color="#007AFF", hover_color="#262626",
                   font=("Arial Black", 9),
                   command=lambda e=engine, d=dev: self._show_device_diagnostic(e, d)
               )
               button.pack(side="left", padx=(DASHBOARD_DIAGNOSE_GAP, 0))
               entry = {"row": row, "labels": labels, "button": button, "last_values": None, "last_color": None}
               row_widgets[dev.mac] = entry
           else:
               # Existing device — only touch a label's widget if its text
               # or color actually changed since last refresh. Most devices
               # sit in "Online" with unchanged text between cycles, so
               # this usually skips almost all of the ~8 .configure() calls
               # per device — CTkLabel.configure() isn't free (it redraws
               # the widget's internal canvas/image), so avoiding it when
               # nothing changed is what keeps a 50-device refresh cheap.
               row, labels = entry["row"], entry["labels"]
               texts = [v[0] for v in values]
               if entry["last_values"] != texts or entry["last_color"] != dev.color:
                   for lbl, (text, font), old_text in zip(labels, values, entry["last_values"] or [None] * len(values)):
                       if text != old_text or entry["last_color"] != dev.color:
                           lbl.configure(text=text, text_color=dev.color)
               entry["last_values"] = texts
               entry["last_color"] = dev.color

       # Only reposition rows if the actual ORDER (or filtered visibility)
       # of devices changed — pack_forget()+pack() on 50 already-correctly-
       # placed rows every single refresh forces Tkinter to redo geometry
       # management for the whole list for no reason. New/removed devices,
       # or a change in the search box, always change this list, so those
       # cases still get repositioned; steady-state refreshes (the
       # overwhelming majority) skip this entirely.
       new_order = [dev.mac for dev in visible_devices]
       order_changed = new_order != panel.get("_row_order")
       if order_changed:
           visible_set = set(new_order)
           # Hide rows for devices that exist but are filtered out by the
           # search box right now — they keep their widgets (cheap to bring
           # back), they're just unpacked from the list.
           for mac, entry in row_widgets.items():
               if mac not in visible_set:
                   entry["row"].pack_forget()
           for mac in new_order:
               row = row_widgets[mac]["row"]
               row.pack_forget()
               row.pack(fill="x", pady=2)
           panel["_row_order"] = new_order


       # Scrollbar visibility only needs rechecking when the list's total
       # height could have changed — i.e. rows were added/removed. Forcing
       # update_idletasks() (a full layout pass) after every refresh, even
       # when only a label's text changed, was extra unconditional cost on
       # top of everything else.
       if order_changed:
           def _check_scroll():
               list_inner.update_idletasks()
               list_canvas.configure(scrollregion=list_canvas.bbox("all"))
               if list_inner.winfo_reqheight() > list_canvas.winfo_height():
                   list_sb.pack(side="right", fill="y")
               else:
                   list_sb.pack_forget()
           self.after(50, _check_scroll)


       radar_win = panel.get("radar_window")
       radar_canvas = panel.get("radar_canvas")
       if radar_win is not None and radar_canvas is not None and radar_win.winfo_exists():
           self.after(50, lambda: self._draw_radar(radar_canvas, engine))


   # ─────────────────────────────────────────────
   # PER-DEVICE DIAGNOSTIC POPUP (data only, no suggestions)
   # ─────────────────────────────────────────────
   def _show_device_history(self, device):
       """Simple plain-text log of when this device flagged Unstable,
       Idle, or Offline, and what its numbers looked like at that moment
       — most recent first."""
       win = ctk.CTkToplevel(self)
       win.title(f"History — {device.name}")
       win.geometry("480x520")
       win.minsize(380, 320)
       win.resizable(True, True)
       win.configure(fg_color="#121212")
       win.attributes("-topmost", True)


       ctk.CTkLabel(
           win, text="STATUS HISTORY", font=("Arial Black", 14), text_color="white"
       ).pack(pady=(16, 2))
       ctk.CTkLabel(
           win, text=device.name, font=("Courier New", 13), text_color="#66AAFF"
       ).pack(pady=(0, 10))


       body_outer, body, body_canvas, body_scrollbar = self._make_smart_scroll(win, bg="#1A1A1A")
       body_outer.pack(fill="both", expand=True, padx=16, pady=(0, 12))


       history = list(reversed(getattr(device, "status_history", [])))
       status_colors = dict(STATUS_COLORS)


       if not history:
           ctk.CTkLabel(
               body, text="No flagged status changes yet, this device has\nstayed Online since it was first seen.",
               font=("Courier New", 13), text_color="#555555", justify="left"
           ).pack(anchor="w", padx=14, pady=14)
       else:
           for entry in history:
               color = status_colors.get(entry["status"], "#AAAAAA")
               row = ctk.CTkFrame(body, fg_color="#0D0D0D", corner_radius=6)
               row.pack(fill="x", padx=10, pady=4)
               ctk.CTkLabel(
                   row, text=f"{entry['ts']}    {entry['status'].upper()}",
                   font=("Courier New", 13, "bold"), text_color=color, anchor="w"
               ).pack(anchor="w", padx=10, pady=(8, 2))
               ctk.CTkLabel(
                   row,
                   text=(f"latency: {entry['latency']}   jitter: {entry['jitter']}   "
                         f"loss: {entry['packet_loss']}   speed: {entry['network_speed']}"),
                   font=("Courier New", 12), text_color="#888888", anchor="w"
               ).pack(anchor="w", padx=10, pady=(0, 8))


       def _refresh_scroll():
           body.update_idletasks()
           body_canvas.configure(scrollregion=body_canvas.bbox("all"))
           if body.winfo_reqheight() > body_canvas.winfo_height():
               body_scrollbar.pack(side="right", fill="y")
           else:
               body_scrollbar.pack_forget()
       win.after(50, _refresh_scroll)


       ctk.CTkButton(
           win, text="CLOSE", width=120, height=32,
           fg_color="#1E1E1E", border_color="#66AAFF", border_width=1,
           text_color="#66AAFF", hover_color="#262626",
           font=("Arial Black", 10),
           command=win.destroy
       ).pack(pady=(0, 16))


   def _show_device_bandwidth_popup(self, engine, device):
       """Bandwidth page for one device — opened by clicking the device's
       NAME in the dashboard row. Built as an in-app PAGE via
       _show_full_page, the same page-navigation mechanism History Log
       and Troubleshoot Log already use, instead of spawning a separate
       Toplevel window — so opening it feels like navigating inside the
       app rather than popping open a second OS window on top of it.
       Shows the network total and this device's own total (both pulled
       from the same snapshot so they're always consistent with each
       other), plus a small graph of this device's consumption over the
       last couple of minutes. Everything here is an estimate — a
       normal client machine can't meter another device's traffic for
       real without router-side support this app doesn't have (see
       engine.get_bandwidth_snapshot / get_device_bandwidth_history)."""
       self._hide_radar_header_controls()

       def _cleanup():
           self._restore_radar_header_controls()

       def _build(page):
           ctk.CTkLabel(
               page, text="BANDWIDTH CONSUMPTION",
               font=("Arial Black", 16), text_color="white"
           ).pack(pady=(0, 2))
           ctk.CTkLabel(
               page, text=device.name, font=("Courier New", 13), text_color="#66AAFF"
           ).pack(pady=(0, 16))

           network_frame = ctk.CTkFrame(
               page, fg_color="#1A1A1A", border_color="#252525",
               border_width=1, corner_radius=8
           )
           network_frame.pack(fill="x", padx=4, pady=(0, 10))
           ctk.CTkLabel(
               network_frame, text="TOTAL NETWORK CONSUMPTION",
               font=("Arial Black", 11), text_color="#666666"
           ).pack(anchor="w", padx=16, pady=(12, 0))
           network_value_lbl = ctk.CTkLabel(
               network_frame, text="--", font=("Courier New", 24, "bold"),
               text_color="#00CC66"
           )
           network_value_lbl.pack(anchor="w", padx=16, pady=(0, 12))

           device_frame = ctk.CTkFrame(
               page, fg_color="#1A1A1A", border_color="#252525",
               border_width=1, corner_radius=8
           )
           device_frame.pack(fill="x", padx=4, pady=(0, 16))

           device_header_row = ctk.CTkFrame(device_frame, fg_color="transparent")
           device_header_row.pack(fill="x", padx=16, pady=(12, 0))
           ctk.CTkLabel(
               device_header_row, text="THIS DEVICE'S TOTAL CONSUMPTION",
               font=("Arial Black", 11), text_color="#666666"
           ).pack(side="left", anchor="w")

           # (No manual CLEAR button here anymore: this device's total now
           # resets automatically at local midnight together with the
           # network total — see engine._reset_bandwidth_at_midnight_if_needed.)

           device_value_lbl = ctk.CTkLabel(
               device_frame, text="--", font=("Courier New", 24, "bold"),
               text_color="#66AAFF"
           )
           device_value_lbl.pack(anchor="w", padx=16, pady=(0, 12))

           # Graph: this device's estimated usage per interval over the last
           # ~2 minutes (see engine.get_device_bandwidth_history) — fills the
           # rest of the page's space below the two total cards.
           ctk.CTkLabel(
               page, text="CONSUMPTION OVER TIME",
               font=("Arial Black", 11), text_color="#666666"
           ).pack(anchor="w", padx=4, pady=(0, 6))

           graph_frame = ctk.CTkFrame(
               page, fg_color="#1A1A1A", border_color="#252525",
               border_width=1, corner_radius=8
           )
           graph_frame.pack(fill="both", expand=True, padx=4, pady=(0, 16))

           # Horizontal scrollbar packed BEFORE the canvas so it reserves its
           # own strip at the bottom of graph_frame — packing it after the
           # canvas (which fills+expands) would leave it no room to claim.
           graph_hscroll = ctk.CTkScrollbar(
               graph_frame, orientation="horizontal", command=lambda *a: graph_canvas.xview(*a)
           )
           graph_hscroll.pack(side="bottom", fill="x", padx=10, pady=(0, 6))

           graph_canvas = ctk.CTkCanvas(graph_frame, bg="#1A1A1A", highlightthickness=0)
           graph_canvas.pack(fill="both", expand=True, padx=10, pady=(10, 0))
           graph_canvas.configure(xscrollcommand=graph_hscroll.set)

           # Trackpad/shift-wheel horizontal scroll as a convenience, since
           # not every user will reach for the scrollbar itself.
           def _on_graph_shift_wheel(event):
               graph_canvas.xview_scroll(int(-1 * (event.delta / 120)), "units")
           graph_canvas.bind("<Shift-MouseWheel>", _on_graph_shift_wheel)

           # Points are spaced at least this many pixels apart no matter how
           # many samples there are — this is the actual fix for "compact"
           # graphs: rather than squeezing all ~60 samples into whatever
           # width the page happens to be (which crushes points/labels
           # together), the canvas's drawable area grows wider than the
           # visible viewport once there are enough points, and the
           # scrollbar above lets the user pan across it. With few samples,
           # content still stretches to fill the visible width exactly like
           # before — this only kicks in once points would otherwise get
           # cramped.
           MIN_POINT_SPACING = 55

           def _draw_graph():
               """Draws the consumption trend as a line + circle-marker
               chart: gridlines with an arrowed y-axis (no side value
               labels — each value is shown right at its own point
               instead), an arrowed x-axis with time labels, and a
               connecting trend line. Markers/labels are thinned out on
               dense data so they don't overlap into a solid blob."""
               if not page.winfo_exists():
                   return
               # Capture the scroll position BEFORE wiping/redrawing so we
               # can tell whether the user was already looking at the right
               # (most recent) edge — if so, keep following new data there;
               # if they'd panned left to inspect older points, leave their
               # view alone instead of yanking them back to the end.
               try:
                   _prev_first, prev_last = graph_canvas.xview()
               except Exception:
                   prev_last = 1.0
               was_following = prev_last >= 0.995

               graph_canvas.delete("all")
               visible_w = graph_canvas.winfo_width()
               height = graph_canvas.winfo_height()
               if visible_w < 20 or height < 20:
                   return

               raw_history = engine.get_device_bandwidth_history(device.mac)
               # None entries mean the device WAS responding but no usable
               # speed reading came back that cycle (see the docstring on
               # get_device_bandwidth_history) — genuinely unknown, not zero
               # usage. Confirmed-zero entries (0.0, from cycles the device
               # was unreachable) and unknown entries are both left out of
               # what gets plotted — drawing either produced a long flat
               # baseline that told the wrong story — but they're counted
               # separately first so the empty-state message can tell the
               # user which situation they're actually in.
               no_reading_count = sum(1 for _, b in raw_history if b is None)
               history = [(t, b) for t, b in raw_history if b is not None and b > 0]

               # Left padding is much smaller now that the y-axis has no
               # value labels next to it — just enough room for the arrowhead.
               # Extra top padding so a value label above the highest point
               # never gets clipped by the canvas edge.
               pad_l, pad_r, pad_t, pad_b = 14, 14, 26, 40
               n = len(history)
               visible_plot_w = max(1, visible_w - pad_l - pad_r)
               # Content is at least as wide as the visible viewport (so a
               # short history still fills the frame like before), but never
               # narrower than n points at the fixed minimum spacing.
               plot_w = max(visible_plot_w, (n - 1) * MIN_POINT_SPACING) if n > 1 else visible_plot_w
               total_w = pad_l + plot_w + pad_r
               plot_h = max(1, height - pad_t - pad_b)

               if len(history) < 2:
                   graph_canvas.configure(scrollregion=(0, 0, visible_w, height))
                   # If every single sample so far is an "unknown reading"
                   # one, the device is up and being probed but this app
                   # simply can't derive a speed estimate for it (packet-pair
                   # delta never comes out usable — see _estimate_speed_mbps)
                   # — that's a different, more permanent situation than
                   # "still gathering the first few samples", so it gets its
                   # own message instead of implying data is still on its way.
                   if raw_history and no_reading_count == len(raw_history):
                       msg = "Speed reading unavailable for this device"
                   else:
                       msg = "Gathering data..."
                   graph_canvas.create_text(
                       visible_w / 2, height / 2,
                       text=msg, fill="#555555",
                       font=("Courier New", 12)
                   )
                   return

               timestamps = [t for t, _ in history]
               values = [b for _, b in history]
               max_val = max(values) if max(values) > 0 else 1.0
               min_val = 0.0  # bandwidth usage never goes negative, so the baseline always sits at zero
               span = (max_val - min_val) or 1.0

               # Horizontal gridlines only — no y-axis value text, since
               # each point now carries its own value label.
               GRID_STEPS = 4
               for i in range(GRID_STEPS + 1):
                   frac = i / GRID_STEPS
                   y = pad_t + plot_h - frac * plot_h
                   graph_canvas.create_line(
                       pad_l, y, pad_l + plot_w, y, fill="#252525", width=1
                   )

               # Arrowed y-axis. The x-axis intentionally has NO arrowhead —
               # unlike the y-axis (whose top end never coincides with a data
               # point), the x-axis's right end sits exactly where the last
               # data point's marker circle is drawn, and a low-value last
               # point (near the baseline) put the arrowhead right on top of
               # that circle, looking like two overlapping shapes at the
               # endpoint. A plain line here lets the circle be the only
               # marker at that spot.
               graph_canvas.create_line(
                   pad_l, pad_t - 4, pad_l, pad_t + plot_h,
                   fill="#555555", width=1.5, arrow="first"
               )
               graph_canvas.create_line(
                   pad_l, pad_t + plot_h, pad_l + plot_w + 4, pad_t + plot_h,
                   fill="#555555", width=1.5
               )

               # Each point's x is placed by its REAL timestamp (proportional
               # position within the window's actual time span), not by
               # index. Health-check cycles aren't perfectly evenly timed
               # (a slow ping/ARP probe can stretch one cycle longer than
               # another), so spacing points evenly by index silently
               # drifted out of sync with the time-axis labels the longer a
               # session ran. This keeps every point sitting exactly where
               # its timestamp says it should, always.
               t_min, t_max = timestamps[0], timestamps[-1]
               time_span = (t_max - t_min) or 1.0
               points = []
               for t, b in zip(timestamps, values):
                   x = pad_l + ((t - t_min) / time_span) * plot_w
                   y = pad_t + plot_h - ((b - min_val) / span) * plot_h
                   points.append((x, y))

               # Labels near either edge switch to an edge-anchored tkinter
               # anchor ("w"/"e") instead of centered ("") so their text never
               # runs off the canvas — see _label_anchor_and_bounds below,
               # used identically by both the collision check and the actual
               # drawing so the two can never disagree about where a label's
               # edges really land.
               EDGE_MARGIN = 40

               def _label_anchor_and_bounds(x, text_width):
                   """Single source of truth for a label's horizontal anchor
                   AND its resulting left/right pixel bounds at that anchor.
                   An earlier version of the overlap check assumed every
                   label was center-anchored (half the width on each side),
                   but a label near the right edge actually renders "e"-
                   anchored — its FULL width sits to the left of x, not half
                   — so the old check could judge two labels as non-
                   overlapping when they visually touched. Deriving both the
                   anchor and the bounds from the exact same rule here means
                   the collision check always matches what actually gets
                   drawn."""
                   if x < pad_l + EDGE_MARGIN:
                       return "w", x, x + text_width
                   elif x > pad_l + plot_w - EDGE_MARGIN:
                       return "e", x - text_width, x
                   else:
                       half = text_width / 2
                       return "", x - half, x + half

               def _select_label_indices(target_count, width_fn, extra_gap=12):
                   """Evenly-spaced candidate indices, packed left-to-right
                   using each label's REAL measured pixel width (via
                   width_fn(idx)) and its actual render anchor (via
                   _label_anchor_and_bounds) rather than a guessed spacing
                   constant — a guess, or an anchor-blind bounds calc, can
                   both be wrong and still let labels touch. The final point
                   is always forced in (so the chart always shows its most
                   recent reading); if it would visually collide with
                   whichever label was selected right before it, that
                   earlier one is evicted in favor of the final point
                   instead of drawing both on top of each other."""
                   if n == 0:
                       return []
                   if n == 1:
                       return [0]
                   step = max(1, round(n / target_count))
                   candidates = list(range(0, n, step))
                   if candidates[-1] != n - 1:
                       candidates.append(n - 1)
                   selected = []
                   last_right = None
                   for idx in candidates:
                       x = points[idx][0]
                       text_width = width_fn(idx)
                       _, left, right = _label_anchor_and_bounds(x, text_width)
                       if last_right is None or left - extra_gap >= last_right:
                           selected.append(idx)
                           last_right = right
                       elif idx == n - 1:
                           if selected:
                               selected.pop()
                           selected.append(idx)
                           last_right = right
                   return selected

               # Connecting trend line
               for (x1, y1), (x2, y2) in zip(points, points[1:]):
                   graph_canvas.create_line(x1, y1, x2, y2, fill="#66AAFF", width=2)

               # Value labels (above/below each point) and time labels (on
               # the x-axis) are now chosen from ONE shared set of indices —
               # every annotated point gets both, so the time shown under
               # the axis always lines up with the value plotted above it.
               # Previously each was thinned out independently (its own
               # target count, its own font's width), which could and did
               # pick different points for each, leaving values without a
               # matching time directly beneath them. Selecting once, using
               # whichever of the two texts is wider at each candidate point
               # for spacing, keeps both in sync.
               value_font = tkfont.Font(family="Courier New", size=12, weight="bold")
               time_font = tkfont.Font(family="Courier New", size=10)
               value_texts = [NetHealerEngine._format_bytes(v) for v in values]
               time_texts = [
                   datetime.fromtimestamp(ts).strftime("%H:%M:%S") for ts in timestamps
               ]

               # Spacing is checked against whichever of the two labels is
               # visually wider at that point (each measured in its own
               # font), so neither the value nor the time text ends up
               # colliding with its neighbor.
               label_indices = _select_label_indices(
                   6,
                   lambda i: max(
                       value_font.measure(value_texts[i]),
                       time_font.measure(time_texts[i]),
                   ),
               )

               for i in label_indices:
                   x, y = points[i]

                   # Value label: anchored above its point by default,
                   # flipping below when too close to the top edge, and
                   # left/right when too close to a side edge.
                   near_top = (y - 16) < pad_t
                   if near_top:
                       v_anchor, label_y = "n", y + 12
                   else:
                       v_anchor, label_y = "s", y - 12
                   h_anchor, _, _ = _label_anchor_and_bounds(
                       x, value_font.measure(value_texts[i])
                   )
                   graph_canvas.create_text(
                       x, label_y,
                       text=value_texts[i],
                       fill="#66AAFF", font=("Courier New", 12, "bold"),
                       anchor=(v_anchor + h_anchor) or "s"
                   )

                   # Time label: always on the x-axis, directly below the
                   # same point as the value label above.
                   time_label = time_texts[i]
                   t_h_anchor, _, _ = _label_anchor_and_bounds(x, time_font.measure(time_label))
                   graph_canvas.create_text(
                       x, pad_t + plot_h + 8, text=time_label,
                       fill="#888888", font=("Courier New", 10),
                       anchor=("n" + t_h_anchor) if t_h_anchor else "n"
                   )

               graph_canvas.configure(scrollregion=(0, 0, total_w, height))
               # Keep the view pinned to the latest data as new samples come
               # in, but only if the user was already looking at the right
               # edge before this redraw — otherwise leave their scroll
               # position alone so panning left to inspect older points
               # doesn't keep getting yanked back to "now".
               if was_following:
                   graph_canvas.xview_moveto(1.0)

           def _refresh():
               if not page.winfo_exists():
                   return
               snapshot = engine.get_bandwidth_snapshot()
               # IMPORTANT: this label is "TOTAL NETWORK CONSUMPTION" — the
               # running sum of every device's own ESTIMATED consumption,
               # from formatted_network_estimated_total. That figure is its
               # own monotonic counter on the engine (NOT a live sum of the
               # devices list — see engine.get_bandwidth_snapshot's
               # docstring), so clearing one device's own total does not make
               # this figure drop, even though clearing that same device's
               # total DOES reduce estimated_total_bytes (the live sum) if
               # that's ever used instead. Always available (no psutil/
               # interface dependency), unlike the real per-interface total.
               network_value_lbl.configure(text=snapshot["formatted_network_estimated_total"])
               dev_row = next(
                   (row for row in snapshot["devices"] if row["mac"] == device.mac), None
               )
               device_value_lbl.configure(text=dev_row["formatted_estimate"] if dev_row else "--")
               _draw_graph()
               self.after(2000, _refresh)

           self.after(50, _refresh)

           # Redraw on resize (debounced) so the gridlines/labels/markers
           # stay correctly positioned if the user resizes the app window —
           # same pattern used for the Radar canvas.
           resize_job = [None]
           def _on_graph_resize(event):
               if resize_job[0] is not None:
                   self.after_cancel(resize_job[0])
               resize_job[0] = self.after(120, _draw_graph)
           graph_canvas.bind("<Configure>", _on_graph_resize)

       self._show_full_page(_build, on_back=_cleanup)


   def _show_device_diagnostic(self, engine, device):
       """Diagnostic results for one device — an in-app PAGE (built with
       _show_full_page, the same page-navigation mechanism History Log
       and Troubleshoot Log already use) rather than a separate Toplevel
       window, so DIAGNOSE opens by navigating within the app instead of
       spawning a second OS window on top of it."""
       self._hide_radar_header_controls()

       def _cleanup():
           self._restore_radar_header_controls()

       def _build(page):
           ctk.CTkLabel(
               page, text="DEVICE DIAGNOSTIC",
               font=("Arial Black", 17), text_color="white"
           ).pack(pady=(0, 2))
           ctk.CTkLabel(
               page, text=device.name,
               font=("Courier New", 14), text_color="#007AFF"
           ).pack(pady=(0, 8))

           history = getattr(device, "status_history", [])
           ctk.CTkButton(
               page, text=f"VIEW HISTORY ({len(history)})", width=220, height=30,
               fg_color="#1E1E1E", border_color="#66AAFF", border_width=1,
               text_color="#66AAFF", hover_color="#262626", font=("Arial Bold", 11),
               command=lambda d=device: self._show_device_history(d)
           ).pack(pady=(0, 8))

           status_lbl = ctk.CTkLabel(
               page, text="Running diagnostics...",
               font=("Courier New", 14), text_color="#888888"
           )
           status_lbl.pack(pady=(0, 10))

           body_outer, body, body_canvas, body_scrollbar = self._make_smart_scroll(page, bg="#1A1A1A")
           body_outer.pack(fill="both", expand=True, padx=4, pady=(0, 12))

           def _refresh_body_scroll():
               if not page.winfo_exists():
                   return
               body.update_idletasks()
               body_canvas.configure(scrollregion=body_canvas.bbox("all"))
               if body.winfo_reqheight() > body_canvas.winfo_height():
                   body_scrollbar.pack(side="right", fill="y")
               else:
                   body_scrollbar.pack_forget()
           self.after(50, _refresh_body_scroll)

           # Disabled until populate() below has real results to export —
           # exporting mid-scan (or the "DEVICE OFFLINE" state, which never
           # calls populate()) would otherwise produce an empty PDF.
           export_pdf_btn = ctk.CTkButton(
               page, text="EXPORT PDF", width=140, height=34,
               fg_color="#1E1E1E", border_color="#66AAFF", border_width=1,
               text_color="#66AAFF", hover_color="#262626",
               font=("Arial Black", 12), state="disabled",
               command=lambda: self._export_diagnostic_pdf(
                   page, export_pdf_btn, device, last_diag_results[0], last_causes[0]
               )
           )
           export_pdf_btn.pack(pady=(0, 16))

           # The page shows the five diagnostic checks. If the device is still
           # unreachable, AUTO-TROUBLESHOOT is moved to the bottom dashboard log
           # for this network instead of being printed here.
           progress_log = ctk.CTkLabel(
               body, text="", anchor="nw", justify="left",
               font=("Courier New", 14), text_color="#666666",
               wraplength=740
           )
           progress_log.pack(fill="both", expand=True, padx=14, pady=10)
           progress_lines = []

           # These fields are only hidden from the FINAL data table — the live
           # progress log while diagnosing still shows every step, including
           # ARP/ports/DNS checks.
           HIDDEN_FIELDS = {"ARP Table", "Open TCP Ports", "Reverse DNS"}

           def progress(step_msg):
               if not page.winfo_exists():
                   return
               progress_lines.append(f"> {step_msg}")
               progress_log.configure(text="\n".join(progress_lines))

           # Colors for the POSSIBLE CAUSES entries, keyed off the "level" each
           # cause comes back with from engine._analyze_possible_causes.
           # Critical (red) is the most likely single culprit (e.g. gateway
           # itself unreachable, no ARP reply at all), warning (orange) is a
           # real but secondary signal, and info (blue) is context or
           # explanation rather than a problem in itself.
           CAUSE_COLORS = {"critical": "#FF3333", "warning": "#FF8800", "info": "#66AAFF"}

           def show_data(combined, causes=None):
               for widget in body.winfo_children():
                   widget.destroy()

               # POSSIBLE CAUSES sits above the raw data table: it answers
               # "why", while the table below it shows "what". Shown for every
               # status (Offline, Unstable, Idle, and Online all get tailored
               # causes from the engine), not just Offline, since "why is this
               # Idle" or "why did this flag Unstable" are just as useful to
               # answer.
               if causes:
                   ctk.CTkLabel(
                       body, text="POSSIBLE CAUSES", anchor="w",
                       font=("Arial Black", 13), text_color="#CCCCCC"
                   ).pack(anchor="w", padx=14, pady=(8, 6))
                   for cause in causes:
                       color = CAUSE_COLORS.get(cause.get("level"), "#888888")
                       row = ctk.CTkFrame(body, fg_color="#0D0D0D", corner_radius=6)
                       row.pack(fill="x", padx=14, pady=3)
                       ctk.CTkLabel(
                           row, text=f"●  {cause.get('text', '')}", anchor="w",
                           justify="left", font=("Courier New", 13),
                           text_color=color, wraplength=720
                       ).pack(anchor="w", padx=12, pady=8)
                   divider = ctk.CTkFrame(body, fg_color="#2A2A2A", height=1)
                   divider.pack(fill="x", padx=14, pady=(4, 12))

               for label, value in combined.items():
                   if label in HIDDEN_FIELDS:
                       continue
                   # TCP Latency only has a value when one of the probed ports
                   # (80/443/22/8080/445) was actually open — most devices don't
                   # have any of those listening, so it's "--" far more often
                   # than not. Skip the row entirely in that case instead of
                   # showing a dash.
                   if label == "TCP Latency" and value == "--":
                       continue
                   row = ctk.CTkFrame(body, fg_color="transparent")
                   row.pack(fill="x", padx=14, pady=5)
                   # width=210 fits even the longest label ("Gateway Reachability:")
                   # at this font size — it was clipping into the value before,
                   # which is why "Gateway Reachability:Reachable" ran together
                   # with no gap. padx=(0, 10) guarantees a gap either way.
                   ctk.CTkLabel(
                       row, text=f"{label}:", width=210, anchor="w",
                       font=("Courier New", 14, "bold"), text_color="#888888"
                   ).pack(side="left", padx=(0, 10))
                   # wraplength=700 gives values like "Recent Pings" and "ICMP Ping"
                   # enough room to stay on one line at the page's default width,
                   # instead of the old 220px limit that forced them to wrap.
                   ctk.CTkLabel(
                       row, text=str(value), anchor="w",
                       font=("Courier New", 14), text_color="white", wraplength=700, justify="left"
                   ).pack(side="left", fill="x", expand=True)

           def show_offline():
               for widget in body.winfo_children():
                   widget.destroy()
               ctk.CTkLabel(
                   body, text="DEVICE OFFLINE", anchor="center",
                   font=("Arial Black", 18), text_color="#FF3333"
               ).pack(expand=True)

           last_diag_results = [{}]
           last_causes = [None]

           def populate(diag_results):
               if not page.winfo_exists():
                   return
               status_lbl.configure(text="Diagnosis complete")
               snapshot = engine.get_diagnostic_snapshot(device)
               # Pulled out here (rather than left in HIDDEN_FIELDS) so it
               # renders as its own styled section instead of one more plain
               # "Label: value" row in the data table.
               causes = diag_results.pop("_possible_causes", None)
               # Stored post-merge (snapshot + diag_results) and post-pop (causes
               # split out) so EXPORT PDF renders from exactly the same data
               # show_data() is about to display, not the raw pre-merge dict.
               last_diag_results[0] = {**snapshot, **diag_results}
               last_causes[0] = causes
               export_pdf_btn.configure(state="normal")
               show_data(last_diag_results[0], causes)

           # Diagnosis only ever runs here — triggered by opening this page,
           # never automatically, and never written to the activity log.
           engine.run_diagnostic(device, populate, on_progress=progress)

       self._show_full_page(_build, on_back=_cleanup)


   # Same HIDDEN_FIELDS / "TCP Latency: --" skip rules as show_data() above,
   # so the PDF a user downloads always matches what they saw on screen —
   # duplicated here (rather than imported) since show_data is a local
   # closure inside _show_device_diagnostic, not a module-level function.
   _PDF_HIDDEN_FIELDS = {"ARP Table", "Open TCP Ports", "Reverse DNS"}

   def _export_diagnostic_pdf(self, popup, export_pdf_btn, device, combined, causes):
       """EXPORT PDF button handler for the per-device diagnostic popup.
       `combined` is the merged snapshot+diag_results dict and `causes`
       the possible-causes list, exactly as last shown by show_data() —
       see populate() above, which is the only place that fills these in.

       The file-picker dialog has to run on the main thread (it's a native
       Tk dialog), but reportlab's doc.build() — real layout work plus a
       disk write — does not, and previously ran right here inline, which
       froze the whole app (not just this popup) for as long as the PDF
       took to render. It now runs on a background thread; only the final
       success/error popup hops back to the main thread via popup.after,
       since Tkinter widgets aren't safe to touch off the main thread."""
       if not combined:
           self._show_confirm_popup(
               "EXPORT PDF", "No diagnostic results to export yet.",
               on_confirm=lambda: None, confirm_text="OK", single_button=True)
           return

       default_name = f"diagnostic_{re.sub(r'[^A-Za-z0-9_-]+', '_', device.name)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
       path = filedialog.asksaveasfilename(
           parent=popup,
           title="Export Diagnostic as PDF",
           defaultextension=".pdf",
           initialfile=default_name,
           filetypes=[("PDF files", "*.pdf")],
       )
       if not path:
           return  # user cancelled the save dialog

       # Guard against double-clicks firing a second build while the first
       # is still writing to the same file, and give the user feedback that
       # something is actually happening during the (now background) build.
       export_pdf_btn.configure(state="disabled", text="EXPORTING...")

       def worker():
           try:
               self._build_diagnostic_pdf(path, device, combined, causes)
           except Exception as exc:
               result = ("error", str(exc))
           else:
               result = ("ok", None)

           def finish():
               if not popup.winfo_exists():
                   return
               export_pdf_btn.configure(state="normal", text="EXPORT PDF")
               if result[0] == "ok":
                   self._show_confirm_popup(
                       "REPORT SAVED", f"Saved diagnostic report to:\n{path}",
                       on_confirm=lambda: None, confirm_text="OK",
                       danger=False, single_button=True)
               else:
                   self._show_confirm_popup(
                       "EXPORT FAILED", f"Could not save PDF:\n{result[1]}",
                       on_confirm=lambda: None, confirm_text="OK",
                       single_button=True)

           if popup.winfo_exists():
               popup.after(0, finish)

       threading.Thread(target=worker, daemon=True).start()

   def _build_diagnostic_pdf(self, path, device, combined, causes):
       """Renders the diagnostic report to `path` using reportlab. Kept
       separate from _export_diagnostic_pdf so the file-dialog/error-popup
       plumbing above stays clear of the actual document layout below."""
       styles = getSampleStyleSheet()
       title_style = ParagraphStyle(
           "DiagTitle", parent=styles["Title"], fontSize=18, spaceAfter=4,
       )
       subtitle_style = ParagraphStyle(
           "DiagSubtitle", parent=styles["Normal"], fontSize=11,
           textColor=colors.HexColor("#555555"), spaceAfter=14,
       )
       section_style = ParagraphStyle(
           "DiagSection", parent=styles["Heading2"], fontSize=13,
           spaceBefore=14, spaceAfter=6,
       )
       cause_colors = {
           "critical": colors.HexColor("#CC0000"),
           "warning": colors.HexColor("#B36B00"),
           "info": colors.HexColor("#2255AA"),
       }

       story = []
       story.append(Paragraph("Device Diagnostic Report", title_style))
       story.append(Paragraph(
           f"{device.name} &nbsp;&bull;&nbsp; {device.ip} &nbsp;&bull;&nbsp; {device.mac}"
           f"<br/>Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
           subtitle_style,
       ))

       if causes:
           story.append(Paragraph("Possible Causes", section_style))
           for cause in causes:
               color = cause_colors.get(cause.get("level"), colors.HexColor("#444444"))
               cause_style = ParagraphStyle(
                   "Cause", parent=styles["Normal"], fontSize=10.5,
                   textColor=color, spaceAfter=5, leftIndent=10,
               )
               story.append(Paragraph(f"&bull; {cause.get('text', '')}", cause_style))

       rows = []
       for label, value in combined.items():
           if label in self._PDF_HIDDEN_FIELDS:
               continue
           if label == "TCP Latency" and value == "--":
               continue
           rows.append([label, str(value)])

       if rows:
           story.append(Paragraph("Diagnostic Data", section_style))
           table = Table([["Field", "Value"]] + rows, colWidths=[2.1 * inch, 4.2 * inch])
           table.setStyle(TableStyle([
               ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
               ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
               ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
               ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
               ("FONTSIZE", (0, 0), (-1, -1), 9.5),
               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
               ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
               ("VALIGN", (0, 0), (-1, -1), "TOP"),
               ("LEFTPADDING", (0, 0), (-1, -1), 6),
               ("RIGHTPADDING", (0, 0), (-1, -1), 6),
               ("TOPPADDING", (0, 0), (-1, -1), 4),
               ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
           ]))
           story.append(table)

       doc = SimpleDocTemplate(
           path, pagesize=letter,
           topMargin=0.7 * inch, bottomMargin=0.7 * inch,
           leftMargin=0.7 * inch, rightMargin=0.7 * inch,
           title=f"Diagnostic Report - {device.name}",
       )
       doc.build(story)


   # NETWORK REPORT — network-wide PDF (uptime per device, incidents, top
   # bandwidth consumers, plain-language recommendations). The numbers and
   # the PDF layout live in report_builder.py; this is only the button
   # flow: pick a period -> pick a file -> build on a background thread.
   def _open_network_report(self, engine):
       owner = self
       dialog = ctk.CTkToplevel(owner)
       dialog.overrideredirect(True)
       dialog.attributes("-topmost", True)
       dialog.configure(fg_color="#0a0a0a")
       self._center_popup(dialog, 420, 300)
       dialog.lift()
       dialog.grab_set()
       dialog.focus_force()

       card = ctk.CTkFrame(dialog, fg_color="#121212", border_width=2,
                           border_color="#007AFF", corner_radius=10)
       card.pack(fill="both", expand=True)

       ctk.CTkLabel(
           card, text="GROUP REPORT" if getattr(engine, "is_group", False) else "NETWORK REPORT",
           font=("Arial Black", 14),
           text_color="#007AFF"
       ).pack(anchor="w", padx=20, pady=(20, 6))
       ctk.CTkLabel(
           card, text=f"{engine.label}\nChoose the period the report should cover.",
           font=("Courier New", 12), text_color="#999999",
           wraplength=370, justify="left", anchor="w"
       ).pack(anchor="w", padx=20, fill="x")

       def _close():
           dialog.grab_release()
           dialog.destroy()
           try:
               self.focus_force()
           except Exception:
               pass

       def _pick(hours):
           _close()
           self._export_network_report(engine, hours)

       choices = ctk.CTkFrame(card, fg_color="transparent")
       choices.pack(fill="x", padx=20, pady=(14, 0))
       for label, hours in (("LAST 24 HOURS", 24), ("LAST 7 DAYS", 24 * 7), ("LAST 30 DAYS", 24 * 30)):
           ctk.CTkButton(
               choices, text=label, height=34, fg_color="#1E1E1E",
               border_color="#007AFF", border_width=1, text_color="#007AFF",
               hover_color="#262626", font=("Arial Black", 11),
               command=lambda h=hours: _pick(h)
           ).pack(fill="x", pady=3)

       ctk.CTkButton(
           card, text="CANCEL", width=150, height=32, fg_color="#1E1E1E",
           border_color="#444444", border_width=1, text_color="#AAAAAA",
           hover_color="#262626", font=("Arial Bold", 11), command=_close
       ).pack(side="bottom", pady=(0, 14))
       dialog.bind("<Escape>", lambda e: _close())


   def _export_network_report(self, engine, hours):
       """Asks where to save, then gathers the data and renders the PDF on
       a background thread (history_store reads + reportlab layout are real
       work that would otherwise freeze the whole app, same reasoning as
       _export_diagnostic_pdf). Only the final result popup hops back to the
       main thread."""
       safe_label = re.sub(r"[^A-Za-z0-9_-]+", "_", engine.label)
       default_name = f"{'group' if getattr(engine, 'is_group', False) else 'network'}_report_{safe_label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
       path = filedialog.asksaveasfilename(
           parent=self,
           title="Save Network Report as PDF",
           defaultextension=".pdf",
           initialfile=default_name,
           filetypes=[("PDF files", "*.pdf")],
       )
       if not path:
           return  # cancelled

       def worker():
           try:
               data = report_builder.gather_report_data(engine, hours)
               report_builder.build_network_report_pdf(path, data)
           except Exception as exc:
               result = (False, str(exc))
           else:
               result = (True, path)

           def finish():
               kind = "group" if getattr(engine, "is_group", False) else "network"
               if result[0]:
                   self._show_confirm_popup(
                       "REPORT SAVED", f"Saved {kind} report to:\n{result[1]}",
                       on_confirm=lambda: None, confirm_text="OK",
                       danger=False, single_button=True)
               else:
                   self._show_confirm_popup(
                       "EXPORT FAILED", f"Could not create the report:\n{result[1]}",
                       on_confirm=lambda: None, confirm_text="OK",
                       single_button=True)

           try:
               self.after(0, finish)
           except Exception:
               pass

       threading.Thread(target=worker, daemon=True).start()


   def refresh_auto_troubleshoot_log(self, engine):
       """Render the Troubleshoot Log grouped and compiled PER DEVICE.

       Every automatic repair entry carries the device IP/MAC from the
       engine. The page therefore shows one device section at a time instead
       of mixing the repair steps of different devices into one timeline.
       """
       panel = self._panels.get(id(engine))
       if not panel:
           return

       log_box = panel.get("troubleshoot_log")
       if log_box is None or not log_box.winfo_exists():
           return

       # IMPORTANT:
       # Automatic troubleshoot messages must NEVER populate this textbox
       # before the user selects a device.  The engine can still collect the
       # records in auto_troubleshoot_logs, but this page stays visually
       # empty until a device is explicitly clicked.
       selected = panel.get("troubleshoot_selected_device")
       if selected is None:
           log_box.configure(state="normal")
           log_box.delete("1.0", "end")
           log_box.configure(state="disabled")
           summary_label = panel.get("troubleshoot_summary_label")
           if summary_label is not None and summary_label.winfo_exists():
               summary_label.configure(text=_format_troubleshoot_summary(None, []))
           return

       # Once a device is selected, only that device's records may be shown.
       target_ip = str(getattr(selected, "ip", "")).strip()
       if not target_ip:
           return

       # Reuse the exact IP-filtering logic from the troubleshoot page.
       # We intentionally render only the currently selected device.
       target_ip = str(getattr(selected, "ip", "")).strip()

       with engine.lock:
           raw_logs = list(getattr(engine, "auto_troubleshoot_logs", []))

       lines = []
       current_ip = None

       for raw in raw_logs:
           line = str(raw).strip()
           if line.startswith("> "):
               line = line[2:].lstrip()

           match = re.search(
               r"(?:OFFLINE DEVICE DETECTED|AUTO-TROUBLESHOOT STARTED FOR|"
               r"RECOVERED|UNRESOLVED):?.*?\(([^()]+)\)",
               line,
               re.IGNORECASE,
           )
           if match:
               current_ip = match.group(1).strip()
               if current_ip == target_ip:
                   lines.append(line)
               continue

           if current_ip == target_ip:
               lines.append(line)

       log_box.configure(state="normal")
       log_box.delete("1.0", "end")

       if lines:
           log_box.insert("end", "\n".join(lines) + "\n")
       else:
           log_box.insert(
               "end",
               f"> No automatic troubleshooting log for {target_ip} yet.\n"
           )

       log_box.configure(state="disabled")
       log_box.see("end")

       summary_label = panel.get("troubleshoot_summary_label")
       if summary_label is not None and summary_label.winfo_exists():
           summary_label.configure(text=_format_troubleshoot_summary(selected, lines))


   def append_auto_troubleshoot_log_line(self, engine, msg):
       """Refresh the grouped per-device log after a new entry arrives.

       The old implementation appended a raw line because all entries were
       one shared timeline. Since entries are now compiled into device
       sections, rebuilding the bounded log keeps every line under the
       correct device header and also respects the active IP filter.
       """
       self.refresh_auto_troubleshoot_log(engine)


   def update_status(self, text, bg_color, text_color):
       self.after(0, lambda: self.status_bar.configure(text=text, fg_color=bg_color, text_color=text_color))


   @staticmethod
   def _engine_usage_bytes(engine):
       """The running ESTIMATED consumption of one network or group — the
       same figure the Bandwidth page shows as TOTAL NETWORK CONSUMPTION.
       Read straight from the engine's own counter (no snapshot call, so
       ranking many networks/groups every cycle stays cheap)."""
       try:
           if getattr(engine, "is_group", False):
               return float(getattr(engine, "_network_total", 0.0) or 0.0)
           with engine.lock:
               return float(getattr(engine, "_bw_network_estimated_bytes", 0.0) or 0.0)
       except Exception:
           return 0.0

   def _compute_usage_ranking(self):
       """Ranks every monitored network by its estimated usage, and the
       groups of each network against each other. (A group is a slice of
       its network, so groups are never ranked against networks.)

       Returns {"networks": [...], "by_engine": {id(engine): info}} where
       each network entry is {"engine", "label", "bytes", "groups": [...]}
       (both lists sorted highest usage first) and info is
       {"rank", "count", "bytes", "kind", "top_group"}."""
       networks = []
       for net in self._network_engines():
           groups = []
           for g in list(getattr(net, "groups", {}).values()):
               groups.append({"engine": g, "label": g.name,
                              "bytes": self._engine_usage_bytes(g)})
           groups.sort(key=lambda r: r["bytes"], reverse=True)
           networks.append({"engine": net, "label": net.label,
                            "bytes": self._engine_usage_bytes(net),
                            "groups": groups})
       networks.sort(key=lambda r: r["bytes"], reverse=True)

       by_engine = {}
       for i, n in enumerate(networks, start=1):
           top_group = n["groups"][0] if n["groups"] and n["groups"][0]["bytes"] > 0 else None
           by_engine[id(n["engine"])] = {
               "rank": i, "count": len(networks), "bytes": n["bytes"],
               "kind": "network", "top_group": top_group}
           for j, g in enumerate(n["groups"], start=1):
               by_engine[id(g["engine"])] = {
                   "rank": j, "count": len(n["groups"]), "bytes": g["bytes"],
                   "kind": "group", "top_group": None}
       return {"networks": networks, "by_engine": by_engine}

   def _open_usage_ranking_page(self):
       """In-app page ranking every network by estimated usage, with each
       network's groups ranked underneath it. The highest of each list is
       marked HIGHEST. Refreshes itself every 2 seconds while open."""
       self._hide_radar_header_controls()

       def _cleanup():
           self._restore_radar_header_controls()

       def _build(page):
           title_row = ctk.CTkFrame(page, fg_color="transparent")
           title_row.pack(fill="x", padx=2, pady=(0, 4))
           ctk.CTkLabel(
               title_row, text="USAGE RANKING",
               font=("Arial Black", 14), text_color="#007AFF"
           ).pack(side="left", anchor="w")
           title_row.pack_configure(pady=(0, 10))

           outer, inner, _canvas, _sb = self._make_smart_scroll(page, bg="#121212")
           outer.pack(fill="both", expand=True, padx=2, pady=(0, 6))

           # Rows are built ONCE and then updated in place. Destroying and
           # re-creating every row/bar every 2s made the page flicker (and
           # CTk widgets are heavy — each one owns a canvas). The rows are
           # only rebuilt when the STRUCTURE changes: a different order,
           # a network/group added or removed, or the HIGHEST marker moving.
           state = {"sig": None, "rows": {}}

           def _row(parent, rank, name, value_bytes, max_bytes, formatter,
                    indent=0, is_top=False, big=False):
               row = ctk.CTkFrame(parent, fg_color="#151515", corner_radius=6)
               row.pack(fill="x", padx=(4 + indent, 4), pady=3)
               color = "#FFB020" if is_top else "#DDDDDD"
               ctk.CTkLabel(
                   row, text=f"#{rank}", width=44, anchor="w",
                   font=("Courier New", 13, "bold"), text_color=color
               ).pack(side="left", padx=(12, 0), pady=10)
               ctk.CTkLabel(
                   row, text=name, width=260, anchor="w",
                   font=("Courier New", 14 if big else 12, "bold"), text_color=color
               ).pack(side="left", padx=(6, 0), pady=10)
               bar = ctk.CTkProgressBar(
                   row, width=320, height=10, fg_color="#252525",
                   progress_color="#FFB020" if is_top else "#007AFF")
               frac = min(1.0, value_bytes / max_bytes) if max_bytes > 0 else 0.0
               bar.set(frac)
               bar.pack(side="left", padx=(6, 12), pady=10)
               text = formatter(value_bytes)
               val_lbl = ctk.CTkLabel(
                   row, text=text, width=110, anchor="w",
                   font=("Courier New", 12, "bold"), text_color=color
               )
               val_lbl.pack(side="left")
               return {"bar": bar, "val": val_lbl, "frac": frac, "text": text}

           def _update_row(widgets, value_bytes, max_bytes, formatter):
               frac = min(1.0, value_bytes / max_bytes) if max_bytes > 0 else 0.0
               if abs(frac - widgets["frac"]) > 0.002:
                   widgets["bar"].set(frac)
                   widgets["frac"] = frac
               text = formatter(value_bytes)
               if text != widgets["text"]:
                   widgets["val"].configure(text=text)
                   widgets["text"] = text

           def _structure_sig(nets):
               sig = []
               for i, n in enumerate(nets, start=1):
                   sig.append(("n", id(n["engine"]), n["label"],
                               i == 1 and len(nets) > 1 and n["bytes"] > 0))
                   groups = n["groups"]
                   for j, g in enumerate(groups, start=1):
                       sig.append(("g", id(g["engine"]), g["label"],
                                   j == 1 and len(groups) > 1 and g["bytes"] > 0))
                   if not groups:
                       sig.append(("x", id(n["engine"])))
               return tuple(sig)

           def _draw():
               ranking = self._compute_usage_ranking()
               nets = ranking["networks"]
               sig = _structure_sig(nets)

               if sig != state["sig"]:
                   # Structure changed (or first draw): rebuild.
                   for w in inner.winfo_children():
                       w.destroy()
                   state["rows"] = {}
                   state["sig"] = sig
                   if not nets:
                       ctk.CTkLabel(
                           inner, text="No networks are being monitored.",
                           font=("Courier New", 13), text_color="#555555"
                       ).pack(anchor="w", padx=14, pady=14)
                       return
                   net_max = max((n["bytes"] for n in nets), default=0.0)
                   for i, n in enumerate(nets, start=1):
                       fmt = n["engine"]._format_bytes
                       state["rows"][id(n["engine"])] = _row(
                           inner, i, n["label"], n["bytes"], net_max, fmt,
                           is_top=(i == 1 and len(nets) > 1 and n["bytes"] > 0), big=True)
                       groups = n["groups"]
                       g_max = max((g["bytes"] for g in groups), default=0.0)
                       for j, g in enumerate(groups, start=1):
                           state["rows"][id(g["engine"])] = _row(
                               inner, j, f"GROUP: {g['label']}", g["bytes"], g_max, fmt,
                               indent=36,
                               is_top=(j == 1 and len(groups) > 1 and g["bytes"] > 0))
                       if not groups:
                           ctk.CTkLabel(
                               inner, text="no groups on this network", anchor="w",
                               font=("Courier New", 11), text_color="#555555"
                           ).pack(anchor="w", padx=(52, 4), pady=(0, 6))
                   return

               # Same structure: just update the numbers/bars in place.
               if not nets:
                   return
               net_max = max((n["bytes"] for n in nets), default=0.0)
               for n in nets:
                   fmt = n["engine"]._format_bytes
                   w = state["rows"].get(id(n["engine"]))
                   if w is not None:
                       _update_row(w, n["bytes"], net_max, fmt)
                   groups = n["groups"]
                   g_max = max((g["bytes"] for g in groups), default=0.0)
                   for g in groups:
                       gw = state["rows"].get(id(g["engine"]))
                       if gw is not None:
                           _update_row(gw, g["bytes"], g_max, fmt)

           def _tick():
               if not page.winfo_exists():
                   return
               try:
                   _draw()
               except Exception:
                   pass
               page.after(2000, _tick)

           _tick()

       self._show_full_page(_build, on_back=_cleanup)

   def _refresh_all_stats(self):
       # Pre-pass (builds/updates panels, so it must finish before the
       # loop below starts iterating self._panels).
       for _panel in list(self._panels.values()):
           _eng = _panel["engine"]
           if getattr(_eng, "is_group", False):
               self._sync_group_header(_panel, _eng)
           elif (not getattr(_eng, "_groups_restored", False)
                 and _eng._identity_event.is_set()):
               _eng._groups_restored = True
               self._restore_groups_for(_eng)

       for panel in self._panels.values():
           engine = panel["engine"]
           # Only the counts below actually need engine.lock, and reading
           # them is fast. Radar/History are Tkinter widget rebuilds that
           # can take real time (History especially — see _draw_history_log)
           # — doing that INSIDE the lock blocked the engine's own monitor
           # thread from updating device status for however long the redraw
           # took, which is exactly what made offline transitions (which
           # both change status AND add a history entry, right as this loop
           # wants to redraw both) feel like a freeze. Grab the lock only
           # long enough to read the counts, then release it before any
           # widget work happens.
           with engine.lock:
               total    = len(engine.devices)
               online   = len([d for d in engine.devices if d.status == "Online"])
               unstable = len([d for d in engine.devices if d.status == "Unstable"])
               idle     = len([d for d in engine.devices if d.status == "Idle"])
               offline  = len([d for d in engine.devices if d.status == "Offline"])
               gateway_ip = engine.gateway_ip

           panel["total_lbl"].configure(text=str(total))
           panel["online_lbl"].configure(text=str(online))
           panel["unstable_lbl"].configure(text=str(unstable))
           panel["idle_lbl"].configure(text=str(idle))
           panel["offline_lbl"].configure(text=str(offline))
           panel["gateway_lbl"].configure(text=f"WIFI GATEWAY: {gateway_ip}")

           radar_win = panel.get("radar_window")
           radar_canvas = panel.get("radar_canvas")
           if radar_win is not None and radar_canvas is not None and radar_win.winfo_exists():
               self._draw_radar(radar_canvas, engine)

               # Radar's own CONNECTED/ONLINE/UNSTABLE/IDLE/OFFLINE cards
               # (only present while the radar page is open) — reuse the
               # counts just computed above instead of re-reading the lock.
               radar_total_lbl    = panel.get("radar_total_lbl")
               radar_online_lbl   = panel.get("radar_online_lbl")
               radar_unstable_lbl = panel.get("radar_unstable_lbl")
               radar_idle_lbl     = panel.get("radar_idle_lbl")
               radar_offline_lbl  = panel.get("radar_offline_lbl")
               if radar_total_lbl is not None:
                   radar_total_lbl.configure(text=str(total))
               if radar_online_lbl is not None:
                   radar_online_lbl.configure(text=str(online))
               if radar_unstable_lbl is not None:
                   radar_unstable_lbl.configure(text=str(unstable))
               if radar_idle_lbl is not None:
                   radar_idle_lbl.configure(text=str(idle))
               if radar_offline_lbl is not None:
                   radar_offline_lbl.configure(text=str(offline))

           history_win = panel.get("history_window")
           if history_win is not None and history_win.winfo_exists():
               self._draw_history_log(
                   history_win, panel["history_body"], panel["history_canvas"], panel["history_scrollbar"], engine, panel)

           # Troubleshoot Log no longer needs a poll here — add_auto_troubleshoot_log
           # pushes each new line to the widget itself as it happens, so
           # re-rebuilding the whole thing again every 2s was pure waste
           # (and, before the lock fix above, extra time spent holding
           # engine.lock for no benefit).
       self._refresh_job = self.after(2000, self._refresh_all_stats)