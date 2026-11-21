"""
System Audit View for Sentinel Password Auditor.

Provides user interface for running:
1. Linux local account auditing via /etc/shadow:
   - Mode A: Live /etc/shadow audit (requires root/sudo)
   - Mode B: Authorized shadow hash file import
2. Windows auditing:
   - Mode A: Real Local SAM audit of the live Windows OS (requires Administrator)
   - Mode B: Authorized NTLM/LM hash file import
Includes stationary progress indicators, background worker threading, results table,
fully scrollable content container for small windows, and direct export actions.
"""

import logging
import platform
import threading
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, List, Optional

import customtkinter as ctk

from auditors.audit_result import AuditResult, AuditStatus, AuditSummary
from collectors.windows_sam_collector import (
    WindowsSAMAcquisitionService,
    detect_windows,
    is_admin,
)
from core.audit_engine import AuditEngine
from core.config import (
    BG_CARD,
    BG_DARK,
    BG_HOVER,
    BG_INPUT,
    BG_MAIN,
    BORDER_COLOR,
    BTN_SECONDARY_BORDER,
    BTN_SECONDARY_FG,
    BTN_SECONDARY_HOVER,
    DANGER,
    PRIMARY,
    PRIMARY_HOVER,
    SUCCESS,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    WARNING,
    get_treeview_colors,
)
from core.dictionary_manager import DictionaryManager

logger = logging.getLogger(__name__)


class SystemAuditView(ctk.CTkFrame):
    """View for executing system-level password audits."""

    def __init__(
        self,
        master: Any,
        dict_manager: DictionaryManager,
        on_audit_complete: Optional[Callable[[AuditSummary], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=BG_MAIN, **kwargs)
        self.dict_manager = dict_manager
        self.on_audit_complete = on_audit_complete
        self.audit_engine = AuditEngine()
        self.current_summary: Optional[AuditSummary] = None
        self.var_show_passwords = ctk.BooleanVar(value=True)
        self.linux_results: List[AuditResult] = []
        self.windows_results: List[AuditResult] = []

        if detect_windows():
            try:
                WindowsSAMAcquisitionService.purge_leftover_temp_hives()
            except Exception:
                pass

        is_win = platform.system().lower() == "windows"
        self.default_font = ctk.CTkFont(size=12)
        self.mono_font = ctk.CTkFont(family="Consolas" if is_win else "monospace", size=11)

        self._build_ui()
        self.update_theme()

    def _build_ui(self) -> None:
        # ── Header ──────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(16, 6))

        ctk.CTkLabel(
            header,
            text="System Account Auditor",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="Audit local accounts across Linux (/etc/shadow) and Windows (Local SAM database & hash exports).",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(2, 0))

        # ── Main Scrollable Container (allows full scrolling on small windows) ──
        self.scroll_container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_container.pack(fill="both", expand=True, padx=24, pady=(0, 10))

        # ── Wordlist / Dictionary Toolbar ───────────────────────────────────
        dict_bar = ctk.CTkFrame(
            self.scroll_container,
            fg_color=BG_INPUT,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        dict_bar.pack(fill="x", pady=(0, 10))

        self.lbl_dict_info = ctk.CTkLabel(
            dict_bar,
            text=self._get_dict_info_text(),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        self.lbl_dict_info.pack(side="left", padx=14, pady=8)

        btn_dict_frame = ctk.CTkFrame(dict_bar, fg_color="transparent")
        btn_dict_frame.pack(side="right", padx=10, pady=6)

        self.btn_refresh_dict = ctk.CTkButton(
            btn_dict_frame,
            text="Reload",
            width=80,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._on_refresh_dict_clicked,
        )
        self.btn_refresh_dict.pack(side="left", padx=(0, 6))

        self.btn_change_dict = ctk.CTkButton(
            btn_dict_frame,
            text="Browse Wordlist...",
            width=135,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._on_change_dict_clicked,
        )
        self.btn_change_dict.pack(side="left")

        # ── Main Tabview for platform separation ─────────────────────────────
        self.tabview = ctk.CTkTabview(self.scroll_container, fg_color=BG_CARD)
        self.tabview.pack(fill="x", expand=True, pady=(0, 10))

        self.tabview.add("Linux Audit (/etc/shadow)")
        self.tabview.add("Windows Audit (Local SAM & NTLM)")

        self._setup_linux_tab()
        self._setup_windows_tab()

        # Automatic platform selection based on current OS
        is_windows = platform.system().lower() == "windows"
        if is_windows:
            self.tabview.set("Windows Audit (Local SAM & NTLM)")
        else:
            self.tabview.set("Linux Audit (/etc/shadow)")

    def _get_dict_info_text(self) -> str:
        """Format current dictionary status string without emojis."""
        path = getattr(self.dict_manager, "wordlist_path", None)
        fname = path.name if path else "wordlist.txt"
        count = self.dict_manager.word_count
        return f"Active Wordlist: {fname}  ({count:,} passwords in memory)"

    def update_dict_display(self) -> None:
        """Update dictionary info label on screen."""
        if hasattr(self, "lbl_dict_info") and self.lbl_dict_info.winfo_exists():
            self.lbl_dict_info.configure(text=self._get_dict_info_text())

    def _on_refresh_dict_clicked(self) -> None:
        """Handle dictionary refresh button click."""
        success = self.dict_manager.reload()
        if success:
            self.update_dict_display()
            parent = self.winfo_toplevel()
            if hasattr(parent, "on_dictionary_updated"):
                parent.on_dictionary_updated()
            messagebox.showinfo(
                "Dictionary Reloaded",
                f"Wordlist successfully reloaded from disk.\n{self._get_dict_info_text()}",
            )
        else:
            err = self.dict_manager.load_error or "Unknown error"
            messagebox.showerror("Reload Failed", f"Could not reload dictionary:\n{err}")

    def _on_change_dict_clicked(self) -> None:
        """Handle pick another dictionary file button click."""
        filename = filedialog.askopenfilename(
            title="Select Custom Wordlist / Password Dictionary",
            filetypes=[
                ("Text & Wordlist Files", "*.txt *.wordlist *.dict *.lst"),
                ("All Files", "*.*"),
            ],
        )
        if filename:
            success = self.dict_manager.load_wordlist(Path(filename))
            if success:
                self.update_dict_display()
                parent = self.winfo_toplevel()
                if hasattr(parent, "on_dictionary_updated"):
                    parent.on_dictionary_updated()
                messagebox.showinfo(
                    "Wordlist Updated",
                    f"Custom wordlist successfully loaded.\n{self._get_dict_info_text()}",
                )
            else:
                err = self.dict_manager.load_error or "Unknown error"
                messagebox.showerror("Load Failed", f"Could not load custom dictionary:\n{err}")

    def _setup_linux_tab(self) -> None:
        tab = self.tabview.tab("Linux Audit (/etc/shadow)")

        # ── Mode A: Live /etc/shadow Audit Card ─────────────────────────────
        mode_a_card = ctk.CTkFrame(
            tab,
            fg_color=BG_INPUT,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        mode_a_card.pack(fill="x", padx=15, pady=(10, 8))

        ctk.CTkLabel(
            mode_a_card,
            text="Mode A: Live /etc/shadow Audit",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=15, pady=(10, 4))

        is_linux = platform.system().lower() == "linux"
        notice_text = (
            "Host system is Linux. Sudo/root privileges required to access /etc/shadow directly."
            if is_linux
            else "Host system is Windows. Linux live /etc/shadow auditing is available when running on Linux."
        )
        notice_color = SUCCESS if is_linux else WARNING

        ctk.CTkLabel(
            mode_a_card,
            text=notice_text,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=notice_color,
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=15, pady=(0, 8))

        btn_row = ctk.CTkFrame(mode_a_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(0, 8))

        self.btn_run_linux = ctk.CTkButton(
            btn_row,
            text="Start Linux Audit",
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._start_linux_audit,
            height=34,
        )
        self.btn_run_linux.pack(side="left", padx=(0, 10))

        self.lbl_linux_status = ctk.CTkLabel(
            btn_row,
            text="Ready",
            font=self.default_font,
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self.lbl_linux_status.pack(side="left", fill="x", expand=True, padx=10)

        # Stationary Progress bar inside Card A (prevents layout shifting and double headers)
        self.linux_live_progress = ctk.CTkProgressBar(
            mode_a_card,
            height=4,
            corner_radius=2,
            fg_color=BG_CARD,
            progress_color=PRIMARY,
        )
        self.linux_live_progress.pack(fill="x", padx=15, pady=(0, 10))
        self.linux_live_progress.set(0)

        # ── Mode B: Import Shadow Hash File Card ───────────────────────────
        mode_b_card = ctk.CTkFrame(
            tab,
            fg_color=BG_INPUT,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        mode_b_card.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(
            mode_b_card,
            text="Mode B: Shadow Hash File Import",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=15, pady=(10, 4))

        ctk.CTkLabel(
            mode_b_card,
            text=(
                "Import an authorized text file containing shadow entries (username:hash or full shadow lines). "
                "Algorithms supported: SHA-512 ($6$), SHA-256 ($5$), yescrypt ($y$), bcrypt ($2b$), MD5 ($1$), DES."
            ),
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY,
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=15, pady=(0, 8))

        file_row = ctk.CTkFrame(mode_b_card, fg_color="transparent")
        file_row.pack(fill="x", padx=15, pady=(0, 8))

        self.entry_linux_hash_file = ctk.CTkEntry(
            file_row,
            placeholder_text="Select shadow hash file (username:hash or full shadow lines)...",
            height=34,
        )
        self.entry_linux_hash_file.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ctk.CTkButton(
            file_row,
            text="Browse...",
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._browse_linux_hash_file,
            width=90,
            height=34,
        ).pack(side="left")

        row_b = ctk.CTkFrame(mode_b_card, fg_color="transparent")
        row_b.pack(fill="x", padx=15, pady=(0, 8))

        self.btn_run_linux_file = ctk.CTkButton(
            row_b,
            text="Start Shadow File Audit",
            fg_color="#059669",
            hover_color="#047857",
            command=self._start_linux_file_audit,
            height=34,
        )
        self.btn_run_linux_file.pack(side="left", padx=(0, 10))

        self.lbl_linux_file_status = ctk.CTkLabel(
            row_b,
            text="Ready",
            font=self.default_font,
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self.lbl_linux_file_status.pack(side="left", fill="x", expand=True, padx=10)

        # Stationary Progress bar inside Card B
        self.linux_file_progress = ctk.CTkProgressBar(
            mode_b_card,
            height=4,
            corner_radius=2,
            fg_color=BG_CARD,
            progress_color=PRIMARY,
        )
        self.linux_file_progress.pack(fill="x", padx=15, pady=(0, 10))
        self.linux_file_progress.set(0)

        # Primary alias for compatibility
        self.linux_progress = self.linux_live_progress

        # Results table
        self._create_results_tree(tab, "linux")

    def _setup_windows_tab(self) -> None:
        tab = self.tabview.tab("Windows Audit (Local SAM & NTLM)")

        # ── Mode A: Real Local SAM Audit Card ───────────────────────────────
        mode_a_card = ctk.CTkFrame(
            tab,
            fg_color=BG_INPUT,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        mode_a_card.pack(fill="x", padx=15, pady=(10, 8))

        ctk.CTkLabel(
            mode_a_card,
            text="Mode A: Live Local SAM Audit (In-Memory Acquisition)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=15, pady=(10, 4))

        # Administrator Privilege Indicator
        is_win = detect_windows()
        is_elevated = is_admin() if is_win else False

        if not is_win:
            priv_badge = "Host system is not Windows (Local SAM audit is unavailable on this OS)."
            priv_color = TEXT_SECONDARY
        elif is_elevated:
            priv_badge = "Elevated Privileges: Running as Administrator (Live Local SAM acquisition available)."
            priv_color = SUCCESS
        else:
            priv_badge = "Standard User Privileges: Run Sentinel as Administrator to perform live Local SAM audits."
            priv_color = WARNING

        self.lbl_admin_indicator = ctk.CTkLabel(
            mode_a_card,
            text=priv_badge,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=priv_color,
            justify="left",
            wraplength=700,
        )
        self.lbl_admin_indicator.pack(anchor="w", padx=15, pady=(0, 8))

        sam_info = (
            "Acquires local account hashes directly from the live Windows SAM database. "
            "Extracted credential secrets exist strictly in volatile memory and are never saved to disk or logged."
        )
        ctk.CTkLabel(
            mode_a_card,
            text=sam_info,
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY,
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=15, pady=(0, 8))

        row_a = ctk.CTkFrame(mode_a_card, fg_color="transparent")
        row_a.pack(fill="x", padx=15, pady=(0, 8))

        self.btn_run_local_sam = ctk.CTkButton(
            row_a,
            text="Start Local SAM Audit",
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            command=self._start_windows_local_sam_audit,
            height=34,
            font=ctk.CTkFont(weight="bold"),
        )
        self.btn_run_local_sam.pack(side="left", padx=(0, 10))

        self.lbl_sam_status = ctk.CTkLabel(
            row_a,
            text="Ready" if is_elevated else "Elevation required",
            font=self.default_font,
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self.lbl_sam_status.pack(side="left", fill="x", expand=True, padx=10)

        # Stationary Progress bar inside Windows Card A
        self.windows_sam_progress = ctk.CTkProgressBar(
            mode_a_card,
            height=4,
            corner_radius=2,
            fg_color=BG_CARD,
            progress_color=PRIMARY,
        )
        self.windows_sam_progress.pack(fill="x", padx=15, pady=(0, 10))
        self.windows_sam_progress.set(0)

        # ── Mode B: Authorized Hash Import Card ────────────────────────
        mode_b_card = ctk.CTkFrame(
            tab,
            fg_color=BG_INPUT,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        mode_b_card.pack(fill="x", padx=15, pady=(0, 10))

        ctk.CTkLabel(
            mode_b_card,
            text="Mode B: Authorized Hash File Import",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=15, pady=(10, 4))

        ctk.CTkLabel(
            mode_b_card,
            text="Import an authorized hash export (pwdump, LM:NT, username:NTLM, or raw NTLM hashes).",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY,
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=15, pady=(0, 8))

        file_row = ctk.CTkFrame(mode_b_card, fg_color="transparent")
        file_row.pack(fill="x", padx=15, pady=(0, 8))

        self.entry_hash_file = ctk.CTkEntry(
            file_row,
            placeholder_text="Select hash file (pwdump, LM:NT, username:NTLM, or raw hashes)...",
            height=34,
        )
        self.entry_hash_file.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ctk.CTkButton(
            file_row,
            text="Browse...",
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._browse_hash_file,
            width=90,
            height=34,
        ).pack(side="left")

        row_b = ctk.CTkFrame(mode_b_card, fg_color="transparent")
        row_b.pack(fill="x", padx=15, pady=(0, 8))

        self.btn_run_windows = ctk.CTkButton(
            row_b,
            text="Start Hash File Audit",
            fg_color="#059669",
            hover_color="#047857",
            command=self._start_windows_audit,
            height=34,
        )
        self.btn_run_windows.pack(side="left", padx=(0, 10))

        self.lbl_windows_status = ctk.CTkLabel(
            row_b,
            text="Ready",
            font=self.default_font,
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        self.lbl_windows_status.pack(side="left", fill="x", expand=True, padx=10)

        # Stationary Progress bar inside Windows Card B
        self.windows_file_progress = ctk.CTkProgressBar(
            mode_b_card,
            height=4,
            corner_radius=2,
            fg_color=BG_CARD,
            progress_color=PRIMARY,
        )
        self.windows_file_progress.pack(fill="x", padx=15, pady=(0, 10))
        self.windows_file_progress.set(0)

        # Primary alias for compatibility
        self.windows_progress = self.windows_sam_progress

        # Results table
        self._create_results_tree(tab, "windows")

    def _create_results_tree(self, parent: ctk.CTkFrame, platform_key: str) -> None:
        # Results Table Toolbar (Heading + Show/Hide Discovered Passwords Switch)
        tb_frame = ctk.CTkFrame(parent, fg_color="transparent")
        tb_frame.pack(fill="x", padx=15, pady=(4, 6))

        ctk.CTkLabel(
            tb_frame,
            text="Audit Findings",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        # Switch to enable/disable showing discovered passwords
        switch_show = ctk.CTkSwitch(
            tb_frame,
            text="Show Discovered Passwords",
            variable=self.var_show_passwords,
            command=self._on_toggle_show_passwords,
            font=ctk.CTkFont(size=12, weight="bold"),
            progress_color=PRIMARY,
        )
        switch_show.pack(side="right")

        # Fixed minimum height container for treeview to ensure it is always readable
        tree_frame = ctk.CTkFrame(parent, fg_color="transparent", height=320)
        tree_frame.pack_propagate(False)
        tree_frame.pack(fill="x", padx=15, pady=(0, 15))

        if platform_key == "linux":
            self.linux_tree_frame = tree_frame
        else:
            self.windows_tree_frame = tree_frame

        # Configure 2D grid for treeview and CustomTkinter scrollbars
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        columns = ("username", "algorithm", "status", "password", "recommendation")
        tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            style="Audit.Treeview",
            selectmode="browse",
        )
        tree.heading("username", text="Username")
        tree.heading("algorithm", text="Algorithm")
        tree.heading("status", text="Audit Status")
        tree.heading("password", text="Discovered Password")
        tree.heading("recommendation", text="Recommendation / Remediation")

        tree.column("username", width=140, minwidth=110, anchor="w", stretch=False)
        tree.column("algorithm", width=110, minwidth=90, anchor="w", stretch=False)
        tree.column("status", width=150, minwidth=130, anchor="center", stretch=False)
        tree.column("password", width=170, minwidth=140, anchor="center", stretch=False)
        tree.column("recommendation", width=550, minwidth=350, anchor="w", stretch=True)

        # Custom-styled rounded CTkScrollbars matching theme
        v_scrollbar = ctk.CTkScrollbar(
            tree_frame,
            orientation="vertical",
            command=tree.yview,
            width=12,
            corner_radius=6,
        )
        h_scrollbar = ctk.CTkScrollbar(
            tree_frame,
            orientation="horizontal",
            command=tree.xview,
            height=12,
            corner_radius=6,
        )
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns", padx=(4, 0))
        h_scrollbar.grid(row=1, column=0, sticky="ew", pady=(4, 0))

        if platform_key == "linux":
            self.linux_tree = tree
        else:
            self.windows_tree = tree

    def update_theme(self, is_dark: Optional[bool] = None) -> None:
        """Update ttk Treeview style and tag colors for Dark or Light appearance."""
        if is_dark is None:
            is_dark = ctk.get_appearance_mode().lower() == "dark"
        colors = get_treeview_colors(is_dark)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        is_win = platform.system().lower() == "windows"
        font_name = "Segoe UI" if is_win else "Helvetica"

        style.configure(
            "Audit.Treeview",
            background=colors["bg"],
            foreground=colors["fg"],
            rowheight=28,
            fieldbackground=colors["bg"],
            font=(font_name, 10),
            borderwidth=0,
        )
        style.configure(
            "Audit.Treeview.Heading",
            background=colors["heading_bg"],
            foreground=colors["heading_fg"],
            relief="flat",
            font=(font_name, 10, "bold"),
            padding=(8, 6),
        )
        style.map(
            "Audit.Treeview",
            background=[("selected", colors["selected_bg"])],
            foreground=[("selected", colors["fg"])],
        )

        for tree in (getattr(self, "linux_tree", None), getattr(self, "windows_tree", None)):
            if tree is not None:
                tree.tag_configure("weak", foreground=colors["weak"])
                tree.tag_configure("strong", foreground=colors["strong"])
                tree.tag_configure("locked", foreground=colors["locked"])
                tree.tag_configure("error", foreground=colors["error"])

    def _render_results_tree(self, platform_key: str) -> None:
        """Render or re-render results into the specified platform treeview."""
        tree = getattr(self, "linux_tree", None) if platform_key == "linux" else getattr(self, "windows_tree", None)
        if tree is None:
            return

        results = self.linux_results if platform_key == "linux" else self.windows_results

        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)

        show_pwd = self.var_show_passwords.get()

        for res in results:
            tag = "error"
            if res.status == AuditStatus.WEAK_PASSWORD.value:
                tag = "weak"
                if show_pwd:
                    pwd_display = res.matched_word if res.matched_word else "<blank>"
                else:
                    pwd_display = "•••••••• (Masked)"
            elif res.status == AuditStatus.STRONG_PASSWORD.value:
                tag = "strong"
                pwd_display = "— (Not Found)"
            elif res.status == AuditStatus.LOCKED.value:
                tag = "locked"
                pwd_display = "— (Account Locked)"
            else:
                pwd_display = "—"

            tree.insert(
                "",
                "end",
                values=(
                    res.username,
                    res.algorithm,
                    res.status,
                    pwd_display,
                    res.recommendation,
                ),
                tags=(tag,),
            )

    def _on_toggle_show_passwords(self) -> None:
        """Handler for toggling discovered passwords visibility."""
        if hasattr(self, "linux_tree"):
            self._render_results_tree("linux")
        if hasattr(self, "windows_tree"):
            self._render_results_tree("windows")

    def _browse_hash_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select Authorized Hash File",
            filetypes=[
                ("Hash & Dump Files", "*.txt *.hash *.hashes *.pwdump"),
                ("All Files", "*.*"),
            ],
        )
        if filename:
            self.entry_hash_file.delete(0, "end")
            self.entry_hash_file.insert(0, filename)

    def _browse_linux_hash_file(self) -> None:
        """Browse for a Linux shadow hash file."""
        filename = filedialog.askopenfilename(
            title="Select Shadow Hash File",
            filetypes=[
                ("Shadow & Hash Files", "*.txt *.shadow *.hash *.hashes"),
                ("All Files", "*.*"),
            ],
        )
        if filename:
            self.entry_linux_hash_file.delete(0, "end")
            self.entry_linux_hash_file.insert(0, filename)

    def _update_progress(self, target: str, current: int, total: int, msg: str) -> None:
        """Update progress bar and status label smoothly without layout jumps."""
        if target == "linux":
            lbl = self.lbl_linux_status
            prog = self.linux_live_progress
        elif target == "linux_file":
            lbl = self.lbl_linux_file_status
            prog = self.linux_file_progress
        elif target == "windows_sam":
            lbl = self.lbl_sam_status
            prog = self.windows_sam_progress
        else:
            lbl = self.lbl_windows_status
            prog = self.windows_file_progress

        lbl.configure(text=msg, font=self.mono_font, text_color=PRIMARY)
        if total > 0 and current > 0:
            try:
                prog.stop()
                prog.configure(mode="determinate")
                prog.set(current / total)
            except Exception:
                pass

    def _start_linux_audit(self) -> None:
        self.btn_run_linux.configure(state="disabled")
        self.btn_run_linux_file.configure(state="disabled")
        self.lbl_linux_status.configure(text="Running Linux shadow audit...", text_color=PRIMARY)

        self.linux_progress = self.linux_live_progress
        self.linux_live_progress.configure(mode="indeterminate")
        self.linux_live_progress.start()

        self.linux_results = []
        self._render_results_tree("linux")

        threading.Thread(target=self._run_linux_audit_worker, daemon=True).start()

    def _run_linux_audit_worker(self) -> None:
        summary = self.audit_engine.run_linux_audit(
            progress_callback=lambda c, t, msg: self.after(
                0, lambda cur=c, tot=t, m=msg: self._update_progress("linux", cur, tot, m)
            )
        )
        self.after(0, lambda: self._on_audit_done(summary, "linux", "linux_live"))

    def _start_linux_file_audit(self) -> None:
        """Handler for Linux Mode B: Shadow hash file audit."""
        shadow_file = self.entry_linux_hash_file.get().strip()
        if not shadow_file:
            messagebox.showwarning("File Required", "Please select a shadow hash file first.")
            return

        self.btn_run_linux.configure(state="disabled")
        self.btn_run_linux_file.configure(state="disabled")
        self.lbl_linux_file_status.configure(text="Running Linux shadow file audit...", text_color=PRIMARY)

        self.linux_progress = self.linux_file_progress
        self.linux_file_progress.configure(mode="indeterminate")
        self.linux_file_progress.start()

        self.linux_results = []
        self._render_results_tree("linux")

        threading.Thread(target=self._run_linux_file_audit_worker, args=(shadow_file,), daemon=True).start()

    def _run_linux_file_audit_worker(self, shadow_file: str) -> None:
        summary = self.audit_engine.run_linux_shadow_file_audit(
            shadow_file,
            progress_callback=lambda c, t, msg: self.after(
                0, lambda cur=c, tot=t, m=msg: self._update_progress("linux_file", cur, tot, m)
            ),
        )
        self.after(0, lambda: self._on_audit_done(summary, "linux", "linux_file"))

    def _start_windows_local_sam_audit(self) -> None:
        """Handler for Mode A: Live Local SAM audit."""
        if not detect_windows():
            messagebox.showerror(
                "Platform Unsupported",
                "Local SAM auditing is only supported on Windows.",
            )
            return

        if not is_admin():
            messagebox.showwarning(
                "Administrator Rights Required",
                "Local SAM acquisition requires Administrator privileges.\n\n"
                "Please close the application and launch it with 'Run as administrator', "
                "or use Mode B below to import an authorized hash export.",
            )
            self.lbl_sam_status.configure(
                text="Acquisition blocked: Administrator rights required.",
                text_color=DANGER,
            )
            return

        self.btn_run_local_sam.configure(state="disabled")
        self.btn_run_windows.configure(state="disabled")
        self.lbl_sam_status.configure(text="Acquiring local SAM hashes...", text_color=PRIMARY)

        self.windows_progress = self.windows_sam_progress
        self.windows_sam_progress.configure(mode="indeterminate")
        self.windows_sam_progress.start()

        self.windows_results = []
        self._render_results_tree("windows")

        threading.Thread(target=self._run_windows_local_sam_worker, daemon=True).start()

    def _run_windows_local_sam_worker(self) -> None:
        summary = self.audit_engine.run_windows_local_sam_audit(
            progress_callback=lambda c, t, msg: self.after(
                0, lambda cur=c, tot=t, m=msg: self._update_progress("windows_sam", cur, tot, m)
            )
        )
        self.after(0, lambda: self._on_audit_done(summary, "windows", "windows_sam"))

    def _start_windows_audit(self) -> None:
        """Handler for Mode B: Authorized Hash file audit."""
        hash_file = self.entry_hash_file.get().strip()
        if not hash_file:
            messagebox.showwarning("File Required", "Please select an authorized hash file first.")
            return

        self.btn_run_windows.configure(state="disabled")
        self.btn_run_local_sam.configure(state="disabled")
        self.lbl_windows_status.configure(text="Running Windows hash audit...", text_color=PRIMARY)

        self.windows_progress = self.windows_file_progress
        self.windows_file_progress.configure(mode="indeterminate")
        self.windows_file_progress.start()

        self.windows_results = []
        self._render_results_tree("windows")

        threading.Thread(target=self._run_windows_audit_worker, args=(hash_file,), daemon=True).start()

    def _run_windows_audit_worker(self, hash_file: str) -> None:
        summary = self.audit_engine.run_windows_audit(
            hash_file,
            progress_callback=lambda c, t, msg: self.after(
                0, lambda cur=c, tot=t, m=msg: self._update_progress("windows_file", cur, tot, m)
            ),
        )
        self.after(0, lambda: self._on_audit_done(summary, "windows", "windows_file"))

    def _on_audit_done(self, summary: AuditSummary, audit_type: str, mode: str = "") -> None:
        self.current_summary = summary
        if mode == "linux_file":
            prog = self.linux_file_progress
        elif mode == "linux_live" or audit_type == "linux":
            prog = self.linux_live_progress
        elif mode == "windows_file":
            prog = self.windows_file_progress
        else:
            prog = self.windows_sam_progress

        # Stop animation and set progress state cleanly without layout shifts
        try:
            prog.stop()
            prog.configure(mode="determinate")
            prog.set(1.0 if summary.total_accounts > 0 else 0.0)
        except Exception:
            pass

        if audit_type == "linux":
            self.btn_run_linux.configure(state="normal")
            if hasattr(self, "btn_run_linux_file"):
                self.btn_run_linux_file.configure(state="normal")
            status_lbl = self.lbl_linux_file_status if mode == "linux_file" else self.lbl_linux_status
            self.linux_results = summary.results
        else:
            self.btn_run_local_sam.configure(state="normal")
            self.btn_run_windows.configure(state="normal")
            status_lbl = self.lbl_windows_status if mode == "windows_file" else self.lbl_sam_status
            self.windows_results = summary.results

        # Populate and render table with discovered password column
        self._render_results_tree(audit_type)

        if summary.error_message:
            status_lbl.configure(text=f"Audit stopped: {summary.error_message}", font=self.default_font, text_color=DANGER)
        else:
            status_msg = f"Completed. {summary.total_accounts} accounts audited, {summary.weak_accounts} weak detected."
            status_lbl.configure(text=status_msg, font=self.default_font, text_color=SUCCESS if summary.weak_accounts == 0 else DANGER)

        if self.on_audit_complete:
            self.on_audit_complete(summary)
