"""
Dashboard view for Sentinel Password Auditor.

Displays system health, platform detection, dictionary metrics, privilege status,
and high-level executive security posture cards with clean, enterprise-grade design.
"""

import logging
import platform
import sys
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any, Callable, Dict, Optional

import customtkinter as ctk

from core.config import (
    APP_NAME,
    APP_VERSION,
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
)
from core.dictionary_manager import DictionaryManager

logger = logging.getLogger(__name__)


class DashboardView(ctk.CTkFrame):
    """Clean cybersecurity dashboard page."""

    def __init__(
        self,
        master: Any,
        dict_manager: DictionaryManager,
        navigate_callback: Optional[Callable[[str], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=BG_MAIN, **kwargs)
        self.dict_manager = dict_manager
        self.navigate_callback = navigate_callback

        self._build_ui()

    def _build_ui(self) -> None:
        # Header banner
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=30, pady=(24, 14))

        title_lbl = ctk.CTkLabel(
            header_frame,
            text=f"{APP_NAME}",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        title_lbl.pack(anchor="w")

        subtitle_lbl = ctk.CTkLabel(
            header_frame,
            text=f"Version {APP_VERSION} · Automated Credential Auditing & Defensive Policy Assessment",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        )
        subtitle_lbl.pack(anchor="w", pady=(2, 0))

        # Main Scrollable / Card Container
        cards_container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        cards_container.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        # Top row: System Info & Dictionary Cards
        top_grid = ctk.CTkFrame(cards_container, fg_color="transparent")
        top_grid.pack(fill="x", pady=(0, 14))
        top_grid.grid_columnconfigure((0, 1), weight=1, uniform="top_cards")

        self._create_system_card(top_grid, col=0)
        self._create_dict_card(top_grid, col=1)

        # Middle row: Security Assessment & Quick Actions
        mid_grid = ctk.CTkFrame(cards_container, fg_color="transparent")
        mid_grid.pack(fill="x", pady=(0, 14))
        mid_grid.grid_columnconfigure((0, 1), weight=1, uniform="mid_cards")

        self._create_summary_card(mid_grid, col=0)
        self._create_quick_actions_card(mid_grid, col=1)

        # Bottom row: Defensive Guidelines card
        self._create_guidelines_card(cards_container)

    def _create_system_card(self, parent: ctk.CTkFrame, col: int) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.grid(row=0, column=col, padx=(0, 8), sticky="nsew", ipady=8)

        ctk.CTkLabel(
            card,
            text="System Environment",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        os_name = platform.system()
        os_release = platform.release()
        hostname = platform.node()
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

        # Privilege detection
        is_elevated = False
        if os_name == "Windows":
            try:
                import ctypes
                is_elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_elevated = False
        else:
            import os
            is_elevated = os.geteuid() == 0

        priv_text = "Elevated (Administrator)" if is_elevated else "Standard User (Limited Privilege)"
        priv_color = SUCCESS if is_elevated else WARNING

        info_rows = [
            ("Operating System:", f"{os_name} {os_release}"),
            ("Hostname:", hostname),
            ("Python Runtime:", f"Python {py_ver}"),
            ("Privilege Level:", priv_text),
        ]

        for label, val in info_rows:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=3)
            ctk.CTkLabel(
                row,
                text=label,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=TEXT_SECONDARY,
                width=130,
                anchor="w",
            ).pack(side="left")
            color = priv_color if label == "Privilege Level:" else TEXT_PRIMARY
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(size=12), text_color=color).pack(side="left")

    def _create_dict_card(self, parent: ctk.CTkFrame, col: int) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.grid(row=0, column=col, padx=(8, 0), sticky="nsew", ipady=8)

        ctk.CTkLabel(
            card,
            text="Wordlist & Dictionary Engine",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.dict_val_labels: Dict[str, ctk.CTkLabel] = {}

        stats = self.dict_manager.stats
        word_count = self.dict_manager.word_count
        status_text = "Active in Memory (O(1) Set)" if self.dict_manager.is_loaded else "Unloaded"
        status_color = SUCCESS if self.dict_manager.is_loaded else WARNING
        load_time = f"{stats.load_time_seconds:.4f}s" if stats else "0.00s"
        size_human = stats.file_size_human if stats else "N/A"
        fname = Path(self.dict_manager.wordlist_path).name if hasattr(self.dict_manager, "wordlist_path") else "wordlist.txt"

        info_rows = [
            ("dict_file", "Active File:", fname),
            ("status", "Dictionary Status:", status_text),
            ("words", "Unique Passwords:", f"{word_count:,} entries loaded"),
            ("size", "Wordlist Size:", size_human),
            ("time", "Load Time:", load_time),
        ]

        for key, label, val in info_rows:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=20, pady=2)
            ctk.CTkLabel(
                row,
                text=label,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=TEXT_SECONDARY,
                width=130,
                anchor="w",
            ).pack(side="left")
            color = status_color if key == "status" else TEXT_PRIMARY
            val_lbl = ctk.CTkLabel(row, text=val, font=ctk.CTkFont(size=12), text_color=color)
            val_lbl.pack(side="left")
            self.dict_val_labels[key] = val_lbl

        # Action Buttons in Dictionary Card
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(10, 4))

        ctk.CTkButton(
            btn_row,
            text="Reload",
            width=80,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._on_refresh_dict,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="Browse Wordlist...",
            width=130,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=BTN_SECONDARY_FG,
            hover_color=BTN_SECONDARY_HOVER,
            border_color=BTN_SECONDARY_BORDER,
            border_width=1,
            text_color=TEXT_PRIMARY,
            command=self._on_change_dict,
        ).pack(side="left")

    def update_dictionary_stats(self) -> None:
        """Dynamically update dictionary metrics displayed on dashboard."""
        if not hasattr(self, "dict_val_labels") or not self.dict_val_labels:
            return

        stats = self.dict_manager.stats
        word_count = self.dict_manager.word_count
        status_text = "Active in Memory (O(1) Set)" if self.dict_manager.is_loaded else "Unloaded"
        status_color = SUCCESS if self.dict_manager.is_loaded else WARNING
        load_time = f"{stats.load_time_seconds:.4f}s" if stats else "0.00s"
        size_human = stats.file_size_human if stats else "N/A"
        fname = Path(self.dict_manager.wordlist_path).name if hasattr(self.dict_manager, "wordlist_path") else "wordlist.txt"

        if "dict_file" in self.dict_val_labels:
            self.dict_val_labels["dict_file"].configure(text=fname)
        if "status" in self.dict_val_labels:
            self.dict_val_labels["status"].configure(text=status_text, text_color=status_color)
        if "words" in self.dict_val_labels:
            self.dict_val_labels["words"].configure(text=f"{word_count:,} entries loaded")
        if "size" in self.dict_val_labels:
            self.dict_val_labels["size"].configure(text=size_human)
        if "time" in self.dict_val_labels:
            self.dict_val_labels["time"].configure(text=load_time)

    def _on_refresh_dict(self) -> None:
        """Handler for refresh button in dashboard."""
        success = self.dict_manager.reload()
        if success:
            self.update_dictionary_stats()
            parent = self.winfo_toplevel()
            if hasattr(parent, "on_dictionary_updated"):
                parent.on_dictionary_updated()
            messagebox.showinfo(
                "Dictionary Reloaded",
                f"Wordlist successfully reloaded ({self.dict_manager.word_count:,} passwords in memory).",
            )
        else:
            err = self.dict_manager.load_error or "Unknown error"
            messagebox.showerror("Reload Failed", f"Could not reload dictionary:\n{err}")

    def _on_change_dict(self) -> None:
        """Handler for change wordlist button in dashboard."""
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
                self.update_dictionary_stats()
                parent = self.winfo_toplevel()
                if hasattr(parent, "on_dictionary_updated"):
                    parent.on_dictionary_updated()
                messagebox.showinfo(
                    "Wordlist Updated",
                    f"Loaded custom wordlist '{Path(filename).name}' ({self.dict_manager.word_count:,} passwords).",
                )
            else:
                err = self.dict_manager.load_error or "Unknown error"
                messagebox.showerror("Load Failed", f"Could not load custom dictionary:\n{err}")

    def _create_summary_card(self, parent: ctk.CTkFrame, col: int) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.grid(row=0, column=col, padx=(0, 8), sticky="nsew", ipady=8)

        ctk.CTkLabel(
            card,
            text="Recent Audit Summary",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.last_audit_label = ctk.CTkLabel(
            card,
            text="No system audit has been performed in this session.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
            wraplength=380,
            justify="left",
        )
        self.last_audit_label.pack(anchor="w", padx=20, pady=(0, 14))

    def _create_quick_actions_card(self, parent: ctk.CTkFrame, col: int) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.grid(row=0, column=col, padx=(8, 0), sticky="nsew", ipady=8)

        ctk.CTkLabel(
            card,
            text="Quick Actions",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=4)

        if self.navigate_callback:
            ctk.CTkButton(
                btn_row,
                text="Audit Local Accounts",
                fg_color=PRIMARY,
                hover_color=PRIMARY_HOVER,
                command=lambda: self.navigate_callback("audit"),
                height=34,
            ).pack(side="left", padx=(0, 10), expand=True, fill="x")

            ctk.CTkButton(
                btn_row,
                text="Check Password",
                fg_color="#059669",
                hover_color="#047857",
                command=lambda: self.navigate_callback("checker"),
                height=34,
            ).pack(side="left", expand=True, fill="x")

    def _create_guidelines_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.pack(fill="x", pady=(0, 14), ipady=8)

        ctk.CTkLabel(
            card,
            text="Security & Privacy Controls",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        points = [
            "• Read-Only Operation: Sentinel never modifies /etc/shadow, SAM databases, or account authentication records.",
            "• Zero Secret Retention: Plaintext passwords and raw NTLM hashes are never logged, cached on disk, or exported in report files.",
            "• In-Memory Comparison: Cryptographic hash comparison is executed strictly in volatile process memory.",
            "• Authorized Importer Workflow: Windows and Linux file auditing strictly processes authorized credential dumps within memory.",
        ]
        for p in points:
            ctk.CTkLabel(
                card,
                text=p,
                font=ctk.CTkFont(size=12),
                text_color=TEXT_SECONDARY,
                anchor="w",
            ).pack(anchor="w", padx=20, pady=2)

    def update_last_audit(self, summary_text: str, is_weak: bool = False) -> None:
        """Update the dashboard when an audit finishes."""
        color = DANGER if is_weak else SUCCESS
        self.last_audit_label.configure(text=summary_text, text_color=color)
