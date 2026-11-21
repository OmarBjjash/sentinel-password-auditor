"""
Main application window for Sentinel Password Auditor.

Provides top-level CTk window with a responsive sidebar navigation menu,
theme management, and view switching between Dashboard, System Audit,
Password Checker, and Reports.
"""

import logging
from typing import Any, Dict, Optional

import customtkinter as ctk

from core.config import (
    APP_NAME,
    APP_VERSION,
    BG_CARD,
    BG_DARK,
    BG_HOVER,
    BG_INPUT,
    BG_MAIN,
    BG_SIDEBAR,
    BORDER_COLOR,
    PRIMARY,
    PRIMARY_HOVER,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)
from core.dictionary_manager import DictionaryManager
from gui.dashboard import DashboardView
from gui.password_checker_view import PasswordCheckerView
from gui.reports_view import ReportsView
from gui.system_audit_view import SystemAuditView

logger = logging.getLogger(__name__)


class SentinelApp(ctk.CTk):
    """Sentinel Password Auditor main GUI window."""

    def __init__(self) -> None:
        super().__init__()

        # Configure CustomTkinter theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1000x640")
        self.minsize(820, 480)
        self.configure(fg_color=BG_MAIN)

        # Initialize core services
        self.dict_manager = DictionaryManager()
        self.dict_manager.load()

        # View registry
        self.views: Dict[str, ctk.CTkFrame] = {}
        self.nav_buttons: Dict[str, ctk.CTkButton] = {}

        self._build_shell()
        self._show_view("dashboard")

    def _build_shell(self) -> None:
        # Layout: Sidebar on left (width ~230), Content frame on right
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ── Sidebar Frame ─────────────────────────────────────────────────────
        self.sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=BG_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        # Brand / Logo Header
        brand_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_frame.pack(fill="x", padx=20, pady=(24, 20))

        ctk.CTkLabel(
            brand_frame,
            text="SENTINEL",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            brand_frame,
            text="Password & Credential Auditor",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(1, 0))

        # Navigation Buttons (clean, professional labels without emoji tropes)
        nav_items = [
            ("dashboard", "Dashboard"),
            ("audit", "System Audit"),
            ("checker", "Password Checker"),
            ("reports", "Audit Reports"),
        ]

        for key, text in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                height=38,
                corner_radius=6,
                fg_color="transparent",
                text_color=TEXT_SECONDARY,
                hover_color=BG_HOVER,
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda k=key: self._show_view(k),
            )
            btn.pack(fill="x", padx=14, pady=3)
            self.nav_buttons[key] = btn

        # ── Sidebar Footer (Appearance Mode + Version) ───────────────────────
        footer_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer_frame.pack(side="bottom", fill="x", padx=16, pady=18)

        ctk.CTkLabel(
            footer_frame,
            text="APPEARANCE",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(0, 6))

        self.theme_selector = ctk.CTkSegmentedButton(
            footer_frame,
            values=["Dark", "Light", "System"],
            command=self._on_theme_changed,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.theme_selector.set("Dark")
        self.theme_selector.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(
            footer_frame,
            text="Local Security Suite",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            footer_frame,
            text=f"v{APP_VERSION} · Python 3.12+",
            font=ctk.CTkFont(size=10),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(1, 0))

        # ── Main Content Container ───────────────────────────────────────────
        self.content_container = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.content_container.grid(row=0, column=1, sticky="nsew")
        self.content_container.grid_rowconfigure(0, weight=1)
        self.content_container.grid_columnconfigure(0, weight=1)

        # Initialize view instances
        self.dashboard_view = DashboardView(
            self.content_container,
            dict_manager=self.dict_manager,
            navigate_callback=self._show_view,
        )
        self.system_audit_view = SystemAuditView(
            self.content_container,
            dict_manager=self.dict_manager,
            on_audit_complete=self._on_audit_completed,
        )
        self.password_checker_view = PasswordCheckerView(
            self.content_container,
            dict_manager=self.dict_manager,
        )
        self.reports_view = ReportsView(
            self.content_container,
        )

        self.views["dashboard"] = self.dashboard_view
        self.views["audit"] = self.system_audit_view
        self.views["checker"] = self.password_checker_view
        self.views["reports"] = self.reports_view

        for view in self.views.values():
            view.grid(row=0, column=0, sticky="nsew")

    def _on_theme_changed(self, mode: str) -> None:
        """Handle theme change between Dark, Light, and System."""
        ctk.set_appearance_mode(mode.lower())
        # Determine actual mode (for System, query CustomTkinter's resolved mode)
        resolved_mode = ctk.get_appearance_mode().lower()
        is_dark = resolved_mode == "dark"

        # Notify registered views to update any ttk / canvas elements
        for view in self.views.values():
            if hasattr(view, "update_theme"):
                view.update_theme(is_dark)

    def _show_view(self, view_key: str) -> None:
        """Switch active view and update button styles."""
        for key, view in self.views.items():
            if key == view_key:
                view.tkraise()
            btn = self.nav_buttons.get(key)
            if btn:
                if key == view_key:
                    btn.configure(fg_color=PRIMARY, text_color=("#FFFFFF", "#FFFFFF"))
                else:
                    btn.configure(fg_color="transparent", text_color=TEXT_SECONDARY)

    def _on_audit_completed(self, summary: Any) -> None:
        """Handle audit completion to sync summary with Dashboard and Reports."""
        # Update reports preview
        self.reports_view.set_audit_summary(summary)

        # Update dashboard last audit card
        summary_text = (
            f"Audit Type: {summary.audit_type.upper()}\n"
            f"Audited Accounts: {summary.total_accounts}\n"
            f"Weak Passwords: {summary.weak_accounts}\n"
            f"Strong Passwords: {summary.strong_accounts}\n"
            f"Status: {'High Risk' if summary.weak_accounts > 0 else 'Secure'}"
        )
        self.dashboard_view.update_last_audit(
            summary_text, is_weak=(summary.weak_accounts > 0)
        )

    def on_dictionary_updated(self) -> None:
        """Handle dictionary updates across all registered views."""
        if hasattr(self, "dashboard_view"):
            self.dashboard_view.update_dictionary_stats()
        if hasattr(self, "system_audit_view"):
            self.system_audit_view.update_dict_display()
