"""
Reports view for Sentinel Password Auditor.

Provides user interface for viewing audit summaries, previewing sanitized reports,
and exporting professional PDF and JSON reports with clean enterprise design.
"""

import logging
from tkinter import filedialog, messagebox
from typing import Any, Optional

import customtkinter as ctk

from auditors.audit_result import AuditSummary
from core.config import (
    BG_CARD,
    BG_DARK,
    BG_HOVER,
    BG_INPUT,
    BG_MAIN,
    BORDER_COLOR,
    DANGER,
    PRIMARY,
    PRIMARY_HOVER,
    REPORT_OUTPUT_DIR,
    SUCCESS,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    WARNING,
)
from reports.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


class ReportsView(ctk.CTkFrame):
    """View for exporting and reviewing security audit reports."""

    def __init__(
        self,
        master: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=BG_MAIN, **kwargs)
        try:
            self.report_generator = ReportGenerator()
        except Exception as exc:
            logger.warning("Could not initialize default ReportGenerator: %s", exc)
            self.report_generator = None
        self.current_summary: Optional[AuditSummary] = None

        self._build_ui()

    def _build_ui(self) -> None:
        # Title
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=(24, 10))

        ctk.CTkLabel(
            header,
            text="Audit Reports & Documentation",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="Generate sanitized PDF compliance reports and structured JSON exports for defensive auditing records.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", pady=(2, 0))

        # Main layout: Split into Action Controls & JSON Preview
        content_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=30, pady=(10, 20))

        # Action Cards (Top)
        actions_card = ctk.CTkFrame(
            content_frame,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        actions_card.pack(fill="x", pady=(0, 14), ipady=6)
        actions_card.pack_propagate(True)

        ctk.CTkLabel(
            actions_card,
            text="Export Actions",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(12, 8))

        btn_row = ctk.CTkFrame(actions_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(0, 10))

        self.btn_export_pdf = ctk.CTkButton(
            btn_row,
            text="Export PDF Report",
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            height=36,
            font=ctk.CTkFont(weight="bold"),
            command=self._export_pdf,
        )
        self.btn_export_pdf.pack(side="left", padx=(0, 12))

        self.btn_export_json = ctk.CTkButton(
            btn_row,
            text="Export JSON Report",
            fg_color="#059669",
            hover_color="#047857",
            height=36,
            font=ctk.CTkFont(weight="bold"),
            command=self._export_json,
        )
        self.btn_export_json.pack(side="left", padx=(0, 12))

        self.lbl_status = ctk.CTkLabel(
            btn_row,
            text="No audit summary loaded. Perform an audit in 'System Audit' first.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        )
        self.lbl_status.pack(side="left", padx=5)

        # Preview Container (Bottom)
        preview_card = ctk.CTkFrame(
            content_frame,
            fg_color=BG_CARD,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            height=380,
        )
        preview_card.pack_propagate(False)
        preview_card.pack(fill="x", expand=True, ipady=8)

        ctk.CTkLabel(
            preview_card,
            text="Sanitized Report Preview (JSON)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=PRIMARY,
        ).pack(anchor="w", padx=20, pady=(14, 8))

        self.txt_preview = ctk.CTkTextbox(
            preview_card,
            fg_color=BG_INPUT,
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=TEXT_PRIMARY,
        )
        self.txt_preview.pack(fill="both", expand=True, padx=20, pady=(0, 14))
        self.txt_preview.insert(
            "1.0",
            "// Run an audit from the System Audit tab to populate the report preview.\n"
            "// All sensitive secrets (plaintext passwords, raw hashes) are automatically excluded.\n",
        )

    def set_audit_summary(self, summary: AuditSummary) -> None:
        """Receive newly completed audit summary to preview."""
        self.current_summary = summary
        from reports.json_generator import generate_json_report

        json_str = generate_json_report(summary, indent=2)
        self.txt_preview.delete("1.0", "end")
        self.txt_preview.insert("1.0", json_str)

        self.lbl_status.configure(
            text=f"Ready to export: {summary.total_accounts} accounts ({summary.weak_accounts} weak)",
            text_color=SUCCESS,
        )

    def _export_pdf(self) -> None:
        if not self.current_summary:
            messagebox.showwarning("No Audit Data", "Please execute an audit first before generating a report.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save PDF Security Report",
            initialdir=str(REPORT_OUTPUT_DIR),
            defaultextension=".pdf",
            filetypes=[("PDF Document", "*.pdf")],
            initialfile=f"Sentinel_Audit_Report_{self.current_summary.audit_type}.pdf",
        )
        if not filename:
            return

        try:
            from reports.pdf_generator import generate_pdf_report

            generate_pdf_report(self.current_summary, filename)
            messagebox.showinfo("Export Success", f"PDF report successfully saved to:\n{filename}")
            self.lbl_status.configure(text=f"PDF saved: {filename}", text_color=SUCCESS)
        except Exception as exc:
            logger.error("Failed to export PDF: %s", exc)
            messagebox.showerror("Export Error", f"Failed to generate PDF report: {exc}")

    def _export_json(self) -> None:
        if not self.current_summary:
            messagebox.showwarning("No Audit Data", "Please execute an audit first before generating a report.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save JSON Audit Report",
            initialdir=str(REPORT_OUTPUT_DIR),
            defaultextension=".json",
            filetypes=[("JSON File", "*.json")],
            initialfile=f"Sentinel_Audit_Report_{self.current_summary.audit_type}.json",
        )
        if not filename:
            return

        try:
            from reports.json_generator import generate_json_report

            generate_json_report(self.current_summary, filename)
            messagebox.showinfo("Export Success", f"JSON report successfully saved to:\n{filename}")
            self.lbl_status.configure(text=f"JSON saved: {filename}", text_color=SUCCESS)
        except Exception as exc:
            logger.error("Failed to export JSON: %s", exc)
            messagebox.showerror("Export Error", f"Failed to generate JSON report: {exc}")
