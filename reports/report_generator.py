"""
Report generator facade for Sentinel Password Auditor.

Coordinates PDF and JSON audit report generation with sanitization and error handling.
"""

import logging
import tempfile
from pathlib import Path
from typing import Optional, Union

from auditors.audit_result import AuditSummary
from core.config import REPORT_OUTPUT_DIR
from reports.json_generator import generate_json_report
from reports.pdf_generator import generate_pdf_report

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Unified interface for generating PDF and JSON security audit reports."""

    def __init__(self, output_dir: Optional[Union[str, Path]] = None) -> None:
        """
        Initialize the report generator.

        Args:
            output_dir: Directory where reports will be saved. Defaults to REPORT_OUTPUT_DIR.
        """
        self.output_dir = Path(output_dir) if output_dir else REPORT_OUTPUT_DIR
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as exc:
            logger.warning(
                "Report directory '%s' is not writable (%s). Falling back to temporary directory.",
                self.output_dir,
                exc,
            )
            self.output_dir = Path(tempfile.gettempdir()) / "sentinel_reports"
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_pdf(
        self,
        summary: AuditSummary,
        filename: Optional[str] = None,
    ) -> Path:
        """
        Generate a PDF security audit report.

        Args:
            summary: The AuditSummary to report on.
            filename: Optional custom filename. Defaults to audit_report_<type>_<timestamp>.pdf

        Returns:
            Path to the generated PDF.
        """
        if not filename:
            ts = summary.timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"audit_report_{summary.audit_type}_{ts}.pdf"

        target_path = self.output_dir / filename
        return generate_pdf_report(summary, target_path)

    def generate_json(
        self,
        summary: AuditSummary,
        filename: Optional[str] = None,
    ) -> Path:
        """
        Generate a sanitized JSON security audit report.

        Args:
            summary: The AuditSummary to report on.
            filename: Optional custom filename. Defaults to audit_report_<type>_<timestamp>.json

        Returns:
            Path to the generated JSON file.
        """
        if not filename:
            ts = summary.timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"audit_report_{summary.audit_type}_{ts}.json"

        target_path = self.output_dir / filename
        generate_json_report(summary, target_path)
        return target_path
