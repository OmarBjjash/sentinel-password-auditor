"""
Tests for PDF and JSON report generators and sanitization.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch
import pytest

from auditors.audit_result import AuditResult, AuditSummary
from core.config import get_report_output_dir, REPORT_OUTPUT_DIR
from reports.json_generator import generate_json_report
from reports.pdf_generator import generate_pdf_report
from reports.report_generator import ReportGenerator


class TestReports:
    """Tests for reports module."""

    def test_json_generation_structure(self, sample_audit_summary: AuditSummary) -> None:
        json_str = generate_json_report(sample_audit_summary)
        data = json.loads(json_str)

        assert "report_metadata" in data
        assert "audit_summary" in data
        assert "account_findings" in data
        assert data["audit_summary"]["statistics"]["total_accounts"] == 5
        assert data["audit_summary"]["statistics"]["weak_accounts"] == 1

    def test_json_no_plaintext_passwords(self, sample_audit_summary: AuditSummary) -> None:
        """Verify that plaintext passwords are never included in JSON output."""
        json_str = generate_json_report(sample_audit_summary)
        data = json.loads(json_str)

        for finding in data["account_findings"]:
            assert "password" not in finding
            assert "plaintext" not in finding
            assert "matched_word" not in finding

    def test_json_no_raw_hashes(self, sample_audit_summary: AuditSummary) -> None:
        """Verify that raw cryptographic hashes are never included in JSON output."""
        json_str = generate_json_report(sample_audit_summary)
        data = json.loads(json_str)

        for finding in data["account_findings"]:
            assert "hash" not in finding
            assert "raw_hash" not in finding
            assert "ntlm_hash" not in finding

    def test_pdf_generation_file_creation(
        self, sample_audit_summary: AuditSummary, tmp_path: Path
    ) -> None:
        pdf_out = tmp_path / "test_report.pdf"
        result_path = generate_pdf_report(sample_audit_summary, pdf_out)

        assert result_path.exists()
        assert result_path.stat().st_size > 1000  # Non-empty valid PDF

        # Check PDF header
        with open(result_path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"

    def test_empty_audit_results(self, tmp_path: Path) -> None:
        empty_summary = AuditSummary.create_empty("linux", "Access denied")
        pdf_out = tmp_path / "empty_report.pdf"
        result_path = generate_pdf_report(empty_summary, pdf_out)
        assert result_path.exists()

        json_str = generate_json_report(empty_summary)
        data = json.loads(json_str)
        assert data["audit_summary"]["statistics"]["total_accounts"] == 0

    def test_report_generator_facade(
        self, sample_audit_summary: AuditSummary, tmp_path: Path
    ) -> None:
        rg = ReportGenerator(output_dir=tmp_path)
        pdf_path = rg.generate_pdf(sample_audit_summary)
        json_path = rg.generate_json(sample_audit_summary)

        assert pdf_path.exists()
        assert json_path.exists()

    def test_report_generator_default_dir(self) -> None:
        """Verify ReportGenerator safely resolves default output dir without raising."""
        rg = ReportGenerator()
        assert rg.output_dir is not None
        assert rg.output_dir.exists()

    def test_report_generator_fallback_on_unwritable(self) -> None:
        """Verify ReportGenerator falls back to tempdir when output_dir cannot be created."""
        target = Path("Z:/read_only_fake_mount_xyz/reports")
        orig_mkdir = Path.mkdir

        def fake_mkdir(self_path, *args, **kwargs):
            if "read_only_fake_mount" in str(self_path):
                raise OSError(30, "Read-only file system")
            return orig_mkdir(self_path, *args, **kwargs)

        with patch.object(Path, "mkdir", new=fake_mkdir):
            rg = ReportGenerator(output_dir=target)
            assert rg.output_dir != target
            assert rg.output_dir.exists()

    def test_get_report_output_dir_frozen(self) -> None:
        """Verify get_report_output_dir never returns _MEIPASS when frozen."""
        with patch.object(sys, "frozen", True, create=True):
            with patch.object(sys, "_MEIPASS", "/tmp/.mount_sentin123/usr/bin/_internal", create=True):
                resolved_dir = get_report_output_dir()
                assert "_MEIPASS" not in str(resolved_dir)
                assert "/tmp/.mount_sentin123" not in str(resolved_dir)
                assert resolved_dir.exists()
