"""
JSON report generator for Sentinel Password Auditor.

Exports audit results into a structured, sanitized JSON format. Ensures
that no plaintext passwords, raw password hashes, or sensitive credentials
are ever included in exported reports.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from auditors.audit_result import AuditResult, AuditSummary
from core.config import APP_NAME, APP_VERSION

logger = logging.getLogger(__name__)


def generate_json_report(
    summary: AuditSummary,
    output_path: Optional[Union[str, Path]] = None,
    indent: int = 2,
) -> str:
    """
    Generate a sanitized JSON report from an AuditSummary.

    Args:
        summary: The AuditSummary instance containing audit results.
        output_path: Optional file path to save the JSON report.
        indent: Indentation spaces for pretty-printed JSON.

    Returns:
        The JSON string representation.
    """
    report_dict = summary.to_dict(include_sensitive=False)

    # Augment with tool metadata
    sanitized_report: Dict[str, Any] = {
        "report_metadata": {
            "application": APP_NAME,
            "version": APP_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "format": "JSON",
            "security_notice": (
                "This report has been automatically sanitized. No plaintext passwords "
                "or raw cryptographic hashes are stored or displayed."
            ),
        },
        "audit_summary": {
            "audit_type": report_dict.get("audit_type", "unknown"),
            "timestamp": report_dict.get("timestamp"),
            "os_info": report_dict.get("os_info", {}),
            "statistics": {
                "total_accounts": report_dict.get("total_accounts", 0),
                "weak_accounts": report_dict.get("weak_accounts", 0),
                "strong_accounts": report_dict.get("strong_accounts", 0),
                "locked_accounts": report_dict.get("locked_accounts", 0),
                "error_accounts": report_dict.get("error_accounts", 0),
                "unsupported_accounts": report_dict.get("unsupported_accounts", 0),
            },
            "error_message": report_dict.get("error_message"),
        },
        "account_findings": [],
    }

    # Add sanitized per-account findings
    for account in report_dict.get("results", []):
        finding = {
            "username": account.get("username"),
            "algorithm": account.get("algorithm"),
            "status": account.get("status"),
            "is_weak": account.get("is_weak"),
            "recommendation": account.get("recommendation"),
            "audit_type": account.get("audit_type"),
            "timestamp": account.get("timestamp"),
        }
        sanitized_report["account_findings"].append(finding)

    json_content = json.dumps(sanitized_report, indent=indent)

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(json_content)
        logger.info("JSON report written to: %s", out)

    return json_content
