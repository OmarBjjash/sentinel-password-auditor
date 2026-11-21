"""
PDF report generator using ReportLab for Sentinel Password Auditor.

Generates a professional cybersecurity audit report in PDF format with:
- Title banner and executive summary
- Metadata (date, platform, dictionary stats)
- Metrics breakdown table
- Per-account audit results table
- Remediation recommendations and limitations
- Strict security sanitization (no plaintext passwords, no raw hashes)
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from auditors.audit_result import AuditResult, AuditStatus, AuditSummary
from core.config import APP_NAME, APP_VERSION

# Eager package import for PyInstaller freeze detection
try:
    import reportlab  # noqa: F401
except ImportError:
    pass

logger = logging.getLogger(__name__)


def generate_pdf_report(
    summary: AuditSummary,
    output_path: Union[str, Path],
) -> Path:
    """
    Generate a professional PDF security audit report.

    Args:
        summary: The AuditSummary to report on.
        output_path: File path to save the generated PDF.

    Returns:
        Path to the generated PDF file.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0a1628"),
        fontName="Helvetica-Bold",
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#2196F3"),
        fontName="Helvetica",
        spaceAfter=15,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0a1628"),
        fontName="Helvetica-Bold",
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica",
    )
    body_bold = ParagraphStyle(
        "BodyDarkBold",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#ffffff"),
        fontName="Helvetica-Bold",
    )
    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
        textColor=colors.white,
        fontName="Helvetica-Bold",
    )
    badge_weak = ParagraphStyle(
        "BadgeWeak",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#dc2626"),
        fontName="Helvetica-Bold",
    )
    badge_strong = ParagraphStyle(
        "BadgeStrong",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#16a34a"),
        fontName="Helvetica-Bold",
    )
    badge_locked = ParagraphStyle(
        "BadgeLocked",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#ca8a04"),
        fontName="Helvetica",
    )

    story = []

    # Title & Header
    story.append(Paragraph(f"{APP_NAME}", title_style))
    story.append(
        Paragraph(
            f"Defensive Password Audit & Security Assessment Report — v{APP_VERSION}",
            subtitle_style,
        )
    )
    story.append(
        HRFlowable(
            width="100%",
            thickness=2,
            color=colors.HexColor("#2196F3"),
            spaceBefore=0,
            spaceAfter=15,
        )
    )

    # Metadata & Scope Table
    os_info_str = "Unknown"
    if summary.os_info:
        os_info_str = f"{summary.os_info.get('platform', 'N/A')} ({summary.os_info.get('hostname', 'Localhost')})"

    timestamp_str = summary.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

    meta_data = [
        [
            Paragraph("<b>Audit Type:</b>", body_style),
            Paragraph(summary.audit_type.upper(), body_style),
            Paragraph("<b>Execution Time:</b>", body_style),
            Paragraph(timestamp_str, body_style),
        ],
        [
            Paragraph("<b>Operating System:</b>", body_style),
            Paragraph(os_info_str, body_style),
            Paragraph("<b>Scope:</b>", body_style),
            Paragraph("Local Accounts / Imported Hashes", body_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[110, 155, 110, 155])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # Executive Summary / Statistics Card
    story.append(Paragraph("Executive Summary", section_style))

    status_color = colors.HexColor("#16a34a") if summary.weak_accounts == 0 else colors.HexColor("#dc2626")
    summary_eval = (
        "SECURE: No common dictionary passwords detected."
        if summary.weak_accounts == 0
        else f"ALERT: Detected {summary.weak_accounts} account(s) using weak or dictionary passwords!"
    )

    stats_data = [
        [
            Paragraph("<b>Total Accounts</b>", body_bold),
            Paragraph("<b>Weak / Compromised</b>", body_bold),
            Paragraph("<b>Strong / Unmatched</b>", body_bold),
            Paragraph("<b>Locked / Disabled</b>", body_bold),
            Paragraph("<b>Errors / Unsupported</b>", body_bold),
        ],
        [
            Paragraph(str(summary.total_accounts), title_style),
            Paragraph(str(summary.weak_accounts), title_style),
            Paragraph(str(summary.strong_accounts), title_style),
            Paragraph(str(summary.locked_accounts), title_style),
            Paragraph(str(summary.error_accounts + summary.unsupported_accounts), title_style),
        ],
    ]
    stats_table = Table(stats_data, colWidths=[106, 106, 106, 106, 106])
    stats_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0f172a")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(stats_table)
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            f"<b>Security Assessment:</b> <font color='{status_color.hexval()}'>{summary_eval}</font>",
            body_style,
        )
    )
    story.append(Spacer(1, 15))

    # Detailed Findings Table
    story.append(Paragraph("Account Audit Findings", section_style))

    findings_data = [
        [
            Paragraph("Username", table_header_style),
            Paragraph("Algorithm", table_header_style),
            Paragraph("Audit Status", table_header_style),
            Paragraph("Remediation / Recommendation", table_header_style),
        ]
    ]

    for res in summary.results:
        if res.status == AuditStatus.WEAK_PASSWORD.value:
            status_p = Paragraph("WEAK PASSWORD", badge_weak)
        elif res.status == AuditStatus.STRONG_PASSWORD.value:
            status_p = Paragraph("NOT IN DICTIONARY", badge_strong)
        elif res.status == AuditStatus.LOCKED.value:
            status_p = Paragraph("LOCKED / DISABLED", badge_locked)
        else:
            status_p = Paragraph(res.status, body_style)

        findings_data.append(
            [
                Paragraph(res.username, body_bold),
                Paragraph(res.algorithm, body_style),
                status_p,
                Paragraph(res.recommendation, body_style),
            ]
        )

    if len(findings_data) == 1:
        findings_data.append(
            [
                Paragraph("No records", body_style),
                Paragraph("—", body_style),
                Paragraph("No data available", body_style),
                Paragraph("No accounts were processed during this audit.", body_style),
            ]
        )

    findings_table = Table(findings_data, colWidths=[100, 95, 115, 220])
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )
    )
    story.append(findings_table)
    story.append(Spacer(1, 15))

    # Recommendations & Remediation Section
    story.append(Paragraph("Security Recommendations & Policy Actions", section_style))
    recs = [
        "1. <b>Mandate Immediate Password Changes:</b> Require all accounts flagged with WEAK PASSWORD to reset their passwords immediately.",
        "2. <b>Enforce Password Complexity & Length:</b> Implement minimum length policies of at least 12-16 characters with character diversity.",
        "3. <b>Deploy Multi-Factor Authentication (MFA):</b> Configure MFA across all local and remote administrative access points.",
        "4. <b>Disable Unused and Dormant Accounts:</b> Regularly review locked and inactive accounts and remove obsolete privileges.",
        "5. <b>Modernize Hashing Algorithms:</b> Transition legacy Unix DES/MD5 crypt hashes to SHA-512 crypt or yescrypt.",
    ]
    for r in recs:
        story.append(Paragraph(r, body_style))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 10))

    # Audit Limitations & Security Privacy Notice
    story.append(Paragraph("Audit Scope & Privacy Safeguards", section_style))
    story.append(
        Paragraph(
            "<b>Privacy Safeguards:</b> Sentinel Password Auditor operates strictly under defensive security principles. "
            "No plaintext passwords, raw NTLM hashes, or shadow secrets are retained or stored within this document. "
            "Password verification is executed in volatile memory and discarded immediately upon completion.",
            body_style,
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            "<b>Limitations:</b> This assessment verifies credentials exclusively against the supplied common-password dictionary. "
            "An account evaluated as 'NOT IN DICTIONARY' is not guaranteed to be invulnerable to targeted brute-force attacks.",
            body_style,
        )
    )

    doc.build(story)
    logger.info("PDF report generated successfully at: %s", out_file)
    return out_file
