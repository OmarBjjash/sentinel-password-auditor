"""
Architecture diagram generator for Sentinel Password Auditor.

Generates visual architecture diagrams in PDF and PNG formats using ReportLab Drawing
and graphics primitives, illustrating:
1. System Account Auditor pipeline (Linux /etc/shadow and Windows NTLM input -> Matching Engine)
2. Interactive Password Checker flow (User input -> Checker -> Dictionary & Policy -> Feedback)
"""

import logging
from pathlib import Path
from typing import Optional, Union

from core.config import BASE_DIR

logger = logging.getLogger(__name__)


def generate_architecture_diagram(
    output_pdf_path: Optional[Union[str, Path]] = None,
    output_png_path: Optional[Union[str, Path]] = None,
) -> tuple[Path, Optional[Path]]:
    """
    Generate the system architecture diagram.

    Args:
        output_pdf_path: File path to save the PDF diagram.
        output_png_path: File path to save the PNG diagram (if renderPM available).

    Returns:
        Tuple of (pdf_path, png_path).
    """
    from reportlab.graphics.shapes import (
        Drawing,
        Group,
        Line,
        Polygon,
        Rect,
        String,
    )
    from reportlab.lib import colors

    pdf_out = Path(output_pdf_path) if output_pdf_path else BASE_DIR / "docs" / "architecture_diagram.pdf"
    png_out = Path(output_png_path) if output_png_path else BASE_DIR / "docs" / "architecture_diagram.png"
    pdf_out.parent.mkdir(parents=True, exist_ok=True)

    width = 750
    height = 560
    d = Drawing(width, height)

    # Background
    d.add(Rect(0, 0, width, height, fillColor=colors.HexColor("#0a1628"), strokeColor=None))

    # Header Title
    d.add(
        String(
            width / 2,
            525,
            "Sentinel Password Auditor — System Architecture",
            fontSize=18,
            fontName="Helvetica-Bold",
            fillColor=colors.HexColor("#ffffff"),
            textAnchor="middle",
        )
    )
    d.add(
        String(
            width / 2,
            505,
            "Defensive Password Auditing, Policy Evaluation & Assessment Framework",
            fontSize=11,
            fontName="Helvetica",
            fillColor=colors.HexColor("#94a3b8"),
            textAnchor="middle",
        )
    )

    # Helper function to draw rounded-looking boxes
    def draw_box(x, y, w, h, title, subtitle="", bg_color="#132040", stroke_color="#2196F3", text_color="#ffffff"):
        d.add(Rect(x, y, w, h, rx=5, ry=5, fillColor=colors.HexColor(bg_color), strokeColor=colors.HexColor(stroke_color), strokeWidth=1.5))
        if subtitle:
            d.add(String(x + w / 2, y + h / 2 + 5, title, fontSize=10, fontName="Helvetica-Bold", fillColor=colors.HexColor(text_color), textAnchor="middle"))
            d.add(String(x + w / 2, y + h / 2 - 8, subtitle, fontSize=8, fontName="Helvetica", fillColor=colors.HexColor("#94a3b8"), textAnchor="middle"))
        else:
            d.add(String(x + w / 2, y + h / 2 - 4, title, fontSize=10, fontName="Helvetica-Bold", fillColor=colors.HexColor(text_color), textAnchor="middle"))

    def draw_arrow(x1, y1, x2, y2, color="#2196F3"):
        d.add(Line(x1, y1, x2, y2, strokeColor=colors.HexColor(color), strokeWidth=1.5))
        # Arrowhead
        dx = x2 - x1
        dy = y2 - y1
        length = (dx * dx + dy * dy) ** 0.5
        if length > 0:
            ux = dx / length
            uy = dy / length
            px = -uy * 4
            py = ux * 4
            d.add(Polygon([x2, y2, x2 - ux * 7 + px, y2 - uy * 7 + py, x2 - ux * 7 - px, y2 - uy * 7 - py], fillColor=colors.HexColor(color), strokeColor=None))

    # ── LEFT / SYSTEM AUDITING PIPELINE (X: 40 to 450) ───────────────────────────
    d.add(Rect(30, 40, 440, 445, rx=8, ry=8, fillColor=colors.HexColor("#0d1b2a"), strokeColor=colors.HexColor("#1e3a8a"), strokeWidth=1))
    d.add(String(250, 465, "SYSTEM ACCOUNT AUDITOR PIPELINE", fontSize=11, fontName="Helvetica-Bold", fillColor=colors.HexColor("#60a5fa"), textAnchor="middle"))

    # Top sources: Linux & Windows
    draw_box(50, 395, 170, 45, "Linux Shadow Collector", "/etc/shadow (read-only)", "#1e293b", "#3b82f6")
    draw_box(270, 395, 180, 45, "Windows SAM Collector", "Local SAM & NTLM Import", "#1e293b", "#3b82f6")

    # Platform Auditors
    draw_box(50, 315, 170, 45, "Linux Auditor", "Crypt / SHA-512 / bcrypt", "#1e293b", "#38bdf8")
    draw_box(270, 315, 180, 45, "Windows Auditor", "NTLM Pre-computation & O(1)", "#1e293b", "#38bdf8")

    draw_arrow(135, 395, 135, 360)
    draw_arrow(360, 395, 360, 360)

    # Audit Engine
    draw_box(145, 235, 210, 45, "Audit Engine", "Workflow & Thread Orchestration", "#172554", "#2563eb")
    draw_arrow(135, 315, 220, 280)
    draw_arrow(360, 315, 280, 280)

    # Core components connected to Audit Engine
    draw_box(50, 160, 160, 40, "Password Hasher", "Linux Crypt & NTLM MD4", "#0f172a", "#64748b")
    draw_box(290, 160, 160, 40, "Dictionary Manager", "wordlist.txt (frozenset)", "#0f172a", "#64748b")

    draw_arrow(220, 235, 150, 200)
    draw_arrow(280, 235, 350, 200)

    # Audit Results
    draw_box(160, 95, 180, 40, "Audit Results", "AuditResult & AuditSummary", "#042f2e", "#10b981", "#34d399")
    draw_arrow(150, 160, 220, 135)
    draw_arrow(350, 160, 280, 135)

    # Reporting Output
    draw_box(60, 50, 160, 32, "GUI Results Table", "Responsive Treeview", "#1e293b", "#475569")
    draw_box(280, 50, 170, 32, "PDF & JSON Export", "Sanitized Security Reports", "#1e293b", "#475569")
    draw_arrow(220, 95, 140, 82)
    draw_arrow(280, 95, 360, 82)

    # ── RIGHT / INTERACTIVE PASSWORD CHECKER (X: 490 to 720) ──────────────────────
    d.add(Rect(490, 40, 230, 445, rx=8, ry=8, fillColor=colors.HexColor("#0d1b2a"), strokeColor=colors.HexColor("#047857"), strokeWidth=1))
    d.add(String(605, 465, "INTERACTIVE CHECKER", fontSize=11, fontName="Helvetica-Bold", fillColor=colors.HexColor("#34d399"), textAnchor="middle"))

    draw_box(515, 395, 180, 45, "User Input", "Masked Password Field (*)", "#1e293b", "#10b981")
    draw_box(515, 315, 180, 45, "Password Checker", "Normalization & Lookups", "#1e293b", "#10b981")
    draw_arrow(605, 395, 605, 360, "#10b981")

    draw_box(515, 235, 180, 45, "Dictionary Check", "Case-Insensitive (O(1))", "#064e3b", "#059669")
    draw_arrow(605, 315, 605, 280, "#10b981")

    draw_box(515, 155, 180, 45, "Password Policy Analyzer", "Diversity, Sequence, Length", "#064e3b", "#059669")
    draw_arrow(605, 235, 605, 200, "#10b981")

    draw_box(515, 65, 180, 55, "Immediate Feedback", "Score (0-100), Level & Advice\n(No password logged/stored)", "#042f2e", "#34d399", "#6ee7b7")
    draw_arrow(605, 155, 605, 120, "#10b981")

    # Render PDF
    from reportlab.graphics import renderPDF
    renderPDF.drawToFile(d, str(pdf_out))
    logger.info("Architecture diagram PDF created at: %s", pdf_out)

    # Render PNG using Pillow
    png_result_path = None
    try:
        from PIL import Image, ImageDraw, ImageFont

        img_w, img_h = 1000, 750
        img = Image.new("RGB", (img_w, img_h), color="#0a1628")
        draw = ImageDraw.Draw(img)

        # Title
        draw.text((img_w // 2, 30), "Sentinel Password Auditor — System Architecture", fill="#ffffff", anchor="mm")
        draw.text((img_w // 2, 55), "Defensive Password Auditing, Policy Evaluation & Assessment Framework", fill="#94a3b8", anchor="mm")

        def pil_box(x, y, w, h, title, subtitle="", bg="#132040", stroke="#2196F3"):
            draw.rounded_rectangle([x, y, x + w, y + h], radius=6, fill=bg, outline=stroke, width=2)
            if subtitle:
                draw.text((x + w // 2, y + h // 2 - 8), title, fill="#ffffff", anchor="mm")
                draw.text((x + w // 2, y + h // 2 + 10), subtitle, fill="#94a3b8", anchor="mm")
            else:
                draw.text((x + w // 2, y + h // 2), title, fill="#ffffff", anchor="mm")

        def pil_arrow(x1, y1, x2, y2, color="#2196F3"):
            draw.line([x1, y1, x2, y2], fill=color, width=2)
            # small arrow head
            draw.polygon([(x2, y2), (x2 - 5, y2 - 6), (x2 + 5, y2 - 6)], fill=color)

        # Left panel (Auditor)
        draw.rounded_rectangle([40, 80, 620, 710], radius=8, fill="#0d1b2a", outline="#1e3a8a", width=2)
        draw.text((330, 105), "SYSTEM ACCOUNT AUDITOR PIPELINE", fill="#60a5fa", anchor="mm")

        pil_box(60, 130, 230, 60, "Linux Shadow Collector", "/etc/shadow (read-only)", "#1e293b", "#3b82f6")
        pil_box(370, 130, 250, 60, "Windows SAM Collector", "Local SAM & NTLM Import", "#1e293b", "#3b82f6")

        pil_box(60, 230, 230, 60, "Linux Auditor", "Crypt / SHA-512 / bcrypt", "#1e293b", "#38bdf8")
        pil_box(370, 230, 250, 60, "Windows Auditor", "NTLM Pre-computation & O(1)", "#1e293b", "#38bdf8")

        draw.line([175, 190, 175, 230], fill="#38bdf8", width=2)
        draw.line([495, 190, 495, 230], fill="#38bdf8", width=2)

        pil_box(180, 330, 300, 65, "Audit Engine", "Workflow & Thread Orchestration", "#172554", "#2563eb")
        draw.line([175, 290, 280, 330], fill="#2563eb", width=2)
        draw.line([495, 290, 380, 330], fill="#2563eb", width=2)

        pil_box(60, 440, 220, 55, "Password Hasher", "Linux Crypt & NTLM MD4", "#0f172a", "#64748b")
        pil_box(380, 440, 220, 55, "Dictionary Manager", "wordlist.txt (frozenset)", "#0f172a", "#64748b")
        draw.line([280, 395, 170, 440], fill="#64748b", width=2)
        draw.line([380, 395, 490, 440], fill="#64748b", width=2)

        pil_box(200, 540, 260, 55, "Audit Results", "AuditResult & AuditSummary", "#042f2e", "#10b981")
        draw.line([170, 495, 280, 540], fill="#10b981", width=2)
        draw.line([490, 495, 380, 540], fill="#10b981", width=2)

        pil_box(70, 630, 220, 50, "GUI Results Table", "Responsive Treeview", "#1e293b", "#475569")
        pil_box(370, 630, 230, 50, "PDF & JSON Export", "Sanitized Security Reports", "#1e293b", "#475569")
        draw.line([280, 595, 180, 630], fill="#475569", width=2)
        draw.line([380, 595, 485, 630], fill="#475569", width=2)

        # Right panel (Password Checker)
        draw.rounded_rectangle([660, 80, 960, 710], radius=8, fill="#0d1b2a", outline="#047857", width=2)
        draw.text((810, 105), "INTERACTIVE CHECKER", fill="#34d399", anchor="mm")

        pil_box(685, 130, 250, 60, "User Input", "Masked Password Field (*)", "#1e293b", "#10b981")
        pil_box(685, 235, 250, 60, "Password Checker", "Normalization & Lookups", "#1e293b", "#10b981")
        draw.line([810, 190, 810, 235], fill="#10b981", width=2)

        pil_box(685, 340, 250, 60, "Dictionary Check", "Case-Insensitive (O(1))", "#064e3b", "#059669")
        draw.line([810, 295, 810, 340], fill="#10b981", width=2)

        pil_box(685, 450, 250, 60, "Password Policy Analyzer", "Diversity, Sequence, Length", "#064e3b", "#059669")
        draw.line([810, 400, 810, 450], fill="#10b981", width=2)

        pil_box(685, 570, 250, 80, "Immediate Feedback", "Score (0-100), Level & Advice\n(No password logged/stored)", "#042f2e", "#34d399")
        draw.line([810, 510, 810, 570], fill="#10b981", width=2)

        img.save(str(png_out), format="PNG")
        png_result_path = png_out
        logger.info("Architecture diagram PNG created at: %s", png_out)
    except Exception as exc:
        logger.warning("Could not render PNG with Pillow: %s", exc)

    return pdf_out, png_result_path


if __name__ == "__main__":
    generate_architecture_diagram()
