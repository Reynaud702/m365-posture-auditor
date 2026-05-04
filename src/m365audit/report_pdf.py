"""Professional PDF report generator using ReportLab.

Produces a deliverable suitable to hand to a paying client. Cover page,
executive summary with posture grade, severity-ranked findings, and an
appendix table of all checks executed.
"""
from __future__ import annotations

from io import BytesIO
from typing import Any

from .models import AuditReport, Severity

SEVERITY_COLORS = {
    "Critical": "#b91c1c",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#2563eb",
    "Informational": "#6b7280",
}

GRADE_COLORS = {
    "A": "#15803d", "A-": "#16a34a", "B": "#65a30d",
    "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c",
}


def render_pdf(report: AuditReport, output_path: str) -> str:
    """Render the audit report to a PDF file. Returns the output path."""
    # Lazy import so the module can be loaded for type checking without reportlab
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=f"M365 Posture Assessment — {report.tenant_name}",
        author=report.auditor,
    )

    styles = getSampleStyleSheet()
    cover_title = ParagraphStyle(
        "CoverTitle", parent=styles["Title"], fontSize=28, leading=34,
        alignment=TA_CENTER, textColor=colors.HexColor("#0f172a"),
    )
    cover_sub = ParagraphStyle(
        "CoverSub", parent=styles["Normal"], fontSize=14, alignment=TA_CENTER,
        textColor=colors.HexColor("#475569"),
    )
    h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"], fontSize=18, leading=22,
        textColor=colors.HexColor("#0f172a"), spaceBefore=14, spaceAfter=8,
    )
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=14, leading=18,
        textColor=colors.HexColor("#0f172a"), spaceBefore=10, spaceAfter=6,
    )
    h3 = ParagraphStyle(
        "H3", parent=styles["Heading3"], fontSize=11, leading=14,
        textColor=colors.HexColor("#1e293b"), spaceBefore=8, spaceAfter=2,
    )
    body = ParagraphStyle(
        "Body", parent=styles["Normal"], fontSize=10, leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    body_muted = ParagraphStyle(
        "BodyMuted", parent=body, textColor=colors.HexColor("#475569"),
    )

    story: list[Any] = []

    # ---- Cover page ----
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("Microsoft 365", cover_sub))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Security Posture Assessment", cover_title))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"<b>{report.tenant_name}</b>", cover_sub))
    story.append(Spacer(1, 1.5 * inch))

    grade_color = GRADE_COLORS.get(report.posture_grade, "#475569")
    grade_para = Paragraph(
        f'<para alignment="center"><font size="60" color="{grade_color}"><b>{report.posture_grade}</b></font>'
        f'<br/><font size="11" color="#475569">Posture Grade</font></para>',
        body,
    )
    story.append(grade_para)
    story.append(Spacer(1, 0.4 * inch))
    story.append(Paragraph(
        f'<para alignment="center" textColor="#475569">'
        f'Risk Score: <b>{report.risk_score}/100</b></para>', body
    ))
    story.append(Spacer(1, 1.0 * inch))
    story.append(Paragraph(
        f'<para alignment="center" textColor="#94a3b8">'
        f'Generated {report.generated_at.strftime("%B %d, %Y")} &nbsp;|&nbsp; '
        f'Tenant ID: {report.tenant_id}</para>', body_muted
    ))
    story.append(PageBreak())

    # ---- Executive summary ----
    story.append(Paragraph("Executive Summary", h1))
    counts = report.summary_counts

    summary_text = (
        f"This assessment evaluated the Microsoft 365 tenant for {report.tenant_name} "
        f"against {len(report.results)} security controls covering identity, email security, "
        f"data sharing, OAuth applications, and Conditional Access. "
    )
    if counts["Critical"] or counts["High"]:
        summary_text += (
            f"<b>{counts['Critical']} Critical</b> and <b>{counts['High']} High</b> severity "
            "findings were identified that require attention. Critical findings should be "
            "remediated immediately; High findings within 30 days."
        )
    else:
        summary_text += "No Critical or High severity findings were identified."
    story.append(Paragraph(summary_text, body))
    story.append(Spacer(1, 0.2 * inch))

    # Severity counts table
    severity_data = [["Severity", "Count"]]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        severity_data.append([sev.value, str(counts[sev.value])])
    sev_table = Table(severity_data, colWidths=[2.5 * inch, 1 * inch])
    sev_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]
    for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO], start=1):
        sev_style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(SEVERITY_COLORS[sev.value])))
        sev_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)
    story.append(Spacer(1, 0.3 * inch))

    # ---- Findings ----
    story.append(Paragraph("Findings", h1))

    severity_seq = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in severity_seq:
        items = [f for f in report.all_findings if f.severity == sev]
        if not items:
            continue
        sev_color = SEVERITY_COLORS[sev.value]
        story.append(Paragraph(
            f'<font color="{sev_color}"><b>{sev.value} ({len(items)})</b></font>', h2
        ))
        for finding in items:
            story.append(Paragraph(f"<b>{finding.check_id}</b> — {finding.title}", h3))
            story.append(Paragraph(f"<b>Description.</b> {finding.description}", body))
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Impact.</b> {finding.impact}", body))
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Recommendation.</b> {finding.recommendation}", body))
            if finding.affected_objects:
                shown = finding.affected_objects[:8]
                more = ""
                if len(finding.affected_objects) > 8:
                    more = f" … plus {len(finding.affected_objects) - 8} more."
                story.append(Spacer(1, 4))
                story.append(Paragraph(
                    f"<b>Affected ({len(finding.affected_objects)}).</b> "
                    + ", ".join(shown) + more,
                    body_muted,
                ))
            if finding.references:
                story.append(Spacer(1, 4))
                story.append(Paragraph(
                    "<b>References.</b> " + "; ".join(finding.references), body_muted
                ))
            story.append(Spacer(1, 0.15 * inch))

    # ---- Appendix: checks executed ----
    story.append(PageBreak())
    story.append(Paragraph("Appendix: Checks Executed", h1))
    appendix_data = [["ID", "Name", "Category", "Status", "Findings"]]
    for r in report.results:
        appendix_data.append([
            r.check_id, r.name[:50], r.category, r.status.value, str(len(r.findings)),
        ])
    appendix = Table(
        appendix_data, colWidths=[0.6 * inch, 3.0 * inch, 1.4 * inch, 0.8 * inch, 0.7 * inch],
        repeatRows=1,
    )
    appendix.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (-1, 0), (-1, -1), "CENTER"),
    ]))
    story.append(appendix)

    doc.build(story)
    return output_path
