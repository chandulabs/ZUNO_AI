"""PDF Report Generation (ReportLab).

Builds comprehensive forensic reports containing evidence from:
- Hybrid Machine Learning (Random Forest, CNN, BiLSTM, Ensemble)
- Explainable AI (SHAP TreeExplainer, Character-level Neural attributions)
- Rule-based Detection
- Local Threat Intelligence (Exact URLs, Domains, File Hashes)
- Android APK Static Analysis
Strictly zero invented or simulated metrics.
"""
import io
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

VCOL = {"SAFE": "#059669", "SUSPICIOUS": "#d97706", "PHISHING": "#dc2626", "UNKNOWN": "#64748b"}
NAVY = colors.HexColor("#0b1020")
VIOLET = colors.HexColor("#7c3aed")


def _p(t, st):
    return Paragraph(escape(str(t)), st)


def _recommendations(verdict, kind, r):
    if verdict == "PHISHING":
        return [
            f"Do not open, click, or enter credentials on this {'URL' if kind == 'url' else 'application'}.",
            "If credentials or tokens were entered, immediately reset passwords and revoke active sessions.",
            f"Block the {'URL and parent domain' if kind == 'url' else 'package and file hash'} at gateway and endpoint firewalls."
        ]
    elif verdict == "SUSPICIOUS":
        return [
            "Exercise extreme caution; destination exhibits high-risk indicators or suspicious domain characteristics.",
            "Do not input credentials or authorize OAuth requests until verified through a separate out-of-band channel.",
            "Monitor network telemetry for secondary connections or staging traffic."
        ]
    elif verdict == "SAFE":
        return [
            "No malicious indicators or anomalies were identified across local AI models and threat intelligence.",
            "Maintain standard zero-trust browsing hygiene and keep operating system and browsers updated."
        ]
    else:
        return [
            "Evidence was insufficient to classify this target as safe. Treat as unverified.",
            "Verify that local AI models are loaded and import recent threat intelligence feeds to improve local coverage."
        ]


def build_pdf(scan: dict) -> bytes:
    r = scan.get("result") or {}
    kind = scan.get("kind", "url")
    verdict = scan.get("verdict", "UNKNOWN")

    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", parent=ss["Title"], textColor=colors.white, fontSize=18, alignment=0, leading=22)
    H2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=VIOLET, fontSize=12, spaceBefore=8, spaceAfter=4)
    B = ParagraphStyle("b", parent=ss["BodyText"], fontSize=8.5, leading=11)
    SM = ParagraphStyle("sm", parent=B, fontSize=7.5, textColor=colors.HexColor("#475569"))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=12 * mm,
        bottomMargin=14 * mm,
        title="PhishGuard AI Security Report",
        author="PhishGuard AI Server"
    )
    W = A4[0] - 28 * mm
    el = []

    # Header
    head = Table(
        [
            [_p("PhishGuard AI — Forensic Security Report", H1)],
            [Paragraph("Hybrid Machine Learning & Local Threat Intelligence", ParagraphStyle("s", parent=B, textColor=colors.HexColor("#a5b4fc")))]
        ],
        colWidths=[W]
    )
    head.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8)
    ]))
    el += [head, Spacer(1, 6)]

    # Meta Table
    meta = [
        ["Report ID", scan.get("id", "N/A")],
        ["Analysis Type", "Hybrid URL Detection" if kind == "url" else "Android APK Static Analysis"],
        ["Target", scan.get("target", "N/A")],
        ["Scan Timestamp", scan.get("created", "")],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")]
    ]
    t = Table([[_p(a, B), _p(b, B)] for a, b in meta], colWidths=[36 * mm, W - 36 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc"))
    ]))
    el += [t]

    # Verdict Banner
    risk = r.get("risk") or {}
    score = risk.get("score", 0)
    vc = colors.HexColor(VCOL.get(verdict, "#64748b"))
    vt = Table(
        [[
            Paragraph(f'<font color="white"><b>VERDICT: {escape(verdict)}</b></font>', ParagraphStyle("v", parent=B, fontSize=13, leading=16)),
            _p(f"Risk Score: {score}/100  ·  Confidence: {risk.get('confidence', 'n/a').upper()}", ParagraphStyle("vs", parent=B, fontSize=11, textColor=colors.white))
        ]],
        colWidths=[W * 0.50, W * 0.50]
    )
    vt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), vc),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10)
    ]))
    el += [Spacer(1, 6), vt]

    # Breakdown Table
    if risk.get("breakdown"):
        el.append(_p("Risk Assessment Breakdown", H2))
        rows = [[_p("Evidence Layer", B), _p("Value", B), _p("Technical Detail", B)]]
        for b in risk["breakdown"]:
            rows.append([
                _p(b.get("source", ""), B),
                _p("n/a" if b.get("value") is None else str(b.get("value")), B),
                _p(b.get("detail", ""), SM)
            ])
        tb = Table(rows, colWidths=[38 * mm, 24 * mm, W - 62 * mm], repeatRows=1)
        tb.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ede9fe")),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        el.append(tb)

    if kind == "url":
        # Machine Learning Section
        el.append(_p("Machine Learning Classification (Random Forest & XGBoost)", H2))
        ml = r.get("ml") or {}
        rf_p = (ml.get("random_forest") or {}).get("probability")
        xgb_p = (ml.get("xgboost") or {}).get("probability")
        active_m = ml.get("active_model_name", "Random Forest").replace("_", " ").title()

        ml_rows = [
            [_p("Model", B), _p("Architecture", B), _p("Probability", B), _p("Role / Status", B)],
            [_p("Random Forest", B), _p("300 estimators, impurity split", B), _p(f"{rf_p*100:.1f}%" if rf_p is not None else "MODEL NOT TRAINED", B), _p("Active Model" if active_m.lower() == "random forest" else "Evaluated", B)],
            [_p("XGBoost", B), _p("Gradient boosted trees (lr=0.05)", B), _p(f"{xgb_p*100:.1f}%" if xgb_p is not None else "MODEL NOT TRAINED", B), _p("Active Model" if active_m.lower() == "xgboost" else "Evaluated", B)]
        ]
        ml_tb = Table(ml_rows, colWidths=[32 * mm, 50 * mm, 28 * mm, W - 110 * mm], repeatRows=1)
        ml_tb.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ede9fe"))
        ]))
        el.append(ml_tb)

        # SHAP Explainability
        sh = r.get("shap") or {}
        el.append(_p("Explainable AI — SHAP TreeExplainer", H2))
        if sh.get("available") and sh.get("contributions"):
            el.append(_p(sh.get("summary", ""), B))
            sh_rows = [[_p("Feature", B), _p("Value", B), _p("SHAP", B), _p("Impact Direction", B)]]
            for c in sh.get("contributions", [])[:10]:
                sh_rows.append([
                    _p(c.get("label", c.get("feature")), B),
                    _p(str(c.get("value", "")), B),
                    _p(f"{c.get('shap', 0.0):+.4f}", B),
                    _p(c.get("meaning", ""), SM)
                ])
            stb = Table(sh_rows, colWidths=[40 * mm, 20 * mm, 22 * mm, W - 82 * mm], repeatRows=1)
            stb.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ede9fe"))
            ]))
            el.append(stb)
        else:
            el.append(_p(sh.get("reason", "SHAP explanation unavailable. (Requires trained Random Forest)"), SM))

    else:
        # APK metadata
        el.append(_p("Android Package Inspection", H2))
        h = r.get("hashes") or {}
        info = [
            ["App Name", r.get("app_name", "N/A")],
            ["Package Name", r.get("package", "N/A")],
            ["Version Name", r.get("version", "N/A")],
            ["SHA-256", h.get("sha256", "N/A")],
            ["SHA-1", h.get("sha1", "N/A")],
            ["MD5", h.get("md5", "N/A")],
            ["File Size", f"{h.get('size_bytes', 0)} bytes"]
        ]
        apk_tb = Table([[_p(a, B), _p(b, B)] for a, b in info], colWidths=[35 * mm, W - 35 * mm])
        apk_tb.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1"))]))
        el.append(apk_tb)

        # Static indicators
        inds = (r.get("static_risk") or {}).get("indicators", [])
        if inds:
            el.append(_p("Static Security Indicators", H2))
            for i in inds:
                el.append(_p(f"• {i['indicator']} (Weight: +{i['weight']}) — {i['detail']}", B))

    # Threat Intelligence Section
    el.append(_p("Local Threat Intelligence Feed Matches", H2))
    ti = r.get("threat_intel") or []
    if ti:
        for t in ti:
            st = t.get("status", "NO_MATCH")
            el.append(_p(f"{t.get('source')}: {st} ({t.get('category', 'n/a')}) — {t.get('message', '')}", B))
    else:
        el.append(_p("No matches found in local threat intelligence feeds.", SM))

    # Recommendations
    el.append(_p("Security Recommendations", H2))
    for rec in _recommendations(verdict, kind, r):
        el.append(_p(f"• {rec}", B))

    el += [
        Spacer(1, 8),
        _p("Generated by PhishGuard AI Server. Prediction and threat analysis conducted entirely on-premise without external API dependencies.", SM)
    ]

    def footer(c, d):
        c.saveState()
        c.setFont("Helvetica", 7.5)
        c.setFillColor(colors.HexColor("#64748b"))
        c.drawString(14 * mm, 8 * mm, "PhishGuard AI — On-Premise Cyber Threat Defense")
        c.drawRightString(A4[0] - 14 * mm, 8 * mm, f"Page {d.page}")
        c.restoreState()

    doc.build(el, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
