from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_report(alerts, pcap_name):

    report_name = pcap_name.replace(
        ".pcap",
        "_report.pdf"
    )

    pdf = SimpleDocTemplate(report_name)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "SCADA IDS Incident Report",
            styles["Title"]
        )
    )

    content.append(
        Paragraph(
            f"Source PCAP: {pcap_name}",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 20))

    total = len(alerts)

    critical = sum(
        1 for a in alerts
        if a["severity"] == "CRITICAL"
    )

    high = sum(
        1 for a in alerts
        if a["severity"] == "HIGH"
    )

    medium = sum(
        1 for a in alerts
        if a["severity"] == "MEDIUM"
    )

    low = sum(
        1 for a in alerts
        if a["severity"] == "LOW"
    )

    content.append(
    Paragraph(
        "Executive Summary",
        styles["Heading1"]
    )
)

    content.append(
        Paragraph(
            f"PCAP File: {pcap_name}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Total Incidents: {total}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Critical: {critical}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"High: {high}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Medium: {medium}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Low: {low}",
            styles["Normal"]
        )
    )

    content.append(PageBreak())

    content.append(
        Paragraph(
            "Incident Details",
            styles["Heading1"]
        )
    )

    for alert in alerts:

        content.append(
            Paragraph(
                f"<b>Event:</b> {alert['event']}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"<b>Severity:</b> {alert['severity']}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"<b>Source:</b> {alert['source']}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"<b>Details:</b> {alert['details']}",
                styles["Normal"]
            )
        )

        content.append(Spacer(1, 12))

    pdf.build(content)

    print(f"Report generated: {report_name}")