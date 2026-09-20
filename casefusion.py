from pathlib import Path
import hashlib
import json
from datetime import datetime
import html

import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas


# ------------------------------------------------
# PROJECT FOLDERS
# ------------------------------------------------

ROOT = Path(__file__).parent
DATA_FOLDER = ROOT / "data"
OUTPUT_FOLDER = ROOT / "generated"

OUTPUT_FOLDER.mkdir(exist_ok=True)


# ------------------------------------------------
# EVIDENCE INTEGRITY
# ------------------------------------------------

def calculate_sha256(file_path):
    file_bytes = file_path.read_bytes()
    return hashlib.sha256(file_bytes).hexdigest()


def create_evidence_register(files):
    evidence_register = []

    for file_path in files:
        evidence_register.append({
            "file_name": file_path.name,
            "sha256": calculate_sha256(file_path),
            "acquired_at": datetime.now().astimezone().isoformat(),
            "status": "Original preserved; parsed copy used for analysis"
        })

    return evidence_register


# ------------------------------------------------
# NORMALIZATION
# ------------------------------------------------

def normalize_phone(phone_number):
    digits = "".join(
        character
        for character in str(phone_number)
        if character.isdigit()
    )

    return digits[-10:]


def normalize_upi(upi_id):
    return str(upi_id).strip().lower()


# ------------------------------------------------
# ENTITY CORRELATION
# ------------------------------------------------

def find_shared_imeis(cdr_data):
    shared_devices = []

    for imei, group in cdr_data.groupby("imei"):
        phone_numbers = sorted(group["caller"].unique())

        if len(phone_numbers) >= 2:
            shared_devices.append({
                "imei": str(imei),
                "linked_phone_numbers": phone_numbers,
                "phone_count": len(phone_numbers),
                "confidence": "HIGH",
                "reason": "Same IMEI appears with multiple caller numbers"
            })

    return shared_devices


def find_possible_mule_accounts(transaction_data):
    possible_mules = []

    for receiver_id, group in transaction_data.groupby("receiver_id"):
        unique_senders = sorted(group["sender_id"].unique())
        total_received = float(group["amount"].sum())

        if len(unique_senders) >= 3:
            possible_mules.append({
                "entity": receiver_id,
                "entity_type": group["receiver_type"].iloc[0],
                "unique_senders": unique_senders,
                "sender_count": len(unique_senders),
                "total_received": total_received,
                "confidence": "HIGH",
                "reason": "Received funds from three or more different sources"
            })

    return possible_mules


# ------------------------------------------------
# RISK SCORING
# ------------------------------------------------

def calculate_risk_scores(transaction_data, shared_imeis, possible_mules):
    risk_scores = {}

    # Rule 1: Money received from three or more distinct sources
    for mule in possible_mules:
        entity = mule["entity"]

        risk_scores[entity] = {
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "reasons": [
                f"Received funds from {mule['sender_count']} different sources (+30)"
            ]
        }

    # Rule 2: Funds routed onward within 15 minutes
    for entity in risk_scores:
        received_transactions = transaction_data[
            transaction_data["receiver_id"] == entity
        ]

        sent_transactions = transaction_data[
            transaction_data["sender_id"] == entity
        ]

        if not received_transactions.empty and not sent_transactions.empty:
            last_received_time = received_transactions["timestamp"].max()
            first_sent_time = sent_transactions["timestamp"].min()

            time_difference = (
                first_sent_time - last_received_time
            ).total_seconds() / 60

            if 0 <= time_difference <= 15:
                risk_scores[entity]["risk_score"] += 25
                risk_scores[entity]["reasons"].append(
                    f"Routed funds onward within {time_difference:.0f} minutes (+25)"
                )

    # Rule 3: Same IMEI linked to multiple caller numbers
    for device in shared_imeis:
        imei_entity = f"IMEI:{device['imei']}"

        risk_scores[imei_entity] = {
            "risk_score": 20,
            "risk_level": "MEDIUM",
            "reasons": [
                f"Shared by {device['phone_count']} caller numbers (+20)"
            ]
        }

    # Convert score to risk label
    for entity in risk_scores:
        score = risk_scores[entity]["risk_score"]

        if score >= 50:
            risk_scores[entity]["risk_level"] = "HIGH"
        elif score >= 20:
            risk_scores[entity]["risk_level"] = "MEDIUM"
        else:
            risk_scores[entity]["risk_level"] = "LOW"

    return risk_scores


# ------------------------------------------------
# FRAUD NETWORK GRAPH
# ------------------------------------------------

def create_network_graph(transaction_data, shared_imeis, risk_scores):
    all_nodes = set(transaction_data["sender_id"])
    all_nodes.update(transaction_data["receiver_id"])

    victim_nodes = sorted([
        node for node in all_nodes
        if str(node).startswith("VICTIM")
    ])

    upi_nodes = sorted([
        node for node in all_nodes
        if "@upi" in str(node).lower()
    ])

    mule_nodes = sorted([
        node for node in all_nodes
        if "MULE" in str(node)
    ])

    cashout_nodes = sorted([
        node for node in all_nodes
        if "CASHOUT" in str(node)
    ])

    positions = {}
    node_colours = {}

    for index, node in enumerate(victim_nodes):
        positions[node] = (130, 130 + index * 145)
        node_colours[node] = "#2878B5"

    for index, node in enumerate(upi_nodes):
        positions[node] = (420, 130 + index * 145)
        node_colours[node] = "#805AD5"

    for index, node in enumerate(mule_nodes):
        positions[node] = (720, 230 + index * 145)
        node_colours[node] = "#D64550"

    for index, node in enumerate(cashout_nodes):
        positions[node] = (1030, 230 + index * 145)
        node_colours[node] = "#E67E22"

    # Extra entities that do not match the categories above
    extra_nodes = sorted(
        all_nodes
        - set(victim_nodes)
        - set(upi_nodes)
        - set(mule_nodes)
        - set(cashout_nodes)
    )

    for index, node in enumerate(extra_nodes):
        positions[node] = (720, 450 + index * 120)
        node_colours[node] = "#555B6E"

    # Add IMEI and linked phone nodes
    for device in shared_imeis:
        imei_node = f"IMEI:{device['imei']}"

        positions[imei_node] = (500, 580)
        node_colours[imei_node] = "#555B6E"

        for index, phone in enumerate(device["linked_phone_numbers"]):
            positions[phone] = (230 + index * 530, 735)
            node_colours[phone] = "#168C84"

    edge_svg = []
    node_svg = []

    # Money-transfer arrows
    for row in transaction_data.itertuples():
        sender = row.sender_id
        receiver = row.receiver_id

        if sender in positions and receiver in positions:
            x1, y1 = positions[sender]
            x2, y2 = positions[receiver]

            edge_svg.append(
                f'<line x1="{x1 + 65}" y1="{y1}" '
                f'x2="{x2 - 65}" y2="{y2}" '
                f'class="transaction-edge" marker-end="url(#arrow)" />'
            )

            label_x = (x1 + x2) / 2
            label_y = (y1 + y2) / 2 - 12

            edge_svg.append(
                f'<text x="{label_x}" y="{label_y}" '
                f'class="edge-label">INR {row.amount:,.0f}</text>'
            )

    # IMEI relationship lines
    for device in shared_imeis:
        imei_node = f"IMEI:{device['imei']}"
        imei_x, imei_y = positions[imei_node]

        for phone in device["linked_phone_numbers"]:
            phone_x, phone_y = positions[phone]

            edge_svg.append(
                f'<line x1="{phone_x}" y1="{phone_y - 55}" '
                f'x2="{imei_x}" y2="{imei_y + 55}" '
                f'class="device-edge" stroke-dasharray="8,6" />'
            )

    # Draw nodes
    for node, position in positions.items():
        x, y = position
        colour = node_colours[node]

        display_name = str(node)

        if len(display_name) > 17:
            display_name = display_name[:14] + "..."

        node_svg.append(
            f'<circle cx="{x}" cy="{y}" r="65" fill="{colour}" />'
        )

        node_svg.append(
            f'<text x="{x}" y="{y - 5}" '
            f'class="node-label" text-anchor="middle">'
            f'{html.escape(display_name)}</text>'
        )

        if node in risk_scores:
            score = risk_scores[node]["risk_score"]
            level = risk_scores[node]["risk_level"]

            node_svg.append(
                f'<text x="{x}" y="{y + 20}" '
                f'class="risk-label" text-anchor="middle">'
                f'{score}/100 {level}</text>'
            )

    findings_html = ""

    for entity, details in risk_scores.items():
        reason_lines = "<br>".join(
            f"- {html.escape(reason)}"
            for reason in details["reasons"]
        )

        findings_html += f"""
        <div class="finding">
            <strong>{html.escape(entity)}</strong>
            <span class="risk">
                {details["risk_score"]}/100 {details["risk_level"]}
            </span>
            <p>{reason_lines}</p>
        </div>
        """

    graph_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Case-Fusion Fraud Network</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            background: #071426;
            color: #EFF6FF;
        }}

        header {{
            background: #0C2746;
            padding: 28px 45px;
        }}

        h1 {{
            margin: 0;
            color: #67D8FF;
        }}

        header p {{
            color: #BCD4E6;
        }}

        main {{
            padding: 30px 45px;
        }}

        svg {{
            width: 100%;
            min-width: 1100px;
            height: 830px;
            background: #0B2038;
            border-radius: 12px;
        }}

        .transaction-edge {{
            stroke: #81B9DF;
            stroke-width: 4;
        }}

        .device-edge {{
            stroke: #5BE0CE;
            stroke-width: 3;
        }}

        .node-label {{
            fill: white;
            font-weight: bold;
            font-size: 14px;
        }}

        .risk-label {{
            fill: #FFF7C2;
            font-size: 12px;
        }}

        .edge-label {{
            fill: #D9ECFF;
            font-size: 12px;
            font-weight: bold;
        }}

        .legend {{
            display: flex;
            gap: 18px;
            flex-wrap: wrap;
            margin: 22px 0;
        }}

        .legend-item {{
            padding: 9px 12px;
            border-radius: 5px;
            font-size: 14px;
        }}

        .victim {{ background: #2878B5; }}
        .upi {{ background: #805AD5; }}
        .mule {{ background: #D64550; }}
        .cashout {{ background: #E67E22; }}
        .device {{ background: #555B6E; }}

        .findings {{
            margin-top: 28px;
            background: #0B2038;
            padding: 20px;
            border-radius: 12px;
        }}

        .finding {{
            border-left: 5px solid #D64550;
            background: #122E4B;
            padding: 14px;
            margin: 12px 0;
        }}

        .risk {{
            color: #FFD166;
            margin-left: 10px;
            font-weight: bold;
        }}
    </style>
</head>

<body>
    <header>
        <h1>Case-Fusion: Fraud Network Analysis</h1>
        <p>Directional money flow, shared-device links, and explainable triage findings</p>
    </header>

    <main>
        <div class="legend">
            <span class="legend-item victim">Victim</span>
            <span class="legend-item upi">UPI Handle</span>
            <span class="legend-item mule">High-risk Mule Account</span>
            <span class="legend-item cashout">Cash-out Account</span>
            <span class="legend-item device">IMEI / Device</span>
        </div>

        <svg viewBox="0 0 1150 830">
            <defs>
                <marker id="arrow" markerWidth="10" markerHeight="10"
                        refX="8" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L9,3 z" fill="#81B9DF" />
                </marker>
            </defs>

            {''.join(edge_svg)}
            {''.join(node_svg)}
        </svg>

        <section class="findings">
            <h2>Risk Findings</h2>
            {findings_html}
        </section>
    </main>
</body>
</html>
"""

    output_file = OUTPUT_FOLDER / "network_graph.html"

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(graph_html)

    return output_file


# ------------------------------------------------
# PDF INVESTIGATION BRIEF
# ------------------------------------------------

def create_investigation_brief(
    transaction_data,
    risk_scores,
    evidence_register
):
    output_file = OUTPUT_FOLDER / "investigation_brief.pdf"

    pdf = canvas.Canvas(str(output_file), pagesize=A4)

    page_width, page_height = A4

    # Header
    pdf.setFillColor(colors.HexColor("#08213D"))
    pdf.rect(0, page_height - 3 * cm, page_width, 3 * cm, fill=1, stroke=0)

    pdf.setFillColor(colors.white)
    pdf.setFont("Helvetica-Bold", 18)

    pdf.drawString(
        1.5 * cm,
        page_height - 1.45 * cm,
        "CASE-FUSION | Investigative Triage Brief"
    )

    pdf.setFont("Helvetica", 9)

    pdf.drawString(
        1.5 * cm,
        page_height - 2.15 * cm,
        "Mock Case CF-2026-001 | Generated locally | Officer verification required"
    )

    y_position = page_height - 4 * cm

    # Priority findings
    pdf.setFillColor(colors.HexColor("#08213D"))
    pdf.setFont("Helvetica-Bold", 13)

    pdf.drawString(1.5 * cm, y_position, "Priority findings")

    y_position -= 0.65 * cm

    for entity, details in risk_scores.items():
        if details["risk_level"] == "HIGH":
            pdf.setFillColor(colors.HexColor("#B00020"))
        else:
            pdf.setFillColor(colors.HexColor("#875A00"))

        pdf.setFont("Helvetica-Bold", 10)

        pdf.drawString(
            1.5 * cm,
            y_position,
            f"{entity}: {details['risk_score']}/100 ({details['risk_level']})"
        )

        pdf.setFillColor(colors.black)
        pdf.setFont("Helvetica", 9)

        for reason in details["reasons"]:
            y_position -= 0.42 * cm
            pdf.drawString(2 * cm, y_position, f"- {reason}")

        y_position -= 0.55 * cm

    # Timeline and immediate actions
    pdf.setFillColor(colors.HexColor("#08213D"))
    pdf.setFont("Helvetica-Bold", 13)

    pdf.drawString(
        1.5 * cm,
        y_position,
        "Timeline and immediate actions"
    )

    y_position -= 0.6 * cm

    total_amount = transaction_data["amount"].sum()

    timeline_actions = [
        f"09:10 to 09:47: INR {total_amount:,.0f} recorded across linked transactions.",
        "09:52: MULE-001 transfers INR 61,000 to CASHOUT-001.",
        "1. Seek preservation or hold action for MULE-001 and CASHOUT-001, subject to authority.",
        "2. Request KYC and transaction records for linked beneficiary handles.",
        "3. Preserve CDR and IPDR records for numbers linked to the shared IMEI."
    ]

    pdf.setFillColor(colors.black)
    pdf.setFont("Helvetica", 9)

    for item in timeline_actions:
        pdf.drawString(1.7 * cm, y_position, f"- {item}")
        y_position -= 0.5 * cm

    # Evidence hash register
    pdf.setFillColor(colors.HexColor("#08213D"))
    pdf.setFont("Helvetica-Bold", 13)

    pdf.drawString(1.5 * cm, y_position, "Evidence integrity")

    y_position -= 0.55 * cm

    pdf.setFillColor(colors.black)
    pdf.setFont("Helvetica", 8)

    for evidence in evidence_register:
        short_hash = evidence["sha256"][:24]

        pdf.drawString(
            1.7 * cm,
            y_position,
            f"- {evidence['file_name']} | SHA-256 {short_hash}..."
        )

        y_position -= 0.42 * cm

    pdf.save()

    return output_file


# ------------------------------------------------
# READ AND NORMALIZE EVIDENCE
# ------------------------------------------------

cdr_file = DATA_FOLDER / "cdr.csv"
transaction_file = DATA_FOLDER / "transactions.csv"

cdr_data = pd.read_csv(cdr_file)
transaction_data = pd.read_csv(transaction_file)

cdr_data["caller"] = cdr_data["caller"].apply(normalize_phone)
cdr_data["callee"] = cdr_data["callee"].apply(normalize_phone)
cdr_data["timestamp"] = pd.to_datetime(cdr_data["timestamp"])

transaction_data["sender_id"] = (
    transaction_data["sender_id"].astype(str).str.strip()
)

transaction_data["receiver_id"] = (
    transaction_data["receiver_id"].astype(str).str.strip()
)

transaction_data.loc[
    transaction_data["sender_type"] == "mule_upi",
    "sender_id"
] = transaction_data.loc[
    transaction_data["sender_type"] == "mule_upi",
    "sender_id"
].apply(normalize_upi)

transaction_data.loc[
    transaction_data["receiver_type"] == "mule_upi",
    "receiver_id"
] = transaction_data.loc[
    transaction_data["receiver_type"] == "mule_upi",
    "receiver_id"
].apply(normalize_upi)

transaction_data["timestamp"] = pd.to_datetime(
    transaction_data["timestamp"]
)

transaction_data["amount"] = pd.to_numeric(
    transaction_data["amount"]
)


# ------------------------------------------------
# CREATE OUTPUTS
# ------------------------------------------------

evidence_register = create_evidence_register([
    cdr_file,
    transaction_file
])

evidence_output_file = OUTPUT_FOLDER / "evidence_register.json"

with open(evidence_output_file, "w", encoding="utf-8") as file:
    json.dump(evidence_register, file, indent=2)

shared_imeis = find_shared_imeis(cdr_data)
possible_mules = find_possible_mule_accounts(transaction_data)

entity_links = {
    "shared_imeis": shared_imeis,
    "possible_mule_accounts": possible_mules
}

links_output_file = OUTPUT_FOLDER / "entity_links.json"

with open(links_output_file, "w", encoding="utf-8") as file:
    json.dump(entity_links, file, indent=2)

risk_scores = calculate_risk_scores(
    transaction_data,
    shared_imeis,
    possible_mules
)

risk_output_file = OUTPUT_FOLDER / "risk_scores.json"

with open(risk_output_file, "w", encoding="utf-8") as file:
    json.dump(risk_scores, file, indent=2)

graph_output_file = create_network_graph(
    transaction_data,
    shared_imeis,
    risk_scores
)

pdf_output_file = create_investigation_brief(
    transaction_data,
    risk_scores,
    evidence_register
)


# ------------------------------------------------
# TERMINAL RESULTS
# ------------------------------------------------

print("\nCASE-FUSION: Triage Analysis Complete")
print("-" * 60)

print("\nShared IMEI findings:")
for device in shared_imeis:
    print(
        f"IMEI: {device['imei']} | "
        f"Phones: {device['linked_phone_numbers']} | "
        f"Confidence: {device['confidence']}"
    )

print("\nPossible mule-account findings:")
for mule in possible_mules:
    print(
        f"Entity: {mule['entity']} | "
        f"Received from: {mule['sender_count']} sources | "
        f"Amount: INR {mule['total_received']:,.0f}"
    )

print("\nRisk scores:")
for entity, details in risk_scores.items():
    print(
        f"{entity}: {details['risk_score']}/100 "
        f"({details['risk_level']})"
    )

print("\nGenerated files:")
print(evidence_output_file)
print(links_output_file)
print(risk_output_file)
print(graph_output_file)
print(pdf_output_file)