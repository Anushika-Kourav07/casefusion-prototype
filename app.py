from pathlib import Path
import json
import subprocess
import sys

import streamlit as st
import streamlit.components.v1 as components


# Project folders
ROOT = Path(__file__).parent
DATA_FOLDER = ROOT / "data"
OUTPUT_FOLDER = ROOT / "generated"

st.set_page_config(
    page_title="Case-Fusion",
    page_icon="🛡️",
    layout="wide"
)


def run_casefusion():
    result = subprocess.run(
        [sys.executable, "casefusion.py"],
        cwd=ROOT,
        capture_output=True,
        text=True
    )

    return result


def load_json(file_name):
    file_path = OUTPUT_FOLDER / file_name

    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    return None


# Dashboard header
st.title("🛡️ Case-Fusion")
st.subheader("Unified Cyber Fraud Analysis and Digital Artifact Correlator")

st.info(
    "Offline forensic triage prototype. "
    "All findings are investigative leads and require officer verification."
)


# Upload section
st.sidebar.header("Evidence Ingestion")

uploaded_cdr = st.sidebar.file_uploader(
    "Upload CDR CSV",
    type=["csv"]
)

uploaded_transactions = st.sidebar.file_uploader(
    "Upload Transaction CSV",
    type=["csv"]
)

if uploaded_cdr is not None:
    cdr_path = DATA_FOLDER / "cdr.csv"

    with open(cdr_path, "wb") as file:
        file.write(uploaded_cdr.getbuffer())

    st.sidebar.success("CDR file loaded")

if uploaded_transactions is not None:
    transaction_path = DATA_FOLDER / "transactions.csv"

    with open(transaction_path, "wb") as file:
        file.write(uploaded_transactions.getbuffer())

    st.sidebar.success("Transaction file loaded")


# Run analysis button
if st.sidebar.button("Run Case-Fusion Analysis", type="primary"):
    with st.spinner("Hashing evidence, correlating entities, and calculating risk..."):
        result = run_casefusion()

    if result.returncode == 0:
        st.success("Analysis completed successfully.")
    else:
        st.error("Analysis failed.")
        st.code(result.stderr)


# Load generated outputs
risk_scores = load_json("risk_scores.json")
entity_links = load_json("entity_links.json")
evidence_register = load_json("evidence_register.json")

if risk_scores is None:
    st.warning(
        "Upload or keep the mock CSV files, then click "
        "'Run Case-Fusion Analysis' to generate results."
    )

else:
    # Main metrics
    st.header("Investigation Summary")

    high_risk_count = sum(
        1
        for details in risk_scores.values()
        if details["risk_level"] == "HIGH"
    )

    mule_count = len(entity_links["possible_mule_accounts"])
    shared_imei_count = len(entity_links["shared_imeis"])

    col1, col2, col3 = st.columns(3)

    col1.metric("High-risk endpoints", high_risk_count)
    col2.metric("Possible mule accounts", mule_count)
    col3.metric("Shared IMEI links", shared_imei_count)

    # Risk findings
    st.header("Risk Findings")

    for entity, details in risk_scores.items():
        risk_score = details["risk_score"]
        risk_level = details["risk_level"]

        if risk_level == "HIGH":
            st.error(f"{entity} — {risk_score}/100 ({risk_level})")
        elif risk_level == "MEDIUM":
            st.warning(f"{entity} — {risk_score}/100 ({risk_level})")
        else:
            st.info(f"{entity} — {risk_score}/100 ({risk_level})")

        for reason in details["reasons"]:
            st.write(f"- {reason}")

    # Network graph
    st.header("Fraud Network Graph")

    graph_path = OUTPUT_FOLDER / "network_graph.html"

    if graph_path.exists():
        graph_html = graph_path.read_text(encoding="utf-8")
        components.html(graph_html, height=880, scrolling=True)

    # Entity links
    st.header("Entity Correlation")

    st.subheader("Shared IMEI Devices")

    for device in entity_links["shared_imeis"]:
        st.write(
            f"**IMEI:** {device['imei']}  \n"
            f"**Linked numbers:** {', '.join(device['linked_phone_numbers'])}  \n"
            f"**Confidence:** {device['confidence']}  \n"
            f"**Reason:** {device['reason']}"
        )

    st.subheader("Possible Mule Accounts")

    for mule in entity_links["possible_mule_accounts"]:
        st.write(
            f"**Entity:** {mule['entity']}  \n"
            f"**Received from:** {mule['sender_count']} sources  \n"
            f"**Total received:** INR {mule['total_received']:,.0f}  \n"
            f"**Confidence:** {mule['confidence']}"
        )

    # Evidence integrity
    st.header("Evidence Integrity Register")

    st.json(evidence_register)

    # Download investigation brief
    st.header("Investigation Brief")

    pdf_path = OUTPUT_FOLDER / "investigation_brief.pdf"

    if pdf_path.exists():
        with open(pdf_path, "rb") as file:
            st.download_button(
                label="Download Investigation Brief PDF",
                data=file,
                file_name="investigation_brief.pdf",
                mime="application/pdf"
            )