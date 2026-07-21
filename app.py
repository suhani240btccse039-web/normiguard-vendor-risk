#!/usr/bin/env python3
"""
NormiGuard — web version of vendor_risk.py

Upload a vendor CSV, confirm/override a risk rating per vendor, and get a
ranked risk report right in the browser. All the assessment logic (control
mapping, sensitivity classification, recommendations) is imported from
vendor_risk.py — this file is only the UI layer on top of it.

Run locally:
    pip install streamlit
    streamlit run app.py

Deploy: push to GitHub, then deploy for free on share.streamlit.io
(Streamlit Community Cloud), pointing it at this file.
"""

import io
import datetime

import streamlit as st

from vendor_risk import (
    FRAMEWORKS, RISK_RANK, REVIEW_CADENCE_DAYS, DEFAULT_ORG,
    parse_vendor_rows, map_controls, suggest_risk, build_recommendation,
    build_markdown_report, finding,
)

st.set_page_config(page_title="NormiGuard — Vendor Risk Assessment", page_icon="🛡️",
                   layout="wide")

st.title("🛡️ NormiGuard")
st.caption("Third-party vendor risk assessment — upload a CSV, confirm a risk "
          "rating per vendor, get a ranked report.")

with st.sidebar:
    st.header("Settings")
    org = st.text_input("Organisation name", value=DEFAULT_ORG)
    prepared_by = st.text_input("Prepared by (optional)", value="")
    framework_name = st.selectbox(
        "Control framework", options=list(FRAMEWORKS.keys()),
        format_func=lambda k: FRAMEWORKS[k]["label"])
    st.markdown("---")
    st.markdown(
        "**CSV columns expected:**\n\n"
        "`vendor name, service provided, data they access, contract exists`")

uploaded = st.file_uploader("Upload vendor CSV", type="csv")

if not uploaded:
    st.info("Upload a CSV to get started. Don't have one handy? Try the "
            "`vendors_sample.csv` included in the repo.")
    st.stop()

text_stream = io.StringIO(uploaded.getvalue().decode("utf-8-sig"))
try:
    vendors = parse_vendor_rows(text_stream)
except ValueError as e:
    st.error(str(e))
    st.stop()

if not vendors:
    st.warning("No vendor rows found in that CSV.")
    st.stop()

framework = FRAMEWORKS[framework_name]

st.subheader(f"Review {len(vendors)} vendor(s)")
st.caption("Each vendor gets a suggested rating based on data sensitivity and "
          "contract status. Confirm or override it — the final call is yours.")

RISK_OPTIONS = ["LOW", "MEDIUM", "HIGH"]
findings = []

for row in vendors:
    controls, sensitivity, contract = map_controls(row, framework)
    suggested = suggest_risk(sensitivity, contract)
    existing = (row.get("risk_rating") or "").strip().upper()
    default_rating = existing if existing in RISK_RANK else suggested

    with st.expander(f"{row['vendor']} — {row['service']}  ·  suggested: {suggested}"):
        col1, col2 = st.columns([2, 1])
        with col1:
            st.write(f"**Data accessed:** {row['data_access']}")
            st.write(f"**Sensitivity:** {sensitivity}")
            st.write(f"**Contract on file:** {'yes' if contract else 'no'}")
            st.write("**Controls:**")
            for c in controls:
                st.write(f"- `{c['status']}` — {c['id']} {c['name']}")
        with col2:
            risk_rating = st.radio(
                "Risk rating", RISK_OPTIONS,
                index=RISK_OPTIONS.index(default_rating),
                key=f"risk_{row['vendor']}")

    recommendation = build_recommendation(row, sensitivity, contract, risk_rating)
    next_review = (datetime.date.today() +
                   datetime.timedelta(days=REVIEW_CADENCE_DAYS[risk_rating])).isoformat()

    findings.append(finding(
        vendor=row["vendor"], service=row["service"], data_access=row["data_access"],
        contract=contract, sensitivity=sensitivity, suggested_risk=suggested,
        risk_rating=risk_rating, controls=controls, recommendation=recommendation,
        next_review=next_review, trend="N/A — web version doesn't track history",
    ))

st.markdown("---")
st.subheader("Report")

findings_sorted = sorted(findings, key=lambda f: RISK_RANK[f["risk_rating"]])

counts = {}
for f in findings:
    counts[f["risk_rating"]] = counts.get(f["risk_rating"], 0) + 1

cols = st.columns(3)
for col, r in zip(cols, ["HIGH", "MEDIUM", "LOW"]):
    col.metric(r, counts.get(r, 0))

st.dataframe(
    [{"Vendor": f["vendor"], "Service": f["service"], "Risk": f["risk_rating"],
      "Contract": "yes" if f["contract"] else "no", "Sensitivity": f["sensitivity"],
      "Next Review": f["next_review"]} for f in findings_sorted],
    use_container_width=True, hide_index=True)

for f in findings_sorted:
    st.markdown(f"**[{f['risk_rating']}] {f['vendor']}** — {f['recommendation']}")

report_md = build_markdown_report(findings_sorted, framework["label"], uploaded.name,
                                  org, prepared_by or None)
st.download_button(
    "Download markdown report", data=report_md,
    file_name=f"vendor_risk_{datetime.date.today().isoformat()}.md",
    mime="text/markdown")
