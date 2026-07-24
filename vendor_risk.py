#!/usr/bin/env python3
"""
Third-Party Vendor Risk Assessment
-----------------------------------
Reads an organisation's vendor list from a CSV (vendor name, service
provided, data they access, whether a contract exists), maps each vendor
against a control framework (NIST CSF or ISO 27001, simplified), and
produces a markdown risk-assessment report ranked by risk.

The final risk rating (low/medium/high) per vendor is a human judgement
call. This tool proposes a starting point based on data sensitivity and
contract status, but asks you to confirm or override it for every vendor.

Usage:
    python3 vendor_risk.py vendors.csv
    python3 vendor_risk.py vendors.csv --framework iso27001
    python3 vendor_risk.py vendors.csv --auto           # skip prompts, use suggested ratings
    python3 vendor_risk.py vendors.csv --report
    python3 vendor_risk.py vendors.csv --report --org "Normi AI" --by "Suhani Gupta"

CSV columns expected (header row, case-insensitive):
    vendor name, service provided, data they access, contract exists

Each run appends to vendor_risk_history.csv (in the working directory) so
repeat assessments show whether a vendor's risk moved up, down, or stayed
the same since the last run. Use --no-history to skip this.
"""

import os
import re
import sys
import csv
import datetime


RISK_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
DEFAULT_ORG = "Normi AI"
HISTORY_FILE = "vendor_risk_history.csv"

# How often a vendor at each risk level should be reassessed.
REVIEW_CADENCE_DAYS = {"HIGH": 90, "MEDIUM": 180, "LOW": 365}

# ------------------------------------------------------------------
# NormiGuard — the terminal persona for this tool. Pure formatting/text,
# no AI or API calls involved: nothing here costs tokens or makes requests.
# ------------------------------------------------------------------

BOLD = "\033[1m"
CYAN = "\033[96m"
RESET = "\033[0m"
RISK_COLORS = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}


def _use_color():
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _tag(risk_rating):
    """A colored [RISK] tag for terminal output, plain text otherwise."""
    if _use_color():
        return f"{RISK_COLORS.get(risk_rating, '')}{BOLD}[{risk_rating}]{RESET}"
    return f"[{risk_rating}]"


def print_banner(org):
    line = "=" * 52
    title = "NormiGuard — Vendor Risk Assistant"
    subtitle = f"Keeping {org}'s third-party risk in check"
    if _use_color():
        print(f"{CYAN}{BOLD}{line}\n  {title}\n  {subtitle}\n{line}{RESET}")
    else:
        print(f"{line}\n  {title}\n  {subtitle}\n{line}")

# ------------------------------------------------------------------
# Control frameworks (simplified). Each control has a "category" —
# governance/incident controls can be checked from contract status alone;
# access/data/monitoring controls can't be verified from a vendor list,
# so they're flagged for review and prioritized by data sensitivity.
# ------------------------------------------------------------------

FRAMEWORKS = {
    "nist-csf": {
        "label": "NIST Cybersecurity Framework (simplified)",
        "controls": [
            ("ID.SC", "Supply Chain Risk Management", "governance",
             "Third parties are identified, prioritized, and assessed for risk."),
            ("PR.AC", "Identity Management & Access Control", "access",
             "Vendor access to systems/data is authenticated and limited to least privilege."),
            ("PR.DS", "Data Security", "data",
             "Data shared with or accessible to the vendor is protected at rest and in transit."),
            ("DE.CM", "Security Continuous Monitoring", "monitoring",
             "Vendor access and activity is monitored for anomalies."),
            ("RS.CO", "Response Planning & Communications", "incident",
             "Contract defines breach notification and incident response obligations."),
        ],
    },
    "iso27001": {
        "label": "ISO/IEC 27001:2022 Annex A (simplified)",
        "controls": [
            ("A.5.19", "Information security in supplier relationships", "governance",
             "Security requirements are agreed upon and documented with the supplier."),
            ("A.8.2", "Privileged access rights", "access",
             "Vendor access privileges are restricted and reviewed."),
            ("A.8.24", "Use of cryptography", "data",
             "Data accessible to the vendor is encrypted where appropriate."),
            ("A.8.16", "Monitoring activities", "monitoring",
             "Vendor access and activity is logged and monitored."),
            ("A.5.24", "Information security incident management planning", "incident",
             "Incident response and notification responsibilities are defined with the vendor."),
        ],
    },
}

HIGH_SENSITIVITY_KEYWORDS = [
    "pii", "personal", "ssn", "social security", "health", "phi", "medical",
    "credit card", "card number", "payment", "financial", "bank",
    "credential", "password", "secret", "api key", "source code",
    "confidential", "customer data", "biometric",
]
MEDIUM_SENSITIVITY_KEYWORDS = [
    "email", "contact", "usage", "analytics", "log", "internal", "employee",
    "address", "phone",
]
LOW_SENSITIVITY_KEYWORDS = ["public", "marketing", "aggregate", "anonymi"]

# Catches "none", "no data", "no customer data", "n/a", "none - just X", etc.
# Checked before keyword matching so a negated phrase isn't caught by a
# substring like "customer data" inside "no customer data". Matches at the
# START of the text (not just an exact full match) so trailing explanation
# text ("none - automated validation only") is still caught.
NO_ACCESS_RE = re.compile(
    r"^(none|no|n/?a)\b|\bno\b[\w\s]{0,20}\b(data|access|information|pii)\b")


def finding(vendor, service, data_access, contract, sensitivity,
            suggested_risk, risk_rating, controls, recommendation,
            next_review, trend):
    """Every vendor assessment returns one of these. Structured data, not printed text."""
    return {
        "vendor": vendor,
        "service": service,
        "data_access": data_access,
        "contract": contract,
        "sensitivity": sensitivity,
        "suggested_risk": suggested_risk,
        "risk_rating": risk_rating,
        "controls": controls,
        "recommendation": recommendation,
        "next_review": next_review,
        "trend": trend,
    }


# ------------------------------------------------------------------
# Data collection: CSV -> vendor rows
# ------------------------------------------------------------------

HEADER_ALIASES = {
    "vendor": "vendor", "vendor name": "vendor", "name": "vendor",
    "service": "service", "service provided": "service", "services": "service",
    "data": "data_access", "data accessed": "data_access",
    "data they access": "data_access", "data access": "data_access",
    "contract": "contract", "contract exists": "contract",
    "has contract": "contract", "contract in place": "contract",
    "whether a contract exists": "contract",
    "risk": "risk_rating", "risk rating": "risk_rating",
}


def parse_vendor_rows(fh):
    """Parse an already-open CSV file/text stream. Returns a list of raw vendor row dicts.

    Shared by read_vendors() (CLI, opens a path) and anything else that
    already has a file-like object (e.g. a web upload) — so the header
    matching and validation logic only lives in one place.
    """
    vendors = []
    reader = csv.DictReader(fh)
    field_map = {}
    for raw in reader.fieldnames or []:
        key = HEADER_ALIASES.get(raw.strip().lower())
        if key:
            field_map[raw] = key

    required = {"vendor", "service", "data_access", "contract"}
    missing = required - set(field_map.values())
    if missing:
        raise ValueError(
            f"CSV is missing required column(s): {', '.join(sorted(missing))}. "
            f"Expected headers like: vendor name, service provided, "
            f"data they access, contract exists.")

    for row in reader:
        vendor_row = {}
        for raw_header, value in row.items():
            key = field_map.get(raw_header)
            if key:
                vendor_row[key] = (value or "").strip()
        if not vendor_row.get("vendor"):
            continue
        vendors.append(vendor_row)
    return vendors


def read_vendors(csv_path):
    """Read the vendor CSV from a file path. Returns a list of raw vendor row dicts."""
    with open(csv_path, newline="", encoding="utf-8-sig") as fh:
        return parse_vendor_rows(fh)


# ------------------------------------------------------------------
# Control mapping
# ------------------------------------------------------------------

def classify_sensitivity(data_access_text):
    """Classify the sensitivity of data a vendor accesses from free text."""
    text = data_access_text.strip().lower()
    if not text or NO_ACCESS_RE.search(text):
        return "LOW"
    if any(k in text for k in HIGH_SENSITIVITY_KEYWORDS):
        return "HIGH"
    if any(k in text for k in LOW_SENSITIVITY_KEYWORDS):
        return "LOW"
    if any(k in text for k in MEDIUM_SENSITIVITY_KEYWORDS):
        return "MEDIUM"
    # unclassified free text defaults to MEDIUM rather than assuming it's safe
    return "MEDIUM"


def parse_contract(value):
    return value.strip().lower() in ("yes", "y", "true", "1")


def map_controls(vendor_row, framework):
    """Map a vendor against a framework's control areas.

    Returns (controls, sensitivity, contract). Status is derived from what
    the CSV actually tells us:
      - governance/incident controls: GAP if no contract, OK if one exists
      - access/data/monitoring controls: can't be verified from a CSV alone,
        so they're flagged for review, prioritized by data sensitivity
    """
    contract = parse_contract(vendor_row["contract"])
    sensitivity = classify_sensitivity(vendor_row["data_access"])

    controls = []
    for cid, name, category, description in framework["controls"]:
        if category in ("governance", "incident"):
            status = "OK" if contract else "GAP"
            note = ("Documented in vendor contract." if contract else
                    "No contract on file — this control has no documented basis.")
        else:
            if sensitivity == "HIGH":
                status = "PRIORITY REVIEW"
            elif sensitivity == "MEDIUM":
                status = "REVIEW"
            else:
                status = "LOW PRIORITY"
            note = (f"Data sensitivity classified as {sensitivity} from "
                    f"\"{vendor_row['data_access']}\" — cannot confirm control "
                    f"implementation from a vendor list alone; verify directly "
                    f"with the vendor.")
        controls.append({
            "id": cid, "name": name, "description": description,
            "status": status, "note": note,
        })
    return controls, sensitivity, contract


def suggest_risk(sensitivity, contract):
    """Heuristic starting point — not a substitute for human judgement."""
    if not contract and sensitivity == "HIGH":
        return "HIGH"
    if not contract:
        return "MEDIUM"   # no contract is itself a risk, regardless of data
    if sensitivity == "HIGH":
        return "MEDIUM"
    return "LOW"


def build_recommendation(vendor_row, sensitivity, contract, risk_rating):
    recs = []
    if not contract:
        recs.append(
            f"Put a signed contract in place with {vendor_row['vendor']} covering "
            "data handling, confidentiality, and breach notification before "
            "continuing to share access.")
    if sensitivity == "HIGH":
        recs.append(
            "Confirm encryption, access controls, and monitoring directly with "
            "the vendor given the sensitivity of the data involved; consider "
            "requesting a SOC 2 report or equivalent attestation.")
    if risk_rating == "HIGH":
        recs.append("Escalate for review before renewing or expanding this relationship.")
    if not recs:
        recs.append("No immediate action — reassess at next periodic vendor review.")
    return " ".join(recs)


# ------------------------------------------------------------------
# History: tracks risk ratings across runs so trends are visible
# ------------------------------------------------------------------

def read_last_ratings(history_path):
    """Returns {vendor: most_recent_risk_rating} from a prior history file."""
    last = {}
    try:
        with open(history_path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                vendor = row.get("vendor")
                rating = row.get("risk_rating")
                if vendor and rating:
                    last[vendor] = rating   # later rows overwrite earlier ones
    except (OSError, FileNotFoundError):
        pass
    return last


def append_history(findings, history_path, org):
    """Append this run's ratings to the history log for future trend comparisons."""
    today = datetime.date.today().isoformat()
    file_exists = True
    try:
        open(history_path, "r").close()
    except OSError:
        file_exists = False

    with open(history_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if not file_exists:
            writer.writerow(["date", "org", "vendor", "service", "risk_rating",
                             "contract", "sensitivity", "next_review"])
        for f in findings:
            writer.writerow([today, org, f["vendor"], f["service"], f["risk_rating"],
                             "yes" if f["contract"] else "no", f["sensitivity"],
                             f["next_review"]])


# ------------------------------------------------------------------
# Risk rating: human judgement, gathered separately from the mapping above
# ------------------------------------------------------------------

def assign_risk_ratings(vendors, framework, auto=False, last_ratings=None):
    """Run the assessment for each vendor. Returns a list of finding dicts.

    If a vendor row already has a risk_rating column filled in, that value
    is used. Otherwise this prompts interactively, unless auto=True, in
    which case the suggested heuristic rating is used without prompting.
    """
    last_ratings = last_ratings or {}
    findings = []
    for row in vendors:
        controls, sensitivity, contract = map_controls(row, framework)
        suggested = suggest_risk(sensitivity, contract)

        existing = (row.get("risk_rating") or "").strip().upper()
        if existing in RISK_RANK:
            risk_rating = existing
        elif auto:
            risk_rating = suggested
        else:
            risk_rating = _prompt_risk_rating(row, sensitivity, contract, suggested)

        recommendation = build_recommendation(row, sensitivity, contract, risk_rating)
        next_review = (datetime.date.today() +
                       datetime.timedelta(days=REVIEW_CADENCE_DAYS[risk_rating])).isoformat()

        previous = last_ratings.get(row["vendor"])
        if previous is None:
            trend = "NEW"
        elif previous == risk_rating:
            trend = "UNCHANGED"
        elif RISK_RANK.get(previous, 1) < RISK_RANK[risk_rating]:
            trend = "IMPROVED"        # e.g. HIGH -> LOW
        else:
            trend = "WORSENED"        # e.g. LOW -> HIGH

        findings.append(finding(
            vendor=row["vendor"], service=row["service"],
            data_access=row["data_access"], contract=contract,
            sensitivity=sensitivity, suggested_risk=suggested,
            risk_rating=risk_rating, controls=controls,
            recommendation=recommendation, next_review=next_review,
            trend=trend,
        ))
    return findings


def _prompt_risk_rating(row, sensitivity, contract, suggested):
    print(f"\n  Next up: {row['vendor']} — {row['service']}", file=sys.stderr)
    print(f"    Data accessed: {row['data_access']} (sensitivity: {sensitivity})",
          file=sys.stderr)
    print(f"    Contract on file: {'yes' if contract else 'no'}", file=sys.stderr)
    print(f"    My best guess: {suggested}", file=sys.stderr)
    while True:
        answer = input(
            f"    What's your call — low, medium, or high? (Enter to go with {suggested}): "
        ).strip().upper()
        if answer == "":
            return suggested
        if answer in RISK_RANK:
            return answer
        print("    Just type low, medium, or high.", file=sys.stderr)


# ------------------------------------------------------------------
# Reporting — separate from data collection and risk assignment
# ------------------------------------------------------------------

def print_report(findings, framework_label, org):
    print_banner(org)
    print(f"  Framework: {framework_label}")
    print(f"  {datetime.date.today().isoformat()}")
    print("=" * 52)

    counts = {}
    for f in findings:
        counts[f["risk_rating"]] = counts.get(f["risk_rating"], 0) + 1
    summary = "  ".join(f"{_tag(r)} {counts[r]}"
                        for r in sorted(counts, key=lambda r: RISK_RANK[r]))
    print(f"\nHere's how it shakes out — {summary}   ({len(findings)} vendor(s) reviewed)\n")

    for f in sorted(findings, key=lambda f: RISK_RANK[f["risk_rating"]]):
        print("-" * 68)
        print(f"{_tag(f['risk_rating'])}  {f['vendor']} — {f['service']}  ({f['trend']})")
        print("-" * 68)
        print(f"  Data accessed: {f['data_access']} (sensitivity: {f['sensitivity']})")
        print(f"  Contract on file: {'yes' if f['contract'] else 'no'}")
        print(f"  Suggested rating: {f['suggested_risk']}  |  Assigned: {f['risk_rating']}")
        print(f"  Next review due: {f['next_review']}")
        print("  Controls:")
        for c in f["controls"]:
            print(f"    [{c['status']}] {c['id']} {c['name']}")
        print(f"\n  RECOMMENDATION: {f['recommendation']}")
        print()

    print("=" * 68)
    print("  That's the full picture — full write-up saved if you passed --report.\n")


def build_markdown_report(findings, framework_label, csv_path, org, prepared_by=None):
    """Build the markdown report as a string. Used by both the CLI (which
    writes it to disk) and anything else that wants the content directly
    (e.g. a web app offering it as a download)."""
    today = datetime.date.today().isoformat()

    counts = {}
    for f in findings:
        counts[f["risk_rating"]] = counts.get(f["risk_rating"], 0) + 1

    lines = [
        f"# Third-Party Vendor Risk Assessment — {org}",
        "",
        f"**Date:** {today}  ",
    ]
    if prepared_by:
        lines.append(f"**Prepared by:** {prepared_by}  ")
    lines += [
        f"**Source:** {csv_path}  ",
        f"**Framework:** {framework_label}  ",
        "**Method:** Vendor-supplied data (service, data accessed, contract "
        "status) mapped to control areas; risk ratings are human-assigned, "
        "with a heuristic suggestion shown alongside for reference.",
        "",
        "## Summary",
        "",
        "| Risk | Vendors |",
        "|---|---|",
    ]
    for r in sorted(counts, key=lambda r: RISK_RANK[r]):
        lines.append(f"| {r} | {counts[r]} |")

    lines += [
        "",
        "| Vendor | Service | Risk | Trend | Contract | Data Sensitivity | Next Review |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in sorted(findings, key=lambda f: RISK_RANK[f["risk_rating"]]):
        lines.append(
            f"| {f['vendor']} | {f['service']} | {f['risk_rating']} | {f['trend']} | "
            f"{'yes' if f['contract'] else 'no'} | {f['sensitivity']} | {f['next_review']} |")

    lines += ["", "## Findings", ""]

    for f in sorted(findings, key=lambda f: RISK_RANK[f["risk_rating"]]):
        lines.append(f"### [{f['risk_rating']}] {f['vendor']} — {f['service']} ({f['trend']})")
        lines.append("")
        lines.append(f"- **Data accessed:** {f['data_access']}")
        lines.append(f"- **Data sensitivity:** {f['sensitivity']}")
        lines.append(f"- **Contract on file:** {'yes' if f['contract'] else 'no'}")
        lines.append(f"- **Suggested rating:** {f['suggested_risk']}  |  "
                      f"**Assigned rating:** {f['risk_rating']}")
        lines.append(f"- **Next review due:** {f['next_review']}")
        lines.append("")
        lines.append("| Control | Area | Status | Note |")
        lines.append("|---|---|---|---|")
        for c in f["controls"]:
            lines.append(f"| {c['id']} {c['name']} | {c['description']} | "
                         f"{c['status']} | {c['note']} |")
        lines.append("")
        lines.append(f"**Recommendation:** {f['recommendation']}")
        lines.append("")

    lines += [
        "## Limitations",
        "",
        "- Data sensitivity is classified from free-text keywords in the "
        "vendor list; it is a starting point, not a confirmed classification.",
        "- Access, data protection, and monitoring controls cannot be "
        "verified from a vendor list alone — they are flagged for review, "
        "not pass/fail.",
        "- Risk ratings are human-assigned; the suggested rating is a "
        "heuristic based only on contract status and data sensitivity.",
        "- This assessment reflects a single point in time and should be "
        "repeated on a periodic basis (e.g. annually, or on contract renewal).",
        "- Trend (NEW/UNCHANGED/IMPROVED/WORSENED) is based on this tool's "
        f"own history log ({HISTORY_FILE}); it has no visibility into "
        "assessments done outside this tool.",
        "",
    ]

    return "\n".join(lines)


def write_report(findings, framework_label, csv_path, org, prepared_by=None):
    """Write the markdown report to disk — the CLI deliverable."""
    today = datetime.date.today().isoformat()
    stem = csv_path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    filename = f"vendor_risk_{stem}_{today}.md"
    content = build_markdown_report(findings, framework_label, csv_path, org, prepared_by)
    with open(filename, "w") as fh:
        fh.write(content)
    return filename


def _flag_value(name, default=None):
    if name in sys.argv:
        idx = sys.argv.index(name)
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return default


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 vendor_risk.py <vendors.csv> [--framework nist-csf|iso27001] "
              "[--auto] [--report] [--org \"Name\"] [--by \"Your Name\"] [--no-history]")
        print("Example: python3 vendor_risk.py vendors.csv --framework iso27001 --report "
              "--org \"Normi AI\" --by \"Suhani Gupta\"")
        sys.exit(1)

    csv_path = sys.argv[1]

    framework_name = _flag_value("--framework", "nist-csf")
    if framework_name not in FRAMEWORKS:
        print(f"Unknown framework '{framework_name}'. Choose from: "
              f"{', '.join(FRAMEWORKS)}")
        sys.exit(1)
    framework = FRAMEWORKS[framework_name]

    auto = "--auto" in sys.argv
    org = _flag_value("--org", DEFAULT_ORG)
    prepared_by = _flag_value("--by")
    track_history = "--no-history" not in sys.argv

    try:
        vendors = read_vendors(csv_path)
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not vendors:
        print("No vendor rows found in CSV.")
        sys.exit(1)

    last_ratings = read_last_ratings(HISTORY_FILE) if track_history else {}

    print(f"NormiGuard here — reviewing {len(vendors)} vendor(s) against "
          f"{framework['label']} ...", file=sys.stderr)
    findings = assign_risk_ratings(vendors, framework, auto=auto, last_ratings=last_ratings)
    print_report(findings, framework["label"], org)

    if track_history:
        append_history(findings, HISTORY_FILE, org)

    if "--report" in sys.argv:
        filename = write_report(findings, framework["label"], csv_path, org, prepared_by)
        print(f"\nReport written to: {filename}")


if __name__ == "__main__":
    main()
