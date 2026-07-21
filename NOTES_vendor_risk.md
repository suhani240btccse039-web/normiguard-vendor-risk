# Notes: vendor_risk.py — Third-Party Vendor Risk Assessment

## What it does

Takes a CSV of an organisation's vendors and produces a markdown report
ranking them by risk, with a control-by-control breakdown and
recommendations for each. It's a small GRC (Governance, Risk & Compliance)
tool: it doesn't scan or probe anything — it reasons over data you already
have (vendor name, service, data accessed, contract status).

## Why it's structured this way

Mirrors `audit.py`'s pattern, which separates three concerns that are easy
to tangle together if you're not careful:

1. **Data collection** — get raw facts, no judgement calls yet.
2. **Assessment** — turn raw facts into a structured verdict per item.
3. **Reporting** — take the structured verdicts and render them (console
   or markdown). Reporting never re-derives facts; it only formats.

Keeping these separate means you can test/debug each stage independently,
and swap out the reporting format later without touching the logic that
decides risk.

## Key concepts (for GRC background)

**NIST CSF** (Cybersecurity Framework) — a US framework organizing security
work into five functions: Identify, Protect, Detect, Respond, Recover. Each
function has sub-categories with codes like `PR.AC` (Protect → Access
Control). This tool uses five sub-categories relevant to vendor risk.

**ISO/IEC 27001** — an international standard for information security
management. Its Annex A lists specific controls (e.g. `A.5.19` — security
in supplier relationships). This tool maps the same five risk areas to
ISO control IDs instead, so you can pick whichever framework your
organisation reports against.

**Why only 5 controls, and why these 5** — a vendor CSV only tells you
service, data accessed, and contract status. Rather than pretend to
assess controls you have no evidence for, the tool picks controls that
map cleanly onto what's actually knowable from those three fields:
supply-chain governance, access control, data protection, monitoring,
and incident response.

## Code walkthrough

### `finding()`
One structured dict per vendor — the atomic unit of output. Contains raw
facts (vendor, service, data_access, contract) *and* derived judgements
(sensitivity, suggested_risk, risk_rating, controls, recommendation) in
one place, so reporting never has to recompute anything.

### `read_vendors(csv_path)` — data collection
Parses the CSV. `HEADER_ALIASES` lets the CSV header be phrased a few
different ways ("vendor name" vs "vendor", "data they access" vs "data
accessed") and still map to the same internal field names. Raises early
if a required column is missing, rather than failing confusingly later.

### `classify_sensitivity(text)` — control mapping, step 1
Keyword-matches the free-text "data they access" field into
HIGH / MEDIUM / LOW. Checks for negation first (`NO_ACCESS_RE`) — this is
the bug we hit and fixed: `"No customer data"` contains the substring
`"customer data"` (a HIGH keyword), so naive substring matching
misclassified it as HIGH. The regex checks for a "no ... data/access"
pattern *before* keyword matching, so negated phrases are caught first.

### `map_controls(vendor_row, framework)` — control mapping, step 2
For each of the 5 controls in the chosen framework:
- **governance / incident controls** (depend on contract): status is a
  definitive `OK` or `GAP` — contract existing or not is a known fact.
- **access / data / monitoring controls** (depend on data sensitivity):
  status is `REVIEW` / `PRIORITY REVIEW` / `LOW PRIORITY` — the CSV can't
  tell you whether these controls are actually implemented, only how
  urgently they're worth checking, based on data sensitivity.

This distinction matters: it's honest about what a spreadsheet can and
can't tell you, instead of pretending everything is pass/fail.

### `suggest_risk()` and `assign_risk_ratings()` — the human step
`suggest_risk()` is a simple heuristic (no contract + high sensitivity →
HIGH, etc.) — a *starting point*, not a verdict. `assign_risk_ratings()`
is where the actual rating gets set: it shows you the suggestion and
prompts you to confirm or override, per vendor. This is the deliberate
"human in the loop" step — risk rating is a judgement call, not something
a script should decide unsupervised. `--auto` skips the prompt and just
takes the suggestion, for quick test runs.

### `print_report()` / `write_report()` — reporting
Take the list of finding dicts, sort by risk (HIGH → MEDIUM → LOW), and
render. `print_report` is for the terminal; `write_report` produces the
markdown deliverable (summary table, per-vendor ranked table, one section
per vendor with its control table and recommendation, plus a
"Limitations" section that's honest about what the assessment can't
confirm).

## Usage

```
python3 vendor_risk.py vendors_sample.csv                     # interactive, prompts per vendor
python3 vendor_risk.py vendors_sample.csv --framework iso27001
python3 vendor_risk.py vendors_sample.csv --auto --report     # no prompts, write markdown
```

CSV needs a header row with (some phrasing of): vendor name, service
provided, data they access, contract exists. An optional `risk rating`
column can pre-fill ratings to skip prompting on re-runs.

## Limitations to keep in mind

- Sensitivity classification is keyword-based — it will miss data types
  it doesn't have keywords for (defaults to MEDIUM rather than assuming
  safety).
- Access/data/monitoring control status is a *priority to review*, not a
  pass/fail — the tool cannot confirm implementation from a CSV alone.
- The heuristic-suggested risk rating is a nudge, not authoritative — the
  point of the human prompt is that judgement stays with the person doing
  the assessment.
