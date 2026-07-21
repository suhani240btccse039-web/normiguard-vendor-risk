# NormiGuard — Third-Party Vendor Risk Assessment

A Python CLI tool that assesses third-party vendor risk against simplified
**NIST CSF** or **ISO/IEC 27001** control frameworks, and produces a
ranked markdown risk report with recommendations.

Built as part of a security/GRC internship project, to bring some
structure to how vendor risk gets tracked instead of relying on ad-hoc
spreadsheet judgement calls.

## What it does

1. **Reads** a CSV of vendors (name, service provided, data they access,
   whether a contract exists).
2. **Maps** each vendor against 5 control areas from your chosen
   framework — governance, access control, data protection, monitoring,
   and incident response.
3. **Assigns risk** (low/medium/high) — the tool suggests a starting
   point based on data sensitivity and contract status, but a human
   confirms or overrides every rating. Risk is a judgement call, not
   something a script should decide unsupervised.
4. **Tracks history** across runs — re-run it later and each vendor is
   tagged `NEW` / `UNCHANGED` / `IMPROVED` / `WORSENED` against its last
   assessment, with a review-due date based on risk level (HIGH → 90
   days, MEDIUM → 180 days, LOW → 365 days).
5. **Reports** — writes a clean markdown deliverable, separate from the
   assessment logic itself.

## Why it's built this way

The code deliberately separates three concerns:
- **Data collection** (`read_vendors`) — just facts, no judgement.
- **Assessment** (`map_controls`, `assign_risk_ratings`) — turns facts
  into a structured verdict per vendor.
- **Reporting** (`print_report`, `write_report`) — takes the verdicts and
  renders them. Never re-derives facts, only formats.

It's also honest about what a CSV can and can't tell you: contract
status is a known fact, so governance/incident-response controls get a
definitive `OK`/`GAP`. Access, data protection, and monitoring controls
can't be verified from a vendor list alone, so those are flagged for
review — prioritized by data sensitivity — rather than faked as pass/fail.

## Usage

```bash
python3 vendor_risk.py vendors_sample.csv --report
python3 vendor_risk.py vendors_sample.csv --framework iso27001
python3 vendor_risk.py vendors_sample.csv --auto --report   # skip prompts, use suggested ratings
python3 vendor_risk.py vendors_sample.csv --report --org "Your Company" --by "Your Name"
```

CSV columns expected (header row, case-insensitive — a few phrasings are
accepted, e.g. "vendor name" or "vendor"):

```
vendor name, service provided, data they access, contract exists
```

Each run appends to `vendor_risk_history.csv` so repeat assessments show
risk trend over time. Use `--no-history` to skip logging.

## Example output

Running against the included `vendors_sample.csv` ranks vendors from
highest to lowest risk, e.g. a freelance contractor with source code
access and no signed contract comes out `[HIGH]`, while an analytics
vendor with an executed contract and only aggregated data comes out
`[LOW]`.

## Limitations

- Data sensitivity is classified from free-text keywords — a starting
  point, not a confirmed classification.
- Access/data/monitoring control status reflects review priority, not
  verified implementation.
- Risk ratings are human-assigned; the heuristic suggestion is a nudge,
  not authoritative.
- This is a single point-in-time assessment tool — real vendor risk
  management requires periodic re-review, which is why history tracking
  and review-due dates are built in.

See [`NOTES_vendor_risk.md`](NOTES_vendor_risk.md) for a fuller
walkthrough of the design decisions and code structure.
