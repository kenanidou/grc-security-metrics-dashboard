"""
Automated data preparation for the GRC metrics dashboard.

Reads the raw extracts, applies validation and cleaning rules, derives the fields the
dashboard needs (SLA due dates, overdue flags, ageing, time to remediate, expiring
exceptions) and writes:

  data/clean/*.csv               -> loaded into Power BI
  data/clean/data_quality_log.csv -> every rule, how many records it affected, action taken
  data/clean/date_table.csv      -> calendar table for time intelligence

Run it again whenever new raw extracts arrive; refresh Power BI afterwards.

Usage:
    python scripts/prepare_data.py
"""

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
CLEAN = ROOT / "data" / "clean"
CLEAN.mkdir(parents=True, exist_ok=True)

REPORTING_DATE = pd.Timestamp("2026-11-01")
SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}
VALID_SEVERITIES = list(SLA_DAYS)

dq_log = []


def log(table: str, rule: str, affected: int, action: str) -> None:
    dq_log.append({"table": table, "rule": rule, "records_affected": affected, "action": action})


def standardise(df: pd.DataFrame, col: str, allowed: list, table: str) -> pd.DataFrame:
    """Map values to a canonical list, ignoring case and extra spaces; log what changed."""
    canonical = {a.lower(): a for a in allowed}
    cleaned = df[col].astype("string").str.strip().str.lower().map(canonical)
    changed = int((df[col].notna() & (df[col].astype("string") != cleaned)).sum())
    if changed:
        log(table, f"Inconsistent values in '{col}'", changed, "Mapped to standard list")
    df[col] = cleaned
    return df


# ------------------------------------------------------------------ assets
assets = pd.read_csv(RAW / "assets.csv")
BUSINESS_UNITS = ["Manufacturing", "R&D", "Commercial", "Corporate IT", "Supply Chain"]
assets = standardise(assets, "business_unit", BUSINESS_UNITS, "assets")
assets = standardise(assets, "criticality", ["Critical", "High", "Medium", "Low"], "assets")
missing_owner = assets["owner"].isna().sum()
assets["owner"] = assets["owner"].fillna("Unassigned")
log("assets", "Asset without owner", int(missing_owner), "Owner set to 'Unassigned' (flag for follow-up)")

# --------------------------------------------------------- vulnerabilities
v = pd.read_csv(RAW / "vulnerabilities.csv", parse_dates=["discovered_date", "remediated_date"])

n = len(v)
v = v.drop_duplicates(subset=["vuln_id"])
log("vulnerabilities", "Duplicate vuln_id (repeated scanner export)", n - len(v), "Removed duplicates")

v = standardise(v, "severity", VALID_SEVERITIES, "vulnerabilities")
missing_sev = v["severity"].isna()
# derive missing severity from CVSS score (CVSS v3 qualitative bands)
v.loc[missing_sev, "severity"] = pd.cut(v.loc[missing_sev, "cvss_score"],
                                        bins=[0, 3.9, 6.9, 8.9, 10.0],
                                        labels=["Low", "Medium", "High", "Critical"]).astype("string")
log("vulnerabilities", "Missing severity", int(missing_sev.sum()), "Derived from CVSS score")

bad_dates = v["remediated_date"] < v["discovered_date"]
log("vulnerabilities", "Remediated before discovered", int(bad_dates.sum()),
    "Remediation date cleared, record re-opened for review")
v.loc[bad_dates, "remediated_date"] = pd.NaT
v.loc[bad_dates, "status"] = "Open"

orphans = ~v["asset_id"].isin(assets["asset_id"])
log("vulnerabilities", "Reference to unknown asset_id", int(orphans.sum()),
    "Kept, asset_id set to 'UNKNOWN' (inventory gap)")
v.loc[orphans, "asset_id"] = "UNKNOWN"
if orphans.any():
    assets = pd.concat([assets, pd.DataFrame([{
        "asset_id": "UNKNOWN", "hostname": "unknown", "asset_type": "Unknown", "operating_system": "Unknown",
        "business_unit": "Unknown", "criticality": "Unknown", "owner": "Unassigned"}])], ignore_index=True)

# derived fields
v["sla_days"] = v["severity"].map(SLA_DAYS)
v["sla_due_date"] = v["discovered_date"] + pd.to_timedelta(v["sla_days"], unit="D")
v["is_open"] = v["remediated_date"].isna()
v["days_to_remediate"] = (v["remediated_date"] - v["discovered_date"]).dt.days
v["age_days"] = (REPORTING_DATE - v["discovered_date"]).dt.days.where(v["is_open"])
v["within_sla"] = (v["remediated_date"] <= v["sla_due_date"]).where(~v["is_open"])
v["is_overdue"] = v["is_open"] & (REPORTING_DATE > v["sla_due_date"])
v["age_bucket"] = pd.cut(v["age_days"], bins=[-1, 30, 60, 90, 180, 10_000],
                         labels=["0-30", "31-60", "61-90", "91-180", "180+"]).astype("string")
v["severity_order"] = v["severity"].map({"Critical": 1, "High": 2, "Medium": 3, "Low": 4})

# ----------------------------------------------------------- control tests
ct = pd.read_csv(RAW / "control_tests.csv", parse_dates=["test_date"])
ct["result_score"] = ct["test_result"].map({"Effective": 1.0, "Partially Effective": 0.5, "Ineffective": 0.0})
ct["is_latest_test"] = ct["test_date"] == ct.groupby("control_ref")["test_date"].transform("max")

# -------------------------------------------------------------- exceptions
ex = pd.read_csv(RAW / "exceptions.csv", parse_dates=["requested_date", "expiry_date"])
miss_rr = ex["risk_rating"].isna()
ex = ex.merge(v[["vuln_id", "severity"]], on="vuln_id", how="left")
ex.loc[miss_rr, "risk_rating"] = ex.loc[miss_rr, "severity"]
ex = ex.drop(columns="severity")
log("exceptions", "Missing risk rating", int(miss_rr.sum()), "Inherited from linked vulnerability severity")

approved = ex["approval_status"].eq("Approved")
ex["is_active"] = approved & (ex["expiry_date"] >= REPORTING_DATE)
ex["is_expired"] = approved & (ex["expiry_date"] < REPORTING_DATE)
ex["days_to_expiry"] = (ex["expiry_date"] - REPORTING_DATE).dt.days.where(ex["is_active"])
ex["expiring_30d"] = ex["is_active"] & (ex["days_to_expiry"] <= 30)

# ------------------------------------------------------------------ issues
iss = pd.read_csv(RAW / "issues.csv", parse_dates=["opened_date", "due_date", "closed_date"])
iss["is_open"] = iss["closed_date"].isna()
iss["is_overdue"] = iss["is_open"] & (REPORTING_DATE > iss["due_date"])
iss["age_days"] = (REPORTING_DATE - iss["opened_date"]).dt.days.where(iss["is_open"])
iss["days_to_close"] = (iss["closed_date"] - iss["opened_date"]).dt.days

# -------------------------------------------------------------- date table
dates = pd.DataFrame({"date": pd.date_range("2025-11-01", "2027-12-31", freq="D")})
dates["year"] = dates["date"].dt.year
dates["month_num"] = dates["date"].dt.month
dates["month"] = dates["date"].dt.strftime("%b %Y")
dates["month_start"] = dates["date"].dt.to_period("M").dt.start_time
dates["quarter"] = "Q" + dates["date"].dt.quarter.astype(str) + " " + dates["year"].astype(str)

# ------------------------------------------------- business unit dimension
# one shared slicer table that filters assets (and through them vulnerabilities),
# control tests, exceptions and issues
bu_dim = pd.DataFrame({"business_unit": sorted(set(assets["business_unit"]) | set(ct["business_unit"])
                                              | set(ex["business_unit"]) | set(iss["business_unit"]))})

# ------------------------------------------------------------------- write
outputs = {"business_units": bu_dim, "assets": assets, "vulnerabilities": v, "control_tests": ct,
           "exceptions": ex, "issues": iss, "date_table": dates}
for name, df in outputs.items():
    df.to_csv(CLEAN / f"{name}.csv", index=False, date_format="%Y-%m-%d")

dq = pd.DataFrame(dq_log)
dq.insert(0, "run_date", REPORTING_DATE.date())
dq.to_csv(CLEAN / "data_quality_log.csv", index=False)

# ------------------------------------------------------------------ summary
closed = v[~v["is_open"]]
print("Data quality log:")
print(dq.drop(columns="run_date").to_string(index=False))
print("\nHeadline metrics (check against Power BI):")
print(f"  Open vulnerabilities          {int(v['is_open'].sum())}")
print(f"  Overdue (past SLA)            {int(v['is_overdue'].sum())}")
print(f"  Remediated within SLA         {closed['within_sla'].mean():.1%}")
print(f"  Mean time to remediate (days) {closed['days_to_remediate'].mean():.1f}")
latest = ct[ct["is_latest_test"]]
print(f"  Controls effective (latest)   {(latest['test_result'] == 'Effective').mean():.1%}")
print(f"  Active exceptions             {int(ex['is_active'].sum())}  (expiring in 30d: {int(ex['expiring_30d'].sum())})")
print(f"  Open issues / overdue         {int(iss['is_open'].sum())} / {int(iss['is_overdue'].sum())}")
