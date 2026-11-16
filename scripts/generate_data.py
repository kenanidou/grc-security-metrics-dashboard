"""
Generate a synthetic GRC (Governance, Risk & Compliance) dataset for a fictional company.

Creates raw CSV extracts as they might arrive from upstream tools (asset inventory,
vulnerability scanner, control testing, exception register, issue tracker).
Some data quality problems are injected on purpose so that prepare_data.py has
something real to clean and report on.

All data is synthetic. No real company, asset or vulnerability is represented.

Usage:
    python scripts/generate_data.py
"""

import random
from datetime import date, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

TODAY = date(2026, 11, 1)          # reporting date
START = date(2025, 11, 1)          # 12 months of history

BUSINESS_UNITS = ["Manufacturing", "R&D", "Commercial", "Corporate IT", "Supply Chain"]
ASSET_TYPES = ["Server", "Workstation", "Network Device", "Cloud Instance", "Database", "Web Application"]
OS_BY_TYPE = {
    "Server": ["Windows Server 2019", "Windows Server 2022", "RHEL 8", "Ubuntu 22.04"],
    "Workstation": ["Windows 10", "Windows 11", "macOS 14"],
    "Network Device": ["Cisco IOS", "FortiOS", "Junos"],
    "Cloud Instance": ["Amazon Linux 2", "Ubuntu 22.04", "Windows Server 2022"],
    "Database": ["Oracle 19c", "SQL Server 2019", "PostgreSQL 14"],
    "Web Application": ["N/A"],
}
CRITICALITY = ["Critical", "High", "Medium", "Low"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHTS = [0.08, 0.22, 0.45, 0.25]
SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}
VULN_CATEGORIES = ["Missing Patch", "Misconfiguration", "Weak Encryption", "Outdated Software",
                   "Default Credentials", "Exposed Service"]


def rand_date(start: date, end: date) -> date:
    return start + timedelta(days=random.randint(0, (end - start).days))


# ---------------------------------------------------------------- assets
def make_assets(n=300) -> pd.DataFrame:
    rows = []
    for i in range(1, n + 1):
        a_type = random.choice(ASSET_TYPES)
        rows.append({
            "asset_id": f"AST-{i:04d}",
            "hostname": f"{a_type[:3].lower()}-{random.choice(['ath', 'thes', 'bru', 'nyc'])}-{i:04d}",
            "asset_type": a_type,
            "operating_system": random.choice(OS_BY_TYPE[a_type]),
            "business_unit": random.choice(BUSINESS_UNITS),
            "criticality": random.choices(CRITICALITY, [0.1, 0.25, 0.4, 0.25])[0],
            "owner": f"owner{random.randint(1, 40):02d}@example.com",
        })
    df = pd.DataFrame(rows)
    # data quality issues: missing owner, inconsistent casing
    df.loc[df.sample(8, random_state=1).index, "owner"] = None
    df.loc[df.sample(10, random_state=2).index, "business_unit"] = df["business_unit"].str.upper()
    return df


# ---------------------------------------------------------- vulnerabilities
def make_vulnerabilities(assets: pd.DataFrame, n=1800) -> pd.DataFrame:
    rows = []
    for i in range(1, n + 1):
        sev = random.choices(SEVERITIES, SEVERITY_WEIGHTS)[0]
        cvss = {"Critical": (9.0, 10.0), "High": (7.0, 8.9), "Medium": (4.0, 6.9), "Low": (0.1, 3.9)}[sev]
        discovered = rand_date(START, TODAY)
        sla = SLA_DAYS[sev]
        # probability that it has been remediated, and how fast
        if random.random() < 0.72:
            days = int(np.random.gamma(2.0, sla / 2.2))
            remediated = discovered + timedelta(days=max(days, 1))
            remediated = remediated if remediated <= TODAY else None
        else:
            remediated = None
        status = "Closed" if remediated else random.choice(["Open", "Open", "In Progress", "Risk Accepted"])
        rows.append({
            "vuln_id": f"VUL-{i:05d}",
            "asset_id": random.choice(assets["asset_id"].tolist()),
            "finding_title": f"{random.choice(VULN_CATEGORIES)} (synthetic finding {i})",
            "category": random.choice(VULN_CATEGORIES),
            "severity": sev,
            "cvss_score": round(random.uniform(*cvss), 1),
            "discovered_date": discovered.isoformat(),
            "remediated_date": remediated.isoformat() if remediated else None,
            "status": status,
            "scanner": random.choice(["Scanner A", "Scanner B"]),
        })
    df = pd.DataFrame(rows)

    # data quality issues
    dupes = df.sample(25, random_state=3)                                   # duplicate scanner exports
    df = pd.concat([df, dupes], ignore_index=True)
    df.loc[df.sample(12, random_state=4).index, "severity"] = None          # missing severity
    df.loc[df.sample(15, random_state=5).index, "severity"] = "high"        # inconsistent casing
    bad = df[df["remediated_date"].notna()].sample(6, random_state=6).index  # remediated before discovered
    df.loc[bad, "remediated_date"] = (pd.to_datetime(df.loc[bad, "discovered_date"])
                                      - pd.Timedelta(days=5)).dt.date.astype(str)
    df.loc[df.sample(5, random_state=7).index, "asset_id"] = "AST-9999"     # orphan asset reference
    return df


# ---------------------------------------------------------------- controls
CONTROLS = [
    ("Identify", "A.5.9", "Inventory of information and other associated assets"),
    ("Identify", "A.5.12", "Classification of information"),
    ("Protect", "A.5.15", "Access control"),
    ("Protect", "A.5.17", "Authentication information"),
    ("Protect", "A.8.2", "Privileged access rights"),
    ("Protect", "A.8.5", "Secure authentication"),
    ("Protect", "A.8.7", "Protection against malware"),
    ("Protect", "A.8.9", "Configuration management"),
    ("Protect", "A.8.13", "Information backup"),
    ("Protect", "A.8.24", "Use of cryptography"),
    ("Protect", "A.6.3", "Information security awareness, education and training"),
    ("Detect", "A.8.15", "Logging"),
    ("Detect", "A.8.16", "Monitoring activities"),
    ("Detect", "A.8.8", "Management of technical vulnerabilities"),
    ("Respond", "A.5.24", "Incident management planning and preparation"),
    ("Respond", "A.5.26", "Response to information security incidents"),
    ("Recover", "A.5.29", "Information security during disruption"),
    ("Recover", "A.5.30", "ICT readiness for business continuity"),
    ("Govern", "A.5.1", "Policies for information security"),
    ("Govern", "A.5.31", "Legal, statutory, regulatory and contractual requirements"),
]


def make_control_tests() -> pd.DataFrame:
    rows, test_no = [], 1
    for function, ref, name in CONTROLS:
        owner_bu = random.choice(BUSINESS_UNITS)
        # quarterly tests over the last 12 months
        for q in range(4):
            test_date = START + timedelta(days=90 * q + random.randint(0, 60))
            if test_date > TODAY:
                continue
            p_eff = 0.55 + 0.08 * q  # effectiveness improves over the year
            result = random.choices(["Effective", "Partially Effective", "Ineffective"],
                                    [p_eff, (1 - p_eff) * 0.65, (1 - p_eff) * 0.35])[0]
            rows.append({
                "test_id": f"CT-{test_no:04d}",
                "control_ref": ref,
                "control_name": name,
                "csf_function": function,
                "framework": "ISO/IEC 27001:2022 Annex A",
                "business_unit": owner_bu,
                "test_date": test_date.isoformat(),
                "test_result": result,
                "tester": random.choice(["1st line", "2nd line", "Internal Audit"]),
            })
            test_no += 1
    return pd.DataFrame(rows)


# --------------------------------------------------------------- exceptions
def make_exceptions(vulns: pd.DataFrame, n=70) -> pd.DataFrame:
    rows = []
    candidates = vulns[vulns["severity"].isin(["Critical", "High", "Medium"])]
    for i in range(1, n + 1):
        v = candidates.sample(1, random_state=100 + i).iloc[0]
        requested = rand_date(START, TODAY - timedelta(days=5))
        approved = random.random() < 0.85
        expiry = requested + timedelta(days=random.choice([90, 180, 365]))
        rows.append({
            "exception_id": f"EXC-{i:04d}",
            "vuln_id": v["vuln_id"],
            "business_unit": random.choice(BUSINESS_UNITS),
            "risk_rating": v["severity"],
            "justification": random.choice(["Legacy system, vendor patch unavailable",
                                            "Business-critical uptime window",
                                            "Compensating control in place",
                                            "Planned decommission"]),
            "requested_date": requested.isoformat(),
            "approval_status": "Approved" if approved else random.choice(["Pending", "Rejected"]),
            "expiry_date": expiry.isoformat() if approved else None,
            "approver": random.choice(["CISO", "BU Risk Owner", "Deputy CISO"]) if approved else None,
        })
    df = pd.DataFrame(rows)
    df.loc[df.sample(3, random_state=8).index, "risk_rating"] = None  # missing rating
    return df


# ------------------------------------------------------------------- issues
def make_issues(n=140) -> pd.DataFrame:
    rows = []
    for i in range(1, n + 1):
        sev = random.choices(["High", "Medium", "Low"], [0.25, 0.5, 0.25])[0]
        opened = rand_date(START, TODAY)
        due = opened + timedelta(days={"High": 60, "Medium": 120, "Low": 180}[sev])
        closed = None
        if random.random() < 0.6:
            c = opened + timedelta(days=random.randint(10, 200))
            closed = c if c <= TODAY else None
        rows.append({
            "issue_id": f"ISS-{i:04d}",
            "source": random.choices(["Internal Audit", "Self-Assessment", "Penetration Test",
                                      "Regulatory Inspection", "Incident Review"],
                                     [0.3, 0.3, 0.2, 0.1, 0.1])[0],
            "control_ref": random.choice(CONTROLS)[1],
            "business_unit": random.choice(BUSINESS_UNITS),
            "severity": sev,
            "opened_date": opened.isoformat(),
            "due_date": due.isoformat(),
            "closed_date": closed.isoformat() if closed else None,
            "status": "Closed" if closed else random.choice(["Open", "In Remediation"]),
        })
    return pd.DataFrame(rows)


if __name__ == "__main__":
    assets = make_assets()
    vulns = make_vulnerabilities(assets)
    controls = make_control_tests()
    exceptions = make_exceptions(vulns)
    issues = make_issues()

    for name, df in [("assets", assets), ("vulnerabilities", vulns), ("control_tests", controls),
                     ("exceptions", exceptions), ("issues", issues)]:
        df.to_csv(RAW_DIR / f"{name}.csv", index=False)
        print(f"raw/{name}.csv  {len(df):>5} rows")
