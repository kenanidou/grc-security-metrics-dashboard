"""
Bundle the clean tables into one Excel workbook (one sheet per table) for Power BI.

Using a single typed workbook avoids locale problems with decimal separators and
date formats when CSV files are imported on non-English systems.

Usage:
    python scripts/export_excel.py      (run after prepare_data.py)
"""

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "data" / "clean"
OUT = ROOT / "data" / "GRC_data.xlsx"

DATE_COLUMNS = {
    "vulnerabilities": ["discovered_date", "remediated_date", "sla_due_date"],
    "control_tests": ["test_date"],
    "exceptions": ["requested_date", "expiry_date"],
    "issues": ["opened_date", "due_date", "closed_date"],
    "date_table": ["date", "month_start"],
    "data_quality_log": ["run_date"],
}
TABLES = ["business_units", "assets", "vulnerabilities", "control_tests",
          "exceptions", "issues", "date_table", "data_quality_log"]

with pd.ExcelWriter(OUT, engine="openpyxl") as writer:
    for name in TABLES:
        dates = DATE_COLUMNS.get(name, [])
        df = pd.read_csv(CLEAN / f"{name}.csv", parse_dates=dates)
        for col in dates:
            df[col] = df[col].dt.date
        df.to_excel(writer, sheet_name=name, index=False)
        print(f"{name:<18} {len(df):>5} rows")

print(f"\nWritten {OUT.relative_to(ROOT)}")
