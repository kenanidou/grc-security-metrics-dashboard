# Metric definitions

Reporting date: 1 Nov 2026. "Open" means no remediation / close date.

| Metric | Definition | Source fields |
|---|---|---|
| Open Vulnerabilities | Count of findings with no remediation date | vulnerabilities.is_open |
| Open Critical & High | Open findings with severity Critical or High | severity, is_open |
| Overdue Vulnerabilities | Open findings where reporting date > SLA due date | is_overdue |
| % Overdue | Overdue / Open | |
| % Remediated Within SLA | Remediated findings closed on or before SLA due date / all remediated findings | within_sla |
| MTTR (days) | Average days from discovery to remediation, remediated findings only | days_to_remediate |
| SLA due date | discovered_date + SLA days (Critical 15, High 30, Medium 90, Low 180) | sla_due_date |
| Age bucket | Days open for open findings: 0-30, 31-60, 61-90, 91-180, 180+ | age_bucket |
| % Controls Effective | Controls whose most recent test is "Effective" / controls tested | control_tests.is_latest_test, test_result |
| Control Effectiveness Score | Average of test scores (Effective 1, Partially 0.5, Ineffective 0) | result_score |
| Active Exceptions | Approved exceptions with expiry date on or after reporting date | exceptions.is_active |
| Exceptions Expiring 30d | Active exceptions that expire within 30 days | expiring_30d |
| Expired Exceptions | Approved exceptions past their expiry date (should be renewed or closed) | is_expired |
| Open Issues | Audit / assessment issues with no close date | issues.is_open |
| Overdue Issues | Open issues past their due date | issues.is_overdue |

## Data quality rules

| Rule | Action |
|---|---|
| Duplicate vuln_id | Removed |
| Severity not in standard list (e.g. "high") | Mapped to standard value |
| Severity missing | Derived from CVSS v3 band (0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10 Critical) |
| Remediated before discovered | Remediation date cleared, finding re-opened |
| asset_id not in inventory | Set to UNKNOWN |
| Asset owner missing | Set to Unassigned |
| Exception risk rating missing | Inherited from linked vulnerability |
