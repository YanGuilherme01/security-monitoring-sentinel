# Security monitoring migration: on-premises SIEM to Microsoft Sentinel

A migration playbook for moving a hybrid company from a legacy on-premises SIEM (IBM QRadar) to Microsoft Sentinel: log-source prioritization, rule rewriting from AQL to KQL, workbooks and SOAR automation, shown on a fictional company.

**Author:** [Yan Aragão](https://github.com/YanGuilherme01) · Solutions architect focused on cybersecurity architecture and business outcomes.

> **Status: fictional case study.** The company, environment and all numbers are invented to illustrate the method. The KQL queries and the playbook design are drafts that have not been run against a Sentinel workspace. No customer data or employer material is used. See [what is and is not verified](#what-is-and-is-not-verified).

## Scenario

*MedLogística* (fictional) runs hospital logistics across eight Brazilian states with a hybrid environment (on-premises plus partial Azure). Its six-year-old QRadar deployment shows typical legacy symptoms:

| Problem (assumed) | Effect |
| --- | --- |
| Azure AD, Microsoft 365 and cloud workload logs never reached the SIEM | About 40% of the environment invisible |
| 1,200+ alerts per day, all at the same severity | Two analysts cannot triage; critical incidents detected after days |
| Correlation rules not reviewed in 18 months | Low MITRE ATT&CK coverage |
| Outsourced team spends most of its time on SIEM infrastructure | Little time for detection work |

## Method

1. **Prioritize log sources by detection value**, not by volume:
   - Weeks 1–2: Entra ID sign-in and audit logs, Microsoft 365 activity (identity first).
   - Weeks 3–4: Defender for Endpoint, on-premises Windows events.
   - Weeks 5–6: firewall (CEF/Syslog) and the second EDR.
   - Month 2: email protection and Defender for Cloud.
2. **Rewrite rules, do not just translate them.** Each QRadar rule is classified as migrate, rewrite or retire ([methodology](docs/migration-methodology.md), in Portuguese). Example: a fixed-threshold AQL brute-force rule becomes a KQL rule that excludes machine accounts, separates brute force from password spraying and joins threat intelligence.
3. **Replace dashboards with four workbooks:** SOC operations, identity and access, executive summary, threat hunting.
4. **Automate the most repeated responses** with Logic Apps playbooks: block an IP in Conditional Access, disable a compromised account, enrich IPs with reputation data ([playbook design](playbooks/disable-compromised-account.md), in Portuguese).

## Detection content

[`queries/sentinel-detection-queries.kql`](queries/sentinel-detection-queries.kql) holds draft rules mapped to MITRE ATT&CK:

| Domain | Detection | Technique |
| --- | --- | --- |
| Identity | Impossible travel (two countries within 30 minutes) | T1078 |
| Identity | MFA fatigue / push bombing | T1621 |
| Identity | New privileged role assignment | T1098 |
| Endpoint | Admin tools used by unusual accounts | T1569, T1047, T1053 |
| Cloud | SharePoint/OneDrive mass download | T1567.002 |
| Cloud | Risky service principal activity | T1098.001 |
| Hunting | Same account across three or more distinct alerts | Correlation |

Comments inside the queries are in Portuguese.

## Success criteria for a real migration

The first draft of this repository presented before/after results as if measured. They were illustrative, so they are now framed as the targets a real migration would set and measure at day 60:

| Metric | Target to measure |
| --- | --- |
| Environment coverage | Every in-scope log source connected and healthy |
| MITRE ATT&CK coverage | Mapped and tracked per technique, not as one percentage |
| Daily alert volume | Reduced to what the team can triage, with severity tiers |
| Mean time to detect, critical incidents | Measured from the first event to alert, tracked weekly |
| Analyst time on SIEM infrastructure | Near zero after the SaaS move |

## Lessons

1. Reduce noise before adding rules. A team drowning in alerts misses the critical one.
2. Source coverage comes before correlation. Rules over half the environment correlate nothing.
3. Migrate by detection value, identity first, in waves.

## What is and is not verified

| Item | Status |
| --- | --- |
| Company, environment, counts, timelines | Fictional |
| KQL queries | Drafts; not executed against a workspace |
| Logic Apps playbook | Design only; not deployed; metrics are illustrative targets |
| Before/after results | Removed; replaced by success criteria to measure |

## Repository layout

```text
security-monitoring-sentinel/
├── README.md
├── docs/migration-methodology.md             # phases, prioritization matrix, rule template (PT)
├── playbooks/disable-compromised-account.md  # SOAR design (PT)
└── queries/sentinel-detection-queries.kql    # draft detections
```

## References

- [Microsoft Sentinel documentation](https://learn.microsoft.com/azure/sentinel/)
- [Migrate QRadar detection rules to Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/migration-qradar-detection-rules)
- [MITRE ATT&CK](https://attack.mitre.org/)

Related: [detection-lab](https://github.com/YanGuilherme01/detection-lab) · [zero-trust-blueprint](https://github.com/YanGuilherme01/zero-trust-blueprint) · [cspm-assessment](https://github.com/YanGuilherme01/cspm-assessment) · [cdn-waf-review](https://github.com/YanGuilherme01/cdn-waf-review)
