# SOC Threat Detection & Incident Response Lab

**Hands-on Splunk SIEM project | Security log analysis · Detection engineering · Alerting · SOC investigation**

This repository documents a practical, three-phase Security Operations Center (SOC) learning project. The aim is to demonstrate how an analyst can investigate security logs, create detections, validate alerts, visualise activity, and document evidence-based findings.

> **Lab disclaimer:** This is an educational project using historical sample logs, **not** a live production SOC or a confirmed security incident.

## Project roadmap

| Phase | Focus | Status |
| --- | --- | --- |
| **Phase 1 — SSH Brute-Force Detection** | OpenSSH log ingestion, SPL analysis, threshold-based detection, scheduled alert testing, four-panel dashboard, incident investigation | **Technical work completed; publishing evidence** |
| **Phase 2 — Windows & Linux Security Log Investigation** | Authentication and security-event investigation across Windows/Linux and relevant endpoint logs | Planned |
| **Phase 3 — SOC Detection, Alerts & Incident Response** | Expanded detections, alert triage, incident response, and reporting | Planned |

## Phase 1 at a glance

I analysed the publicly available `OpenSSH_2k.log` sample using Splunk Enterprise. The core SPL rule identifies **at least 10 failed SSH password events from the same source IP within a fixed five-minute bucket**.

| Verified lab observation | Result |
| --- | ---: |
| Total `Failed password` events | **520** |
| Most active IP | `183.62.140.253` |
| Failed-password events from that IP (entire sample) | **286** |
| Highest five-minute count for that IP | **141** |
| Distinct IPs crossing the rule threshold | **6** |
| IP/time-window matches returned by the rule | **10** |
| Dashboard panels built | **4** |

[**Explore Phase 1: SSH Brute-Force Detection**](https://github.com/vishvha/SOC-Threat-Detection-Lab/tree/main/Phase_1_SSH_Bruteforce)

### What I built

- SPL queries for investigating failed authentication, extracting source IPs, counting events, and identifying time-based bursts.
- A scheduled detection rule configured to evaluate recent activity every five minutes.
- A **separate historical-data test alert** that successfully produced triggered-alert records; the test alert was disabled after verification.
- A four-panel **SSH Security Monitoring Dashboard**: failure timeline, Top 10 source IPs, total failures, and detection-results table.
- An incident investigation examining repeated `root` attempts, invalid-user messages, successful SSH authentication elsewhere in the dataset, and detection limitations.

## Technology and skills

| Tools/data | Skills demonstrated |
| --- | --- |
| Splunk Enterprise, SPL | Log ingestion, searching, field extraction, `stats`, time bucketing and filtering |
| OpenSSH authentication log sample | Authentication-event interpretation and correlation |
| Splunk alerts and dashboards | Detection scheduling, controlled alert testing and security visualisation |
| GitHub | Technical documentation, evidence handling and portfolio publishing |

## Repository layout

```text
SOC-Threat-Detection-Lab/
├── README.md                         # You are here
└── Phase_1_SSH_Bruteforce/
    └── README.md                     # Detailed Phase 1 write-up
```

*Supporting SPL files, a redacted screenshot set and the investigation report can be added to the Phase 1 folder as separate evidence artefacts. Phase 2 and Phase 3 folders will be added when that work is underway.*

## Scope and evidence standards

- The log sample is **historical and static**; these results are not based on live continuous forwarding.
- The primary alert is configured for recent events, but the triggered-alert evidence comes from a separate test search covering the historical data.
- A triggered brute-force rule indicates **suspicious activity to investigate**, not proven compromise.
- Figures refer to **log messages**, not necessarily distinct human login attempts.
- The source logs omit the year. Splunk's displayed year is an ingestion interpretation, **not a verified original log year**.
- Personal details, licence banners and secrets should be removed from screenshots before they are published.

## Data attribution

The SSH log sample is **`OpenSSH_2k.log` from the public Loghub OpenSSH dataset**. Credit for the original log collection belongs to its authors and maintainers; the analysis and documentation here concern the lab workflow performed with that sample.

---

*This repository is a learning portfolio. Findings are limited to the events available in the sample and the checks documented in each phase.*
