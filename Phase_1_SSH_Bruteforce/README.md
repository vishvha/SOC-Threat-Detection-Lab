# Phase 1 — SSH Brute-Force Detection Using Splunk

**SOC investigation lab | Splunk Enterprise · SPL · OpenSSH authentication logs**

[← Back to project overview](../README.md)

## 1. Executive summary

I ingested a historical OpenSSH log sample into Splunk and analysed failed-password activity. I built an SPL rule to identify source IPs producing **10 or more failed SSH password log events per fixed five-minute time bucket**, tested scheduled alerting using a separate historical-data alert, and created a four-panel SOC security dashboard. I then investigated the most active IP and documented the supporting evidence and limitations.

**Outcome:** The evidence is consistent with SSH password brute-force activity and possible username probing. **No successful SSH authentication from the primary suspicious IP was observed in the available dataset; compromise was not established.**

> This is a controlled educational lab, not a live attack investigation. The year shown in Splunk was interpreted during ingestion because the raw sample lacks a year.

## 2. Environment and data

| Property | Lab value |
| --- | --- |
| SIEM | Splunk Enterprise, locally installed on Windows |
| Dataset | Public Loghub `OpenSSH_2k.log` (2,000 raw events) |
| Splunk index | `soc_ssh_lab` |
| Sourcetype | `ssh_lab_auth` |
| Host in log events | `LabSZ` |
| Investigation time picker | **All time** (historical sample) |
| Detection threshold | **10+ `Failed password` events / source IP / fixed 5-minute bucket** |

### Working method

1. Ingest the historical OpenSSH sample into Splunk.
2. Inspect `Failed password`, `Invalid user` and `Accepted password` messages.
3. Extract source IP addresses, aggregate by time bucket and investigate anomalous counts.
4. Configure a scheduled detection and test its execution safely against historical data.
5. Build a dashboard and write an evidence-based SOC incident report.

## 3. Core SPL detection

```spl
index=soc_ssh_lab "Failed password"
| rex field=_raw "from\s+(?<src_ip>\S+)\s+port"
| bin _time span=5m
| stats count by _time, src_ip
| where count >= 10
```

**Explanation:** Filter failed-password events → extract `src_ip` → place timestamps in fixed five-minute buckets → count failures for each source IP and bucket → retain results meeting the threshold.

> This is a **fixed-window**, event-count rule, not a distinct-session or rolling-five-minute detector. A single authentication attempt can produce multiple SSH log messages of different types.

### Verified detection output

The query returned **10 rows**, representing **6 distinct flagged source IPs**:

| Five-minute bucket (Splunk display) | Source IP | Failed-password events |
| --- | --- | ---: |
| 07:25 | `112.95.230.3` | 26 |
| 08:25 | `5.188.10.180` | 15 |
| 09:10 | `103.99.0.122` | 30 |
| 09:10 | `185.190.58.151` | 11 |
| 09:10 | `187.141.143.180` | 25 |
| 09:15 | `187.141.143.180` | 54 |
| 10:50 | `183.62.140.253` | 16 |
| 10:55 | `183.62.140.253` | **141** |
| 11:00 | `103.99.0.122` | 16 |
| 11:00 | `183.62.140.253` | 129 |

The source timestamps in the sample omit a year; the table intentionally shows **time of day only**. The `10:55` count of **141** is the highest matching bucket observed for `183.62.140.253`. Its **286** failed-password events are the total across the sample, **not one five-minute window**.

## 4. Supporting SPL searches

**Total number of failed-password events**

```spl
index=soc_ssh_lab "Failed password"
| stats count
```

**Top 10 source IPs by failed-password event count**

```spl
index=soc_ssh_lab "Failed password"
| rex field=_raw "from\s+(?<src_ip>\S+)\s+port"
| stats count by src_ip
| sort - count
| head 10
```

**Failed-password events over time (all source IPs)**

```spl
index=soc_ssh_lab "Failed password"
| bin _time span=5m
| stats count by _time
```

**Explore all `Invalid user` messages from the primary IP**

```spl
index=soc_ssh_lab "183.62.140.253" "Invalid user"
```

**Search successful SSH password authentications**

```spl
index=soc_ssh_lab "Accepted password"
```

## 5. Alert design and verification

### Main saved alert

| Configuration | Value |
| --- | --- |
| Alert name | `SSH Brute Force Detection - Phase 1` |
| Search | Core detection SPL in Section 3 |
| Mode | Scheduled |
| Cron | `*/5 * * * *` (every five minutes) |
| Search time range | Most recent five-minute window |
| Trigger condition | Results count **greater than 0** |
| Action | **Add to Triggered Alerts** (Medium severity) |

**Critical testing distinction:** The data was imported from a historical file. The main alert evaluates a **recent** five-minute window and is not expected to discover these old events automatically. To test scheduled execution, I created a **separate temporary alert** searching **All time**, scheduled it at one-minute intervals, and confirmed that it created triggered-alert records. I then **disabled the test alert**. These were test triggers using old events, **not real-time attacks**.

## 6. Splunk security dashboard

The **SSH Security Monitoring Dashboard** includes four verified panels:

| Panel | Chart/table type | Analytical purpose |
| --- | --- | --- |
| **Failed SSH Logins Over Time** | Line chart | Reveal bursts and trends across fixed five-minute time buckets |
| **Top Source IPs by Failed SSH Attempts** | Column chart, Top 10 | Compare sources by total failed-password event count |
| **Total Failed SSH Logins** | Single value | Show **520** sample-wide failed-password events |
| **SSH Brute-Force Detection Results** | Statistics table | Display matching source IP, five-minute bucket and event count |

*Dashboard screenshots should be uploaded separately after redacting the developer-licence email address. No image paths are referenced here until those evidence files exist in the repository.*

## 7. SOC investigation — lab case `INC-2026-001`

**Alert:** Potential SSH brute-force activity and username probing  
**Initial severity:** Medium  
**Primary source:** `183.62.140.253`  
**Disposition:** Investigation completed; pending review  
**Incident ID is a lab identifier, not a production ticket.**

### Detection and evidence

- **286** `Failed password` log events originated from the primary IP in the full sample.
- **276** of those failed-password messages contained `root`, and **10** did not contain `root`.
- The busiest fixed five-minute bucket had **141** failed-password events from that IP.
- The source also generated **18 `Invalid user` log events**. Some were observed close in time to failed-password messages; these may represent multiple messages relating to the same attempted authentication.
- Additional attempted username strings included `git`, `ubuntu`, `test` and other names. One event showed `Failed password for git`; this **does not by itself prove** that `git` was an authorised or active account.
- **No `Accepted password` event was observed from the primary source** in the available log sample.

### Cross-check: separate successful authentication

A separate IP, `119.137.62.142`, had an observed `Accepted password` event for user `fztu` at **09:32:20** and a later session close at **09:45:06**. No failed-password attempts for that IP or username were observed in the searches performed. The available evidence does **not** establish that the user was authorised, nor link that successful session to the primary suspicious IP.

### Analyst conclusion

The volume and timing of the failed SSH events support a finding of **suspected password brute force**. Attempts involving invalid usernames also suggest **username enumeration/probing**. There is **no observed successful authentication from the primary source in the provided logs**, and **system compromise is not confirmed**.

### Recommended next steps in a production investigation

Confirm whether the IP is an authorised scanner, review host and network telemetry around the event, check related authentication methods and account activity, identify possible successful logins or post-login actions, and escalate according to SOC procedures. Block or otherwise contain a source **only with appropriate authorisation and supporting context**.

## 8. Limitations and false-positive considerations

- **Historical data:** Static sample data; the dashboard is not evidence of continuous production monitoring.
- **Time windows:** `bin _time span=5m` uses fixed buckets; clustered events near a boundary can be split across buckets.
- **Log counts:** Failed-password log events are not necessarily unique users, sessions, or login attempts.
- **Missing original year:** Splunk inferred/interpreted a year during ingestion; it should not be treated as sourced from the original log lines.
- **Field extraction:** The `rex` pattern is designed for the observed OpenSSH message format and may need adjustment for other log sources.
- **Alert severity:** Medium is a lab starting point; production severity depends on asset criticality, source reputation, successful logins and other context.
- **Potential benign activity:** Authorised scans and configuration/automation errors may trigger the same count-based rule.
- **Limited visibility:** These authentication logs cannot alone prove or disprove post-authentication compromise.

## 9. Evidence and publication checklist

The following supporting artefacts can be added alongside this README. They are **not claimed as already uploaded**:

- [ ] Exported `.spl` or `.txt` files containing the detection and supporting queries.
- [ ] Redacted four-panel dashboard screenshot (remove developer-licence email).
- [ ] Redacted triggered-alert test screenshot (clearly label historical-data test).
- [ ] Final incident investigation report (`INC-2026-001`, lab case).
- [ ] Optional contribution-style activity heatmap based only on verifiable work dates.

## 10. Dataset credit

This lab uses **`OpenSSH_2k.log` from the Loghub public OpenSSH log dataset collection**. The original log content is attributed to its maintainers; the SPL, investigation findings and dashboard work document the analysis conducted for this portfolio project.

---

**Phase 1 scope:** Technical investigation, detection, scheduled-alert testing and dashboarding completed. This README describes those verified activities; repository evidence files should be added and checked before marking publication complete.
