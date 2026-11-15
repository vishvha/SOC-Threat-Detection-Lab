# Phase 2 — Windows & Linux Security Log Investigations

## Overview

This phase of my SOC Threat Detection & Incident Response Lab focuses on investigating Windows and Linux security logs using Splunk Enterprise.

The objective was to develop practical SOC analyst skills in authentication log analysis, suspicious activity identification, SPL-based detection, and security dashboard development.

**Status:** Completed — November 2026

## Tools and Technologies

- Splunk Enterprise and Splunk Processing Language (SPL)
- Windows Security Event Logs
- Sysmon event analysis
- Linux SSH authentication logs
- Historical and synthetic security datasets

## Investigation Activities

### 1. Windows Security Log Analysis

Studied and investigated Windows authentication events, including:

- Event ID 4624 — Successful logon
- Event ID 4625 — Failed logon
- Event ID 4740 — Account lockout
- Windows logon types and authentication-related fields

Configured local Windows Security log collection in Splunk and used a separate synthetic Windows authentication dataset for additional username and source-IP investigations.

### 2. Sysmon Analysis

Studied Sysmon telemetry, including process creation, network connections, image loading, and file creation events.

Practised investigating process-related information and understanding how endpoint telemetry supports SOC investigations.

### 3. Linux SSH Investigation

Analysed Linux SSH authentication logs to identify:

- Failed and successful SSH authentication attempts
- Repeated login failures from source IP addresses
- Usernames targeted during authentication attempts
- Suspicious authentication patterns

### 4. Cross-Platform Password-Spraying Detection

Developed SPL searches to extract and normalise usernames and source IP addresses from Windows and Linux datasets.

Implemented a detection condition for source IPs targeting **three or more distinct usernames within a fixed 10-minute interval**.

This rule identifies potential password-spraying behaviour. Detection matches are not automatically confirmed security incidents.

## Key Findings

| Finding | Result |
|---|---|
| Windows failed authentication events | 5,129 |
| Linux failed SSH authentication events | 520 |
| Potential password-spraying matches | 120 |
| Detection threshold | 3+ distinct usernames per IP per 10-minute bucket |
| Highest observed distinct username count | 27 |

The Linux and Windows datasets represent different environments and time periods. These findings should not be interpreted as evidence of one coordinated attack.

## Splunk SOC Dashboard

Created **SOC Authentication Security Monitoring**, containing five investigation panels:

1. Windows vs Linux Authentication Failures
2. Top 10 Source IPs by Failed Logons
3. Potential Password-Spraying Detections by Dataset
4. Windows Failed Logon Timeline — 15-Minute Intervals
5. SOC Password-Spraying Investigation Results

The dashboard supports authentication monitoring, investigation prioritisation, and review of detection-rule matches.

## SPL Skills Developed

Practised using SPL commands including `rex`, `eval`, `coalesce()`, `stats`, `dc()`, `bin`, `where`, `sort`, `table`, and `timechart` for log extraction, field normalisation, aggregation, and security analysis.

## Limitations

- The Windows authentication dataset is synthetic.
- The Linux dataset contains historical authentication records.
- Detection logic uses fixed 10-minute time buckets rather than rolling windows.
- The `Alert` classification represents a search result, not an active Splunk alert.
- Additional investigation would be necessary before confirming malicious activity.

## Outcome

Completed hands-on investigations involving Windows authentication logs, Linux SSH activity, Sysmon concepts, cross-platform detection logic, and dashboard development.

This phase provides a foundation for **Phase 3 — SOC Detection, Alerts & Incident Response**.
