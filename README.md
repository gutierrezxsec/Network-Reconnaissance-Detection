# Network Reconnaissance Detection — Splunk Dashboard & Incident Triage

**Dataset:** Boss of the SOC v3 (BOTSv3)
**Tools:** Splunk Enterprise Free Tier

---

## Overview

A self-directed practice project applying SIEM fundamentals against a real security dataset. It demonstrates a complete Tier 1 SOC workflow: building visibility into network traffic, designing a detection rule for anomalous behavior, manually triaging a flagged incident end-to-end, and mapping findings to a recognized adversary technique (MITRE ATT&CK) — all using the BOTSv3 dataset in Splunk.

---

## Objective

The dashboard answers four fundamental questions about perimeter network traffic:

1. Who is generating the highest volume of network activity?
2. What destination ports are being targeted most frequently?
3. Is any single host executing an automated network scan?
4. Is there anomalous volume indicating potential data exfiltration?

---

## Dashboard

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/64421267-eb97-4f33-8a9c-95a4d17d0c74" />


---


### Panel 1 — Top Talkers (External Traffic)

Filters out internal address ranges (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) to focus only on external-facing traffic, then groups results by source IP and approximate country using `iplocation`. This is the first-pass triage view — high-volume external sources and the ports they touched are usually the first thing an analyst checks.

```spl
index=botsv3 sourcetype="stream:tcp" NOT (src_ip=10.0.0.0/8 OR src_ip=192.168.0.0/16 OR src_ip=172.16.0.0/12)
| iplocation src_ip
| stats count, values(dest_port) as targeted_ports by src_ip, Country
| sort - count
```

<img width="827" height="418" alt="image" src="https://github.com/user-attachments/assets/6a70f3fd-6138-4418-8bf4-d09e7e9c2de8" />


---

### Panel 2 — Destination Port Distribution

Aggregates traffic by `dest_port` to surface which ports see the most activity, making traffic to unusual or non-standard ports visible at a glance.

```spl
index=botsv3 sourcetype="stream:tcp"
| stats count by dest_port
| sort -count
| head 15
```

<img width="1072" height="380" alt="image" src="https://github.com/user-attachments/assets/b155ac07-0913-4881-bf5b-5123ae838379" />


---

### Panel 3 — Scan Detection (core panel)

The main detection logic of the project. Buckets traffic into 5-minute windows and counts how many distinct destination ports each source IP touches within that window. A typical host only touches a handful of ports; a host touching many different ports in a short window shows the textbook signature of network reconnaissance. A threshold of 15+ ports flags that behavior automatically instead of relying on manual review of raw logs.

```spl
index=botsv3 sourcetype=stream:tcp
| bucket _time span=5m
| stats dc(dest_port) as unique_ports by src_ip, _time
| where unique_ports > 15
```

<img width="356" height="431" alt="image" src="https://github.com/user-attachments/assets/6e611558-1d1c-47da-9550-b82efbfd234b" />


---

### Panel 4 — DNS Query Volume Over Time

Tracks DNS query volume over time as a supporting signal alongside the TCP panels above. DNS is commonly abused both for reconnaissance (enumerating internal hosts) and for data exfiltration (tunneling data out through queries), so monitoring its volume extends visibility beyond a single protocol.

```spl
index=botsv3 sourcetype=stream:dns
| timechart count
```

<img width="591" height="418" alt="image" src="https://github.com/user-attachments/assets/21aea3a3-bb73-42f3-a17b-2644200b9db9" />


---

## Alert Configuration

The Panel 3 search was saved as a correlation search with the following configuration:

| Setting | Value |
|---|---|
| **Trigger condition** | Number of results > 0 |
| **Schedule** | Every 5 minutes |
| **Logic** | Flags any `src_ip` with `unique_ports > 15` in a rolling 5-minute bucket |

**Note on real-time behavior:** BOTSv3 is a static, historical dataset rather than a live data stream, so this alert was configured and validated against the dataset rather than tested under continuous real-time conditions. The trigger logic, threshold, and schedule are configured exactly as they would be in production — the only difference is the absence of live incoming data to trigger against repeatedly over time. This is a property of the dataset, not a limitation of the alert design.

**MITRE ATT&CK Mapping:** `T1046` — Network Service Discovery

---

## Findings

### Finding 1 — SSH Brute-Force: 104.128.69.207 → 172.31.38.181

| | |
|---|---|
| **Source IP** | `104.128.69.207` (Las Vegas, NV, US) |
| **Destination** | `172.31.38.181:22` (internal) |
| **Unique ports touched** | 1 (port 22 only) |
| **Total connection attempts** | 210 |
| **Pattern** | Single-port brute-force (not a scan) |
| **MITRE ATT&CK** | `T1110` — Brute Force |

From Panel 1's top-talkers view, `104.128.69.207` stood out for its connection volume on port 22 — the administrative SSH gateway into internal infrastructure. The full triage trail below documents how this was investigated and validated.

<details>
<summary><strong>Full Triage Runbook (click to expand)</strong></summary>

#### 0. Origin — How the destination and direction were identified

**0.1 — Locate the flagged IP and determine its role**
```spl
index=botsv3 "104.128.69.207" sourcetype=stream:tcp
| stats count by src_ip, dest_ip
```
<img width="1447" height="201" alt="0.1 result" src="https://github.com/user-attachments/assets/a6d23a71-6aba-418e-a6c2-fdf20ceb9450"/>

Confirmed `104.128.69.207` consistently appears as `src_ip` — it is the initiator of the connection, not the target.

**0.2 — Identify everything this IP targeted**
```spl
index=botsv3 src_ip="104.128.69.207"
| stats count by dest_ip, dest_port
```
<img width="1448" height="215" alt="0.2 result" src="https://github.com/user-attachments/assets/fce18a0b-fa8f-4fd7-b5a0-690ab49d7c0c"/>

This is the query that surfaced `172.31.38.181:22` as the target.

**0.3 — Confirm the destination is internal**
`172.31.38.181` falls inside `172.16.0.0/12` (RFC 1918 private range) and specifically matches AWS's default VPC CIDR block (`172.31.0.0/16`) — confirming it's an internal, likely cloud-hosted asset, and confirming traffic direction as **external → internal**.

---

#### A. Asset Context

**A.1 — Is the SSH service banner/version visible?**
```spl
index=botsv3 dest_ip="172.31.38.181" dest_port=22 sourcetype=stream:ssh
| table _time, src_ip, dest_ip, ssh_version, software_version
```
<img width="1452" height="242" alt="A.1 result" src="https://github.com/user-attachments/assets/9d1bee50-496c-483d-9721-0c872520e949"/>

Empty result — confirms a visibility gap. The Stream app did not parse SSH protocol-level details, so service/software version cannot be verified from this query.

**A.2 — What else does this host show up as?**
```spl
index=botsv3 "172.31.38.181"
| stats count by sourcetype
```
<img width="1452" height="416" alt="A.2 result" src="https://github.com/user-attachments/assets/985f4026-7915-4c99-9020-c58f9915dc4e"/>

This host also generates `stream:smtp` (email) and `stream:dns` traffic. A traffic-direction check was not performed to confirm inbound vs. outbound, but this profile is consistent with mail server infrastructure — a plausible high-value target.

**A.3 — Did this attacker touch any other internal hosts?**
```spl
index=botsv3 src_ip="104.128.69.207"
| stats count by dest_ip, dest_port
```
<img width="1453" height="226" alt="A.3 result" src="https://github.com/user-attachments/assets/bfa2237d-de4c-4643-8fda-6515f144cb08"/>

This actor's activity in the dataset is limited to a single destination host and port, with no evidence of broader scanning behavior from this specific IP.

---

#### B. Threat Characterization

**B.4 — Single port (brute-force) vs. many ports (scan)?**
```spl
index=botsv3 src_ip="104.128.69.207" dest_ip="172.31.38.181" sourcetype=stream:tcp
| stats dc(dest_port) as unique_ports, count as total_connections by dest_ip
```
<img width="1453" height="223" alt="B.4 result" src="https://github.com/user-attachments/assets/d2f11714-7a4a-43a1-8e13-ec7d3a0123f7"/>

Result: `unique_ports=1`, `total_connections=210` — all attempts hit port 22 only. Confirms a single-port brute-force, not a scan.

> **Data reconciliation note:** An earlier version of this query (without a `sourcetype` filter) returned an inflated total of 628. Investigation traced this to a data-layer mismatch — `stream:ip` (Layer 3, 418 events) has no `dest_port` field and was being silently included or excluded depending on query structure, while `stream:tcp` (Layer 4, 210 events) is the layer that actually carries port data. Both sourcetypes represent the *same* underlying 210 connection attempts, captured at two different layers of the stack. Restricting to `sourcetype=stream:tcp` resolves the discrepancy and confirms 210 as the accurate, reconciled count used throughout this report.

**B.5 — Field discovery (avoid guessing field names)**
```spl
index=botsv3 src_ip="104.128.69.207" dest_ip="172.31.38.181" dest_port=22
| fieldsummary
| table field, count, distinct_count, values
```
Narrowed to the most relevant fields for the report:
```spl
index=botsv3 src_ip="104.128.69.207" dest_ip="172.31.38.181" dest_port=22
| fieldsummary
| search field IN ("source", "sourcetype", "app", "tcp_status")
| table field, count, distinct_count, values
```
<img width="1452" height="333" alt="B.5 result" src="https://github.com/user-attachments/assets/6b76f628-a31b-4148-9c51-9be62c2f64f3"/>

---

#### C. Success / Impact

**C.6 — Any sign of successful connections?**
```spl
index=botsv3 src_ip="104.128.69.207" dest_ip="172.31.38.181" dest_port=22
| table _time, src_port, dest_port, duration, bytes_in, bytes_out
| head 20
```
<img width="1437" height="547" alt="C.6 result" src="https://github.com/user-attachments/assets/a92c3243-36c4-43da-8967-ba06fb259918"/>

Two patterns in this data point toward automated, scripted activity rather than manual login attempts:

- **No measurable duration:** `duration` is blank across nearly every row, consistent with a script disconnecting immediately after each attempt rather than a human pausing to type credentials.
- **Uniform byte sizes:** `bytes_in` (~2100) and `bytes_out` (~2769) are nearly identical across all 210 attempts — consistent with a fixed-size automated request and a fixed-size automated rejection response, repeated at scale.

210 repeated attempts against a single internal host is not consistent with normal user error. Network-layer evidence here suggests automated, likely-unsuccessful attempts; however, **this cannot be definitively confirmed without host-level logs** (see C.7).

**C.7 — Host-level authentication logs**
```spl
index=botsv3 dest_ip="172.31.38.181" (sourcetype="linux_secure" OR sourcetype="linux_audit" OR sourcetype="syslog")
| table _time, sourcetype, host, user, action
| sort _time
```
<img width="1447" height="188" alt="C.7 result" src="https://github.com/user-attachments/assets/4f30c88b-0ce5-4097-8802-547f84ec2c4c"/>

**Zero events returned.** This host has no local authentication logging reaching the SIEM — meaning success or failure of the 210 SSH attempts cannot be confirmed at the OS level. This is a **visibility gap**, not evidence that the attack failed. Per the Response Decision Workflow below, this pushes the finding toward **Scenario 3 (Visibility Gap / Inconclusive)** rather than a clean Scenario 1.

**C.8 — Follow-on / post-exploitation activity check**
```spl
index=botsv3 (host="172.31.38.181" OR src_ip="172.31.38.181")
| stats count by sourcetype
```
<img width="1451" height="381" alt="C.8 result" src="https://github.com/user-attachments/assets/4f526a05-42f4-4375-9f4a-cba7dbb90092"/>

| sourcetype | count |
|---|---|
| stream:arp | 336 |
| stream:dhcp | 22 |
| stream:dns | 27,672 |
| stream:http | 1 |
| stream:ip | 25,863 |
| stream:tcp | 969 |
| stream:udp | 24,078 |

Volumes are consistent with normal host network activity — no unusual spike or unexpected new sourcetype that would suggest post-exploitation behavior. Combined with C.7, this supports (but does not conclusively prove, given the host-log visibility gap) that no follow-on compromise occurred.

---

#### D. Scope

**D.9 — Distributed attack check**
```spl
index=botsv3 dest_ip="172.31.38.181" dest_port=22 NOT (src_ip="10.0.0.0/8" OR src_ip="192.168.0.0/16" OR src_ip="172.16.0.0/12")
| stats count by src_ip
| sort -count
```
<img width="1438" height="653" alt="D.9 result" src="https://github.com/user-attachments/assets/851d028d-bbf5-4dae-8313-f83c4a1cd9b2"/>

`104.128.69.207` accounts for 210 connections — overwhelmingly the dominant source. All other external IPs hitting this host on port 22 show only 1–4 connections each. Confirms a **single dominant attacker**, not a distributed/botnet pattern.

**D.10 — Are other internal hosts targeted on port 22 from outside?**
```spl
index=botsv3 dest_port=22 NOT (src_ip="10.0.0.0/8" OR src_ip="192.168.0.0/16" OR src_ip="172.16.0.0/12")
| stats count by src_ip, dest_ip
| sort dest_ip
```
<img width="1446" height="707" alt="D.10 result" src="https://github.com/user-attachments/assets/dfba7b45-16f6-4f15-b6c1-df8d98d5cdca"/>

This returned 548 events from 215 distinct external IPs across 5 internal hosts. Critically, almost all of those IPs connected only 1–4 times each (mostly to `172.16.0.109`) — consistent with routine internet-wide SSH scanning noise, not a coordinated campaign.

Cross-checking against A.3 confirms `104.128.69.207` does **not** appear against the other 4 hosts — its activity is concentrated entirely on `172.31.38.181`, where it accounts for 210 of that host's 293 total port-22 attempts (~72%).

**Conclusion:** This is not one attacker sweeping 5 hosts. It's two separate phenomena layered together — background SSH-scanning noise hitting the network generally, and one specific actor concentrated on a single host. This incident is scoped to `172.31.38.181`; the other 4 hosts are a separate, lower-priority hygiene note (general SSH exposure to background internet scanning).

---

#### E. Attribution

**E.11 — Geolocation**
```spl
index=botsv3 src_ip="104.128.69.207"
| iplocation src_ip
| table src_ip, Country, Region, City
```
<img width="1445" height="706" alt="E.11 result" src="https://github.com/user-attachments/assets/34ca5b56-ff6c-48a5-8cef-6fe8b5b757ed"/>

Resolves to **Las Vegas, Nevada, United States**. (ASN/WHOIS ownership would require an external lookup outside Splunk.)

**E.12 — Does this IP appear anywhere else in the dataset?**
```spl
index=botsv3 "104.128.69.207"
| stats count by sourcetype
```
<img width="1451" height="248" alt="E.12 result" src="https://github.com/user-attachments/assets/368eb47a-dd20-4eac-94d4-eacd917c6942"/>

This IP interacts exclusively with raw network wire-data layers: 418 events in `stream:ip` (Layer 3) and 210 events in `stream:tcp` (Layer 4) — the same underlying activity addressed in B.4. No application-layer, web server, or OS authentication events recorded this IP anywhere else in the environment.

---

#### F. Response Decision Workflow

| Scenario | Criteria | Action |
|---|---|---|
| **1 — Brute-Force (Contained)** | IP exceeds threshold connections; auth logs show zero successes | Block source IP at perimeter firewall; continue monitoring |
| **2 — Active Compromise (Critical)** | Auth logs show a successful login event | Isolate host immediately; escalate to IR team |
| **3 — Visibility Gap (Inconclusive)** | Heavy network-layer activity; host-level auth logs missing entirely | Document the gap; submit ticket to enable host-level auditing |

**Classification: Scenario 3 — Visibility Gap.** No successful authentication was observed, but this could not be confirmed at the host level (C.7). The network-layer evidence (volume, automation pattern, single-port targeting) is consistent with a failed brute-force, but cannot be called "contained" with full confidence without host logs.

</details>

#### Analyst Next Step

Block `104.128.69.207` at the perimeter firewall and continue monitoring — network-layer evidence shows no successful breach pattern. In parallel, escalate the host-level logging gap on `172.31.38.181`: submit a request to enable OS-level authentication logging (`linux_secure`/`syslog`) so future incidents on this host can be conclusively classified rather than left inconclusive. This finding does not currently warrant IR escalation, but the visibility gap itself should be tracked as a follow-up action.

---

### Finding 2 — Internal Port Scan: 192.168.8.103 (host "hoth")

| | |
|---|---|
| **Source IP** | `192.168.8.103` (internal — host "hoth") |
| **Unique ports touched** | 35 |
| **Pattern** | Consistent with automated network reconnaissance |
| **MITRE ATT&CK** | `T1046` — Network Service Discovery |

This host is documented in the BOTSv3 scenario as having executed `hdoor.exe`, a known backdoor/RAT with built-in scanning capability — internal reconnaissance across 35 distinct ports is consistent with post-compromise lateral-movement staging from an already-compromised asset, rather than an external probing attempt.

**Analyst Next Step:** Unlike Finding 1, this is not an open question — `hoth` is independently confirmed as compromised. Isolate `192.168.8.103` from the network immediately and escalate to the Incident Response team for full containment and eradication (Scenario 2 in the Response Decision Workflow above). The port-scanning activity should be treated as evidence of active post-compromise behavior, not a standalone ambiguous signal.

---

## Skills Demonstrated

- Splunk environment setup and dashboard creation
- SPL basic query writing (`stats`, `bucket`, `dc()`, `eval`, `where`, `fieldsummary`, `iplocation`)
- Mapping detections to MITRE ATT&CK techniques (T1046, T1110)
- Working with a real-world security dataset (BOTSv3)

---

## Summary

> Built a Splunk dashboard visualizing network traffic patterns from the BOTSv3 dataset, including top talkers, port distribution, and time-series scan detection. Configured a correlation search/alert to flag source IPs contacting 15+ distinct destination ports within a 5-minute window, mapped to MITRE ATT&CK T1046 (Network Service Discovery). Independently triaged a flagged SSH brute-force incident end-to-end — tracing connection direction, characterizing attack pattern, assessing impact, scoping the incident against background network noise, and documenting a response decision — mapped to MITRE ATT&CK T1110 (Brute Force).
