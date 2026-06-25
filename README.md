# Network Reconnaissance Detection — Splunk Dashboard & Alert Configuration

---

**Author:** Rafael Gabriel Gutierrez

**Target Role:** Entry-Level SOC Analyst (Tier 1)

**Dataset:** Boss of the SOC v3 (BOTSv3)

**Tools Used:** Splunk Enterprise Free Tier

---

## Overview

This is a self-directed practice project built to apply SIEM fundamentals against a real security dataset. It demonstrates a basic but complete Tier 1 SOC workflow: building visibility into network traffic, designing a detection rule for anomalous behavior, and mapping the finding to a recognized adversary technique using the BOTSv3 dataset in Splunk.

---

## Objective

The objective of the dashboard is to answer four fundamental questions regarding perimeter network traffic:

1. Who is generating the highest volume of network activity?
2. What destination ports are being targeted most frequently?
3. Is any single host executing an automated network scan?
4. Is there anomalous volume indicating potential data exfiltration?

---

## Dashboard

**Panel 1 — Top Talkers (External Traffic)**
Filters out internal address ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12) to focus only on external-facing traffic, then groups results by source IP and approximate country using `iplocation`. This gives a first-pass triage view — high-volume external sources and the ports they touched are usually the first thing an analyst checks.

```
index=botsv3 sourcetype="stream:tcp" NOT (src_ip=10.0.0.0/8 OR src_ip=192.168.0.0/16 OR src_ip=172.16.0.0/12)
| iplocation src_ip
| stats count, values(dest_port) as targeted_ports by src_ip, Country
| sort - count
```

![Top Talkers panel]<img width="693" height="417" alt="image" src="https://github.com/user-attachments/assets/aed417c2-b232-49a9-b4d6-6f36a65a4af6"/>

**Panel 2 — Destination Port Distribution**
Aggregates traffic by `dest_port` to surface which ports see the most activity. Helps spot traffic to unusual or non-standard ports at a glance.

```
index=botsv3 sourcetype="stream:tcp"
| stats count by dest_port
| sort -count
| head 15
```

![Destination Port Distribution panel]<img width="693" height="302" alt="image" src="https://github.com/user-attachments/assets/b84fcc34-26cc-4018-b294-e8a455dc6503"/>

**Panel 3 — Scan Detection (core panel)**

This is the main detection logic of the project. It buckets traffic into 5-minute windows and counts how many distinct destination ports each source IP touches within that window. A typical host only touches a handful of ports; a host touching many different ports in a short window is showing the textbook signature of network reconnaissance. Setting a threshold (here, more than 15 ports) flags that behavior automatically instead of relying on manual review of raw logs.

```
index=botsv3 sourcetype=stream:tcp
| bucket _time span=5m
| stats dc(dest_port) as unique_ports by src_ip, _time
| where unique_ports > 15
```

![Scan Detection panel]<img width="700" height="227" alt="image" src="https://github.com/user-attachments/assets/8c019c52-d93a-4461-a122-5ec7e8eb88d2"/>

**Panel 4 — DNS Query Volume Over Time**
Tracks DNS query volume over time as a supporting signal alongside the TCP panels above. DNS is commonly abused both for reconnaissance (enumerating internal hosts) and for data exfiltration (tunneling data out through queries), so keeping an eye on its volume adds visibility beyond a single protocol.

```
index=botsv3 sourcetype=stream:dns
| timechart count
```

![DNS Query Volume panel]<img width="692" height="297" alt="image" src="https://github.com/user-attachments/assets/b8128b5c-805d-4c5f-a3cf-4f3ac17d4519"/>

---

## Alert Configuration

The Panel 3 search was saved as a correlation search with the following configuration:

- **Trigger condition:** number of results > 0
- **Schedule:** every 5 minutes
- **Logic:** flags any `src_ip` with `unique_ports > 15` in a rolling 5-minute bucket

**Note on real-time behavior:** BOTSv3 is a static, historical dataset rather than a live data stream, so this alert was configured and validated against the dataset rather than tested under continuous real-time conditions. The trigger logic, threshold, and schedule are configured exactly as they would be in a production environment — the only difference is the absence of live incoming data to trigger against repeatedly over time. This is a property of the dataset, not a limitation of the alert design.

**MITRE ATT&CK Mapping:** T1046 — Network Service Discovery

![Triggered alert example](alert-triggered.png)

---

## Findings

- Source IP(s) flagged: `[fill in]`
- Number of unique ports touched / time window: `[fill in]`
- Cross-check against BOTSv3's documented scenario: `[does it match a known scan event in the dataset's answer key?]`
- Analyst next step: `[what would you do — escalate, gather more context, check against threat intel, close as benign?]`

*(This is the part of the writeup that shows investigative thinking, not just SPL syntax — worth taking the time to fill in properly rather than leaving generic.)*

---

## Skills Demonstrated

- Splunk environment setup and dashboard creation
- SPL query writing (`stats`, `bucket`, `dc()`, `eval`, `where`)
- Correlation search / alert configuration (trigger logic, scheduling, thresholds)
- Mapping detections to MITRE ATT&CK techniques
- Working with a real-world security dataset (BOTSv3)

---

## Summary (for resume / one-line use)

> Built a Splunk dashboard visualizing network traffic patterns from the BOTSv3 dataset, including top talkers, port distribution, and time-series scan detection. Configured a correlation search/alert to flag source IPs contacting 15+ distinct destination ports within a 5-minute window, mapped to MITRE ATT&CK T1046 (Network Service Discovery).
