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

<img width="693" height="417" alt="image" src="https://github.com/user-attachments/assets/aed417c2-b232-49a9-b4d6-6f36a65a4af6"/>

---

**Panel 2 — Destination Port Distribution**
Aggregates traffic by `dest_port` to surface which ports see the most activity. Helps spot traffic to unusual or non-standard ports at a glance.

```
index=botsv3 sourcetype="stream:tcp"
| stats count by dest_port
| sort -count
| head 15
```

<img width="693" height="302" alt="image" src="https://github.com/user-attachments/assets/b84fcc34-26cc-4018-b294-e8a455dc6503"/>

---

**Panel 3 — Scan Detection (core panel)**

This is the main detection logic of the project. It buckets traffic into 5-minute windows and counts how many distinct destination ports each source IP touches within that window. A typical host only touches a handful of ports; a host touching many different ports in a short window is showing the textbook signature of network reconnaissance. Setting a threshold (here, more than 15 ports) flags that behavior automatically instead of relying on manual review of raw logs.

```
index=botsv3 sourcetype=stream:tcp
| bucket _time span=5m
| stats dc(dest_port) as unique_ports by src_ip, _time
| where unique_ports > 15
```

<img width="700" height="227" alt="image" src="https://github.com/user-attachments/assets/8c019c52-d93a-4461-a122-5ec7e8eb88d2"/>

---

**Panel 4 — DNS Query Volume Over Time**
Tracks DNS query volume over time as a supporting signal alongside the TCP panels above. DNS is commonly abused both for reconnaissance (enumerating internal hosts) and for data exfiltration (tunneling data out through queries), so keeping an eye on its volume adds visibility beyond a single protocol.

```
index=botsv3 sourcetype=stream:dns
| timechart count
```

<img width="692" height="297" alt="image" src="https://github.com/user-attachments/assets/b8128b5c-805d-4c5f-a3cf-4f3ac17d4519"/>
```
---



## Alert Configuration

The Panel 3 search was saved as a correlation search with the following configuration:

- **Trigger condition:** number of results > 0
- **Schedule:** every 5 minutes
- **Logic:** flags any `src_ip` with `unique_ports > 15` in a rolling 5-minute bucket

**Note on real-time behavior:** BOTSv3 is a static, historical dataset rather than a live data stream, so this alert was configured and validated against the dataset rather than tested under continuous real-time conditions. The trigger logic, threshold, and schedule are configured exactly as they would be in a production environment — the only difference is the absence of live incoming data to trigger against repeatedly over time. This is a property of the dataset, not a limitation of the alert design.

**MITRE ATT&CK Mapping:** T1046 — Network Service Discovery


---
<!--
## FINDINGS

- Source IP(s) flagged: `[fill in]` 
For top talkers this source ip address 104.128.69.207 has unusual amount of connections via port 22 which crucial because it acts as the primary administrative gateway to your infrastructure

##Q1 Triage Runbook


##0. Origin — How dest_ip and direction were discovered? 
0.1 — Find where the flagged IP shows up, and in which field (role)
i tried to look where does the src_ip is connecting and it is confirmed that its inside internal's ip addresses public ip

index=botsv3 "104.128.69.207" sourcetype=stream:tcp
| stats count by src_ip, dest_ip

<img width="1447" height="201" alt="image" src="https://github.com/user-attachments/assets/a6d23a71-6aba-418e-a6c2-fdf20ceb9450"/>



##0.2 — Once confirmed as src_ip, pull everything it targeted (this is the query that produced 172.31.38.181)
- This query confirmed all the destination route of the malicious ip address including the destination port and number of connections

index=botsv3 src_ip="104.128.69.207"
| stats count by dest_ip, dest_port

<img width="1448" height="215" alt="image" src="https://github.com/user-attachments/assets/fce18a0b-fa8f-4fd7-b5a0-690ab49d7c0c" />

0.3 — Confirm the discovered dest_ip is actually internal
172.31.38.181 falls inside 172.16.0.0/12 (RFC 1918 private range), and specifically matches AWS's default VPC CIDR block (172.31.0.0/16) — confirming it's an internal, likely cloud-hosted asset, and confirming direction as external → internal. 


##A. Asset Context

A.1 — Is SSH service banner/version visible? (checks if Stream app parsed SSH protocol)

splindex=botsv3 dest_ip="172.31.38.181" dest_port=22 sourcetype=stream:ssh
| table _time, src_ip, dest_ip, ssh_version, software_version

<img width="1452" height="242" alt="image" src="https://github.com/user-attachments/assets/9d1bee50-496c-483d-9721-0c872520e949" />

The SSH banner query came back completely empty, which means we have a visibility gap and can't see the exact software version; however, our basic network logs are still absolute proof that the outsider tried to force their way into this internal server 210 times


A.2 — What else does this host show up as? (identify role/hostname)

splindex=botsv3 "172.31.38.181"
| stats count by sourcetype

<img width="1452" height="416" alt="image" src="https://github.com/user-attachments/assets/985f4026-7915-4c99-9020-c58f9915dc4e" />

A review of the server’s log types revealed that it heavily generates email traffic (stream:smtp) and network name lookups (stream:dns), proving that this internal IP is a legitimate corporate mail server and a high-value target for the attacker.


A.3 — Did 104.128.69.207 touch any other internal hosts?
index=botsv3 src_ip="104.128.69.207"
| stats count by dest_ip, dest_port

<img width="1453" height="226" alt="image" src="https://github.com/user-attachments/assets/bfa2237d-de4c-4643-8fda-6515f144cb08" />

These findings support the conclusion that this was likely a targeted attack.

##B. Threat Characterization


B.4 — Single port (brute-force) vs. many ports (scan)?

splindex=botsv3 src_ip="104.128.69.207"
| stats dc(dest_port) as unique_ports, count as total_connections by dest_ip, dest_port

<img width="1453" height="266" alt="image" src="https://github.com/user-attachments/assets/1612a82a-0abe-4dec-9a7f-cf3a4b6034ab" />

The findings show that the attacker consistently attempted to connect to port 22, which is a clear sign of a brute-force attack


B.5 — Discover what fields actually have data (don't guess field names)

Initially, a broad structural summary query was executed to discover all populated fields:

splindex=botsv3 src_ip="104.128.69.207" dest_ip="172.31.38.181" dest_port=22
| fieldsummary
| table field, count, distinct_count, values

To isolate the most critical evidentiary fields for the report and provide a scannable verification table, the query was optimized as follows:
index=botsv3 src_ip="104.128.69.207" dest_ip="172.31.38.181" dest_port=22 
| fieldsummary 
| search field IN ("source", "sourcetype", "app", "tcp_status")
| table field, count, distinct_count, values

<img width="1452" height="333" alt="image" src="https://github.com/user-attachments/assets/6b76f628-a31b-4148-9c51-9be62c2f64f3" />

The goal of this process is to determine what other log types were created between these two IP addresses

##C. Success / Impact
C.6 — Any sign of successful connections (using fields confirmed in B.5)

splindex=botsv3 src_ip="104.128.69.207" dest_ip="172.31.38.181" dest_port=22
| table _time, src_port, dest_port, duration, bytes_in, bytes_out
| head 20

<img width="1437" height="547" alt="image" src="https://github.com/user-attachments/assets/a92c3243-36c4-43da-8967-ba06fb259918" />

* **`bytes_in` (The Attacker's Voice):** Every time the attacker tries a password, they are shouting a small piece of data into your network.
* **`bytes_out` (Your Server's Voice):** Every time your server says "Wrong password, access denied," it sends a small piece of data back.

While the attack failed to get in, the data shows the textbook fingerprint of a malicious hacking script, not a human making a mistake.

No Human Typing Speed (Blank Duration): A real person takes at least a few seconds to type a username and password. The duration column is completely blank because a computer script was slamming the server, sending a guess, and disconnecting in less than a millisecond.

Perfect Computer Uniformity (Identical Bytes): When humans type, data sizes change because passwords have different lengths and people make typos. Here, bytes_in (~2100) and bytes_out (2769) are exactly the same on almost every line. This proves a script was repeatedly throwing a fixed-size password guess and getting the exact same automated "Access Denied" reply.

The Rule of 210: A normal employee might forget their password 3 or 5 times. No one forgets their password 210 times in a row on a critical internal mail server.


C.7 — Host-level auth logs (if this host has OS-level visibility)
index=botsv3 dest_ip="172.31.38.181" (sourcetype="linux_secure" OR sourcetype="linux_audit" OR sourcetype="syslog")
| table _time, sourcetype, host, user, action
| sort _time

<img width="1447" height="188" alt="image" src="https://github.com/user-attachments/assets/4f30c88b-0ce5-4097-8802-547f84ec2c4c" />

To cross-reference network-layer findings by checking if the target system generated local authentication logs (linux_secure / syslog) and successfully transmitted them to the central SIEM (Splunk). This check aims to verify internal operating system visibility, identify the specific usernames targeted by the threat actor, and definitively confirm whether the brute-force attempts succeeded or failed.

C.8 — Follow-on activity after any apparent success

index=botsv3 (host="172.31.38.181" OR src_ip="172.31.38.181")
| stats count by sourcetype

<img width="1451" height="381" alt="image" src="https://github.com/user-attachments/assets/4f526a05-42f4-4375-9f4a-cba7dbb90092" />

To sweep the SIEM for all available log sources (sourcetypes) interacting with or originating from the target IP (172.31.38.181). This broad check serves as a follow-on triage step to profile the asset's total digital footprint and discover any signs of post-exploitation activity following the network attack.


##D. Scope

D.9 — Other external sources hitting this same host/port (distributed attack check)



<img width="1438" height="653" alt="image" src="https://github.com/user-attachments/assets/851d028d-bbf5-4dae-8313-f83c4a1cd9b2" />








- Number of unique ports touched / time window: The number of unique ports touched is 35 unique ports by the ip address 192.168.8.103 which means that this is a recconnaissance

- Cross-check against BOTSv3's documented scenario: ??????
- Analyst next step: `[what would you do — escalate, gather more context, check against threat intel, close as benign?]`

*(This is the part of the writeup that shows investigative thinking, not just SPL syntax — worth taking the time to fill in properly rather than leaving generic.)*
-->
---

## Skills Demonstrated

- Splunk environment setup and dashboard creation
- SPL query writing (`stats`, `bucket`, `dc()`, `eval`, `where`)
- Correlation search / alert configuration (trigger logic, scheduling, thresholds)
- Mapping detections to MITRE ATT&CK techniques
- Working with a real-world security dataset (BOTSv3)

---
<!--
## Summary (for resume / one-line use)

> Built a Splunk dashboard visualizing network traffic patterns from the BOTSv3 dataset, including top talkers, port distribution, and time-series scan detection. Configured a correlation search/alert to flag source IPs contacting 15+ distinct destination ports within a 5-minute window, mapped to MITRE ATT&CK T1046 (Network Service Discovery).
-->
