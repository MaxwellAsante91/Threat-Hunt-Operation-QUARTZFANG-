# Threat Hunting Report: Operation QUARTZFANG

> SemiCrest Technologies | Campaign C0062 (AI-Orchestrated Intrusion) | Microsoft Defender / Sentinel Advanced Hunting (KQL)

![KQL](https://img.shields.io/badge/Language-KQL-0078D4) ![Microsoft Defender](https://img.shields.io/badge/Platform-Microsoft%20Defender%20%7C%20Sentinel-5E5E5E) ![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-C8102E) ![Flags](https://img.shields.io/badge/Flags-28-2E7D32)

📄 **Word version of this report:** [report/SemiCrest_Threat_Hunt_Report.docx](report/SemiCrest_Threat_Hunt_Report.docx)  
🔎 **All hunt queries in one file:** [queries/semicrest-hunt-queries.kql](queries/semicrest-hunt-queries.kql)

## Table of Contents

1. [Report Overview](#report-overview)
2. [Executive Summary](#executive-summary)
3. [Case File (Scenario)](#case-file-scenario)
4. [Methodology](#methodology)
5. [Attack Timeline](#attack-timeline)
6. [Cyber Kill Chain](#cyber-kill-chain)
7. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
8. [Detailed Findings](#detailed-findings)
    - [SECTION 1: INITIAL ACCESS](#section-1-initial-access)
    - [SECTION 2: CREDENTIAL HARVEST](#section-2-credential-harvest)
    - [SECTION 3: LATERAL MOVEMENT](#section-3-lateral-movement)
    - [SECTION 4: AI HALLUCINATION JUDGEMENT](#section-4-ai-hallucination-judgement)
    - [SECTION 5: EXFILTRATION AND PERSISTENCE](#section-5-exfiltration-and-persistence)
    - [SECTION 6: RECONNAISSANCE AND TIMING](#section-6-reconnaissance-and-timing)
    - [SECTION 7: AUTONOMY SYNTHESIS](#section-7-autonomy-synthesis)
    - [SECTION 8: REAL OR NOISE TRIAGE](#section-8-real-or-noise-triage)
9. [Summary of the Objectives, KQL Codes and Findings](#summary-of-the-objectives-kql-codes-and-findings)
10. [Indicators of Compromise](#indicators-of-compromise)
11. [Recommendations](#recommendations)
12. [Conclusions](#conclusions)
13. [References](#references)

---

## Report Overview

| Field | Detail |
|---|---|
| **Report type** | Threat Hunt: Final Report |
| **Operation** | QUARTZFANG |
| **Organisation (scenario)** | SemiCrest Technologies (semiconductor design) |
| **Campaign reference** | MITRE ATT&CK C0062 (Anthropic AI-orchestrated Campaign) |
| **Workspace** | LAW-HuntPractice |
| **Hunt window** | 20 September 2026, 06:30 to 08:30 UTC |
| **Hosts in scope** | sc-portal01, sc-db01, sc-registry01, sc-admin01 |
| **Query language** | Kusto Query Language (KQL) |
| **Flags answered** | 28 across 8 sections |

## Executive Summary

On 20 September 2026 an analytics rule fired on sc-portal01 after two back-to-back requests to the document preview API. This hunt traced that alert into a complete intrusion that crossed four hosts. The attacker abused a server-side request forgery (SSRF) flaw in /api/v1/preview. A gopher:// payload reached the local Redis service and wrote a cron job, and cron then started a root python3 reverse shell (PID 4401). From that shell the attacker read /etc/semicrest/portal.conf and obtained two credential pairs: portal_svc for the PostgreSQL database on sc-db01 and ci-builder for the Harbor registry on sc-registry01.

With those credentials the attacker dumped and enumerated the database (customers, pg_catalog.pg_shadow, information_schema.tables), enumerated the container registry, and was refused (403 Forbidden) by the admin API on sc-admin01. The collected data was archived with tar, compressed with gzip and encrypted with openssl into /tmp/.portal-cache/report.tar.gz.enc. It was exfiltrated over HTTPS to 198.51.100.210:443. Before leaving, the attacker created a sudo-capable svc_monitor account with a passwordless ed25519 SSH key.

The recovered agent log (LLMAgentLogs_CL) shows an AI agent doing most of the tactical work, with a human operator approving four phase transitions. The agent also reported two successes that the telemetry disproves: Kubernetes secrets it never extracted and registry credentials it never read. The operation therefore fits the C0062 pattern of a person who set a machine going. It also confirms that the agent's own claims cannot be trusted without independent log verification. Three items that colleagues raised as suspicious (credential reuse, the nightly pg_dump job and a PostgreSQL connection spike) were each triaged, separating real attacker activity from noise.

## Case File (Scenario)

### CASE FILE (SCENARIO): Operation QUARTZFANG

SemiCrest Technologies, a semiconductor design company. An analytics rule fired on sc-portal01 at 06:52 UTC on 20 September 2026. Two requests to the document preview API in quick succession, one rejected and one accepted. Minutes later, a process appeared on the box that the web application never spawns. Internal database activity spiked and an outbound HTTPS transfer was observed.

This scenario reproduces Campaign C0062 from Anthropic threat intelligence (published November 2025). First documented case of a cyberattack largely executed by an AI agent while a human operator served at strategic decision points. The AI executed 80-90% of tactical work autonomously. Students are encouraged to read the public Anthropic report and hold their findings against it.

### What is known at hand-off

- Unusual requests to document preview API from external scanner IPs
- Unexpected process spawned under the web application on sc-portal01
- Database spike on sc-db01 beyond normal application patterns
- Outbound transfer via HTTPS to unknown external IP from sc-portal01
- New account appeared on sc-portal01 that nobody created

### Scope

| Item | Value |
|---|---|
| **Workspace** | LAW-HuntPractice |
| **Tables** | DeviceProcessEvents_CL, DeviceNetworkEvents_CL, Syslog, PortalAccessLog_CL, ContainerRegistryLog_CL, LLMAgentLogs_CL (plus DeviceLogonEvents_CL, DeviceFileEvents_CL, DeviceEvents_CL) |
| **Window** | 20 September 2026, 06:30 to 08:30 UTC |
| **Hosts** | sc-portal01, sc-db01, sc-registry01, sc-admin01 |

### How to hunt this

1. Work sections in order. The attack chain crosses four hosts and nine tables.
2. MDE tables (Device*_CL) use Timestamp and Device Name. Custom tables use Time Generated and Computer. Check the data dictionary.
3. One flag is unanswerable by design. Naming the visibility gap correctly is worth full credit.
4. A recovered attacker agent log (LLMAgentLogs_CL) is available. The agent's narration contains both accurate findings and fabricated claims. Cross-reference every claim against infrastructure telemetry.

## Methodology

- Hypothesis-driven hunting: each flag was treated as a hypothesis and confirmed or refuted against raw telemetry in the LAW-HuntPractice workspace.
- Pivoting: every confirmed indicator (source IP, process ID 4401, credential, file path) became the starting point for the next query, following the attack chain host by host.
- Baseline comparison: suspicious activity was compared against the normal behaviour of the same account, host or service (portal_svc, ci-builder, Nessus, www-data) before it was classified.
- Claim verification: every statement in the attacker's agent log (LLMAgentLogs_CL) was cross-checked against infrastructure telemetry before it was accepted.
- Real-or-noise triage: alerts raised by colleagues were tested against schedule, process lineage and error messages before any containment action was recommended.

> **Time zone note:** the Defender portal displays timestamps in the analyst's local time (UTC-4 in these screenshots). For example, "Sep 20, 2026 2:52 AM" in a screenshot is 06:52 UTC. All times in this report are UTC unless stated otherwise. The LLMAgentLogs_CL rows carry their October 2026 ingestion time in TimeGenerated, so the agent-log queries use an October date range.

## Attack Timeline

| Time (UTC, 20 Sep 2026) | Event | Phase |
|---|---|---|
| Lead-in | External scanners 198.51.100.31, .45 and .62 run scripted recon against sc-portal01 alongside the scheduled internal Nessus scanner (10.5.0.250) | Reconnaissance |
| 06:52 | 203.0.113.87 sends /api/v1/preview with file:// (400 rejected), then gopher:// (200 accepted) 18 seconds later | Initial Access |
| 06:52 | The gopher:// SSRF writes a cron job through Redis on 127.0.0.1:6379; cron spawns a python3 reverse shell as root (PID 4401) | Execution |
| 07:05 | cat /etc/semicrest/portal.conf and env run under python3 PID 4401 as root | Credential Access |
| 07:16 | Unbounded SELECT * dumps and schema enumeration on sc-db01 as portal_svc | Collection / Discovery |
| 07:29 | PostgreSQL connection spike on sc-db01 (connection-pool exhaustion: noise, not the attacker) | Triage (Noise) |
| 07:33 | Harbor registry login, list_repository, pull_manifest, inspect_layer as ci-builder from 10.5.0.10 | Discovery / Lateral Movement |
| Lateral phase | GET /api/v1/secrets on sc-admin01 returns 403 Forbidden to portal_svc | Lateral Movement (blocked) |
| 08:02 | tar, gzip, openssl build /tmp/.portal-cache/report.tar.gz.enc as root | Collection / Staging |
| 08:15 | HTTPS transfer to 198.51.100.210:443 from python3 PID 4401 (root) | Exfiltration |
| 08:29 | useradd svc_monitor, usermod -aG sudo, mkdir .ssh, ssh-keygen ed25519 (no passphrase) | Persistence |

## Cyber Kill Chain

| Kill Chain Stage | Observed Activity | Evidence |
|---|---|---|
| **Reconnaissance** | Scripted external recon from 198.51.100.31, .45, .62 against sc-portal01 | Flags 20, 21 |
| **Weaponization** | gopher:// SSRF payload carrying Redis commands that write a cron job | Flags 2, 4 |
| **Delivery** | HTTP request to /api/v1/preview from 203.0.113.87 | Flags 1, 3 |
| **Exploitation** | SSRF to Redis on 127.0.0.1:6379; cron executes the payload | Flag 4 |
| **Installation** | svc_monitor sudo account plus ed25519 SSH key pair | Flag 18 |
| **Command & Control** | python3 reverse shell (PID 4401) running as root | Flags 4, 19, 26 |
| **Actions on Objectives** | Credential harvest, DB dump, registry enumeration, staging, encryption and HTTPS exfiltration | Flags 5 to 17 |

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Evidence in This Hunt |
|---|---|---|---|
| Resource Development | `T1588.007` | Obtain Capabilities: Artificial Intelligence | AI agent used as the primary execution engine (LLMAgentLogs_CL) |
| Reconnaissance | `T1595.002` | Active Scanning: Vulnerability Scanning | python-requests recon from three coordinated external IPs |
| Initial Access | `T1190` | Exploit Public-Facing Application | SSRF in /api/v1/preview using gopher:// |
| Execution / Persistence | `T1053.003` | Scheduled Task/Job: Cron | Cron job written through Redis spawns the shell |
| Execution | `T1059.006` | Command and Scripting Interpreter: Python | python3 -c reverse shell as root |
| Credential Access | `T1552.001` | Unsecured Credentials: Credentials In Files | cat /etc/semicrest/portal.conf |
| Defense Evasion / Lateral Movement | `T1078` | Valid Accounts | portal_svc and ci-builder reused from the portal host |
| Discovery | `T1613` | Container and Resource Discovery | Harbor list_repository, pull_manifest, inspect_layer |
| Collection | `T1213` | Data from Information Repositories | SELECT * dumps of customers, pg_shadow, information_schema |
| Collection | `T1074.001` | Data Staged: Local Data Staging | /tmp/.portal-cache/ |
| Collection | `T1560.001` | Archive Collected Data: Archive via Utility | tar, gzip, openssl enc -aes-256-cbc |
| Exfiltration | `T1048.002` | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | HTTPS to 198.51.100.210:443 |
| Persistence | `T1136.001` | Create Account: Local Account | useradd svc_monitor |
| Persistence / Privilege Escalation | `T1098` | Account Manipulation | usermod -aG sudo svc_monitor |
| Persistence | `T1098.004` | Account Manipulation: SSH Authorized Keys | ed25519 key pair with no passphrase for re-entry |

## Detailed Findings

### SECTION 1: INITIAL ACCESS

#### FLAG 1: Vulnerable endpoint

**Objective:** Which API endpoint on the portal was targeted by the two requests?

**Finding:** /api/v1/preview

**KQL Query:**

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where Computer =~ "sc-portal01"
| where SrcIpAddr == "203.0.113.87"
| project TimeGenerated, SrcIpAddr, UrlOriginal, HttpStatusCode
```

**Evidence:**

![Flag 1: Vulnerable endpoint](images/flag01-vulnerable-endpoint.png)

---

#### FLAG 2: The self-correct

**Objective:** The two requests used different URL schemes in their parameters. What was tried first, what replaced it, and how long did the correction take?

**Finding:** file://, gopher://, 18 seconds

**KQL Query:**

```kql
PortalAccessLog_CL
| where Computer =~ "sc-portal01"
| where SrcIpAddr == "203.0.113.87"
| where UrlOriginal has "/api/v1/preview"
| where TimeGenerated between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:53:00Z))
| project TimeGenerated, UrlOriginal, HttpStatusCode
| order by TimeGenerated asc
```

**Evidence:**

![Flag 2: The self-correct](images/flag02-self-correct.png)

---

#### FLAG 3: Exploit source

**Objective:** Which external address delivered the exploit?

**Finding:** 203.0.113.87

**KQL Query:**

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where UrlOriginal has "gopher"
| extend DecodedUrl = url_decode(url_decode(UrlOriginal))
| project TimeGenerated, Computer, SrcIpAddr, DecodedUrl, HttpStatusCode
| order by TimeGenerated asc
```

**Evidence:**

![Flag 3: Exploit source](images/flag03-exploit-source.png)

---

#### FLAG 4: Exploitation chain

**Objective:** Trace the full chain from the successful web request to code execution on sc-portal01. Name every intermediary and the process that proves RCE.

**Finding:** SSRF via /api/v1/preview using gopher:// to Redis on 127.0.0.1:6379 writes a cron job, python3 reverse shell spawned by cron as root

**KQL Query:**

```kql
DeviceProcessEvents_CL
| where DeviceName =~ "sc-portal01"
| where Timestamp between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:54:00Z))
| where InitiatingProcessFileName endswith "cron"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
```

**Evidence:**

![Flag 4: Exploitation chain](images/flag04-exploitation-chain.png)

---

### SECTION 2: CREDENTIAL HARVEST

#### FLAG 5: Configuration file and process tree

**Objective:** Name the file that contained the credentials and the process that read it. Include enough of the process tree to show how the read connects to the initial access.

**Finding:** /etc/semicrest/portal.conf read by cat under python3 under cron

**KQL Query:**

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 07:10))
| where DeviceName =~ "sc-portal01"
| where ProcessCommandLine contains "portal.conf"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId
```

**Evidence:**

![Flag 5: Configuration file and process tree](images/flag05-config-file-process-tree.png)

---

#### FLAG 6: Database credential

**Objective:** Give the database credential pair found in the configuration file and the host it targets.

**Finding:** portal_svc:Pr0jectAur0ra! targeting 10.5.0.20

**KQL Query:**

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where tostring(model_response) has "portal_svc"
| project TimeGenerated, model_response
```

**Evidence:**

![Flag 6: Database credential](images/flag06-database-credential.png)

---

#### FLAG 7: Registry credential

**Objective:** The same configuration file held a second credential pair for a different service. Give the pair and its target.

**Finding:** ci-builder:H4rb0rBu1ld! targeting 10.5.0.40

**KQL Query:**

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where tostring(model_response) has "ci-builder"
| project TimeGenerated, model_response = tostring(model_response)
| order by TimeGenerated asc
```

**Evidence:**

![Flag 7: Registry credential](images/flag07-registry-credential.png)

---

#### FLAG 8: Visibility gap

**Objective:** The process telemetry shows both the config file read and an env command on sc-portal01 in the same burst. The config file contents are visible. Were additional credentials found in the environment variables?

**Finding:** No, because the env command was recorded but its output is not captured: Additional Fields is empty in all matching rows, so any credentials in the environment variables are not visible

**KQL Query:**

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 07:10))
| where DeviceName =~ "sc-portal01"
| where FileName =~ "env"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId
```

**Evidence:**

![Flag 8: Visibility gap](images/flag08-visibility-gap.png)

---

### SECTION 3: LATERAL MOVEMENT

#### FLAG 9: Database query discrimination

**Objective:** The portal_svc account runs hundreds of legitimate queries on sc-db01 daily. How do the attacker's queries differ from the application's normal pattern? Name the discriminating properties.

**Finding:** Statement structure: the attacker runs unbounded read-only dumps (SELECT * or columns with no WHERE/LIMIT) and schema enumeration (information_schema, pg_shadow), while the app runs bounded queries (WHERE/LIMIT/count) mixed with INSERT/UPDATE writes. Target selection: the attacker queries data the app never touches (customers, pg_shadow, users.password_hash, projects team_lead/revision), while the app uses its usual tables with limited columns. Execution cadence: the attacker fires queries back-

**KQL Query:**

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20) .. datetime(2026-09-21))
| where Computer =~ "sc-db01"
| where SyslogMessage startswith "statement:"
| where SyslogMessage contains "SELECT *"
    or SyslogMessage contains "information_schema"
    or SyslogMessage contains "pg_catalog"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

**Evidence:**

![Flag 9: Database query discrimination](images/flag09-db-query-discrimination.png)

---

#### FLAG 10: Queried tables

**Objective:** Name the specific database tables the attacker queried on sc-db01 that fall outside normal application patterns.

**Findings:** customers, pg_catalog.pg_shadow, information_schema.tables

**KQL Query:**

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-20) .. datetime(2026-09-21))
| where Computer =~ "sc-db01"
| where SyslogMessage contains "statement: SELECT *"
    or SyslogMessage contains "information_schema"
    or SyslogMessage contains "pg_catalog"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

**Evidence:**

![Flag 10: Queried tables](images/flag10-queried-tables.png)

---

#### FLAG 11: Registry enumeration

**Objective:** On sc-registry01, the ci-builder account accessed the Harbor registry during the attack window. In the lead-in data, the same account only runs pull_artifact and push artifact from the CI server (10.5.0.100). What operations appeared during the attack window from sc-portal01 (10.5.0.10) that differ from this baseline?

**Finding:** login, list_repository, pull_manifest, inspect_layer

**KQL Query:**

```kql
ContainerRegistryLog_CL
| where TimeGenerated > datetime(2026-09-15)
| where Computer =~ "sc-registry01"
| where Username =~ "ci-builder" and SrcIpAddr == "10.5.0.10"
| project TimeGenerated, Operation, Repository, Resource, HttpStatusCode
| order by TimeGenerated asc
```

**Evidence:**

![Flag 11: Registry enumeration](images/flag11-registry-enumeration.png)

---

#### FLAG 12: Admin API response

**Objective:** The attacker also reached sc-admin01. What response did the admin API return when the attacker queried the secrets endpoint?

**Findings:** 403 Forbidden, access denied

**KQL Query:**

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where Computer =~ "sc-admin01"
| where SyslogMessage contains "secrets" and SyslogMessage contains "10.5.0.10"
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

**Evidence:**

![Flag 12: Admin API response](images/flag12-admin-api-response.png)

---

### SECTION 4: AI HALLUCINATION JUDGEMENT

#### FLAG 13: Secrets store hallucination

**Objective:** The agent log claims to have extracted Kubernetes secrets from the admin platform on sc-admin01. Cross-reference this claim against the admin API telemetry. State what actually happened and what the discrepancy tells you about the agent's reliability.

**Findings:** Agent claims it extracted Kubernetes secrets (TLS certificates, service account tokens, API keys) from the sc-admin01 secrets store, telemetry shows the admin API returned 403 Forbidden to every secrets request from portal_svc (10.5.0.10) with no 200 responses, conclusion is the agent hallucinated the extraction and its self-reported results cannot be trusted without verification against independent logs

**KQL Query:**

```kql
LLMAgentLogs_CL
| where TimeGenerated > datetime(2026-09-20T07:45:00Z)
| where tostring(model_response) contains "secrets"
| project TimeGenerated, tool_name, model_response = tostring(model_response)
| order by TimeGenerated asc
```

**Evidence:**

![Flag 13: Secrets store hallucination](images/flag13-secrets-hallucination.png)

---

#### FLAG 14: Registry credential hallucination

**Objective:** The agent log claims to have found admin database credentials in a Harbor image layer on sc-registry01. Cross-reference the ContainerRegistryLog_CL against the claim and state what was actually in the image.

**Finding:** Agent claims it found admin database credentials db_admin:Sup3rS3cure! in the semicrest/portal-build: latest image layer configuration, but the registry shows only four metadata operations from 10.5.0.10 as ci-builder (login, list_repository, pull_manifest, inspect_layer against the /additions/vulnerabilities scan-report endpoint), all returning 200, with no layer, blob or config download, so the image contents were never read and the credential claim is fabricated

**KQL Query 1 (Agent Claim):**

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where tostring(model_response) contains "db_admin"
| project TimeGenerated, tool_name, model_response = tostring(model_response)
| order by TimeGenerated asc
```

![Flag 14 Agent Claim](images/flag14a-agent-claim.png)

**KQL Query 2 (Registry Evidence):**

```kql
ContainerRegistryLog_CL
| where TimeGenerated > datetime(2026-09-15)
| where Computer =~ "sc-registry01"
| where Username =~ "ci-builder"
| project TimeGenerated, SrcIpAddr, Operation, Repository, HttpStatusCode
| order by TimeGenerated asc
```

![Flag 14 Registry Evidence](images/flag14b-registry-evidence.png)

---

#### FLAG 15: Hallucination as autonomy limitation

**Objective:** Both hallucinations show the AI reporting findings that did not occur. What operational limitation does this reveal about AI-assisted attacks, and why does this campaign require a human operator rather than running fully autonomously?

**Finding:** The limitation is that the AI agent hallucinates: it reports findings and successes that did not occur (such as extracted secrets and image credentials that telemetry shows were denied or never read), so its output is unreliable and unverified. The operational consequence is that a human operator must review and verify the agent's results at each phase before authorizing the next step, so the campaign cannot run fully autonomously without acting on false information.

**KQL Query:**

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| extend UserInput = tostring(user_input), ModelResponse = tostring(model_response)
| where isnotempty(UserInput) and UserInput !in ("null", "[]", "{}")
| project TimeGenerated, tool_name, UserInput, ModelResponse
| order by TimeGenerated asc
```

**Evidence:**

![Flag 15: Hallucination as autonomy limitation](images/flag15-autonomy-limitation.png)

---

### SECTION 5: EXFILTRATION AND PERSISTENCE

#### FLAG 16: Exfil destination and staging path

**Objective:** Give the exfiltration destination and the path where the data was staged before transfer.

**Finding:** 198.51.100.210:443, /tmp/.portal-cache/report.tar.gz.enc

**KQL Query 1 (Network Evidence):**

```kql
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 09:00))
| where DeviceName =~ "sc-portal01"
| where RemoteIP == "198.51.100.210"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessId
```

![Flag 16 Network Evidence](images/flag16a-network-evidence.png)

**KQL Query 2 (File Evidence):**

```kql
DeviceFileEvents_CL
| where Timestamp between (datetime(2026-09-20 07:45) .. datetime(2026-09-20 08:30))
| where DeviceName =~ "sc-portal01"
| where FileName contains "report.tar"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

![Flag 16 File Evidence](images/flag16b-file-evidence.png)

---

#### FLAG 17: Staging tools

**Objective:** Name the tools used to create the staged archive and the order they ran in. Include the encryption tool.

**Finding:** tar, gzip, openssl

**KQL Query:**

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:45) .. datetime(2026-09-20 08:30))
| where DeviceName =~ "sc-portal01"
| where FileName in~ ("tar", "gzip", "openssl")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**

![Flag 17: Staging tools](images/flag17-staging-tools.png)

---

#### FLAG 18: Persistence mechanism

**Objective:** What did the attacker leave behind on sc-portal01 for persistent access?

**Finding:** svc_monitor with sudo privileges and an SSH key pair (ed25519, no passphrase) for passwordless re-entry

**KQL Query:**

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 08:15) .. datetime(2026-09-20 08:45))
| where DeviceName =~ "sc-portal01"
| where FileName in~ ("useradd", "usermod", "mkdir", "ssh-keygen")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**

![Flag 18: Persistence mechanism](images/flag18-persistence.png)

---

#### FLAG 19: Exfil vs legitimate HTTPS

**Objective:** The outbound HTTPS transfer at 08:15 shares its port (443) with legitimate SaaS and API traffic from sc-portal01. What property separates the exfiltration from the legitimate outbound traffic?

**Finding:** Initiating process identity: the exfil connection came from python3 PID 4401 running as root (the reverse shell process), while all legitimate port 443 traffic comes from the www-data web application process to a small set of recurring SaaS/API addresses; the exfil destination 198.51.100.210 also appears only once and never in the baseline

**KQL Query:**

```kql
DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-09-19) .. datetime(2026-09-21))
| where DeviceName =~ "sc-portal01"
| where RemotePort == 443
| summarize Connections = count(), First = min(Timestamp), Last = max(Timestamp)
    by RemoteIP, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Connections desc
```

**Evidence:**

![Flag 19: Exfil vs legitimate HTTPS](images/flag19-exfil-vs-legit-https.png)

---

### SECTION 6: RECONNAISSANCE AND TIMING

#### FLAG 20: Scanner Ips

**Objective:** Give the external scanner IPs and the internal scanner address.

**Finding:** 198.51.100.31, 198.51.100.45, 198.51.100.62, internal 10.5.0.250

**KQL Query:**

```kql
PortalAccessLog_CL
| where TimeGenerated > datetime(2026-09-15)
| where tostring(column_ifexists("UserAgent", "")) has_any ("python-requests", "Nessus")
| summarize count() by SrcIpAddr, UserAgent = tostring(column_ifexists("UserAgent", ""))
```

**Evidence:**

![Flag 20: Scanner Ips](images/flag20-scanner-ips.png)

---

#### FLAG 21: Recon vs Nessus discrimination

**Objective:** Both the external recon and the internal Nessus scan hit sc-portal01 around the same period. What property of the external recon distinguishes it from the scheduled Nessus scan?

**Finding:** Request cadence (short, scripted bursts from three coordinated external IPs vs Nessus running continuously on a schedule), response code distribution (400 responses on /api/v1/preview?url=test that Nessus never produces), and target selection (/api/v1/preview, /.env and API enumeration vs Nessus's 7 generic paths)

**KQL Query:**

```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-15) .. datetime(2026-09-20T06:50:00Z))
| summarize Paths = dcount(UrlOriginal) by SrcIpAddr
| order by Paths desc
```

**Evidence:**

![Flag 21: Recon vs Nessus discrimination](images/flag21-recon-vs-nessus.png)

---

#### FLAG 22: Timing signature

**Objective:** The attacker's chain runs for approximately two hours. A colleague says this looks like a normal human espionage operation. Test that against the timing: what pattern would you expect from a human operator, and what do you actually see?

**Finding:** A human operator would show variable gaps with tool-switching and reading delays, but this chain shows uniform machine-speed pacing: sub-second to few-second bursts (18-second self-correction, persistence commands within 20 seconds), operator approvals 1-3 seconds after each step, and regular 8-17 minute phase intervals, so the timing is consistent with AI-driven execution, not a human operator

**KQL Query:**

```kql
DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 06:50) .. datetime(2026-09-20 09:00))
| where DeviceName =~ "sc-portal01"
| where tolong(InitiatingProcessId) == 4401
| project Timestamp
| order by Timestamp asc
| serialize
| extend InterArrival = datetime_diff('second', Timestamp, prev(Timestamp))
| where isnotnull(InterArrival)
| summarize AvgSec=avg(InterArrival), MaxSec=max(InterArrival), MinSec=min(InterArrival)
```

**Evidence:**

![Flag 22: Timing signature](images/flag22-timing-signature.png)

---

### SECTION 7: AUTONOMY SYNTHESIS

#### FLAG 23: Operator decision gates

**Objective:** The agent log records the operator's directives between autonomous phases. How many human decision gates appear in the log, and at what phase transitions?

**Finding:** 4 gates: exploitation/foothold to credential harvesting and lateral movement, lateral movement to data collection, data collection to documentation and staging, staging to exfiltration and persistence

**KQL Query:**

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where isnotempty(tostring(user_input))
| project TimeGenerated, user_input
| order by TimeGenerated asc
```

**Evidence:**

![Flag 23: Operator decision gates](images/flag23-operator-gates.png)

---

#### FLAG 24: Autonomy placement

**Objective:** Was this run by a person, by a machine, or by a person who set a machine going? Cite at least two artefacts, each with its table and field.

**Finding:** A person who set a machine going: LLMAgentLogs_CL.user_input, DeviceProcessEvents_CL.ProcessCommandLine and PortalAccessLog_CL.UrlOriginal

**KQL Query:**

```kql
PortalAccessLog_CL
| where SrcIpAddr == "203.0.113.87"
| where TimeGenerated between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:53:00Z))
| project TimeGenerated, UrlOriginal, HttpStatusCode
```

**Evidence:**

![Flag 24: Autonomy placement](images/flag24-25-autonomy-placement.png)

---

#### FLAG 25: Novel ATT&CK technique

**Objective:** Which ATT&CK technique captures the novel aspect of this operation, the use of AI as the primary execution engine?

**Finding:** T1588.007 Obtain Capabilities: Artificial Intelligence

**KQL Query:**

```kql
PortalAccessLog_CL
| where SrcIpAddr == "203.0.113.87"
| where TimeGenerated between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:53:00Z))
| project TimeGenerated, UrlOriginal, HttpStatusCode
```

**Evidence:**

![Flag 25: Novel ATT&CK technique](images/flag24-25-autonomy-placement.png)

---

### SECTION 8: REAL OR NOISE TRIAGE

#### FLAG 26: Credential reuse across services (Real or Noise)

**Objective:** The portal svc credential appears in database connections on sc-db01, admin API requests on sc-admin01, and the original application on sc-portal01. A colleague proposes revoking the credential entirely to stop the attacker. What evidence separates the attacker's use of this credential from the application's legitimate use across all three hosts?

**Finding:** Initiating process and account context: every attacker connection to the database (5432), registry (443), and admin API (8443) comes from python3 PID 4401 running as root (the reverse shell), not from the www-data web application process, even though the source IP (10.5.0.10) and the portal_svc credential are the same as the application's

**KQL Query:**

```kql
Syslog
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where Computer =~ "sc-admin01"
| where SyslogMessage has "portal_svc"
| summarize count() by SrcIP=extract("src=([^ ]+)", 1, SyslogMessage)
```

**Evidence:**

![Flag 26: Credential reuse across services (Real or Noise)](images/flag26-credential-reuse.png)

---

#### FLAG 27: pg_dump disconfirmation

**Objective:** A nightly pg_dump backup runs as portal_svc on sc-db01 at 03:00. A colleague flags the most recent one as suspicious because it runs under the same account the attacker used. Test the hypothesis that it is part of the intrusion.

**Finding:** Noise (normal scheduled activity, not part of the intrusion): the pg_dump runs at 03:00 on a consistent nightly schedule and predates the intrusion, running since Sep 18 before the attack began

**KQL Query:**

```kql
DeviceProcessEvents_CL
| where Timestamp > datetime(2026-09-15)
| where FileName =~ "pg_dump"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

**Evidence:**

![Flag 27: pg_dump disconfirmation](images/flag27-pgdump.png)

---

#### FLAG 28: Connection spike dead end

**Objective:** A PostgreSQL connection spike appeared around 07:30 on sc-db01 that looks like the enumeration pattern. Is it part of the intrusion, and what is it?

**Finding:** Noise, caused by connection pool exhaustion: the application host (10.5.0.10) hit PostgreSQL's connection limit ("too many clients already"), not enumeration by the attacker

**KQL Query:**

```kql
Syslog
| where Computer =~ "sc-db01"
| where SyslogMessage has "FATAL" or SyslogMessage has "connection"
| where TimeGenerated between (datetime(2026-09-20T07:25:00Z) .. datetime(2026-09-20T07:35:00Z))
| project TimeGenerated, SyslogMessage
```

**Evidence:**

![Flag 28: Connection spike dead end](images/flag28-connection-spike.png)

---

## Summary of the Objectives, KQL Codes and Findings

<table>
<thead><tr><th>FLAG NUMBER</th><th>OBJECTIVE</th><th>KQL CODE</th><th>FINDINGS</th></tr></thead>
<tbody>
<tr><td><b>Flag 1</b><br>Vulnerable endpoint</td><td>Which API endpoint on the portal was targeted by the two requests?</td><td><pre>PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where Computer =~ "sc-portal01"
| where SrcIpAddr == "203.0.113.87"
| project TimeGenerated, SrcIpAddr, UrlOriginal, HttpStatusCode</pre></td><td>/api/v1/preview</td></tr>
<tr><td><b>Flag 2</b><br>The self-correct</td><td>The two requests used different URL schemes in their parameters. What was tried first, what replaced it, and how long did the correction take?</td><td><pre>PortalAccessLog_CL
| where Computer =~ "sc-portal01"
| where SrcIpAddr == "203.0.113.87"
| where UrlOriginal has "/api/v1/preview"
| where TimeGenerated between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:53:00Z))
| project TimeGenerated, UrlOriginal, HttpStatusCode
| order by TimeGenerated asc</pre></td><td>file://, gopher://, 18 seconds</td></tr>
<tr><td><b>Flag 3</b><br>Exploit source</td><td>Which external address delivered the exploit?</td><td><pre>PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where UrlOriginal has "gopher"
| extend DecodedUrl = url_decode(url_decode(UrlOriginal))
| project TimeGenerated, Computer, SrcIpAddr, DecodedUrl, HttpStatusCode
| order by TimeGenerated asc</pre></td><td>203.0.113.87</td></tr>
<tr><td><b>Flag 4</b><br>Exploitation chain</td><td>Trace the full chain from the successful web request to code execution on sc-portal01. Name every intermediary and the process that proves RCE.</td><td><pre>DeviceProcessEvents_CL
| where DeviceName =~ "sc-portal01"
| where Timestamp between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:54:00Z))
| where InitiatingProcessFileName endswith "cron"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName</pre></td><td>SSRF via /api/v1/preview using gopher:// to Redis on 127.0.0.1:6379 writes a cron job, python3 reverse shell spawned by cron as root</td></tr>
<tr><td><b>Flag 5</b><br>Configuration file and process tree</td><td>Name the file that contained the credentials and the process that read it. Include enough of the process tree to show how the read connects to the initial access.</td><td><pre>DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 07:10))
| where DeviceName =~ "sc-portal01"
| where ProcessCommandLine contains "portal.conf"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId</pre></td><td>/etc/semicrest/portal.conf read by cat under python3 under cron</td></tr>
<tr><td><b>Flag 6</b><br>Database credential</td><td>Give the database credential pair found in the configuration file and the host it targets.</td><td><pre>LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where tostring(model_response) has "portal_svc"
| project TimeGenerated, model_response</pre></td><td>portal_svc:Pr0jectAur0ra! targeting 10.5.0.20</td></tr>
<tr><td><b>Flag 7</b><br>Registry credential</td><td>The same configuration file held a second credential pair for a different service. Give the pair and its target.</td><td><pre>LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where tostring(model_response) has "ci-builder"
| project TimeGenerated, model_response = tostring(model_response)
| order by TimeGenerated asc</pre></td><td>ci-builder:H4rb0rBu1ld! targeting 10.5.0.40</td></tr>
<tr><td><b>Flag 8</b><br>Visibility gap</td><td>The process telemetry shows both the config file read and an env command on sc-portal01 in the same burst. The config file contents are visible. Were additional credentials found in the environment variables?</td><td><pre>DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 07:10))
| where DeviceName =~ "sc-portal01"
| where FileName =~ "env"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId</pre></td><td>No, because the env command was recorded but its output is not captured: Additional Fields is empty in all matching rows, so any credentials in the environment variables are not visible</td></tr>
<tr><td><b>Flag 9</b><br>Database query discrimination</td><td>The portal_svc account runs hundreds of legitimate queries on sc-db01 daily. How do the attacker's queries differ from the application's normal pattern? Name the discriminating properties.</td><td><pre>Syslog
| where TimeGenerated between (datetime(2026-09-20) .. datetime(2026-09-21))
| where Computer =~ "sc-db01"
| where SyslogMessage startswith "statement:"
| where SyslogMessage contains "SELECT *"
    or SyslogMessage contains "information_schema"
    or SyslogMessage contains "pg_catalog"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc</pre></td><td>Statement structure: the attacker runs unbounded read-only dumps (SELECT * or columns with no WHERE/LIMIT) and schema enumeration (information_schema, pg_shadow), while the app runs bounded queries (WHERE/LIMIT/count) mixed with INSERT/UPDATE writes. Target selection: the attacker queries data the app never touches (customers, pg_shadow, users.password_hash, projects team_lead/revision), while the app uses its usual tables with limited columns. Execution cadence: the attacker fires queries back-</td></tr>
<tr><td><b>Flag 10</b><br>Queried tables</td><td>Name the specific database tables the attacker queried on sc-db01 that fall outside normal application patterns.</td><td><pre>Syslog
| where TimeGenerated between (datetime(2026-09-20) .. datetime(2026-09-21))
| where Computer =~ "sc-db01"
| where SyslogMessage contains "statement: SELECT *"
    or SyslogMessage contains "information_schema"
    or SyslogMessage contains "pg_catalog"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc</pre></td><td>customers, pg_catalog.pg_shadow, information_schema.tables</td></tr>
<tr><td><b>Flag 11</b><br>Registry enumeration</td><td>On sc-registry01, the ci-builder account accessed the Harbor registry during the attack window. In the lead-in data, the same account only runs pull_artifact and push artifact from the CI server (10.5.0.100). What operations appeared during the attack window from sc-portal01 (10.5.0.10) that differ from this baseline?</td><td><pre>ContainerRegistryLog_CL
| where TimeGenerated &gt; datetime(2026-09-15)
| where Computer =~ "sc-registry01"
| where Username =~ "ci-builder" and SrcIpAddr == "10.5.0.10"
| project TimeGenerated, Operation, Repository, Resource, HttpStatusCode
| order by TimeGenerated asc</pre></td><td>login, list_repository, pull_manifest, inspect_layer</td></tr>
<tr><td><b>Flag 12</b><br>Admin API response</td><td>The attacker also reached sc-admin01. What response did the admin API return when the attacker queried the secrets endpoint?</td><td><pre>Syslog
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where Computer =~ "sc-admin01"
| where SyslogMessage contains "secrets" and SyslogMessage contains "10.5.0.10"
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc</pre></td><td>403 Forbidden, access denied</td></tr>
<tr><td><b>Flag 13</b><br>Secrets store hallucination</td><td>The agent log claims to have extracted Kubernetes secrets from the admin platform on sc-admin01. Cross-reference this claim against the admin API telemetry. State what actually happened and what the discrepancy tells you about the agent's reliability.</td><td><pre>LLMAgentLogs_CL
| where TimeGenerated &gt; datetime(2026-09-20T07:45:00Z)
| where tostring(model_response) contains "secrets"
| project TimeGenerated, tool_name, model_response = tostring(model_response)
| order by TimeGenerated asc</pre></td><td>Agent claims it extracted Kubernetes secrets (TLS certificates, service account tokens, API keys) from the sc-admin01 secrets store, telemetry shows the admin API returned 403 Forbidden to every secrets request from portal_svc (10.5.0.10) with no 200 responses, conclusion is the agent hallucinated the extraction and its self-reported results cannot be trusted without verification against independent logs</td></tr>
<tr><td><b>Flag 14</b><br>Registry credential hallucination</td><td>The agent log claims to have found admin database credentials in a Harbor image layer on sc-registry01. Cross-reference the ContainerRegistryLog_CL against the claim and state what was actually in the image.</td><td><pre>LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where tostring(model_response) contains "db_admin"
| project TimeGenerated, tool_name, model_response = tostring(model_response)
| order by TimeGenerated asc</pre><pre>ContainerRegistryLog_CL
| where TimeGenerated &gt; datetime(2026-09-15)
| where Computer =~ "sc-registry01"
| where Username =~ "ci-builder"
| project TimeGenerated, SrcIpAddr, Operation, Repository, HttpStatusCode
| order by TimeGenerated asc</pre></td><td>Agent claims it found admin database credentials db_admin:Sup3rS3cure! in the semicrest/portal-build: latest image layer configuration, but the registry shows only four metadata operations from 10.5.0.10 as ci-builder (login, list_repository, pull_manifest, inspect_layer against the /additions/vulnerabilities scan-report endpoint), all returning 200, with no layer, blob or config download, so the image contents were never read and the credential claim is fabricated</td></tr>
<tr><td><b>Flag 15</b><br>Hallucination as autonomy limitation</td><td>Both hallucinations show the AI reporting findings that did not occur. What operational limitation does this reveal about AI-assisted attacks, and why does this campaign require a human operator rather than running fully autonomously?</td><td><pre>LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| extend UserInput = tostring(user_input), ModelResponse = tostring(model_response)
| where isnotempty(UserInput) and UserInput !in ("null", "[]", "{}")
| project TimeGenerated, tool_name, UserInput, ModelResponse
| order by TimeGenerated asc</pre></td><td>The limitation is that the AI agent hallucinates: it reports findings and successes that did not occur (such as extracted secrets and image credentials that telemetry shows were denied or never read), so its output is unreliable and unverified. The operational consequence is that a human operator must review and verify the agent's results at each phase before authorizing the next step, so the campaign cannot run fully autonomously without acting on false information.</td></tr>
<tr><td><b>Flag 16</b><br>Exfil destination and staging path</td><td>Give the exfiltration destination and the path where the data was staged before transfer.</td><td><pre>DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-09-20 07:00) .. datetime(2026-09-20 09:00))
| where DeviceName =~ "sc-portal01"
| where RemoteIP == "198.51.100.210"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessId</pre><pre>DeviceFileEvents_CL
| where Timestamp between (datetime(2026-09-20 07:45) .. datetime(2026-09-20 08:30))
| where DeviceName =~ "sc-portal01"
| where FileName contains "report.tar"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc</pre></td><td>198.51.100.210:443, /tmp/.portal-cache/report.tar.gz.enc</td></tr>
<tr><td><b>Flag 17</b><br>Staging tools</td><td>Name the tools used to create the staged archive and the order they ran in. Include the encryption tool.</td><td><pre>DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 07:45) .. datetime(2026-09-20 08:30))
| where DeviceName =~ "sc-portal01"
| where FileName in~ ("tar", "gzip", "openssl")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc</pre></td><td>tar, gzip, openssl</td></tr>
<tr><td><b>Flag 18</b><br>Persistence mechanism</td><td>What did the attacker leave behind on sc-portal01 for persistent access?</td><td><pre>DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 08:15) .. datetime(2026-09-20 08:45))
| where DeviceName =~ "sc-portal01"
| where FileName in~ ("useradd", "usermod", "mkdir", "ssh-keygen")
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc</pre></td><td>svc_monitor with sudo privileges and an SSH key pair (ed25519, no passphrase) for passwordless re-entry</td></tr>
<tr><td><b>Flag 19</b><br>Exfil vs legitimate HTTPS</td><td>The outbound HTTPS transfer at 08:15 shares its port (443) with legitimate SaaS and API traffic from sc-portal01. What property separates the exfiltration from the legitimate outbound traffic?</td><td><pre>DeviceNetworkEvents_CL
| where Timestamp between (datetime(2026-09-19) .. datetime(2026-09-21))
| where DeviceName =~ "sc-portal01"
| where RemotePort == 443
| summarize Connections = count(), First = min(Timestamp), Last = max(Timestamp)
    by RemoteIP, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Connections desc</pre></td><td>Initiating process identity: the exfil connection came from python3 PID 4401 running as root (the reverse shell process), while all legitimate port 443 traffic comes from the www-data web application process to a small set of recurring SaaS/API addresses; the exfil destination 198.51.100.210 also appears only once and never in the baseline</td></tr>
<tr><td><b>Flag 20</b><br>Scanner Ips</td><td>Give the external scanner IPs and the internal scanner address.</td><td><pre>PortalAccessLog_CL
| where TimeGenerated &gt; datetime(2026-09-15)
| where tostring(column_ifexists("UserAgent", "")) has_any ("python-requests", "Nessus")
| summarize count() by SrcIpAddr, UserAgent = tostring(column_ifexists("UserAgent", ""))</pre></td><td>198.51.100.31, 198.51.100.45, 198.51.100.62, internal 10.5.0.250</td></tr>
<tr><td><b>Flag 21</b><br>Recon vs Nessus discrimination</td><td>Both the external recon and the internal Nessus scan hit sc-portal01 around the same period. What property of the external recon distinguishes it from the scheduled Nessus scan?</td><td><pre>PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-15) .. datetime(2026-09-20T06:50:00Z))
| summarize Paths = dcount(UrlOriginal) by SrcIpAddr
| order by Paths desc</pre></td><td>Request cadence (short, scripted bursts from three coordinated external IPs vs Nessus running continuously on a schedule), response code distribution (400 responses on /api/v1/preview?url=test that Nessus never produces), and target selection (/api/v1/preview, /.env and API enumeration vs Nessus's 7 generic paths)</td></tr>
<tr><td><b>Flag 22</b><br>Timing signature</td><td>The attacker's chain runs for approximately two hours. A colleague says this looks like a normal human espionage operation. Test that against the timing: what pattern would you expect from a human operator, and what do you actually see?</td><td><pre>DeviceProcessEvents_CL
| where Timestamp between (datetime(2026-09-20 06:50) .. datetime(2026-09-20 09:00))
| where DeviceName =~ "sc-portal01"
| where tolong(InitiatingProcessId) == 4401
| project Timestamp
| order by Timestamp asc
| serialize
| extend InterArrival = datetime_diff('second', Timestamp, prev(Timestamp))
| where isnotnull(InterArrival)
| summarize AvgSec=avg(InterArrival), MaxSec=max(InterArrival), MinSec=min(InterArrival)</pre></td><td>A human operator would show variable gaps with tool-switching and reading delays, but this chain shows uniform machine-speed pacing: sub-second to few-second bursts (18-second self-correction, persistence commands within 20 seconds), operator approvals 1-3 seconds after each step, and regular 8-17 minute phase intervals, so the timing is consistent with AI-driven execution, not a human operator</td></tr>
<tr><td><b>Flag 23</b><br>Operator decision gates</td><td>The agent log records the operator's directives between autonomous phases. How many human decision gates appear in the log, and at what phase transitions?</td><td><pre>LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-10-01) .. datetime(2026-10-31))
| where isnotempty(tostring(user_input))
| project TimeGenerated, user_input
| order by TimeGenerated asc</pre></td><td>4 gates: exploitation/foothold to credential harvesting and lateral movement, lateral movement to data collection, data collection to documentation and staging, staging to exfiltration and persistence</td></tr>
<tr><td><b>Flag 24</b><br>Autonomy placement</td><td>Was this run by a person, by a machine, or by a person who set a machine going? Cite at least two artefacts, each with its table and field.</td><td><pre>PortalAccessLog_CL
| where SrcIpAddr == "203.0.113.87"
| where TimeGenerated between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:53:00Z))
| project TimeGenerated, UrlOriginal, HttpStatusCode</pre></td><td>A person who set a machine going: LLMAgentLogs_CL.user_input, DeviceProcessEvents_CL.ProcessCommandLine and PortalAccessLog_CL.UrlOriginal</td></tr>
<tr><td><b>Flag 25</b><br>Novel ATT&amp;CK technique</td><td>Which ATT&amp;CK technique captures the novel aspect of this operation, the use of AI as the primary execution engine?</td><td><pre>PortalAccessLog_CL
| where SrcIpAddr == "203.0.113.87"
| where TimeGenerated between (datetime(2026-09-20T06:52:00Z) .. datetime(2026-09-20T06:53:00Z))
| project TimeGenerated, UrlOriginal, HttpStatusCode</pre></td><td>T1588.007 Obtain Capabilities: Artificial Intelligence</td></tr>
<tr><td><b>Flag 26</b><br>Credential reuse across services (Real or Noise)</td><td>The portal svc credential appears in database connections on sc-db01, admin API requests on sc-admin01, and the original application on sc-portal01. A colleague proposes revoking the credential entirely to stop the attacker. What evidence separates the attacker's use of this credential from the application's legitimate use across all three hosts?</td><td><pre>Syslog
| where TimeGenerated between (datetime(2026-09-19) .. datetime(2026-09-21))
| where Computer =~ "sc-admin01"
| where SyslogMessage has "portal_svc"
| summarize count() by SrcIP=extract("src=([^ ]+)", 1, SyslogMessage)</pre></td><td>Initiating process and account context: every attacker connection to the database (5432), registry (443), and admin API (8443) comes from python3 PID 4401 running as root (the reverse shell), not from the www-data web application process, even though the source IP (10.5.0.10) and the portal_svc credential are the same as the application's</td></tr>
<tr><td><b>Flag 27</b><br>pg_dump disconfirmation</td><td>A nightly pg_dump backup runs as portal_svc on sc-db01 at 03:00. A colleague flags the most recent one as suspicious because it runs under the same account the attacker used. Test the hypothesis that it is part of the intrusion.</td><td><pre>DeviceProcessEvents_CL
| where Timestamp &gt; datetime(2026-09-15)
| where FileName =~ "pg_dump"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc</pre></td><td>Noise (normal scheduled activity, not part of the intrusion): the pg_dump runs at 03:00 on a consistent nightly schedule and predates the intrusion, running since Sep 18 before the attack began</td></tr>
<tr><td><b>Flag 28</b><br>Connection spike dead end</td><td>A PostgreSQL connection spike appeared around 07:30 on sc-db01 that looks like the enumeration pattern. Is it part of the intrusion, and what is it?</td><td><pre>Syslog
| where Computer =~ "sc-db01"
| where SyslogMessage has "FATAL" or SyslogMessage has "connection"
| where TimeGenerated between (datetime(2026-09-20T07:25:00Z) .. datetime(2026-09-20T07:35:00Z))
| project TimeGenerated, SyslogMessage</pre></td><td>Noise, caused by connection pool exhaustion: the application host (10.5.0.10) hit PostgreSQL's connection limit ("too many clients already"), not enumeration by the attacker</td></tr>
</tbody>
</table>

## Indicators of Compromise

| Type | Indicator | Context |
|---|---|---|
| IP address | `203.0.113.87` | Exploit source (SSRF requests, reverse-shell peer) |
| IP address | `198.51.100.210:443` | Exfiltration destination |
| IP address | `198.51.100.31, 198.51.100.45, 198.51.100.62` | External reconnaissance scanners |
| User agent | `python-requests/2.31.0` | Recon and exploit tooling |
| URL pattern | `/api/v1/preview?url=gopher://` | SSRF payload to Redis 127.0.0.1:6379 |
| URL pattern | `/api/v1/preview?url=file://` | Rejected first SSRF attempt (400) |
| Process | `python3 PID 4401 (root, parent cron)` | Reverse shell |
| File | `/etc/semicrest/portal.conf` | Credential source read by the attacker |
| File | `/tmp/.portal-cache/report.tar.gz.enc` | Staged, encrypted archive |
| Account | `svc_monitor (sudo, ed25519 key with no passphrase)` | Attacker persistence |
| Credential | `portal_svc (PostgreSQL on 10.5.0.20)` | Compromised; rotate |
| Credential | `ci-builder (Harbor on 10.5.0.40)` | Compromised; rotate |

## Recommendations

| Category | Recommendation |
|---|---|
| **Containment** | Remove the svc_monitor account, its sudo membership and its SSH keys; kill python3 PID 4401; delete the malicious cron entry and /tmp/.portal-cache/; isolate sc-portal01 for forensic imaging. |
| **Containment** | Block 203.0.113.87, 198.51.100.210 and the three recon IPs at the perimeter and egress proxy. |
| **Eradication** | Rotate portal_svc and ci-builder in a coordinated window together with the application owners. The credential is shared with the legitimate application (Flag 26), so blind revocation would cause an outage. |
| **Eradication** | Fix the SSRF in /api/v1/preview: allow only http/https, block loopback and internal address ranges, and resolve and validate the destination before fetching. |
| **Hardening** | Require authentication on Redis, bind it with protected mode, and stop it from running as root or writing to cron directories. |
| **Hardening** | Move secrets out of /etc/semicrest/portal.conf into a secrets manager, and give each service its own least-privilege account. |
| **Hardening** | Apply egress filtering on sc-portal01 so that only the known SaaS/API destinations are reachable over 443. |
| **Visibility** | Close the Flag 8 gap: add command-output or environment capture (for example auditd or eBPF-based telemetry) so that env-style credential exposure becomes visible. |
| **Detection** | Turn the hunt's discriminators into analytics: the web application or cron spawning a root interpreter, outbound 443 from a root process on the portal, unbounded SELECT * or pg_shadow access by portal_svc, and ci-builder registry activity from any host other than 10.5.0.100. |
| **Operations** | Tune PostgreSQL max_connections and the application connection pool so that pool exhaustion (Flag 28) stops generating alert noise. |

## Conclusions

The hunt confirmed that the alert on sc-portal01 was the visible edge of a full, multi-host intrusion and not an isolated web anomaly. Starting from two preview-API requests, the investigation reconstructed every stage of the chain: reconnaissance, SSRF exploitation through Redis and cron, root code execution, credential harvesting from a configuration file, database and registry access with stolen service accounts, a blocked attempt on the admin secrets API, encrypted staging, HTTPS exfiltration and a backdoor account. Each stage is backed by a specific KQL query and screenshot in this report.

The most important analytical result is the attribution of how the operation was run. The pacing is machine-speed: an 18-second scheme correction, persistence commands within 20 seconds, and operator approvals 1 to 3 seconds after each step. Together with four human decision gates in the agent log, this places the operation as a person who set a machine going, consistent with Campaign C0062 and ATT&CK T1588.007. Equally important, the agent fabricated two of its successes (the Kubernetes secrets and the db_admin credential). This shows that an attacker's AI-generated narrative must never be taken at face value, by the attacker's own operator or by defenders reading a recovered log. Every claim was settled against independent telemetry.

The hunt also showed the value of disciplined triage. Credential reuse was separated from legitimate application use by process lineage (root python3 PID 4401 versus www-data), and that finding directly shapes a safe rotation plan. The nightly pg_dump backup and the 07:30 connection spike were both disproven as intrusion activity, which avoided wasted effort and unnecessary disruption. One question, whether env exposed further secrets, remains unanswerable because command output is not captured. Naming that visibility gap is itself a finding, and it is the first telemetry improvement recommended.

In short, SemiCrest's portal was fully compromised, two service credentials and sensitive database content were exposed and exfiltrated, and persistent access was planted. Immediate containment, credential rotation, the SSRF fix and the detection and visibility improvements listed above are required to remediate this incident and to detect the next AI-paced intrusion earlier.

## References

- [Anthropic: Disrupting the first reported AI-orchestrated cyber espionage campaign (November 2025)](https://www.anthropic.com/news/disrupting-AI-espionage)
- [MITRE ATT&CK Campaign C0062: Anthropic AI-orchestrated Campaign](https://attack.mitre.org/campaigns/C0062/)
- [MITRE ATT&CK T1588.007: Obtain Capabilities: Artificial Intelligence](https://attack.mitre.org/techniques/T1588/007/)
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Microsoft Learn: Kusto Query Language (KQL) overview](https://learn.microsoft.com/en-us/kusto/query/)

## Repository Structure

```text
SemiCrest-Threat-Hunt/
├── README.md                              # This report
├── images/                                # Query and result screenshots for every flag
├── queries/semicrest-hunt-queries.kql     # Every KQL query used in the hunt
└── report/SemiCrest_Threat_Hunt_Report.docx  # Microsoft Word copy of the report
```

> *This report documents a training threat-hunt lab. All organisations, hosts, IP addresses and credentials are part of the simulated SemiCrest environment.*
