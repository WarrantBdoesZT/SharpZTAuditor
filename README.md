# ZeroTrustAuditor v2.0

> **Read-only Zero Trust misconfiguration assessment for Windows Active Directory environments.**
> Pure C# — no PowerShell, no WMI, no external processes. Compiles to a single self-contained executable.

![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)
![.NET](https://img.shields.io/badge/.NET-8.0-purple?style=flat-square)
![Language](https://img.shields.io/badge/language-C%23-239120?style=flat-square)
![Mode](https://img.shields.io/badge/mode-read--only-brightgreen?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## What problem does this solve?

In a Zero Trust environment, you assume an attacker is already inside your network. The question is not *if* they got in — it is *how far can they go?* ZeroTrustAuditor answers that question by reading the configuration of your Active Directory, your servers, and your network, then flagging every misconfiguration that would let an attacker move laterally, escalate privileges, or reach a Domain Controller.

Think of it as a thorough checklist that never forgets a question. It tells you what is wrong, how dangerous it is, which MITRE ATT&CK technique it maps to, and exactly how to fix it.

**What it is NOT:**
- It does not exploit vulnerabilities
- It does not capture credentials
- It does not make any changes to the environment
- It does not require Domain Admin rights

Every check is equivalent to reading configuration data that a standard domain user already has access to.

---

## How it works — the audit flow

```
You run the exe
      │
      ▼
Reads audit-config.json
      │
      ▼
┌─────────────────────────────────────────────────────┐
│              Five checks run in PARALLEL             │
│                                                      │
│  AdAuditor  ProtocolProbe  LateralPath  Share  Seg  │
└─────────────────────────────────────────────────────┘
      │
      ▼
All findings collected → Deduplicated → Scored
      │
      ▼
Correlation rules applied (dangerous combos get boosted)
      │
      ▼
Reports written: JSON · HTML · CSV · Splunk · Sentinel · CEF
```

**Step by step:**

1. **You provide a host list and domain name.** Either comma-separated on the command line or a plain text file with one hostname per line.
2. **Five audit checks launch simultaneously.** Each is an independent C# class running as a parallel async task. They do not wait for each other — all five run at the same time.
3. **Each check queries its target using read-only .NET APIs.** No scripts are written to disk. No commands are executed on target hosts.
4. **All findings flow into the aggregator.** Duplicates are removed. Risk scores are assigned. Correlation rules boost scores for dangerous combinations.
5. **Reports are written** in all configured formats for humans, machines, and SIEM platforms.

---

## The five audit modules

### 1. AdAuditor — Active Directory misconfigurations

Uses `System.DirectoryServices.DirectorySearcher` (LDAP) and `System.DirectoryServices.AccountManagement`. Requires only a standard Domain User account.

| Check | What it finds | Severity |
|---|---|---|
| `KERBEROASTABLE_SPN` | Accounts with Service Principal Names — any domain user can request their password hash and crack it offline | High / Critical |
| `ASREP_ROASTABLE` | Accounts that skip Kerberos pre-auth — anyone can request their hash without a password | High / Critical |
| `UNCONSTRAINED_DELEGATION` | Accounts that can impersonate any user — one compromise = full domain access | Critical |
| `DCSYNC_ACE` | Non-DC accounts with replication rights — can pull every password hash from the DC without touching it | Critical |
| `STALE_PRIVILEGED_ACCOUNT` | Admin accounts unused for 90+ days — attackers love dormant accounts, no one notices when they log in | High |
| `NESTED_GROUP_DA` | Groups nested inside Domain Admins — grants admin rights to everyone in that group, often broader than intended | High |
| `MISSING_PROTECTED_USERS` | Privileged accounts not in Protected Users — can still authenticate with weaker NTLM | Medium |
| `ADMINCOUNT_ORPHAN` | Accounts with AdminCount=1 no longer in privileged groups — broken permission inheritance hides delegated access | Medium |

> **Analogy for new technicians:** These are the skeleton keys in your environment. A Kerberoastable SPN account with AdminCount=1 is a single crackable password away from domain admin — the kind of silent misconfiguration that goes undetected for years.

---

### 2. ProtocolProbe — Insecure protocol configurations

Uses `Microsoft.Win32.RegistryKey.OpenRemoteBaseKey()` to read remote registry values and `System.Net.Sockets.TcpClient` for port checks. No PowerShell. No WMI.

| Check | What it finds | Severity |
|---|---|---|
| `SMB_SIGNING_DISABLED` | Without SMB signing, an attacker on the same network can intercept and relay authentication — logging in as you without knowing your password | High / Critical |
| `NTLM_V1_ENABLED` | NTLMv1 hashes crack with rainbow tables in seconds. LmCompatibilityLevel below 3 means the host accepts them | High / Critical |
| `RDP_NLA_DISABLED` | Without Network Level Authentication, the Windows login screen loads before credentials are checked — exposed to bruteforce tools | High |
| `WINRM_UNENCRYPTED` | WinRM over HTTP (port 5985) without encryption — every command and credential is readable on the wire | High |
| `DCOM_DEFAULT_LAUNCH_PERMISSION` | Absent DCOM permissions default to allowing Everyone to launch COM objects — a known lateral movement path | High |
| `SSH_PASSWORD_AUTH_ENABLED` | Password auth over SSH allows credential stuffing — certificate-based auth is the Zero Trust standard | Medium |

> **Requirement:** The Remote Registry Windows service must be running on target hosts for registry-based checks. Deploy via GPO: `Computer Configuration → Windows Settings → System Services → Remote Registry → Automatic`

---

### 3. LateralPathAnalyzer — Lateral movement paths

Uses `System.DirectoryServices.AccountManagement` to enumerate local security groups on each target and maps which accounts can reach which hosts.

| Check | What it finds | Severity |
|---|---|---|
| `LOCAL_ADMIN_OVERLAP` | Same account has local admin rights on multiple hosts — one compromise enables movement to all of them | Medium → Critical |
| `DOMAIN_GROUP_LOCAL_ADMIN` | Domain group in local Administrators — every member gets local admin, often far more accounts than intended | High |
| `LAPS_NOT_DEPLOYED` | Without LAPS, all machines built from the same image share the same local Administrator password | High |
| `BROAD_RDP_ACCESS` | Large domain groups in Remote Desktop Users — many accounts can RDP directly to servers, bypassing jump server controls | Medium |

> **The lateral movement picture:** This module answers: *"If an attacker compromises one host, which other hosts can they immediately reach without needing additional credentials?"* `LOCAL_ADMIN_OVERLAP` is often the highest-impact finding — one account with local admin on 20 servers turns one breach into twenty.

---

### 4. ShareAuditor — Over-permissive file shares

Uses `System.IO.DirectoryInfo.GetAccessControl()` and `System.Security.AccessControl.FileSystemAccessRule` to read NTFS ACLs via UNC path. No SMB enumeration cmdlets needed.

| Check | What it finds | Severity |
|---|---|---|
| `SYSVOL_WRITE_PERMISSION` | SYSVOL holds Group Policy scripts that run on every domain computer — write access = code execution on every machine | Critical |
| `ADMIN_SHARE_OVERPERMISSIVE` | C$ or ADMIN$ accessible beyond Administrators — direct lateral movement path | Critical |
| `OPEN_SMB_SHARE_WRITE` | Any domain user can write to this share — attackers plant DLLs, replace binaries, or drop ransomware payloads | High |
| `OPEN_SMB_SHARE_READ` | Any domain user can read this share — sensitive data accessible without special permissions | Medium |

---

### 5. SegmentationChecker — Network segmentation gaps

Uses `System.Net.Sockets.TcpClient` for port probing and remote registry reads for firewall and logging configuration. Verifies that your network segmentation actually prevents lateral movement.

| Check | What it finds | Severity |
|---|---|---|
| `CROSS_SEGMENT_ADMIN_PORT` | SMB (445), WMI (135), or WinRM (5985) reachable across network segment boundaries — firewall is not blocking lateral movement protocols | High |
| `WINDOWS_FIREWALL_DISABLED` | Host-based firewall is off — network segmentation without host firewall relies entirely on perimeter controls | High |
| `WEF_NOT_CONFIGURED` | Windows Event Forwarding not set up — attackers know that clearing local logs destroys forensic evidence | Medium |
| `SECURITY_LOG_TOO_SMALL` | Security event log too small — rotates quickly under brute-force load, overwriting evidence of the attack | Low |
| `FIREWALL_LOGGING_DISABLED` | Firewall drop logging disabled — lateral movement attempts and port scans are invisible to the SOC | Medium |

---

## How findings are scored

Every finding gets a base risk score from its severity:

| Severity | Base Score | Meaning | Recommended SLA |
|---|---|---|---|
| **Critical** | 9.0 | Direct path to domain compromise | 24–48 hours |
| **High** | 7.0 | Significant misconfiguration enabling targeted attack | 7 days |
| **Medium** | 5.0 | Defense-in-depth gap; exploitable in combination | 30 days |
| **Low** | 3.0 | Best-practice deviation | 90 days |
| **Informational** | 1.0 | Connectivity note or manual review item | Review only |

### Correlation rules — when two misconfigs are worse together

When two dangerous misconfigurations appear on the **same host**, both scores get a +2.0 boost because the combination forms a complete attack chain:

```
SMB_SIGNING_DISABLED (7.0)  +  LOCAL_ADMIN_OVERLAP (7.0)
           │                              │
           └──────── same host ───────────┘
                         │
                         ▼
           Both scores → 9.0 (effectively Critical)

WHY: An attacker intercepts SMB auth → relays it to any host
     where the account has local admin → instant mass lateral movement.
```

**All six correlation rules:**

| Rule | Check A | Check B | Scope | Why dangerous together |
|---|---|---|---|---|
| SMB relay + admin spread | `SMB_SIGNING_DISABLED` | `LOCAL_ADMIN_OVERLAP` | host | One relayed auth = access to every host the account admins |
| NTLMv1 + admin spread | `NTLM_V1_ENABLED` | `LOCAL_ADMIN_OVERLAP` | host | NTLMv1 cracks in seconds; shared admin = mass compromise |
| Delegation + Kerberoasting | `UNCONSTRAINED_DELEGATION` | `KERBEROASTABLE_SPN` | domain | Crack the SPN → present ticket to delegating host → impersonate anyone |
| DCSync + stale account | `DCSYNC_ACE` | `STALE_PRIVILEGED_ACCOUNT` | domain | Dormant account with replication rights — low detection, maximum blast radius |
| Unencrypted WinRM + admin spread | `WINRM_UNENCRYPTED` | `LOCAL_ADMIN_OVERLAP` | host | Credentials on the wire + shared admin password = immediate mass access |
| RDP NLA disabled + writable share | `RDP_NLA_DISABLED` | `OPEN_SMB_SHARE_WRITE` | host | Pre-auth bruteforce + writable share = remote exec + persistence |

**Rule scope matters.** A `host`-scoped rule only fires when both findings touch a common machine — a genuine attack chain. A `domain`-scoped rule fires when both conditions merely exist somewhere in the domain; it is a weaker signal and every boosted finding is tagged `correlationScope=domain` so you can tell the two apart.

Findings anchored on the domain (such as `LOCAL_ADMIN_OVERLAP`) carry the list of hosts they actually span, so they correlate against per-host findings on exactly those hosts.

---

## What a finding looks like

Each finding in the HTML report and JSON output contains:

```json
{
  "Id": "a3f2c1d8",
  "Host": "SRV01.corp.local",
  "Module": "ProtocolProbe",
  "CheckName": "SMB_SIGNING_DISABLED",
  "Severity": "High",
  "RiskScore": 9.0,
  "Description": "SMB signing is not required on 'SRV01'. SMB relay attacks are possible, enabling code execution without credentials. (Boosted: co-located with LOCAL_ADMIN_OVERLAP)",
  "Evidence": "RequireSecuritySignature=0; EnableSecuritySignature=0",
  "RemediationGuidance": "Set RequireSecuritySignature=1 via GPO: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Microsoft network server: Digitally sign communications (always).",
  "Tags": { "correlationRule": "SMB relay + admin spread" },
  "DiscoveredAt": "2025-05-11T03:15:22Z"
}
```

| Field | What it means |
|---|---|
| `Host` | The machine where this was found |
| `CheckName` | The specific misconfiguration detected |
| `Severity` | Base risk level (Critical / High / Medium / Low / Informational) |
| `RiskScore` | 0–10 score — above base severity means a correlation boost fired |
| `Evidence` | The raw registry value, ACL entry, or configuration that triggered the finding |
| `RemediationGuidance` | Exact GPO path or command to fix the issue |
| `Tags.correlationRule` | Which correlation rule boosted this finding and why |

---

## Permissions required

The tool is designed to run as a **regular domain user**. No Domain Admin, no local admin, no elevated privileges for most checks.

| Module | What it needs | If missing |
|---|---|---|
| AdAuditor | Domain User (read-only LDAP) | Check skips with logged message |
| ProtocolProbe | Remote Registry service running on targets | No registry-based finding for that host, plus a `REMOTE_REGISTRY_UNREACHABLE` Informational finding |
| LateralPathAnalyzer | AccountManagement API access (port 445) | `HOST_UNREACHABLE` Informational finding |
| ShareAuditor | Network read to UNC paths (`\\host\share`) | No share findings for that host, plus a `SMB_UNREACHABLE` Informational finding |
| SegmentationChecker | Network connectivity (TCP SYN only) | Port reported as closed; registry-based sub-checks also get `REMOTE_REGISTRY_UNREACHABLE` |

> **Why this matters:** every module above used to fail *silently* when it couldn't read a host — a locked-down host and a genuinely clean host looked identical in the report. Before launching the five audit modules, the orchestrator now runs a lightweight reachability pre-check against SMB (445) and the Remote Registry on every host, and emits an Informational finding for any host it couldn't reach either way. **A finding-free host is only a clean host if you don't also see a `REMOTE_REGISTRY_UNREACHABLE` or `SMB_UNREACHABLE` entry for it.**

> **Best practice:** Create a dedicated read-only service account (e.g. `CORP\svc-auditor`) and run the tool under that account. Never run as Domain Admin — it produces false negatives on checks like local admin group membership.

---

## Quick start

### Prerequisites

- Windows 10 1809+ or Server 2019+ (domain-joined or with network access to target domain)
- .NET 8 SDK — download from [dot.net/8](https://dotnet.microsoft.com/download/dotnet/8.0) (**SDK**, not Runtime)
- Domain User account
- Remote Registry service running on target hosts (for registry-based checks)

### Build

```powershell
git clone https://github.com/WarrantBdoesZT/ZeroTrustAuditor.git
cd ZeroTrustAuditor

dotnet restore ZeroTrustAuditor.csproj
dotnet publish ZeroTrustAuditor.csproj --configuration Release --runtime win-x64 --self-contained true --output .\dist
```

Or download a pre-built release from the [Releases](../../releases) page.

### Run

```powershell
cd .\dist

# Basic run — comma-separated hosts
.\ZeroTrustAuditor.exe --hosts DC01,SRV01,SRV02 --domain corp.local

# Using a targets file (one hostname per line, # for comments)
.\ZeroTrustAuditor.exe --hosts-file .\targets.txt --domain corp.local

# Skip specific modules
.\ZeroTrustAuditor.exe --hosts-file .\targets.txt --domain corp.local --skip-modules AdAuditor,ShareAuditor

# Full options
.\ZeroTrustAuditor.exe --hosts-file .\targets.txt --domain corp.local --config .\audit-config.json --output .\reports
```

### Targets file format

```text
# targets.txt
# Domain Controllers — always audit first
DC01
DC02

# Tier-1 Servers
SRV01
SRV02
DB01

# Workstation sample
WS01
# WS02  <-- commented out, skip this one
```

### Available flags

| Flag | Description |
|---|---|
| `--hosts h1,h2` | Comma-separated list of hostnames |
| `--hosts-file file.txt` | Path to text file with one hostname per line |
| `--domain corp.local` | Active Directory domain FQDN **(required)** |
| `--output ./reports` | Output directory for reports (default: `./reports`) |
| `--config audit-config.json` | Path to config file (default: `audit-config.json` next to exe) |
| `--skip-modules A,B` | Skip specific modules: `AdAuditor`, `ProtocolProbe`, `LateralPathAnalyzer`, `ShareAuditor`, `SegmentationChecker` |
| `--no-graph` | Skip lateral movement graph generation |
| `--help`, `-h` | Show usage and exit |

Set the environment variable `ZTA_DEBUG=1` to print full stack traces on fatal errors (off by default -- normal runs print a plain-English message and a hint instead).

---

## Output formats

All formats are written to the `--output` directory with a timestamp in the filename.

| Format | File | Use case |
|---|---|---|
| HTML | `audit-TIMESTAMP.html` | Human-readable report — open in any browser |
| JSON | `audit-TIMESTAMP.json` | Machine-readable, API ingest, custom tooling |
| CSV | `audit-TIMESTAMP.csv` | Ticket creation in ServiceNow / Jira |
| Splunk HEC | `audit-TIMESTAMP.splunk.json` | Push to Splunk HTTP Event Collector |
| Sentinel | `audit-TIMESTAMP.sentinel.json` | Ingest to Microsoft Sentinel Log Analytics |
| CEF | `audit-TIMESTAMP.cef` | Syslog forwarding to ArcSight, QRadar, or any CEF collector |

Enable additional formats in `audit-config.json`:

```json
"output": {
  "formats": ["json", "html", "csv", "splunk", "sentinel", "cef"]
}
```

---

## Reading the HTML report

1. **Open the file in any browser** — it is fully self-contained, no internet required.
2. **Check the severity dashboard first** — if Critical is non-zero, go straight to those findings before anything else. Click a card to filter the table to just that severity; click it again to clear the filter.
3. **Findings are ordered by risk score**, highest first. Findings with a score above their base severity (e.g. a High sitting at 9.0 instead of 7.0) had a correlation rule fire — these represent complete attack chains and should be treated as Critical.
4. **Use the search box** to filter by host, check name, description, or evidence text as you type.
5. **Check "Group by Check" before remediating.** If `SMB_SIGNING_DISABLED` appears on 30 hosts, that is a Group Policy problem — one GPO change fixes all 30. The grouping toggle clusters every finding by CheckName so you see the full blast radius at a glance instead of fixing them one host at a time.
6. **Click any column header to sort** — click again to reverse the direction.

---

## MITRE ATT&CK coverage

Every finding maps to a specific MITRE ATT&CK technique:

| Tactic | Techniques covered |
|---|---|
| Credential Access | T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting), T1558.001 (Delegation abuse), T1003.006 (DCSync), T1557.001 (NTLM relay), T1110 (Brute force) |
| Lateral Movement | T1021.001 (RDP), T1021.002 (SMB/Admin shares), T1021.003 (DCOM), T1021.006 (WinRM) |
| Persistence | T1484.001 (GPO modification via SYSVOL write) |
| Privilege Escalation | T1078.002 (Valid domain accounts — stale, nested, orphaned) |
| Defense Evasion | T1562.001 (Disable tools — Sysmon), T1562.004 (Disable firewall), T1562.006 (Indicator blocking — WEF, log size) |

---

## Configuration reference

`audit-config.json` controls all thresholds, exclusions, output formats, and correlation rules. The tool ships with sensible defaults — only customize what you need.

```jsonc
{
  "audit": {
    "staleAccountThresholdDays": 90,       // Flag accounts inactive longer than this
    "maxHostsPerRun": 500,                 // Safety cap — prevents accidental full-domain scans
    "parallelModuleTimeout": 300,          // Seconds before a module is cancelled
    "skipModules": [],                     // Permanently skip modules: ["AdAuditor"]
    "excludeHosts": [],                    // Always skip these hosts: ["honeypot01"]
    "excludeChecks": []                    // Suppress specific findings: ["SSH_CONFIG_UNREADABLE"]
  },
  "thresholds": {
    "privilegedGroups": [
      "Domain Admins", "Enterprise Admins", "Schema Admins"
      // Add your org's custom groups here: "Tier0-Admins", "PAW-Users"
    ],
    "lmCompatibilityLevelMinimum": 3       // Flag hosts below this NTLMv1 threshold
  },
  "output": {
    "formats": ["json", "html", "csv"]    // Add "splunk", "sentinel", "cef" as needed
  }
}
```

---

## Architecture — how the code is structured

```
ZeroTrustAuditor/
├── ZeroTrustAuditor.csproj     Entry point project file
├── audit-config.json           Runtime configuration
└── src/
    ├── Program.cs              CLI argument parsing, report dispatch
    ├── Orchestrator.cs         Parallel task runner, deduplication, correlation
    ├── Models/
    │   ├── Finding.cs          Finding data model (Id, Host, CheckName, Severity, ...)
    │   └── AuditConfig.cs      Config model + loader + validation
    ├── Checks/
    │   ├── CheckBase.cs        Shared helpers: port probe, remote registry, finding factory
    │   ├── AdAuditor.cs        System.DirectoryServices LDAP queries
    │   ├── ProtocolProbe.cs    Remote registry + TcpClient port checks
    │   ├── LateralPathAnalyzer.cs  AccountManagement local group enumeration
    │   ├── ShareAuditor.cs     System.Security.AccessControl UNC ACL reads
    │   └── SegmentationChecker.cs  TcpClient port probing + registry firewall checks
    └── Reports/
        ├── ReportRenderer.cs   JSON, CSV, HTML output
        └── SiemRenderer.cs     Splunk HEC, Sentinel, CEF output + MITRE mapping
```

### Tests

```powershell
dotnet test tests\ZeroTrustAuditor.Tests\ZeroTrustAuditor.Tests.csproj
```

The suite covers aggregation (deduplication identity, severity selection, correlation scope) and report encoding. These are regression tests for defects that previously corrupted output silently — a finding-level bug produces a wrong report rather than a crash, so this is the only layer that catches them. CI runs the tests before the publish job.

**Why pure C#?** The first version of this tool used a C# orchestrator that spawned PowerShell 5.1 child processes. This caused three categories of persistent failures: `CimCmdlets` incompatible with PS Core runspaces, UTF-8 encoding errors in PS 5.1, and parser bugs with long string lines. v2.0 replaces every PS call with a native .NET API — the same information, zero compatibility issues.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| AD checks produce 0 findings | Domain unreachable or no LDAP access | Run `nltest /dsgetdc:corp.local` from the audit workstation |
| Registry checks return nothing | Remote Registry service not running on target | Enable via GPO or: `Start-Service RemoteRegistry` on target |
| LateralPath shows all HOST_UNREACHABLE | Port 445 blocked or no network path to target | Test: `Test-NetConnection SRV01 -Port 445` |
| Hosts file not working | File not found at the path you specified | The tool prints the resolved path — check the output |
| 0 findings despite known misconfigs | Access denied is silent — check completes but reads nothing | Verify Remote Registry is running; test with a host you control |
| Antivirus quarantines the exe | Self-contained .NET exes are sometimes flagged | Add Defender exclusion or sign with your org's code-signing certificate |
| Build error: CS0234 DirectoryServices | NuGet restore did not download the package | Run `dotnet restore` with internet access, then rebuild |

---

## Zone-based segmentation

Segment boundaries come from a declared zone map, not from IP address arithmetic.

```powershell
copy zones.example.json  zones.json     # describe your network
copy policy.example.json policy.json    # declare approved cross-zone flows
.\ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local
```

| File | Purpose |
|---|---|
| `zones.json` | CIDR → zone, with a trust tier (0 = control plane … 4 = untrusted) and a role. Matched by **longest prefix**, so `10.30.1.0/24` (tier0) correctly wins over `10.0.0.0/8` (corporate). |
| `policy.json` | The cross-zone flows that are **approved**. Default-deny; each allow carries an owner and an expiry. An expired rule stops authorising traffic and is reported as a stale exception. |
| `services.json` | High-risk service catalog with intrinsic risk levels. OT/ICS protocols are marked `passive-only` and are never actively probed. |

**Severity comes from the zone pair, not the port.** SMB from the management VLAN to an application server is the designed administration path and scores low. The identical SMB from a guest VLAN to a domain controller is Critical. Same port, same protocol, entirely different finding — each one reports the tier delta and the reasoning that produced its score.

> **If `zones.json` is absent, cross-zone analysis is skipped**, and a `ZONE_MAP_NOT_CONFIGURED` finding says so. This is deliberate. The previous release inferred segments from the third octet of the IPv4 address, which treated `10.1.5.0/24` and `10.2.5.0/24` as the same segment while splitting a single `/23` in two. Producing no cross-zone findings is honest; producing confidently wrong ones is not.

Configuration errors (invalid CIDR, duplicate zone id, a policy rule naming a zone that does not exist) **stop the run** rather than being skipped, because a typo in a policy rule silently turns an approved path into a reported violation.

## Reachability verdicts

Every segmentation probe records **why** it got the answer it did:

| Verdict | Wire behaviour | What it means |
|---|---|---|
| **Open** | SYN/ACK | A service is listening and the path is open. |
| **Closed** | RST | The host *answered*. Packets reach it and **nothing is filtering** — there simply is no listener today. Reported as `CROSS_ZONE_UNENFORCED`. |
| **Filtered** | dropped / ICMP prohibited | A boundary control **is** enforcing. Not a finding — this is the evidence your segmentation works. |
| **Unknown** | DNS failure, local egress block, not probed | Nothing can be concluded. Never counted as a pass. |

The **Closed** row is the one that did not previously exist. The old boolean probe recorded a refused connection identically to a firewalled one, so "no findings" could mean either a working control or an empty port. `CROSS_ZONE_UNENFORCED` is the difference between being segmented and being lucky: nothing is exposed today, but nothing is stopping it either — the moment that service is installed, the path is open.

Raw observations for every probe, including Filtered, are written to `reachability-TIMESTAMP.json`.

### Probe safety

```powershell
.\ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local --dry-run
.\ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local --rate 50 --max-concurrency 64
```

Bounded concurrency and rate limiting are enforced (`maxParallelProbes` finally does something). Timeouts are retried, so one dropped SYN on a congested link is not mistaken for a firewall. Services marked `passive-only` in `services.json` — Modbus, S7, DNP3, EtherNet/IP, BACnet — are **never** actively probed unless you pass `--allow-ot-probing` *and* the target zone sets `activeProbing: true`. An unexpected TCP connect can fault a controller.

## The segmentation report

When a zone map is configured, the run produces `segmentation-TIMESTAMP.html` alongside the raw observations:

| Section | Answers |
|---|---|
| **Zone reachability matrix** | Is the network actually segmented? An N×N grid, source zones on rows. Colour is the worst outcome per pair; **grey means not assessed**, which is not the same as clean. |
| **Endpoint exposure register** | *Which servers and endpoints allow high-risk ports*, from where, sorted by severity then blast radius. Also written as `exposure-register-TIMESTAMP.csv` for ticketing. |
| **Policy violations** | Reachable paths policy does not permit, each with the exact firewall change and the NSA/CISA guidance that covers it. |
| **CISA ZTMM scorecard** | Networks-pillar maturity — Traditional / Initial / Advanced / Optimal — scored only from what was measured. |
| **Enforcement evidence** | The boundaries that *do* block. An assessment that reports only failures gets ignored. |

Findings are classified by comparing what was observed against what policy permits:

| Observed | Policy | Status | Meaning |
|---|---|---|---|
| Open | deny | **Violation** | The headline finding |
| Closed | deny | **Unenforced** | Nothing listening, nothing blocking — safe by accident |
| Filtered | deny | **Enforced** | The control works |
| Filtered | allow | **Drift** | An approved path is broken; an outage waiting to happen |
| Open / Closed | allow | **Compliant** | Working as designed |
| Unknown | any | — | Never a violation, never a pass |

### Host context escalates reachable paths

The AD, protocol and share checks are now an **enrichment tier** rather than five co-equal modules. Their findings are still reported in their own right, but they also attach to the specific reachable path they make worse:

> `SMB (tcp/445)` on `10.20.0.5` is reachable from `user-vlan` into `server-tier1`.
> **Why this path is worse than it looks**
> - SMB signing is not required on this host, so a reachable 445 is a viable NTLM relay target.
> - LAPS is not deployed, so this host very likely shares its local Administrator password with every machine from the same image.

A reachable 445 is bad. A reachable 445 with unsigned SMB on a host whose local admin password is shared across twenty machines is a different finding, and the report now says so.

Escalation happens **once** per path however many weaknesses stack, so a pile of medium issues cannot outrank a genuine critical. Only `Open` paths are escalated — a weakness sitting behind a working boundary is a finding in its own right, not an amplifier of a path that does not exist.

This is the correlation the tool originally advertised. The old engine grouped by a host key that host-scoped and domain-scoped checks never shared, so four of its six rules could never fire and the two that could were vacuous.

### NSA and CISA guidance

Every violation carries the specific guidance that applies to it, selected by zone roles, trust tiers and service category rather than pasted onto everything:

- **[CISA/NSA AA23-278A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a)** — Misconfiguration #4 (lack of network segmentation, including the IT/OT callout), #2 (improper user/administrator privilege separation), #3 (insufficient internal network monitoring)
- **[NSA CSI: Advancing Zero Trust Maturity Throughout the Network and Environment Pillar](https://media.defense.gov/2024/Mar/05/2003405462/-1/-1/0/CSI-ZERO-TRUST-NETWORK-ENVIRONMENT-PILLAR.PDF)** — data flow mapping, macro-segmentation, micro-segmentation
- **[CISA Zero Trust Maturity Model v2.0](https://www.cisa.gov/zero-trust-maturity-model)** — Networks pillar
- **[CISA Cross-Sector Cybersecurity Performance Goals](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals)** — segment by trust boundary and platform type
- **NSA CSI: Performing Out-of-Band Network Management** — cited for exposed IPMI/iLO/iDRAC/SNMP
- **NSA Top Ten Cybersecurity Mitigation Strategies** — Segment Networks and Deploy Application-Aware Defenses

> **Coverage.** One run measures one vantage zone, so only that row of the matrix is populated. Unmeasured pairs render as *not assessed* and are excluded from the maturity score. Run from a host in each source zone for full coverage.

## Multi-vantage coverage

One run measures reachability **from one source zone** — one row of the matrix. To fill in the rest, run from a host in each zone and merge:

```powershell
# on a workstation in the user VLAN
.\ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local --output .\user

# on a host in the DMZ
.\ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local --output .\dmz

# combine, and render the matrix across both
.\ZeroTrustAuditor.exe merge .\user\reachability-*.json .\dmz\reachability-*.json ^
    --zones zones.json --policy policy.json --report
```

No agents, no deployed infrastructure, nothing needing a change window.

Observations are keyed by `(source zone, target, transport, port)`, so the same host measured from two zones is **two distinct facts**, not a duplicate — reachability is a property of an ordered pair. Blast radius in the exposure register then counts every zone proven to reach an endpoint.

**Conflicts are surfaced, not smoothed over.** If a path was `Open` in one capture and `Filtered` in another, the more recent measurement wins, and the disagreement is recorded in the merged file. That difference means a control changed or is unstable, which is worth knowing.

**Merging does not invent coverage.** Combining four runs gives four rows, not a complete matrix. Unmeasured pairs stay `not assessed`, are excluded from the maturity score, and the coverage callout states how many source zones were actually measured. Merging several captures from the *same* zone warns that depth improved but coverage did not.

## Known limitations

Read these before treating a clean report as evidence of good segmentation. A full analysis and the planned redesign are in [REARCHITECTURE.md](REARCHITECTURE.md).

| Limitation | What it means for your results |
|---|---|
| **One vantage point** | Every probe originates from the machine running the exe. A result describes reachability *from that one segment* only — it is not a network-wide property, even though findings are presented per target host. |

| **No expected-policy baseline** | Every reachable admin port across a boundary is reported, including approved management paths. There is no allow-list, so triage is manual on every run. |
| **The enrichment path is still unthrottled** | Segmentation probing is now bounded and paced, but `ProtocolProbe`'s legacy boolean port check is not. It runs a fixed handful of ports per host, so the blast radius is small, but it is not rate limited. |
| **Not an assumed-breach tool** | It requires a domain-joined workstation, a valid domain user, and the Remote Registry service on targets. That is a credentialed configuration audit, not an unauthenticated foothold simulation. |

## Legal notice

This tool performs read-only configuration assessment. Even read-only port probing and registry access constitutes computer access under most legal frameworks. **Ensure you have written authorization from the system owner before running against any environment.** The authors accept no liability for unauthorized use.

---

## License

MIT — see [LICENSE](LICENSE) for details.
