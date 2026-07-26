# ZeroTrustAuditor — Evaluation & Rearchitecture to a Segmentation-First Tool

**Reviewed commit:** `bed0ae6` · **Scope:** all 2,712 LOC under `src/`, plus `audit-config.json`, CI, and the committed `ReportExample/`.

---

# Part 1 — Evaluation

## 1.1 Verdict up front

The tool is a **Windows/AD configuration auditor wearing a Zero Trust label**. It is competent at reading registry keys and LDAP attributes. It is not, today, a segmentation assessment tool, and it does not operate from an assumed-breach posture in any meaningful sense — it requires a domain-joined workstation, a valid domain user, and the Remote Registry service enabled on every target. That is a *credentialed compliance scan*, which is close to the opposite of assumed breach.

Separately — and more urgently than the strategic mismatch — **there are seven defects that silently corrupt the output of the current tool.** Several are provable from the sample report committed in this repo. They should be fixed or the code deleted before the rearchitecture, because the new tool will inherit `Orchestrator.Aggregate()` and the `Finding` model if you don't.

## 1.2 Tier A — Correctness defects that invalidate reports

### A1. The deduplication key destroys nearly all AD findings *(most severe bug in the codebase)*

`Orchestrator.cs:227-230` dedupes on `$"{f.Host}|{f.CheckName}"`.

But every finding produced by `AdAuditor` uses `_domain` as the host (`AdAuditor.cs:73, 99, 127, 173, 202, 247, 281, 316`), as do `ShareAuditor.CheckSysvol` (`ShareAuditor.cs:181`) and `LateralPathAnalyzer.CheckAdminOverlap` (`LateralPathAnalyzer.cs:247`).

So all Kerberoastable accounts in the domain share the key `corp.local|KERBEROASTABLE_SPN` and **collapse to a single finding.** Same for AS-REP roastable, unconstrained delegation, DCSync ACEs, stale privileged accounts, Protected Users gaps, nested DA groups, AdminCount orphans, SYSVOL ACEs, and every local-admin-overlap account.

Proven against your own committed sample (`ReportExample/reports/audit-20260511-112453.json`):

```
Duplicate Host|CheckName pairs: NONE
Findings anchored on the domain rather than a host:
  DCSYNC_ACE                sev=Critical
  SYSVOL_WRITE_PERMISSION   sev=Critical
  KERBEROASTABLE_SPN        sev=High      <-- exactly one, for the entire domain
  MISSING_PROTECTED_USERS   sev=Medium    <-- exactly one
  LOCAL_ADMIN_OVERLAP       sev=Medium    <-- exactly one
```

A domain with 60 Kerberoastable service accounts reports `1`. Remediation tracking, blast-radius estimation, and severity counts are all wrong.

### A2. The severity comparator is inverted — dedup keeps the *least* severe finding

```csharp
public enum Severity { Critical, High, Medium, Low, Informational }   // Critical = 0 … Informational = 4
```
```csharp
// Deduplicate: same Host + CheckName, keep highest severity
.Select(g => g.OrderByDescending(f => f.Severity).First())
```

`OrderByDescending` on the underlying int sorts `Informational(4) → Critical(0)`, so `.First()` returns the **least** severe member of the group. The comment states the opposite of the behaviour.

Compounded with A1: among 60 collapsed Kerberoastable accounts, the tool discards the `Critical` ones (AdminCount=1) and keeps a `High`. The sample report shows exactly this — `KERBEROASTABLE_SPN` at `High`.

The same inverted rank appears in `SiemRenderer` if it maps severity ordinally; note the HTML report had to hand-define a *corrected* rank (`SEV_RANK = {Critical:4 … Informational:0}` at `ReportRenderer.cs:190`), which shows the enum ordering was already known to be backwards in one place but never fixed at the source.

### A3. The correlation engine — the README's headline feature — cannot fire

Correlation groups findings by `f.Host` (`Orchestrator.cs:239`). Cross-referencing each configured rule against the host each check actually stamps:

| Rule | CheckA host | CheckB host | Result |
|---|---|---|---|
| SMB relay + admin spread | `SRV01` | `corp.local` | **impossible** |
| NTLMv1 + admin spread | `SRV01` | `corp.local` | **impossible** |
| Unencrypted WinRM + admin spread | `SRV01` | `corp.local` | **impossible** |
| RDP NLA + open share | `SRV01` | `SRV01`, but config says `OPEN_SMB_SHARE` while the emitted names are `OPEN_SMB_SHARE_WRITE` / `_READ` | **impossible (name mismatch)** |
| Unconstrained delegation + Kerberoasting | `corp.local` | `corp.local` | fires, but **vacuous** |
| DCSync + stale account | `corp.local` | `corp.local` | fires, but **vacuous** |

Four of six rules can never trigger. The two that can are not testing "same host" at all — they fire whenever both conditions exist *anywhere in the domain*, which is not a correlation, just an AND of two domain-wide facts.

Confirmed empirically: **0 findings in the sample report carry a `correlationRule` tag**, despite the sample containing both `DCSYNC_ACE` and privileged-account findings.

### A4. "Registry value absent" is treated as "control is missing" — false-positive storm

`GetRemoteReg` returns `null` for *all* of: host offline, Remote Registry stopped, access denied, key genuinely absent (`CheckBase.cs:88-100`). Multiple checks treat `null` as a confirmed failure:

- `LAPS_NOT_DEPLOYED` — **High** (`LateralPathAnalyzer.cs:215-217`)
- `DCOM_DEFAULT_LAUNCH_PERMISSION` — **High** (`ProtocolProbe.cs:183`)
- `DCOM_DEFAULT_ACCESS_PERMISSION` — Medium (`ProtocolProbe.cs:193`)
- `WEF_NOT_CONFIGURED` — Medium (`SegmentationChecker.cs:196`)
- `FIREWALL_LOGGING_DISABLED` — Medium, via `logDropped == null || logDropped == 0` (`SegmentationChecker.cs:144`)

Point this at 200 hosts without Remote Registry and it emits **~1,000 fabricated findings, two of them High per host.** The orchestrator's `REMOTE_REGISTRY_UNREACHABLE` note (added in `bed0ae6`) is an *Informational* line that does not suppress or downgrade any of them.

The LAPS check also only reads the local-state key `SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` and legacy `AdmPwd`; GPO-managed Windows LAPS under `SOFTWARE\Microsoft\Policies\LAPS` is not consulted, so correctly-configured estates can still be flagged.

**Root cause:** the `Finding` model has no way to express *"could not determine."* There is no tri-state.

### A5. The module timeout is dead config

`Orchestrator.cs:44-46` builds a `CancellationTokenSource` from `parallelModuleTimeout` and passes `linked.Token` into `RunSafe`. `RunSafe` (`:103-120`) accepts `CancellationToken ct` and **never references it** — it just awaits `fn()`, and none of the five module `RunAsync()` methods accept a token either. A module blocked on a TCP connect or an LDAP call hangs the entire run indefinitely. `parallelModuleTimeout: 300` does nothing.

### A6. One bad registry value kills an entire module across all hosts

```csharp
protected static int? GetRemoteRegInt(string computer, string subKey, string valueName)
{
    var v = GetRemoteReg(computer, subKey, valueName);   // try/catch inside
    return v == null ? null : Convert.ToInt32(v);        // NO try/catch
}
```

If a value is `REG_SZ`, `REG_BINARY`, or a `REG_DWORD` returned as `byte[]`, `Convert.ToInt32` throws. That propagates out of `CheckFirewallState` → `ProbeAndCheckAsync` → `Task.WhenAll` → `RunSafe`, which catches it and returns an **empty list**. A single malformed value on a single host silently zeroes out `SegmentationChecker` (or `ProtocolProbe`) for *every* host in the run. There is no per-host fault isolation anywhere — every module uses a bare `Task.WhenAll`.

### A7. Every output file is written with a UTF-8 BOM

`Encoding.UTF8` in `ReportRenderer` emits `EF BB BF`. Verified on all five committed sample outputs:

```
audit-...json           efbbbf
audit-...sentinel.json  efbbbf
audit-...splunk.json    efbbbf
audit-...csv            efbbbf
```

A leading BOM is invalid JSON per RFC 8259. Python's `json.load` refuses it outright (I hit this reading your sample). **Splunk HEC and the Sentinel Log Analytics ingestion API will reject these payloads** — meaning the two SIEM formats the README advertises do not actually ingest. Use `new UTF8Encoding(false)`.

Minor, same file: `WriteCsv`'s `Q()` escapes quotes and `\n` but not `\r`, and does not neutralise leading `=`, `+`, `-`, `@` — CSV formula injection into Excel via AD-controlled principal names.

## 1.3 Tier B — Why the segmentation logic specifically does not work

This is the part you're rebuilding, so it matters most.

### B1. "Network segment" is defined as the third octet of an IPv4 address

```csharp
targetOctet = targetIP.Split('.')[2];
crossSegment = auditOctet != null && targetOctet != auditOctet;
```
(`SegmentationChecker.cs:62-63`, `:212-224`)

This is unsound in both directions:

- **False negatives:** `10.1.5.0/24` and `10.2.5.0/24` are entirely different segments, often different sites — both have third octet `5`, so every cross-boundary exposure between them is reported as *safe*.
- **False positives:** a flat `192.168.0.0/16` or a `/23` spanning octets `1` and `2` is one broadcast domain; the tool reports internal traffic as cross-segment violations.
- Subnet masks are never read. VLAN, VRF, and routing topology are invisible. IPv6 is unhandled (`GetHostAddresses` result is filtered to `InterNetwork` only, so v6-only hosts silently yield `crossSegment = false`).

`GetLocalOctet()` additionally picks `Dns.GetHostAddresses(Dns.GetHostName()).FirstOrDefault(...)` — on any multi-homed host (VPN, Hyper-V vSwitch, docker0, second NIC) this returns an arbitrary interface, so the entire cross-segment determination for the run depends on adapter enumeration order.

### B2. Two segmentation config keys are read by nothing

`audit-config.json` declares `network.crossSegmentAdminPorts: ["SMB","WinRM","WMI","RDP"]` and `network.subnetClassificationMethod: "cidr"`. Neither has a corresponding property on `NetworkSettings` (`AuditConfig.cs:158-169`), so both are silently discarded by the deserializer. The check hardcodes `new[] { "SMB", "WMI", "WinRM" }` at `SegmentationChecker.cs:72`. The config advertises CIDR classification; the code does third-octet string comparison.

### B3. The single most important segmentation signal is thrown away

```csharp
catch { return false; }        // CheckBase.cs:64
```

A TCP connect has three distinct outcomes, and for segmentation assessment **the distinction is the entire finding**:

| Outcome | Meaning | Segmentation verdict |
|---|---|---|
| SYN/ACK | service listening | **path is open** |
| RST (`SocketError.ConnectionRefused`, fast) | host reachable, nothing listening | **no filtering between us and it** — the firewall is *not* enforcing |
| timeout / ICMP admin-prohibited | packet dropped | **path is filtered** — control is working |

The current code maps all three to `bool`, collapsing "blocked by firewall" and "host reachable but port closed" into the same `false`. That means the tool **cannot tell a working segmentation control from a dead host** — which is precisely the question it claims to answer. A host that is simply powered off looks identical to a properly firewalled one.

### B4. One vantage point, reported as if it were a network-wide property

Every probe originates from the machine running the exe. A finding of "SMB is reachable on SRV01" is a statement about *one* source segment. The report presents it as a property of SRV01. Segmentation is a property of an **ordered pair** — `(source zone → destination zone : port)` — and the current data model has no field for the source at all.

### B5. No expected-policy baseline

Every reachable admin port across an octet boundary becomes a `High` finding. But some cross-segment admin access is *required* — the management VLAN must reach servers over WinRM; backup infrastructure must reach 445; DCs must reach each other. With no declared allow-policy, the tool cannot distinguish a violation from designed-and-approved flow, so output on a real network is dominated by noise the operator must manually triage every run. There is no baseline, no diffing between runs, and no suppression model beyond a flat `excludeChecks` list.

### B6. Scan safety and accuracy are unmanaged

- `maxParallelProbes: 50` is in the config, has no model property, and is enforced nowhere. `_hosts.Select(ProbeAndCheckAsync)` fans out unbounded — 500 hosts × 7 ports = **3,500 concurrent TCP connects** from one process. You will exhaust the ephemeral port range and the Windows half-open connection limit, and the resulting timeouts get recorded as *"port closed"* — i.e. as **evidence of good segmentation**. The tool gets more optimistic the harder you push it.
- A fixed 3,000 ms timeout with no retry means one dropped SYN on a congested link is silently a "pass."
- No SYN-only / connect-scan distinction, no rate limiting, and no notion of fragile targets. Blind TCP connects against ICS/OT ranges (Modbus 502, S7 102, DNP3 20000) can fault PLCs — this needs to be an explicit opt-in, not an accident.

### B7. Open port ≠ the service you assume

Port 445 open is recorded as "SMB." No banner grab, no protocol handshake, no TLS certificate inspection. A host with a non-standard service on 3389, or SSH on 2222, is misclassified in both directions.

## 1.4 Tier C — Engineering hygiene

- **Build artifacts are committed.** `obj/` is in the repo, including `ZeroTrustAuditor.dll`, `apphost.exe`, and `.pdb`. There is **no `.gitignore`.** Shipping binaries in a security tool's source repo undermines the trust story — nobody can verify the exe corresponds to the source.
- **No LICENSE file**, though the README links to one and claims MIT.
- **Zero tests.** For a tool whose output drives remediation decisions, and which currently has an inverted comparator and a dead correlation engine, this is the root cause of Tier A. All of A1–A3 are catchable by one unit test on `Aggregate()`.
- **`PathGraphBuilder.AddEdge` is O(E) per insert** via `_edges.Any(...)` linear scan (`:135-139`), making graph construction O(E²). `LOCAL_ADMIN_OVERLAP` generates an all-pairs mesh (`:182-188`) — n² edges for n hosts. At 200 overlap hosts that's ~40,000 edges and ~800M comparisons. Use a `HashSet<(string,string,EdgeType)>`.
- **Host classification by substring** (`LooksLikeDc`, `:467-472`): `h.Contains("dc")` matches `CDC-APP01`, `MEDCART02`, `ABCDC-WEB`. Tier assignment (`GuessTier`) is likewise hostname-substring guessing. Both should come from AD (`userAccountControl & 8192`, OU path) or explicit config.
- `README` documents a `--no-graph` flag and `ZTA_DEBUG`, both real — but also documents `SSH_PASSWORD_AUTH_ENABLED` detection that requires reading `\\host\C$\ProgramData\ssh\sshd_config`, i.e. **local admin on the target**, contradicting the "no elevated privileges" claim on the same page.
- `--skip-modules` accepts arbitrary strings with no validation; a typo silently runs everything.

## 1.5 What is genuinely good and should survive

- The pure-.NET decision (no PowerShell child processes) is correct and well-executed.
- `Finding` → renderer separation is clean; adding output formats is cheap.
- The HTML report is self-contained, XSS-safe (`WebUtility.HtmlEncode` on every field), and the group-by-check affordance is the right instinct for GPO-level remediation.
- Per-check remediation text is specific and actionable — real GPO paths, not "consult your administrator." Keep this bar in the rewrite.
- `RunSafe` isolating module failures is the right shape (it just needs per-host granularity and the timeout wired up).
- The MITRE mapping is a good backbone to hang NSA/CISA references on.

---

# Part 2 — Rearchitecture: segmentation-first, assumed breach

## 2.1 The one architectural decision everything else follows from

> **Change the unit of analysis from `Finding(Host, CheckName)` to `Reachability(VantageZone → TargetEndpoint : Port, Verdict)`.**

A segmentation flaw is not a property of a host. It is a property of a **path between two zones**. Until the data model has a source, a destination, a port, and a *policy expectation*, no amount of check-writing produces a segmentation tool. This single change forces the zone model, the policy baseline, the multi-vantage design, and the matrix report to fall out naturally.

The corollary: **the probe engine must be unauthenticated.** Assumed breach means an attacker with a foothold and no credentials. Everything requiring a domain user or Remote Registry moves to an *optional enrichment tier* that adds context when available and is never a prerequisite.

## 2.2 Target architecture

```
                      ┌──────────────────────────────────────────┐
   zones.json ───────►│  ZoneResolver                            │
   policy.json ──────►│  IP/CIDR → Zone, Role, Trust Tier        │
                      │  Longest-prefix match, IPv4 + IPv6       │
                      └────────────────┬─────────────────────────┘
                                       │
   ┌───────────────────────────────────▼─────────────────────────┐
   │  DiscoveryEngine        (what exists — unauthenticated)     │
   │   • CIDR expansion, ARP/ND cache, DNS + reverse DNS         │
   │   • host liveness: TCP-ACK ping, ICMP, common-port sweep    │
   └───────────────────────────────────┬─────────────────────────┘
                                       │  Endpoint[]
   ┌───────────────────────────────────▼─────────────────────────┐
   │  ProbeEngine            (what is reachable — the core)      │
   │   • bounded worker pool, token-bucket rate limit            │
   │   • TRI-STATE per port: Open / Closed / Filtered            │
   │   • retry-on-timeout to separate loss from filtering        │
   │   • optional service confirmation (banner / TLS / SMB nego) │
   │   • SafeMode: never probes OT ranges without explicit opt-in│
   └───────────────────────────────────┬─────────────────────────┘
                                       │  ReachabilityObservation[]
   ┌───────────────────────────────────▼─────────────────────────┐
   │  PolicyEvaluator        (what SHOULD be reachable)          │
   │   observed ⊖ expected  →  violations, and ALSO              │
   │   expected-but-blocked → drift, and unexercised allow-rules │
   └───────────────────────────────────┬─────────────────────────┘
                                       │  SegmentationFinding[]
   ┌───────────────────────────────────▼─────────────────────────┐
   │  RiskScorer   zone-pair class × service class × exposure    │
   └───────────────────────────────────┬─────────────────────────┘
                                       │
   ┌───────────────────────────────────▼─────────────────────────┐
   │  Reporters   Zone Matrix · Endpoint Exposure · ZTMM Scorecard│
   │              HTML · JSON · CSV · SIEM (BOM-free)            │
   └─────────────────────────────────────────────────────────────┘
                                       ▲
   ┌───────────────────────────────────┴─────────────────────────┐
   │  EnrichmentTier   (OPTIONAL, never required)                │
   │   AD role/tier, host firewall state, SMB signing, LAPS      │
   │   — degrades to Unknown, never to a finding                 │
   └─────────────────────────────────────────────────────────────┘
```

`AdAuditor`, `LateralPathAnalyzer`, `ShareAuditor`, and `ProtocolProbe` do not disappear — they become the enrichment tier, demoted from "five co-equal modules" to "context that makes a reachability finding more or less severe." A reachable 445 is High; a reachable 445 on a host that *also* has SMB signing disabled and shares a local admin account is Critical. That is the correlation the current engine was trying and failing to express — and it works now because both facts are keyed to the same endpoint.

## 2.3 Zone model — replaces the third-octet heuristic

```jsonc
// zones.json
{
  "zones": [
    { "id": "user-vlan",    "name": "Corporate Users",   "cidrs": ["10.10.0.0/16"],
      "trustTier": 3, "role": "user" },
    { "id": "server-tier1", "name": "Application Servers","cidrs": ["10.20.0.0/16"],
      "trustTier": 1, "role": "server" },
    { "id": "tier0",        "name": "Domain Controllers / PAW",
      "cidrs": ["10.30.1.0/24"], "trustTier": 0, "role": "tier0" },
    { "id": "mgmt",         "name": "Out-of-Band Management",
      "cidrs": ["10.99.0.0/24"], "trustTier": 0, "role": "management" },
    { "id": "ot",           "name": "Plant Floor / ICS",  "cidrs": ["172.16.0.0/16"],
      "trustTier": 1, "role": "ot", "safeMode": true, "activeProbing": false },
    { "id": "dmz",          "name": "DMZ",               "cidrs": ["192.168.200.0/24"],
      "trustTier": 2, "role": "dmz" },
    { "id": "guest",        "name": "Guest / BYOD",      "cidrs": ["10.200.0.0/16"],
      "trustTier": 4, "role": "untrusted" }
  ],
  "unclassifiedZone": { "id": "unknown", "trustTier": 4,
                        "note": "Any address not matching a declared CIDR. A large unknown zone IS a finding — it means the network diagram is incomplete." }
}
```

Longest-prefix match, IPv4 and IPv6, backed by a radix trie. `trustTier` follows the Microsoft tier model (0 = identity/control plane) so it composes with the AD enrichment.

Note the `unclassifiedZone` behaviour: if 40% of discovered endpoints land in `unknown`, that itself is reported as a **Critical data-flow-mapping gap** — NSA's Network & Environment pillar names data flow mapping as the prerequisite capability for segmentation, and you cannot segment what you haven't inventoried.

## 2.4 Policy matrix — turns noise into violations

```jsonc
// policy.json — default-deny between zones, explicit allows
{
  "defaultAction": "deny",
  "rules": [
    { "from": "mgmt", "to": ["server-tier1","tier0"],
      "services": ["WINRM_HTTPS","RDP","SSH"], "action": "allow",
      "justification": "Jump-host administration path",
      "owner": "infra@corp", "reviewedOn": "2026-03-01", "expiresOn": "2026-09-01" },

    { "from": "server-tier1", "to": "tier0",
      "services": ["KERBEROS","LDAPS","DNS"], "action": "allow",
      "justification": "Domain membership" },

    { "from": "user-vlan", "to": "server-tier1",
      "services": ["HTTPS"], "action": "allow" }
  ]
}
```

Every observation is then classified:

| Observed | Policy says | Classification |
|---|---|---|
| Open | allow | **Compliant** — informational, proves the path works |
| Open | deny / no rule | **VIOLATION** — the headline finding |
| Filtered | deny | **Enforced** — evidence the control works (report this; it's how you prove segmentation *exists*) |
| Filtered | allow | **Drift** — an approved flow is broken; will cause an outage ticket |
| Closed (RST) | deny | **Unenforced** — nothing is listening today, but nothing is *blocking* either. One service install away from a violation. Report as Medium. |
| Unknown | any | **Unknown** — never a violation, never a pass |

That "Closed but unenforced" row is a class of finding the current tool cannot express at all, and it's one of the most valuable: it's the difference between "we're safe" and "we're lucky."

Rules carry `owner`, `reviewedOn`, and `expiresOn` so the policy file doubles as the auditable record of *approved* exceptions — which is what an assessor will ask for.

## 2.5 High-risk service catalog

Risk is a function of **service class × zone-pair**, not of the port number alone. The catalog defines the service; the matrix defines the severity.

```jsonc
// services.json (excerpt)
{
  "serviceClasses": [
    { "id": "SMB",         "ports": [445, 139], "proto": "tcp", "risk": "critical",
      "class": "remote-admin", "mitre": "T1021.002",
      "confirm": "smb-negotiate" },
    { "id": "RPC_EPM",     "ports": [135], "dynamicRange": "49152-65535", "risk": "critical",
      "class": "remote-admin", "mitre": "T1021.003" },
    { "id": "RDP",         "ports": [3389], "risk": "critical", "class": "remote-admin",
      "mitre": "T1021.001", "confirm": "tls-cert" },
    { "id": "WINRM_HTTP",  "ports": [5985], "risk": "critical", "class": "remote-admin",
      "mitre": "T1021.006" },
    { "id": "WINRM_HTTPS", "ports": [5986], "risk": "high",     "class": "remote-admin" },
    { "id": "SSH",         "ports": [22],   "risk": "high",     "class": "remote-admin",
      "confirm": "banner" },
    { "id": "VNC",         "ports": [5900,5901], "risk": "critical", "class": "remote-admin" },
    { "id": "WINRM_PSEXEC_SVC", "ports": [4899], "risk": "critical", "class": "remote-admin" },

    { "id": "MSSQL",       "ports": [1433,1434], "risk": "high", "class": "database" },
    { "id": "ORACLE",      "ports": [1521],      "risk": "high", "class": "database" },
    { "id": "MYSQL",       "ports": [3306],      "risk": "high", "class": "database" },
    { "id": "POSTGRES",    "ports": [5432],      "risk": "high", "class": "database" },
    { "id": "MONGO",       "ports": [27017],     "risk": "high", "class": "database" },
    { "id": "REDIS",       "ports": [6379],      "risk": "critical", "class": "database",
      "note": "Frequently unauthenticated by default" },
    { "id": "ELASTIC",     "ports": [9200],      "risk": "high", "class": "database" },
    { "id": "MEMCACHED",   "ports": [11211],     "risk": "critical", "class": "database" },

    { "id": "IPMI",        "ports": [623], "proto": "udp", "risk": "critical",
      "class": "oob-management", "note": "Cipher-zero auth bypass; BMC = permanent host takeover" },
    { "id": "ILO_IDRAC",   "ports": [17988,17990,443], "risk": "critical", "class": "oob-management" },
    { "id": "ESXI",        "ports": [902,903],   "risk": "critical", "class": "hypervisor" },
    { "id": "VCENTER",     "ports": [9443],      "risk": "critical", "class": "hypervisor" },
    { "id": "SNMP",        "ports": [161], "proto": "udp", "risk": "high",
      "class": "oob-management", "note": "Default community strings expose full config" },

    { "id": "TELNET",      "ports": [23],  "risk": "critical", "class": "cleartext-legacy" },
    { "id": "FTP",         "ports": [21],  "risk": "high",     "class": "cleartext-legacy" },
    { "id": "TFTP",        "ports": [69], "proto": "udp", "risk": "high", "class": "cleartext-legacy" },
    { "id": "RSERVICES",   "ports": [512,513,514], "risk": "critical", "class": "cleartext-legacy" },
    { "id": "NFS",         "ports": [2049], "risk": "high",    "class": "file-share" },
    { "id": "LDAP_CLEAR",  "ports": [389],  "risk": "high",    "class": "directory" },

    { "id": "MODBUS",      "ports": [502],   "risk": "critical", "class": "ot-ics",
      "probePolicy": "passive-only" },
    { "id": "S7COMM",      "ports": [102],   "risk": "critical", "class": "ot-ics",
      "probePolicy": "passive-only" },
    { "id": "DNP3",        "ports": [20000], "risk": "critical", "class": "ot-ics",
      "probePolicy": "passive-only" },
    { "id": "ETHERNET_IP", "ports": [44818], "risk": "critical", "class": "ot-ics",
      "probePolicy": "passive-only" },
    { "id": "BACNET",      "ports": [47808], "proto": "udp", "risk": "high", "class": "ot-ics",
      "probePolicy": "passive-only" }
  ]
}
```

`probePolicy: "passive-only"` is a hard safety interlock: these are never actively connected to unless the operator passes `--allow-ot-probing` *and* the target zone sets `activeProbing: true`. Default behaviour is to report them from discovery data only.

**Severity is then computed from the zone pair:**

| Source zone trust → Target zone trust | remote-admin | database | oob-mgmt | cleartext | ot-ics |
|---|---|---|---|---|---|
| untrusted/guest (4) → any internal | Critical | Critical | Critical | Critical | Critical |
| user (3) → tier0 (0) | **Critical** | Critical | Critical | Critical | Critical |
| user (3) → server (1) | **Critical** | High | Critical | High | Critical |
| server (1) → server (1), different app | High | Medium | Critical | High | Critical |
| dmz (2) → internal (≤1) | **Critical** | Critical | Critical | Critical | Critical |
| mgmt (0) → server (1) | Low (expected) | Low | Low | Medium | Medium |
| any → ot (unless IT/OT boundary declared) | Critical | Critical | Critical | Critical | High |

The IT→OT row directly implements the AA23-278A callout that *"lack of segmentation between IT and OT environments places OT environments at risk."*

## 2.6 The finding model

```csharp
public enum ReachabilityVerdict { Open, Closed, Filtered, Unknown }
public enum PolicyStatus { Violation, Compliant, Enforced, Unenforced, Drift, NoPolicyDefined }

public sealed record SegmentationFinding
{
    public string   Id            { get; init; }
    // --- the path (this is what was missing) ---
    public string   VantageHost   { get; init; }   // where we probed FROM
    public string   VantageZoneId { get; init; }
    public string   TargetIp      { get; init; }
    public string?  TargetHostname{ get; init; }
    public string   TargetZoneId  { get; init; }
    public string?  TargetRole    { get; init; }   // from AD enrichment, else null
    public int      Port          { get; init; }
    public string   Transport     { get; init; }   // tcp | udp
    public string   ServiceClass  { get; init; }   // SMB, RDP, IPMI...

    // --- what we saw, and how sure we are ---
    public ReachabilityVerdict Verdict { get; init; }
    public ProbeEvidence Evidence      { get; init; }
    public double   Confidence         { get; init; }   // 0..1

    // --- what it means ---
    public PolicyStatus Policy   { get; init; }
    public string?  MatchedRuleId{ get; init; }
    public Severity Severity     { get; init; }
    public double   RiskScore    { get; init; }

    // --- how to fix it ---
    public IReadOnlyList<GuidanceRef> Guidance { get; init; }  // NSA / CISA / MITRE
    public string   Remediation  { get; init; }

    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen  { get; init; }
}

public sealed record ProbeEvidence(
    string  Method,          // "tcp-connect" | "tcp-syn" | "udp-probe" | "passive"
    string  TcpResponse,     // "syn-ack" | "rst" | "timeout" | "icmp-admin-prohibited"
    int     RttMs,
    int     Attempts,
    string? Banner,
    string? TlsSubject,
    string? ServiceConfirmation);
```

`Severity` is fixed here as an **explicitly-valued, correctly-ordered** enum so A2 cannot recur:

```csharp
public enum Severity { Informational = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }
```

And dedup is keyed on the actual identity of the thing — `(VantageZoneId, TargetIp, Transport, Port)` — not `Host|CheckName`, which is what caused A1.

## 2.7 Multi-vantage collection

One run = one vantage point = one honest statement about one source zone. To fill the N×N matrix you need a probe in each source zone. Three supported modes, in increasing fidelity:

1. **Single vantage** (default). The tool labels its own zone, probes outward, and the report explicitly states *"rows other than `user-vlan` were not measured"* — no silent extrapolation.
2. **Merge mode.** Run the exe from a host in each zone; `ZeroTrustAuditor merge run1.json run2.json … -o combined.json` unions the observations by `(vantageZone, target, port)`. No agents, no infrastructure, works in any change-controlled environment. **This is the recommended default.**
3. **Relay mode** (later phase). A signed, ephemeral, listener-only helper deployed to one host per zone, driven over mTLS from the orchestrator, self-terminating after the run. Only worth building once modes 1–2 are solid.

The report must never present an unmeasured zone pair as "no findings" — it renders as a distinct **"not assessed"** cell. Conflating *unmeasured* with *secure* is the same class of error as A4, and it is the one that gets people breached.

## 2.8 The report

**Sheet 1 — Zone Reachability Matrix** (the executive artifact). N×N grid, source zone on rows, destination on columns, each cell coloured by the worst violation found and annotated with the count of high-risk service classes crossing that boundary. Grey = not assessed. One glance answers "is our network actually segmented?"

**Sheet 2 — Endpoint Exposure Register.** This is the deliverable you asked for by name — *which servers and endpoints allow high-risk ports*:

| Target | Hostname | Zone | Role | Open high-risk services | Worst severity | Reachable from |
|---|---|---|---|---|---|---|
| 10.20.4.11 | SQL01 | server-tier1 | database | SMB(445), RDP(3389), MSSQL(1433) | Critical | user-vlan, guest |
| 10.30.1.5 | DC01 | tier0 | domain-controller | SMB(445), RPC(135), LDAP(389) | Critical | user-vlan |
| 10.20.9.40 | ESX03 | server-tier1 | hypervisor | ESXi(902), IPMI(623) | Critical | user-vlan |

Sortable by blast radius (how many source zones reach it) and by service risk class.

**Sheet 3 — Policy Violations**, ranked, each with the matched-or-missing rule and the exact firewall change to make.

**Sheet 4 — CISA ZTMM Scorecard.** Score the Networks pillar per zone against Traditional / Initial / Advanced / Optimal, with the observed evidence for the score. This converts a scan result into the language leadership and auditors already use.

**Sheet 5 — Enforcement Evidence.** The boundaries that *are* working. Assessments that only ever report failures get ignored; showing "these 14 boundaries correctly filtered all 9 admin protocols" is how you get budget to fix the other six.

## 2.9 NSA / CISA guidance mapping

Each finding carries `GuidanceRef[]`, resolved from a bundled, versioned `guidance.json` so citations update without a recompile. The mapping:

| Finding class | Authoritative guidance |
|---|---|
| Any cross-zone high-risk service reachable | **CISA/NSA AA23-278A**, Misconfiguration **#4 — Lack of network segmentation**: *"no security boundaries between user, production, and critical system networks… allows an actor who has compromised a resource to move laterally uncontested."* |
| IT → OT reachable | **AA23-278A #4** (IT/OT callout) + CISA OT segmentation guidance; enforce a DMZ/conduit between IT and OT per the zones-and-conduits model |
| Admin protocol (SMB/RDP/WinRM/RPC) crossing a tier boundary | **NSA CSI, *Advancing Zero Trust Maturity Throughout the Network and Environment Pillar*** (March 2024) — macro-segmentation capability; **AA23-278A #2 — Improper separation of user/administrator privilege** |
| Flat zone, no internal boundaries | NSA CSI N&E Pillar — **macro-segmentation**, target maturity; **CISA ZTMM v2.0**, Networks pillar → *Network Segmentation* function |
| Same-zone lateral reachability (server↔server, workstation↔workstation) | NSA CSI N&E Pillar — **micro-segmentation**; ZTMM *Advanced/Optimal* requires ingress/egress micro-perimeters. Workstation-to-workstation SMB/RDP has no legitimate business use in most estates and is the #1 ransomware propagation path |
| Large `unknown` zone / unmapped hosts | NSA CSI N&E Pillar — **data flow mapping** is the prerequisite capability; you cannot segment an undocumented network |
| Filtered but unlogged; no visibility on drops | **AA23-278A #3 — Insufficient internal network monitoring**; ZTMM Networks → *Network Traffic Management* / visibility & analytics |
| OOB management (IPMI/iLO/iDRAC/SNMP) reachable from user zones | **NSA CSI, *Performing Out-of-Band Network Management*** — management plane must ride a physically or cryptographically separate path |
| Cleartext protocols crossing zones | ZTMM Networks → *Network Encryption* function; NSA CSI N&E Pillar |
| Overall program posture | **CISA Cross-Sector Cybersecurity Performance Goals (CPG 2.0)** — segment networks according to trust boundaries and platform type (IT, IoT, OT, mobile, guest), permitting only required communications between segments |
| Strategic framing | **NSA Top Ten Cybersecurity Mitigation Strategies** — *Segment Networks and Deploy Application-Aware Defenses*; **NIST SP 800-207** for architectural vocabulary |

The remediation text for each finding should be specific in the way your existing GPO guidance already is — not "implement segmentation" but *"deny 10.10.0.0/16 → 10.30.1.0/24 on tcp/445,135,3389,5985 at the core firewall; route administrative access via the mgmt zone jump host."*

## 2.10 Safety and authorization

An unauthenticated internal port sweep is an intrusive act even when authorized. Build these in from commit one:

- `--authorization <ref>` required, non-empty, recorded in every report header and SIEM event (engagement ID / change ticket).
- Rate limiting: token bucket, default **≤100 probes/sec**, `--rate` to lower.
- Bounded concurrency: a real semaphore, default `min(256, cores × 32)` — and *enforced*, unlike `maxParallelProbes` today.
- Global `--dry-run` printing the exact target × port plan before any packet.
- OT interlock: `probePolicy: passive-only` honoured by default; active OT probing requires both the CLI flag and the zone opt-in.
- Structured audit log of every probe sent, for the blue team's inevitable "what was that scan?" ticket.
- Hard scope guard: refuse any target outside declared zone CIDRs unless `--allow-unscoped`.

## 2.11 Migration plan

**Phase 0 — Stop the bleeding (1–2 days).** Fix A1–A7 in place, or the new tool inherits them. Add `.gitignore`, `git rm -r --cached obj/`, add the LICENSE the README promises. Add the first three unit tests: dedup preserves distinct entities, severity comparator picks Critical, correlation rule fires on a synthetic same-host pair. These tests would have caught every Tier A bug.

**Phase 1 — Zone + policy foundation (1 week).** `ZoneResolver` (radix trie, v4+v6), `zones.json` / `policy.json` schemas and validation, `Severity` re-valued, new `SegmentationFinding` model alongside the old one. Delete `GetLocalOctet`.

**Phase 2 — Probe engine (1–2 weeks).** Tri-state verdict with RST/timeout/ICMP discrimination, bounded concurrency, rate limiting, retry logic, CIDR target expansion, service confirmation for the top ~10 classes, SafeMode interlock. This is the heart of the tool — most of the engineering value is here.

**Phase 3 — Policy evaluation + reports (1 week).** `PolicyEvaluator`, zone matrix, endpoint exposure register, ZTMM scorecard, guidance mapping. Fix the BOM. Add run-over-run diffing.

**Phase 4 — Demote the legacy modules (1 week).** Re-wire `AdAuditor` / `ProtocolProbe` / `ShareAuditor` / `LateralPathAnalyzer` as the enrichment tier: they now key findings to endpoints, return tri-state (never "absent ⇒ fail"), and *modify* the severity of reachability findings rather than standing alone. Rewrite the correlation engine to operate on the endpoint key, where it will actually fire.

**Phase 5 — Multi-vantage merge (3–4 days).** The `merge` subcommand and the "not assessed" rendering.

## 2.12 What to delete outright

- `SegmentationChecker.GetLocalOctet()` and the entire third-octet comparison.
- The `correlation.rules` block in `audit-config.json` as written — the check names don't match emitted names, and host-keyed correlation can't work until Phase 4.
- `PathGraphBuilder.LooksLikeDc` / `GuessTier` hostname-substring guessing; replace with AD lookup or explicit zone `role`.
- `obj/` from version control.
- The README's "assumed breach" framing for the *current* tool — it isn't, and the claim is the thing that most obscures the gap this rearchitecture closes.

---

## Sources

- [NSA CSI — Advancing Zero Trust Maturity Throughout the Network and Environment Pillar (March 2024)](https://media.defense.gov/2024/Mar/05/2003405462/-1/-1/0/CSI-ZERO-TRUST-NETWORK-ENVIRONMENT-PILLAR.PDF)
- [CISA/NSA — Red and Blue Teams Share Top Ten Cybersecurity Misconfigurations (AA23-278A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a)
- [CISA — Zero Trust Maturity Model v2.0](https://www.cisa.gov/zero-trust-maturity-model)
- [CISA — Cross-Sector Cybersecurity Performance Goals](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals)
- [CISA — Cybersecurity Performance Goals 2.0](https://www.cisa.gov/cybersecurity-performance-goals-2-0-cpg-2-0)
