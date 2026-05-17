# Monitoring, Logging and Runtime Security — Module Introduction

> **Module:** Monitoring, Logging and Runtime Security
> **CKS Domain Weight:** ~20% of the exam
> **Chapters:** 6
> **Core Question:** Once a workload is running in Kubernetes, how do you detect threats, prevent runtime modifications, and guarantee that what's running matches what you built?

---

## Table of Contents

1. [The Runtime Security Problem](#1-the-runtime-security-problem)
2. [Why Pre-Deploy Controls Are Not Enough](#2-why-pre-deploy-controls-are-not-enough)
3. [Module Architecture — How the Six Chapters Connect](#3-module-architecture--how-the-six-chapters-connect)
4. [Chapter-by-Chapter Breakdown](#4-chapter-by-chapter-breakdown)
5. [The Threat Landscape This Module Addresses](#5-the-threat-landscape-this-module-addresses)
6. [MITRE ATT&CK Container Techniques Covered](#6-mitre-attck-container-techniques-covered)
7. [Core Tools and Technologies](#7-core-tools-and-technologies)
8. [The Detection and Prevention Stack](#8-the-detection-and-prevention-stack)
9. [Real Attack Chains — End-to-End Examples](#9-real-attack-chains--end-to-end-examples)
10. [CKS Exam Coverage and Weight](#10-cks-exam-coverage-and-weight)
11. [Key Concepts Quick Reference Cheatsheet](#11-key-concepts-quick-reference-cheatsheet)
12. [Module Learning Path](#12-module-learning-path)
13. [Links and References](#13-links-and-references)

---

## 1. The Runtime Security Problem

Every other CKS module protects Kubernetes **before workloads run**: hardening the OS, securing the API server, scanning images, enforcing admission policies. This module is different. It asks: **what happens after the pod is admitted and running?**

Once a container is live, it begins processing real traffic, connecting to real services, and making real syscalls to the Linux kernel. At this moment, the pre-deploy security gates go quiet. No admission controller watches what a process does inside a running container. No image scanner catches a zero-day exploit being triggered against a patched application. No network policy prevents a process from reading `/etc/shadow` using a file descriptor it already has open.

Runtime security is the discipline of watching, detecting, and preventing malicious activity in this post-admission window — the window attackers live in.

```
KUBERNETES SECURITY TIMELINE

Build Time                Admission Time               Runtime
─────────────────────────────────────────────────────────────────────
│ Image scan (Trivy)    │ OPA Gatekeeper             │ ← You are here
│ SBOM generation       │ Kyverno policies           │
│ Cosign signing        │ Pod Security Standards      │ Falco watches syscalls
│ SAST/DAST             │ Image policy webhook        │ readOnlyRootFilesystem
│ Dockerfile lint       │ RBAC enforcement            │ Immutable containers
│ Dependency scan       │ Network policies applied    │ Runtime anomaly detection
─────────────────────────────────────────────────────────────────────
  Supply Chain              Cluster Setup /              THIS MODULE
  Security module           Access Control modules
```

This module covers the three pillars of runtime security in Kubernetes:

**Pillar 1 — Detect:** Use syscall monitoring (Falco) to observe what is actually happening inside running containers, alert on anomalies, and produce forensic evidence.

**Pillar 2 — Prevent:** Enforce container immutability (`readOnlyRootFilesystem`, distroless images) so that even a compromised container cannot be weaponised further.

**Pillar 3 — Understand:** Know the threat model (attacker kill chains, syscall patterns, MITRE ATT&CK techniques) well enough to write effective detection rules and policies.

---

## 2. Why Pre-Deploy Controls Are Not Enough

Understanding the limitations of earlier security gates clarifies why this module exists.

### 2.1 The Image Scanner Gap

Trivy and Grype are excellent at finding **known CVEs** in installed packages. They cannot detect:
- Zero-day vulnerabilities (no CVE assigned yet)
- Logic flaws in application code (not a CVE, just a bug that enables RCE)
- Malicious code injected at build time via a compromised dependency (supply chain — detected post-exploit through behaviour, not CVE signature)
- Runtime exploitation of a vulnerability in a patched image (attacker finds a bypass)

**Runtime security fills this gap:** Even when the image is clean, Falco sees the exploitation attempt as anomalous behaviour (unexpected shell spawn, unexpected network connection, unexpected file read).

### 2.2 The Admission Controller Gap

OPA Gatekeeper and Kyverno enforce policy at the moment a resource is created. They cannot:
- See what a running container does after admission
- Detect if an admitted container is later exploited
- React to runtime changes in container behaviour
- Stop an attack already in progress inside a pod

**Runtime security fills this gap:** `readOnlyRootFilesystem` prevents post-admission filesystem modifications. Falco monitors and alerts on post-admission behavioural anomalies.

### 2.3 The Network Policy Gap

Kubernetes Network Policies control which pods can communicate with which other pods. They cannot:
- See the content of network traffic (only source/destination/port)
- Detect data exfiltration if the destination is an allowed address
- Stop a process from reading local sensitive files
- Monitor syscall behaviour

**Runtime security fills this gap:** Falco monitors both syscalls and network connections at the process level, detecting exfiltration regardless of network policy compliance.

### 2.4 The Dwell Time Problem

The industry average time between initial compromise and detection (dwell time) is historically measured in **weeks to months** for environments without runtime security monitoring. With continuous syscall-level monitoring via Falco, detection can be measured in **seconds to minutes** — the moment a suspicious syscall fires, an alert is generated.

```
Without runtime monitoring:  Compromise → Weeks of undetected activity → Breach discovered
With Falco:                  Compromise → Seconds → Alert → Response
```

---

## 3. Module Architecture — How the Six Chapters Connect

The six chapters of this module build a coherent runtime security system. They are not independent topics — each chapter contributes a piece of a layered defence:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              RUNTIME SECURITY SYSTEM — MODULE ARCHITECTURE              │
│                                                                         │
│  CHAPTER 1: Behavioral Analytics of Syscalls                           │
│  ─────────────────────────────────────────────────────────────────────  │
│  Foundation: Understanding the Linux syscall interface as the           │
│  observable boundary between containers and the kernel. Establishes    │
│  WHY syscall monitoring is the right approach and introduces Falco,    │
│  strace, and eBPF as the toolset.                                      │
│                           │                                             │
│                           ▼                                             │
│  CHAPTER 2: Falco Overview and Installation                            │
│  ─────────────────────────────────────────────────────────────────────  │
│  Deployment: Installing Falco on nodes (kernel module vs eBPF) and    │
│  as a DaemonSet via Helm. Architecture deep-dive: libscap, libsinsp,  │
│  policy engine, output channels.                                       │
│                           │                                             │
│                           ▼                                             │
│  CHAPTER 3: Use Falco to Detect Threats                                │
│  ─────────────────────────────────────────────────────────────────────  │
│  Operation: Generating events, monitoring logs in real time, reading   │
│  alerts. Falco rule anatomy: rule, desc, condition, output, priority.  │
│  Lists, macros, and the condition language field reference.            │
│                           │                                             │
│                           ▼                                             │
│  CHAPTER 4: Falco Configuration Files                                  │
│  ─────────────────────────────────────────────────────────────────────  │
│  Configuration: falco.yaml, rules_file loading order and precedence,  │
│  output channels (JSON, file, HTTP, program), rule overrides,         │
│  hot-reload with SIGHUP, and production config hardening.             │
│                           │                                             │
│                           ▼                                             │
│  CHAPTER 5: Mutable vs Immutable Infrastructure                        │
│  ─────────────────────────────────────────────────────────────────────  │
│  Paradigm: In-place updates vs image-based replace. Configuration     │
│  drift. Containers as immutable by design. The Dockerfile as source   │
│  of truth. GitOps and rolling updates as the immutable change         │
│  mechanism.                                                             │
│                           │                                             │
│                           ▼                                             │
│  CHAPTER 6: Ensure Immutability of Containers at Runtime              │
│  ─────────────────────────────────────────────────────────────────────  │
│  Enforcement: readOnlyRootFilesystem, emptyDir volumes for app write  │
│  paths, privileged mode interaction, PSP → Pod Security Standards,    │
│  Kyverno/OPA fleet-wide enforcement. The full hardened pod spec.      │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │  RESULT: Workloads monitored at syscall level (detect) +          │ │
│  │          filesystem modifications blocked (prevent) +              │ │
│  │          attacker persistence eliminated (immutability)            │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

**Detection path (Ch 1–4):** Understand syscalls → Deploy Falco → Write detection rules → Configure output and alerting.

**Prevention path (Ch 5–6):** Understand the immutability principle → Enforce it at the container level with `readOnlyRootFilesystem` and emptyDir volumes → Automate enforcement with policy engines.

---

## 4. Chapter-by-Chapter Breakdown

### Chapter 1 — Perform Behavioral Analytics of Syscall Process

**The foundational question:** How does Kubernetes security tooling observe what's happening inside running containers?

**Core concepts:**
- The Linux syscall interface as the observation point — every container action (read, write, fork, connect) requires a syscall
- The attacker kill chain at the syscall level: Initial Access → Reconnaissance (`stat`, `read`) → Privilege Escalation (`setuid`, `setgid`) → Lateral Movement (`connect`, `sendmsg`) → Persistence (`write`, `cron`) → Cover Tracks (`unlink`, `truncate`)
- strace for single-process syscall tracing
- Tracee (Aqua Security) for eBPF-based syscall monitoring
- Falco as the production-grade runtime security engine
- The credit card analogy: instant notification (Falco alert) → revert transaction (kill pod) → transaction limits (RBAC)

**Key insight:** No matter how sophisticated the attack, it must eventually make syscalls. Monitoring syscalls gives you visibility into 100% of container activity, regardless of what language, framework, or exploit technique is used.

### Chapter 2 — Falco Overview and Installation

**The operational question:** How do you deploy Falco so it reliably monitors all nodes?

**Core concepts:**
- Falco's two kernel instrumentation methods: Kernel Module (intrusive, traditional) and eBPF (sandboxed, preferred on managed Kubernetes)
- The Modern eBPF probe (Falco 0.35+) using CO-RE/BTF for portable instrumentation
- Falco's processing pipeline: `libscap` (capture) → `libsinsp` (enrichment with K8s metadata) → Policy Engine (rule evaluation) → Output Channels
- Node-installed Falco (`apt install falco`, `systemctl start falco`) for maximum isolation
- DaemonSet deployment via Helm for managed Kubernetes clusters
- Falcosidekick for routing alerts to 70+ destinations

**Key commands:**
```bash
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get install -y linux-headers-$(uname -r) && apt install -y falco
systemctl start falco
```

### Chapter 3 — Use Falco to Detect Threats

**The detection question:** How do you write rules that catch real attacks without drowning in false positives?

**Core concepts:**
- The end-to-end detection workflow: verify → generate events → monitor logs → trigger alerts → analyse → write custom rules
- Falco rule anatomy — the five mandatory keys: `rule`, `desc`, `condition`, `output`, `priority`
- Lists: named item collections (`linux_shells: [bash, zsh, ksh, sh, csh]`)
- Macros: reusable condition fragments (`container: container.id != host`)
- The Falco condition language: field namespaces (`proc.*`, `fd.*`, `container.*`, `k8s.*`, `user.*`), operators (`in`, `contains`, `startswith`, `pmatch`)
- Output field formatting with `%field.name` syntax
- `journalctl -fu falco` — the primary log monitoring command

**KodeKloud example rule:**
```yaml
- rule: Detect Shell inside a container
  desc: Alert if a shell such as bash is open inside a container
  condition: container and proc.name in (linux_shells)
  output: Bash Opened (user=%user.name container=%container.id)
  priority: WARNING
- list: linux_shells
  items: [bash, zsh, ksh, sh, csh]
- macro: container
  condition: container.id != host
```

### Chapter 4 — Falco Configuration Files

**The configuration question:** How do you manage Falco's configuration, customise rules, and apply changes without monitoring gaps?

**Core concepts:**
- The configuration file hierarchy: `falco.yaml` → `falco_rules.yaml` → `falco_rules.local.yaml` → `rules.d/`
- Rule loading order and the "last definition wins" precedence rule
- Why `falco_rules.yaml` must never be edited directly (overwritten on apt upgrade)
- `falco_rules.local.yaml` as the safe workspace for all customisations
- Output channels: `stdout_output`, `file_output`, `program_output`, `http_output`, `grpc_output`
- `json_output: true` for SIEM integration
- Overriding built-in rules: repeating the full rule with a changed priority
- Hot-reload with SIGHUP: `kill -1 $(cat /var/run/falco.pid)` — no monitoring gap

**Critical config excerpt:**
```yaml
rules_file:
  - /etc/falco/falco_rules.yaml           # Never edit
  - /etc/falco/falco_rules.local.yaml     # Always use this
  - /etc/falco/rules.d/
json_output: true
priority: warning
```

### Chapter 5 — Mutable vs Immutable Infrastructure

**The paradigm question:** What is the difference between mutable and immutable infrastructure, and why does it matter for security?

**Core concepts:**
- **Mutable infrastructure:** In-place software updates on running servers. Configuration drift occurs when updates fail on some servers but not others.
- **Configuration drift:** Servers that were supposed to be identical end up running different software versions — complicating debugging, creating security gaps, and producing "snowflake servers."
- **Immutable infrastructure:** Replace servers/containers rather than modifying them. New version = new image = new pods. Old pods are terminated, never updated.
- Containers as the natural immutable unit: built from images, never modified in place
- The correct update path: modify Dockerfile → rebuild image → rolling update
- GitOps as the organisational enforcement of immutability: Git is the source of truth, ArgoCD/Flux enforce it in the cluster

**KodeKloud Dockerfile example:**
```dockerfile
FROM nginx:1.19      # Was 1.18 — change only this line
COPY nginx.conf /etc/nginx
ENTRYPOINT ["sh", "entrypoint.sh"]
```

### Chapter 6 — Ensure Immutability of Containers at Runtime

**The enforcement question:** How do you technically enforce container immutability so that even a compromised container cannot be modified at runtime?

**Core concepts:**
- `readOnlyRootFilesystem: true` — the primary immutability enforcement control, implemented at the kernel VFS layer
- Why it must be at the container-level securityContext (not pod-level)
- The Nginx problem: `readOnlyRootFilesystem: true` causes pod failure because Nginx needs to write to `/var/cache/nginx` and `/var/run`
- Solution: emptyDir volumes for required write paths
- `privileged: true` does NOT override `readOnlyRootFilesystem: true` — they are independent kernel-level controls
- The `/proc` escape: privileged containers can modify host kernel parameters through `/proc/sys`
- Pod Security Policy (deprecated K8s 1.25) → Pod Security Standards (built-in) + Kyverno/OPA (policy enforcement)
- Fleet-wide enforcement: Kyverno `validationFailureAction: Enforce`

**KodeKloud complete working pod spec:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: cache-volume
      mountPath: /var/cache/nginx
    - name: runtime-volume
      mountPath: /var/run
  volumes:
  - name: cache-volume
    emptyDir: {}
  - name: runtime-volume
    emptyDir: {}
```

---

## 5. The Threat Landscape This Module Addresses

### 5.1 Runtime-Specific Attack Categories

This module addresses attacks that occur **after a workload is admitted and running** — the attack classes that earlier security modules cannot stop.

**Category 1: Container Escape**
The attacker exploits a vulnerability in the container runtime, kernel, or misconfigured pod spec to gain access to the host.

*Prevention:* Chapter 6 — `readOnlyRootFilesystem: true`, `privileged: false`, drop all capabilities
*Detection:* Chapter 3 — Falco rules for `nsenter`, `mount /proc/host`, kernel module loading

**Category 2: Credential Theft**
The attacker reads sensitive files (`/etc/shadow`, service account tokens, application secrets from env vars) to gain access to other systems.

*Prevention:* Chapter 6 — `/etc/shadow` is read-only in the container image; `readOnlyRootFilesystem` prevents writing a script to extract it
*Detection:* Chapter 3 — Built-in Falco rule: "Read sensitive file untrusted"

**Category 3: Lateral Movement**
The attacker uses tools installed in the container or downloaded at runtime to probe and attack other services within the cluster.

*Prevention:* Chapter 6 — `readOnlyRootFilesystem: true` prevents installing network tools
*Detection:* Chapter 3 — Falco detects `nmap`, `ncat`, unexpected outbound connections

**Category 4: Persistence**
The attacker installs cron jobs, modifies startup scripts, or creates backdoor users to maintain access across container restarts.

*Prevention:* Chapter 6 — `readOnlyRootFilesystem: true` prevents writing to `/etc/cron.d`, `/etc/passwd`, startup script locations
*Detection:* Chapter 1 — Falco detects writes to persistence locations

**Category 5: Data Exfiltration**
The attacker copies application data, database dumps, or credential files to an external server.

*Prevention:* Chapter 6 — Read-only FS prevents staging files; distroless images lack curl/wget
*Detection:* Chapter 3 — Falco detects unexpected outbound network connections and large data transfers

**Category 6: Cryptomining**
The attacker deploys a cryptocurrency miner, consuming cluster compute resources.

*Prevention:* Chapter 6 — `readOnlyRootFilesystem: true` prevents writing the miner binary to disk
*Detection:* Chapter 3 — Falco rule detects known miner binary names (`xmrig`, `minerd`)

**Category 7: Supply Chain Activation**
A backdoor in a dependency activates at runtime (e.g., malicious package that opens a reverse shell on deploy).

*Prevention:* Chapter 6 — Distroless images lack shell; `readOnlyRootFilesystem` limits what the backdoor can do
*Detection:* Chapter 3 — Falco detects unexpected child processes, unexpected network connections

### 5.2 Real-World Incidents Relevant to This Module

| Incident | Year | Attack Type | How This Module Helps |
|---|---|---|---|
| **Tesla Kubernetes Cryptojacking** | 2018 | Exposed kubelet → miner deploy | Falco detects miner execution; readOnlyRootFilesystem blocks install |
| **TeamTNT Kubernetes Campaign** | 2020–2023 | Exposed API → DaemonSet deploy → credentials steal | Falco detects credential file reads and container escape attempts |
| **Log4Shell (CVE-2021-44228)** | 2021 | JNDI RCE → shell spawn | Falco detects Java process spawning bash; readOnlyRootFilesystem blocks file staging |
| **SolarWinds SUNBURST** | 2020 | Build-time backdoor → runtime activation | Falco detects anomalous outbound connections; distroless limits what backdoor can do |
| **Codecov supply chain** | 2021 | CI/CD credential theft via modified uploader | Falco detects credential file access from unexpected processes |
| **Aqua Security TeamTNT report** | 2021 | Container escape → host compromise | readOnlyRootFilesystem + no privileged mode limits escape paths |

---

## 6. MITRE ATT&CK Container Techniques Covered

The MITRE ATT&CK framework's Container Matrix maps attacker techniques to Kubernetes environments. This module directly addresses the following:

| MITRE Tactic | Technique | Technique ID | Detection | Prevention |
|---|---|---|---|---|
| **Initial Access** | Exploit Public-Facing Application | T1190 | Falco: unexpected child processes | readOnlyRootFilesystem |
| **Execution** | Container Administration Command | T1609 | Ch 3: Terminal shell rule | Kyverno: deny exec |
| **Execution** | Deploy Container | T1610 | Ch 3: Falco k8s audit plugin | Admission controls |
| **Execution** | Command and Scripting Interpreter | T1059 | Ch 3: Shell detection rule | Distroless (no shell) |
| **Persistence** | Implant Internal Image | T1525 | Trivy scan (Supply Chain module) | Cosign verification |
| **Persistence** | Scheduled Task/Job: Cron | T1053.003 | Ch 3: Write to cron dir | readOnlyRootFilesystem |
| **Privilege Escalation** | Escape to Host | T1611 | Ch 3: nsenter, mount rules | No privileged containers |
| **Privilege Escalation** | Exploitation for Priv Escalation | T1068 | Ch 1: setuid/setgid syscalls | Drop ALL capabilities |
| **Defence Evasion** | Impair Defences: Disable Cloud Logs | T1562.008 | Ch 3: Process kill rules | RBAC + immutable pods |
| **Credential Access** | Credentials from Files | T1552.001 | Ch 3: Sensitive file read rule | readOnlyRootFilesystem |
| **Credential Access** | Steal Application Access Token | T1528 | Ch 3: SA token access rule | RBAC + short-lived tokens |
| **Discovery** | Container and Resource Discovery | T1613 | Ch 3: kubectl in container rule | No kubectl in containers |
| **Lateral Movement** | Container API | T1552.007 | Ch 3: Kubernetes API access | Network policies |
| **Collection** | Data from Local System | T1005 | Ch 3: Sensitive file read | readOnlyRootFilesystem |
| **Exfiltration** | Exfiltration Over Web Service | T1567 | Ch 3: Outbound connection rule | Egress network policies |
| **Impact** | Resource Hijacking | T1496 | Ch 3: Miner binary detection | readOnlyRootFilesystem |

---

## 7. Core Tools and Technologies

### 7.1 Primary Tool — Falco

Falco is the central technology of this module. It is the CNCF-graduated project that provides syscall-level monitoring for Kubernetes workloads.

| Attribute | Value |
|---|---|
| Vendor | Sysdig (donated to CNCF 2018, graduated 2023) |
| License | Apache 2.0 |
| CNCF Status | Graduated (top-level project) |
| Kernel Interface | Kernel module OR eBPF probe OR Modern eBPF (CO-RE) |
| Rule Language | YAML + condition expression language |
| Output | syslog, stdout, file, HTTP, gRPC |
| K8s Integration | DaemonSet via Helm; Kubernetes metadata enrichment |
| Companion Tools | Falcosidekick (alert routing), Falco Talon (automated response), falcoctl (artifact management) |

**Falco's position in the monitoring stack:**
```
Application logs    → Loki / Elasticsearch (what the app says it did)
K8s audit logs      → Elasticsearch / Falco k8s audit plugin (what Kubernetes did)
Falco syscall logs  → Falcosidekick / SIEM (what processes actually did at the kernel level)
```

### 7.2 Syscall Monitoring Toolset Comparison

| Tool | Use Case | Scope | Production-Ready? |
|---|---|---|---|
| `strace` | Debug single process | One process, high overhead | No |
| `auditd` | System-level audit logging | Host processes, no K8s context | Complementary |
| Tracee (Aqua) | eBPF-based monitoring + OPA | Container + host | Yes |
| Falco (CNCF) | Rule-based syscall alerting | Container + K8s metadata | Yes (primary) |
| Tetragon (Isovalent) | eBPF with in-kernel enforcement | Container + network | Yes |
| Sysdig Secure | Commercial Falco + ML anomaly | Container + cloud | Yes (commercial) |

### 7.3 Supporting Technologies

| Technology | Chapter | Role |
|---|---|---|
| eBPF | Ch 2 | Kernel instrumentation for Falco (non-intrusive probe) |
| `journalctl` | Ch 2, 3, 4 | Viewing Falco alerts on node-installed deployments |
| `systemctl` | Ch 2, 4 | Managing Falco as a systemd service |
| Helm | Ch 2 | DaemonSet deployment of Falco |
| `kill -1` (SIGHUP) | Ch 4 | Hot-reload Falco config without stopping the probe |
| `readOnlyRootFilesystem` | Ch 6 | Kubernetes security context — the immutability enforcer |
| `emptyDir` | Ch 6 | Ephemeral writable volumes for app write requirements |
| Kyverno | Ch 6 | Admission-time enforcement of immutability policies |
| Pod Security Standards | Ch 6 | Built-in K8s namespace-level security profiles |
| GitOps (ArgoCD/Flux) | Ch 5 | Organisational enforcement of immutable deployments |

---

## 8. The Detection and Prevention Stack

The module builds a two-layer runtime security stack:

```
┌────────────────────────────────────────────────────────────────────────┐
│                    RUNTIME SECURITY STACK                              │
│                                                                        │
│  LAYER 2: PREVENTION (Chapters 5–6)                                   │
│  ─────────────────────────────────────────────────────────────────────  │
│  Goal: Make it structurally impossible for attackers to persist        │
│                                                                        │
│  • readOnlyRootFilesystem: true                                        │
│    └── Attacker cannot write malware, modify configs, install tools    │
│                                                                        │
│  • privileged: false                                                   │
│    └── Attacker cannot escape container via kernel capabilities        │
│                                                                        │
│  • emptyDir volumes for required write paths                           │
│    └── Apps still work; writable space is bounded and ephemeral       │
│                                                                        │
│  • Kyverno enforcement                                                 │
│    └── Fleet-wide, no-exception enforcement at admission time          │
│                                                                        │
│  • Distroless images                                                   │
│    └── No shell, no package manager — physical immutability constraint │
│                                                                        │
│  LAYER 1: DETECTION (Chapters 1–4)                                    │
│  ─────────────────────────────────────────────────────────────────────  │
│  Goal: See every suspicious action immediately, even if it fails       │
│                                                                        │
│  • Falco (kernel module or eBPF probe)                                 │
│    └── Monitors every syscall from every container                     │
│                                                                        │
│  • Built-in ruleset                                                    │
│    └── 100+ rules covering MITRE ATT&CK container techniques           │
│                                                                        │
│  • Custom rules (falco_rules.local.yaml)                               │
│    └── Application-specific detection for your threat model            │
│                                                                        │
│  • Alert routing (Falcosidekick)                                       │
│    └── Slack, PagerDuty, SIEM — right alert to the right person        │
│                                                                        │
│  • Hot-reload (SIGHUP)                                                 │
│    └── Rule updates without monitoring gaps                            │
│                                                                        │
│  RESULT: Attacks either fail (prevention) or trigger an immediate      │
│          alert (detection) — usually both simultaneously.              │
└────────────────────────────────────────────────────────────────────────┘
```

### 8.1 Why Both Layers Are Essential

| Scenario | Detection Only (no prevention) | Prevention Only (no detection) | Both |
|---|---|---|---|
| Cryptominer exploits RCE | Alert fires — but miner ran for 30s | Write fails — but no alert | Write fails immediately + alert fires |
| Attacker reads /etc/shadow | Alert fires — too late, creds read | No prevention (reads always work) | Alert fires — attacker caught in the act |
| Zero-day in web framework | Alert fires on shell spawn | readOnlyRootFilesystem blocks file staging | Both layers respond simultaneously |
| Insider threat (kubectl exec) | Alert fires on shell in container | exec not blocked by readOnlyRootFilesystem | Alert fires + exec can be blocked via policy |

The combination achieves what neither layer achieves alone: **immediate detection AND structural limitation of blast radius**.

---

## 9. Real Attack Chains — End-to-End Examples

### Attack Chain 1: Web RCE → Cryptominer (Most Common K8s Attack)

```
Step 1: Attacker exploits web app vulnerability (RCE)
        Syscall: execve("/bin/sh", ["/bin/sh", "-c", "wget ..."])
        Falco: "Terminal shell spawned in container" → WARNING

Step 2: Attacker tries to download miner binary
        Syscall: connect(attacker-server:80) → success
        Falco: "Unexpected outbound connection" → WARNING
        readOnlyRootFilesystem: write("/tmp/xmrig") → EROFS ← ATTACK FAILS

Step 3: Attacker tries in-memory execution
        No writable path available → cannot stage binary anywhere
        Even /tmp is read-only (no emptyDir mounted)

Result: Attack fails at step 2. Two Falco alerts provide forensic trail.
        Security team sees: shell spawn + outbound connection → active incident.
        Pod killed, forensic snapshot taken, incident response begins.
```

### Attack Chain 2: Log4Shell-Style Java RCE → Container Escape Attempt

```
Step 1: JNDI injection through HTTP header triggers RCE
        Syscall: execve in JVM process creating subprocess
        Falco: "Java process spawned shell" → CRITICAL

Step 2: Attacker establishes shell, attempts to escalate
        Syscall: read(/proc/1/status) — looking for host PID namespace
        Falco: "Sensitive /proc path accessed" → WARNING

Step 3: Attacker tries to load kernel module (escape attempt)
        Syscall: finit_module() or init_module()
        Falco: "Kernel module loaded by container process" → CRITICAL
        Prevention: privileged: false → CAP_SYS_MODULE not available → BLOCKED

Step 4: Attacker tries to write to host via /proc/sys
        Falco: "Write to /proc/sys from container" → CRITICAL
        Prevention: privileged: false → /proc/sys not writable → BLOCKED

Result: RCE achieved but escalation blocked by both Falco + security context.
        Four alerts in <10 seconds → automated PagerDuty page → on-call responds.
```

### Attack Chain 3: Insider Threat — Sysadmin Exfiltrating Data

```
Step 1: Sysadmin kubectl exec's into production database pod
        Falco: "Terminal shell in container" → WARNING (expected, but logged)

Step 2: Sysadmin runs mysqldump
        Falco: "mysqldump executed in database container" → ERROR (custom rule)

Step 3: Dump written to /tmp (emptyDir mounted for temp space)
        Falco: "Large file written to /tmp in database container" → WARNING

Step 4: Sysadmin attempts to curl dump to external server
        Falco: "Unexpected outbound connection from database container" → CRITICAL
        Network policy: egress to external IPs blocked → BLOCKED

Result: Data could not leave the cluster. Four correlated alerts form a
        complete story: exec → dump → stage → exfil attempt.
        Correlation tool surfaces as single high-priority incident.
```

### Attack Chain 4: Supply Chain Backdoor Activation

```
Step 1: Backdoored npm package activates on container startup
        The malicious code runs as a subprocess of Node.js
        Falco: "Unexpected child process spawned by Node.js" → WARNING

Step 2: Backdoor tries to read Kubernetes service account token
        Syscall: open(/var/run/secrets/kubernetes.io/serviceaccount/token)
        Falco: "Service account token accessed by unexpected process" → ERROR

Step 3: Backdoor tries to reach attacker C2 server
        Syscall: connect(attacker-c2-ip:443)
        Falco: "Unexpected outbound connection" → WARNING
        Network egress policy: connection blocked → BLOCKED

Step 4: Backdoor tries to write persistence script
        Syscall: write("/etc/cron.d/persist", ...)
        readOnlyRootFilesystem: EROFS error → BLOCKED
        Falco: would have detected write to cron dir → WARNING (for log)

Result: Backdoor achieved execution but could not read tokens, reach C2,
        or persist. Three Falco alerts in <5 seconds. Pod isolated and killed.
```

---

## 10. CKS Exam Coverage and Weight

The Monitoring, Logging and Runtime Security domain is one of the highest-weighted sections of the CKS examination. Based on the official CKS curriculum:

| Topic Area | Estimated Weight | Primary Chapters |
|---|---|---|
| Use Falco to detect threats | High | Ch 3, 4 |
| Configure Falco rules and config files | High | Ch 3, 4 |
| Ensure immutability of containers at runtime | High | Ch 6 |
| Understand behavioral analytics / syscall monitoring | Medium | Ch 1, 2 |
| Mutable vs Immutable infrastructure concepts | Medium | Ch 5 |
| Install and verify Falco | Medium | Ch 2 |

### 10.1 The Highest-Probability Exam Tasks

**Task Type 1: Falco Installation and Verification**
```bash
# Install Falco on a node:
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt update -y && apt-get install -y linux-headers-$(uname -r) && apt install -y falco
systemctl start falco
```

**Task Type 2: Change a Falco Rule Priority**
```bash
# In /etc/falco/falco_rules.local.yaml:
# Copy the rule from falco_rules.yaml, change only priority: NOTICE → WARNING
# Then: kill -1 $(cat /var/run/falco.pid)
```

**Task Type 3: Write a Custom Falco Rule**
```yaml
- rule: Custom Rule Name
  desc: What it detects
  condition: container and <condition expression>
  output: Alert message (pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
```

**Task Type 4: Fix a Pod That Crashes with readOnlyRootFilesystem**
```bash
# Check logs: kubectl logs <pod> | grep "Read-only"
# Identify which paths need write access
# Add emptyDir volumeMounts for those paths
# kubectl delete pod <name> && kubectl apply -f fixed.yaml
```

**Task Type 5: Enforce Immutability on an Existing Pod/Deployment**
```yaml
# Add to container spec:
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  privileged: false
# Add emptyDir volumes for required write paths
```

### 10.2 Exam-Critical Paths and Files

| Path | Purpose | Chapter |
|---|---|---|
| `/etc/falco/falco.yaml` | Main Falco config | Ch 4 |
| `/etc/falco/falco_rules.yaml` | Built-in rules — NEVER edit | Ch 4 |
| `/etc/falco/falco_rules.local.yaml` | Custom rules and overrides — ALWAYS use | Ch 3, 4 |
| `/var/run/falco.pid` | Falco PID for hot-reload | Ch 4 |
| `/etc/apt/sources.list.d/falcosecurity.list` | Falco apt repository | Ch 2 |
| `container.securityContext.readOnlyRootFilesystem` | Immutability field | Ch 6 |

### 10.3 Exam Commands Quick Reference

```bash
# Install Falco
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt update && apt-get install -y linux-headers-$(uname -r) && apt install -y falco
systemctl start falco && systemctl enable falco

# Monitor Falco logs
journalctl -fu falco

# Trigger test alerts
kubectl exec -ti nginx -- bash        # Triggers "shell in container"
cat /etc/shadow                        # Inside container: triggers "sensitive file read"
kubectl exec -ti nginx -- apt update  # After readOnlyRootFilesystem: triggers EROFS

# Hot-reload after rule changes
falco --validate /etc/falco/falco.yaml
kill -1 $(cat /var/run/falco.pid)

# Verify readOnlyRootFilesystem is working
kubectl exec -ti nginx -- touch /test   # Should return "Read-only file system"

# Check which node a pod is on (important for journalctl)
kubectl get pod nginx -o wide
kubectl get pod nginx -o jsonpath='{.spec.nodeName}'
```

---

## 11. Key Concepts Quick Reference Cheatsheet

### Syscall Monitoring

| Concept | Definition |
|---|---|
| Syscall | The interface through which user-space processes request kernel services (open, read, write, execve, connect, etc.) |
| eBPF | Extended Berkeley Packet Filter — sandboxed kernel programs, verified by kernel, cannot crash the host |
| Kernel module | Compiled kernel code (.ko) inserted into running kernel — intrusive but effective |
| strace | Single-process syscall tracer; high overhead; not for production |
| Falco | CNCF runtime security engine; monitors all container syscalls via eBPF or kernel module |

### Falco Rule Components

| Component | Description |
|---|---|
| `rule` | Unique name identifier for the rule |
| `desc` | Human-readable description of what is detected |
| `condition` | Filtering expression — determines when rule fires |
| `output` | Alert message template with `%field.name` embedded values |
| `priority` | Severity: DEBUG → INFORMATIONAL → NOTICE → WARNING → ERROR → CRITICAL → ALERT → EMERGENCY |
| `list` | Named array of items referenced in conditions (`linux_shells: [bash, zsh, sh]`) |
| `macro` | Named condition fragment for reuse (`container: container.id != host`) |

### Falco Fields Reference

| Field | Value | Use |
|---|---|---|
| `proc.name` | `bash`, `cat`, `nginx` | Process binary name |
| `proc.cmdline` | `cat /etc/shadow` | Full command line |
| `proc.pname` | `sshd` | Parent process name |
| `fd.name` | `/etc/shadow` | File path accessed |
| `container.id` | `abc123` / `host` | Container ID; `host` means on the host |
| `container.image.repository` | `nginx` | Container image without tag |
| `k8s.pod.name` | `nginx-7d8f` | Kubernetes pod name |
| `k8s.ns.name` | `production` | Kubernetes namespace |
| `user.name` | `root` | Username |
| `user.uid` | `0` | User ID |
| `fd.rip` | `1.2.3.4` | Remote IP (network connections) |
| `fd.rport` | `4444` | Remote port |

### Configuration Files

| File | Action |
|---|---|
| `/etc/falco/falco.yaml` | Edit for output channels, priority filter, rules_file list |
| `/etc/falco/falco_rules.yaml` | Read-only reference; never edit |
| `/etc/falco/falco_rules.local.yaml` | Edit for all customisations |
| `/etc/falco/rules.d/` | Add additional rule files here |
| `/var/run/falco.pid` | Contains Falco PID for SIGHUP hot-reload |

### Immutability Controls

| Control | YAML Field | Where | What It Prevents |
|---|---|---|---|
| Read-only filesystem | `readOnlyRootFilesystem: true` | Container securityContext | Writing to container FS |
| No privileged | `privileged: false` | Container securityContext | Host kernel access |
| No priv escalation | `allowPrivilegeEscalation: false` | Container securityContext | Gaining root from non-root |
| Non-root user | `runAsNonRoot: true` | Pod or container securityContext | Running as UID 0 |
| Drop capabilities | `capabilities.drop: [ALL]` | Container securityContext | Linux capability abuse |
| Ephemeral writes | `emptyDir: {}` volumes | volumes + volumeMounts | App failure due to read-only FS |

### Hot-Reload vs Restart

| Method | Command | Monitoring Gap? | Use When |
|---|---|---|---|
| Hot-reload (SIGHUP) | `kill -1 $(cat /var/run/falco.pid)` | No | Rule or config changes |
| systemctl reload | `systemctl reload falco` | No | Same as SIGHUP |
| systemctl restart | `systemctl restart falco` | Brief gap | Major config changes, troubleshooting |

---

## 12. Module Learning Path

For maximum retention and exam readiness, work through the module in this sequence:

```
WEEK 1: FOUNDATION
────────────────────
Day 1: Chapter 1 — Behavioral Analytics
       Goal: Understand WHY syscall monitoring is the right approach
       Practice: Use strace on a process; read man pages for key syscalls

Day 2: Chapter 2 — Falco Installation
       Goal: Install Falco on a node; understand the two probe types
       Practice: Install Falco from scratch on a lab node (no notes)

Day 3: Chapter 3 — Using Falco to Detect Threats
       Goal: Write and read Falco rules; monitor logs in real time
       Practice: Deploy nginx, exec in, trigger three different rules

WEEK 2: DEEP DIVE
────────────────────
Day 4: Chapter 4 — Falco Configuration Files
       Goal: Master rules_file precedence; customize rules; hot-reload
       Practice: Override Terminal shell in container from NOTICE to WARNING
               Add a custom rule to falco_rules.local.yaml
               Hot-reload without restarting Falco

Day 5: Chapter 5 — Mutable vs Immutable Infrastructure
       Goal: Deeply understand configuration drift and the immutable update model
       Practice: Update a Dockerfile (FROM nginx:1.18 to 1.19), rebuild, redeploy

Day 6: Chapter 6 — Runtime Immutability Enforcement
       Goal: Configure readOnlyRootFilesystem correctly with emptyDir volumes
       Practice: Apply to nginx pod; observe crash; add volumes; observe success
               Test: verify apt update fails even in privileged mode

WEEK 3: INTEGRATION AND EXAM PREP
────────────────────────────────────
Day 7: Full module review + practice exam questions
       Time yourself on each task type (target: <5 minutes per task)

Day 8: Build the complete runtime security stack from scratch:
       1. Install Falco (node-installed)
       2. Write three custom rules
       3. Configure JSON output + hot-reload
       4. Deploy a hardened nginx pod (readOnlyRootFilesystem + emptyDir)
       5. Trigger alerts and verify output
       6. Apply Kyverno policy to enforce readOnlyRootFilesystem fleet-wide
```

---

## 13. Links and References

- [Falco Official Documentation](https://falco.org/docs/)
- [Falco GitHub Repository](https://github.com/falcosecurity/falco)
- [Falco Default Rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [CNCF Falco Project Page](https://www.cncf.io/projects/falco/)
- [eBPF.io — eBPF Technology Overview](https://ebpf.io/)
- [Kubernetes Pod Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [emptyDir Volumes](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [MITRE ATT&CK Container Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick)
- [Google Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [ArgoCD GitOps](https://argo-cd.readthedocs.io/)
- [Flux CD](https://fluxcd.io/)
- [Kyverno Policy Engine](https://kyverno.io/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [CKS Exam Curriculum](https://github.com/cncf/curriculum/blob/master/CKS_Curriculum_v1.30.pdf)

---

*Module Introduction — Monitoring, Logging and Runtime Security*
*This file provides the conceptual foundation and navigational index for the 6-chapter module.*
*Begin with Chapter 1 and work through sequentially for best results.*
