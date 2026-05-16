# Falco Overview and Installation

> **Module:** Monitoring, Logging and Runtime Security
> **Chapter:** 2 of 6
> **Scope:** Architecture deep-dive, kernel module vs eBPF, installation on bare nodes, Helm DaemonSet deployment, production hardening, and CKS exam guidance.

---

## Table of Contents

1. [What Is Falco and Why It Matters](#1-what-is-falco-and-why-it-matters)
2. [How Falco Operates — Architecture Overview](#2-how-falco-operates--architecture-overview)
3. [Kernel Module vs eBPF — Two Probes Compared](#3-kernel-module-vs-ebpf--two-probes-compared)
4. [The Falco Processing Pipeline](#4-the-falco-processing-pipeline)
5. [Installing Falco Directly on a Node](#5-installing-falco-directly-on-a-node)
6. [Deploying Falco as a DaemonSet with Helm](#6-deploying-falco-as-a-daemonset-with-helm)
7. [Verifying the Installation](#7-verifying-the-installation)
8. [Falco Output Channels and Alert Routing](#8-falco-output-channels-and-alert-routing)
9. [As a DevSecOps / K8s Security Engineer](#9-as-a-devsecops--k8s-security-engineer)
10. [Real Present-Day Scenarios](#10-real-present-day-scenarios)
11. [What Happens If You Don't Follow This](#11-what-happens-if-you-dont-follow-this)
12. [Most Common Commands and Syntax](#12-most-common-commands-and-syntax)
13. [Other Tools and Services Available](#13-other-tools-and-services-available)
14. [How AI Is Impacting This Area](#14-how-ai-is-impacting-this-area)
15. [CKS Exam Tips](#15-cks-exam-tips)
16. [Links and References](#16-links-and-references)

---

## 1. What Is Falco and Why It Matters

Falco is a **cloud-native runtime security tool** created by Sysdig and donated to the **Cloud Native Computing Foundation (CNCF)** in 2018. It has since graduated to CNCF top-level project status — sitting alongside Kubernetes, Prometheus, and Envoy — which makes it the de facto standard for open-source runtime threat detection in Kubernetes environments.

At its core, Falco watches **every system call** made by every process running on a Linux host. This is the lowest-level observable in a running system — because no matter how sophisticated malware or a container escape attempt is, it ultimately has to make syscalls to do anything meaningful (open a file, make a network connection, fork a process, change permissions). By sitting at the syscall boundary, Falco sees everything.

### Why Runtime Security Is Different

Most security tooling operates at build time or admission time:
- **SAST/DAST** — finds vulnerabilities in source code before it ships
- **Container image scanners** (Trivy, Grype, Snyk) — finds known CVEs in packages at build or push time
- **Admission controllers** (OPA Gatekeeper, Kyverno) — enforces policy at the moment a resource is created in Kubernetes

These tools are essential but they share a fundamental blind spot: **they cannot see what happens after a workload is running**. A perfectly clean container image can be exploited at runtime through a zero-day, a misconfigured application, or a supply chain compromise that activates post-deploy. Falco fills this gap by watching the running system continuously, not just at discrete gates.

### The Threat Model Falco Addresses

| Threat Category | Example | Why Pre-Deploy Tools Miss It |
|---|---|---|
| Container escape | `nsenter`, `mount /proc/host` | Happens at runtime; no CVE in the image |
| Credential theft | `cat /etc/shadow`, `env` dump | Legitimate binaries, not a vulnerability |
| Reverse shell | `bash -i >& /dev/tcp/...` | Behavior-based, not signature-based |
| Cryptomining | Unexpected `cpu` spike + network | Dropped at runtime; not in image layers |
| Lateral movement | `kubectl` running inside a pod | Suspicious behavior, not a CVE |
| Privilege escalation | `setuid`, `chmod +s` | Syscall-level indicator |
| Data exfiltration | Unexpected `curl`, `wget` in prod | Behavior anomaly, not a package flaw |

Falco can detect **all of the above** because it monitors behavior, not just signatures.

---

## 2. How Falco Operates — Architecture Overview

Falco works by intercepting **system calls (syscalls)** — the interface through which user-space programs request services from the Linux kernel. Every time a container process reads a file, opens a network socket, forks a child process, or executes a binary, it goes through this interface. Falco installs a hook at this boundary.

The high-level flow is:

```
Container Process
       │
       │  (system call: open, read, write, execve, connect...)
       ▼
Linux Kernel
       │
       ├── Kernel Module Hook   ──────────────┐
       │                                       │
       └── eBPF Program Hook   ───────────────┤
                                               │
                                       Syscall Event Stream
                                               │
                                               ▼
                                    User-Space Falco Libraries
                                    (libscap, libsinsp)
                                               │
                                               ▼
                                       Policy Engine
                                    (evaluates Falco rules)
                                               │
                               ┌───────────────┼───────────────┐
                               ▼               ▼               ▼
                            syslog          stdout          Falcosidekick
                                                        (Slack/PD/SIEM/etc.)
```

![Falco architecture showing applications, syscalls, kernel module, eBPF probe, policy engine, libraries, Falco rules, and output generation](https://kodekloud.com/kk-media/image/upload/v1752871681/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Falco-Overview-and-Installation/frame_90.jpg)

*KodeKloud: Falco's full architecture — from syscall capture at the kernel boundary through the policy engine and out to alert channels.*

The architecture has three distinct layers:

**Layer 1 — Kernel Instrumentation:** Either a kernel module or an eBPF program hooks into the syscall path and captures raw event data. This layer must run with elevated privilege because it touches the kernel.

**Layer 2 — User-Space Processing:** The captured events flow into Falco's user-space libraries (`libscap` for capture, `libsinsp` for inspection and enrichment). Here events are decoded, enriched with Kubernetes metadata (pod name, namespace, labels, container ID), and structured.

**Layer 3 — Policy Engine and Output:** The enriched events are evaluated against Falco rules. Matching events produce alerts which are dispatched through configured output channels — `syslog`, `stdout`, a file, HTTP endpoints, or via `falcosidekick` to dozens of downstream systems.

> **Key Insight:** Installing Falco **directly on a node as a service** (not as a container) ensures that even if the Kubernetes control plane is compromised or the container runtime is tampered with, Falco continues running independently. A container-based Falco deployment can be killed by an attacker who gains container runtime access; a systemd service survives this class of attack.

---

## 3. Kernel Module vs eBPF — Two Probes Compared

The choice of instrumentation method is one of the most important architectural decisions when deploying Falco. Both approaches intercept syscalls but differ significantly in how they do it, the trade-offs they present, and where they are supported.

### 3.1 Kernel Module (`falco-probe.ko`)

The kernel module approach inserts compiled kernel code (a `.ko` file) directly into the running kernel. Once loaded, it hooks into the kernel's syscall table and forwards events to Falco's user-space daemon.

**How it works:**
```
Kernel Space
┌────────────────────────────────────────┐
│  syscall table                          │
│  ┌──────────────────┐                  │
│  │ sys_open         │ ◄── falco-probe  │
│  │ sys_execve       │     kernel module│
│  │ sys_connect      │                  │
│  └──────────────────┘                  │
└────────────────────────────────────────┘
              │ raw events
              ▼
        Falco user-space
```

**Advantages:**
- Mature, battle-tested approach (used since Falco's early days)
- High performance — low-latency event delivery
- Compatible with older kernel versions (3.x and above)
- Works without kernel BPF support

**Disadvantages:**
- **Intrusive** — modifies the running kernel, which increases risk of kernel panic if the module has bugs
- Requires kernel headers to compile the module for the running kernel version
- **Blocked by many managed cloud providers** (GKE Autopilot, EKS Fargate) that prohibit kernel module loading for security reasons
- Module must be recompiled on kernel upgrades
- Some security-focused organisations prohibit `insmod`/`modprobe` on production hosts

**Installation indicator:** When installing Falco via `apt`, the kernel module approach requires:
```bash
apt-get install -y linux-headers-$(uname -r)
```
This installs the kernel headers needed to compile `falco-probe.ko` for the exact running kernel version.

### 3.2 eBPF Probe (`falco-bpf.o`)

eBPF (Extended Berkeley Packet Filter) is a Linux kernel technology that allows sandboxed programs to be loaded into the kernel without inserting a kernel module. eBPF programs are verified by the kernel's built-in verifier before execution — they cannot crash the kernel, loop infinitely, or access arbitrary memory. This makes eBPF fundamentally safer than kernel modules.

**How it works:**
```
Kernel Space
┌────────────────────────────────────────────┐
│  Kprobes / Tracepoints                      │
│  ┌────────────────────────────────────┐    │
│  │  eBPF program (verified, sandboxed)│    │
│  │  attached to syscall entry/exit    │    │
│  └────────────────────────────────────┘    │
│              │                              │
│         BPF Maps (shared memory)           │
└────────────────────────────────────────────┘
                    │ structured events
                    ▼
             Falco user-space
             (reads from BPF maps via perf ring buffer)
```

**Advantages:**
- **Non-intrusive** — sandboxed, kernel-verified, cannot crash the host
- Supported on **GKE, EKS, AKS** and most managed Kubernetes providers
- Does not require kernel headers (uses pre-compiled BPF object)
- No recompilation on kernel upgrades (BPF object is portable within kernel version ranges)
- Allows **kernel upgrade without restarting Falco** in some configurations
- Modern kernels (4.14+) have excellent eBPF support

**Disadvantages:**
- Requires kernel version **4.14 or higher** (ideally 5.x for full feature set)
- Slightly higher user-space overhead in some scenarios (reading from perf buffers)
- Some features require kernel 5.8+ (e.g., BTF-based CO-RE probes)
- `CAP_BPF` or `CAP_SYS_ADMIN` capability still required to load eBPF programs

**To use eBPF with Falco:**
```bash
# Set environment variable before starting Falco
export FALCO_BPF_PROBE=""
falco
# Or configure in /etc/falco/falco.yaml:
# engine:
#   kind: ebpf
#   ebpf:
#     probe: ${HOME}/.falco/falco-bpf.o
```

### 3.3 Modern Falco: The Modern eBPF Probe (Falco 0.35+)

Starting with Falco 0.35, a third option is available: the **modern eBPF probe**. Unlike the classic eBPF probe which ships a pre-compiled `.o` file, the modern probe uses **CO-RE (Compile Once, Run Everywhere)** technology with BTF (BPF Type Format) to dynamically adapt to any kernel without a pre-built binary. This is the future direction for Falco instrumentation.

```
Classic eBPF     → pre-compiled falco-bpf.o, kernel-version specific
Modern eBPF      → BTF + CO-RE, single binary runs on any 5.8+ kernel
Kernel Module    → compiled .ko, requires headers, intrusive
```

### 3.4 Decision Matrix

| Scenario | Recommended Probe |
|---|---|
| GKE Autopilot / EKS Fargate | Modern eBPF |
| Self-managed nodes, kernel 5.8+ | Modern eBPF |
| Self-managed nodes, kernel 4.14–5.7 | Classic eBPF |
| Legacy kernels (3.x / 4.x <4.14) | Kernel Module |
| Air-gapped environments, no internet | Kernel Module (pre-compiled) |
| Maximum performance, bare metal | Kernel Module |
| Security-sensitive, no kernel mods | Classic or Modern eBPF |

---

## 4. The Falco Processing Pipeline

Understanding the processing pipeline helps you tune performance, write better rules, and debug missed detections.

### 4.1 Event Capture (`libscap`)

The `libscap` library is Falco's capture engine. It interfaces with whichever kernel probe is in use and reads raw syscall events. Each event contains:
- Syscall number and direction (enter/exit)
- Timestamp (nanosecond precision)
- Process ID, thread ID, user ID, group ID
- Raw syscall arguments (file paths, flags, addresses)
- Return value

### 4.2 Event Enrichment (`libsinsp`)

Raw syscall events are enriched with higher-level context by `libsinsp`:
- **Process tree**: parent PID, command line, executable path
- **Container metadata**: container ID, image name, image digest
- **Kubernetes metadata**: pod name, namespace, labels, annotations, deployment name
- **Network context**: source/destination IP, port, protocol

This enrichment is what makes Falco's alerts actionable. A raw `execve` syscall becomes: `"container nginx-5d6b7f (image: nginx:1.25, pod: web-pod, namespace: production) executed /bin/sh"`.

### 4.3 Policy Engine and Rules Evaluation

Enriched events are passed to the policy engine which evaluates them against a set of **Falco rules**. Rules are written in YAML with a condition language based on `libsinsp` field names.

A simplified rule:
```yaml
- rule: Terminal shell in container
  desc: A shell was spawned by a non-shell program in a container
  condition: >
    container.id != host and
    proc.name = bash and
    proc.pname not in (bash, sh, ksh, zsh) and
    container.image.repository not in (allowed_images)
  output: >
    Shell spawned in a container
    (user=%user.name container=%container.name image=%container.image.repository
     shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
```

### 4.4 Output Dispatch

When a rule matches, the alert is dispatched to all configured output channels simultaneously:
- `stdout` — human-readable text, good for testing
- `syslog` — integrates with system log infrastructure (journald, rsyslog)
- File output — structured JSON/text for log shippers
- HTTP output — webhook to custom endpoints
- `gRPC` — high-performance programmatic interface used by Falcosidekick

### 4.5 Falcosidekick — Alert Fan-out

`falcosidekick` is a companion service that connects Falco's output to 70+ destinations:

```
Falco → gRPC/HTTP → Falcosidekick → Slack
                                   → PagerDuty
                                   → Datadog
                                   → Elasticsearch
                                   → AWS SNS
                                   → Splunk
                                   → Loki
                                   → JIRA
                                   → ... (70+ outputs)
```

---

## 5. Installing Falco Directly on a Node

Installing Falco as a **systemd service on the host** is the most resilient deployment model because Falco runs completely outside the container runtime and Kubernetes scheduler. An attacker who compromises the container runtime or the kubelet cannot simply kill Falco.

### 5.1 Prerequisites

```bash
# Check kernel version (must be 3.x+ for module, 4.14+ for eBPF)
uname -r

# Check available disk space (Falco + kernel headers = ~200MB)
df -h /

# Verify apt sources are reachable
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | head -1
```

### 5.2 Step-by-Step Installation

**Step 1: Import the Falco GPG key and add the repository**
```bash
# Import the signing key so apt can verify package authenticity
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -

# Add the Falco stable repository
echo "deb https://download.falco.org/packages/deb stable main" \
  | tee -a /etc/apt/sources.list.d/falcosecurity.list
```

**Step 2: Install kernel headers for the running kernel**
```bash
# Update package lists
apt update -y

# Install headers that match the EXACT running kernel version
# $(uname -r) expands to something like "5.15.0-91-generic"
apt-get install -y linux-headers-$(uname -r)
```

> **Why this step matters:** Falco's kernel module (`falco-probe.ko`) is compiled from source against the kernel headers for your specific kernel version. Without the matching headers, the post-install compilation will fail and Falco will not have a working probe. If you upgrade the kernel, you must also install the new kernel's headers and re-trigger Falco's module build.

**Step 3: Install Falco**
```bash
apt install -y falco
```

During installation, the post-install script automatically:
1. Compiles the `falco-probe.ko` kernel module using DKMS
2. Loads the module (`modprobe falco`)
3. Installs the default rules into `/etc/falco/falco_rules.yaml`
4. Installs the local overrides file at `/etc/falco/falco_rules.local.yaml`
5. Configures `/etc/falco/falco.yaml` as the main config

**Step 4: Start and enable the Falco service**
```bash
# Start the service immediately
systemctl start falco

# Enable auto-start on boot
systemctl enable falco

# Verify the service is running
systemctl status falco
```

Expected output:
```
● falco.service - Falco: Container Native Runtime Security
     Loaded: loaded (/lib/systemd/system/falco.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2024-05-16 10:22:31 UTC; 3s ago
   Main PID: 12345 (falco)
     CGroup: /system.slice/falco.service
             └─12345 /usr/bin/falco --pidfile=/var/run/falco.pid
```

### 5.3 Post-Installation File Locations

| Path | Purpose |
|---|---|
| `/etc/falco/falco.yaml` | Main Falco configuration |
| `/etc/falco/falco_rules.yaml` | Built-in ruleset (do not edit directly) |
| `/etc/falco/falco_rules.local.yaml` | Local overrides and custom rules |
| `/etc/falco/rules.d/` | Additional rule files (loaded alphabetically) |
| `/var/log/falco/` | Alert log files (if file output is configured) |
| `/usr/lib/modules/$(uname -r)/extra/falco-probe.ko` | Compiled kernel module |

### 5.4 Installing on Multiple Nodes (Ansible)

In a real cluster you automate this across all nodes:

```yaml
# ansible/falco-install.yml
---
- hosts: k8s_nodes
  become: yes
  tasks:
    - name: Import Falco GPG key
      apt_key:
        url: https://falco.org/repo/falcosecurity-3672BA8F.asc
        state: present

    - name: Add Falco repository
      apt_repository:
        repo: "deb https://download.falco.org/packages/deb stable main"
        state: present
        filename: falcosecurity

    - name: Install kernel headers
      apt:
        name: "linux-headers-{{ ansible_kernel }}"
        state: present
        update_cache: yes

    - name: Install Falco
      apt:
        name: falco
        state: present

    - name: Start and enable Falco
      systemd:
        name: falco
        state: started
        enabled: yes
```

---

## 6. Deploying Falco as a DaemonSet with Helm

When direct node installation is not possible (e.g., managed Kubernetes nodes with read-only filesystems, or organisational policy prohibiting SSH to nodes), deploying Falco as a **Kubernetes DaemonSet** ensures one Falco pod runs on every node automatically.

### 6.1 Why DaemonSet Matters

A `DaemonSet` is a Kubernetes controller that guarantees exactly one pod runs on every eligible node. As nodes are added to the cluster, the DaemonSet controller automatically schedules a Falco pod on them. As nodes are removed, the pod is garbage-collected. This is exactly what you want for a security monitoring tool: **complete node coverage with zero manual intervention**.

### 6.2 Helm Chart Deployment

```bash
# Step 1: Add the Falco Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Step 2: Create a dedicated namespace
kubectl create namespace falco

# Step 3: Install Falco with default settings
helm install falco falcosecurity/falco \
  --namespace falco \
  --set driver.kind=ebpf        # Use eBPF instead of kernel module
```

### 6.3 Customised Helm Install (Production Values)

```yaml
# falco-values.yaml
driver:
  kind: ebpf                    # or "module" for kernel module

falco:
  json_output: true             # Structured JSON alerts
  json_include_output_property: true
  log_level: info
  priority: debug               # Capture everything for tuning; set to WARNING in prod

  # Alert output channels
  syslog_output:
    enabled: true
  file_output:
    enabled: true
    keep_alive: false
    filename: /var/log/falco/events.log
  http_output:
    enabled: true
    url: "http://falcosidekick:2801/"  # Forward to falcosidekick

falcoctl:
  artifact:
    follow:
      enabled: true             # Auto-update rules from OCI registry

resources:
  requests:
    cpu: 100m
    memory: 512Mi
  limits:
    cpu: 500m
    memory: 1024Mi

tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule          # Also monitor control plane nodes

# Deploy falcosidekick alongside
falcosidekick:
  enabled: true
  config:
    slack:
      webhookurl: "https://hooks.slack.com/services/YOUR/WEBHOOK"
      minimumpriority: "warning"
```

```bash
# Install with custom values
helm install falco falcosecurity/falco \
  --namespace falco \
  --values falco-values.yaml
```

### 6.4 Helm Upgrade and Rollback

```bash
# Upgrade to new Falco version
helm upgrade falco falcosecurity/falco --namespace falco --values falco-values.yaml

# Check release history
helm history falco --namespace falco

# Rollback if needed
helm rollback falco 1 --namespace falco
```

### 6.5 DaemonSet vs Node Service — Trade-offs

| Dimension | DaemonSet (Helm) | Node Service (apt) |
|---|---|---|
| Deployment automation | Excellent (Helm, GitOps) | Requires Ansible/Chef/Puppet |
| Managed node support | Yes (GKE, EKS, AKS) | Usually not |
| Isolation from K8s | Low (killed by K8s) | High (survives cluster issues) |
| Configuration management | Helm values + ConfigMaps | /etc/falco/ on host |
| Rule updates | falcoctl auto-update | Manual or scripted |
| Resource visibility | Pod-level metrics | systemd/journald |
| Upgrade process | `helm upgrade` | `apt upgrade falco` |
| Recommended for | Cloud-managed clusters | Self-managed, high-security |

---

## 7. Verifying the Installation

### 7.1 Check Pod Status (DaemonSet)

```bash
kubectl get pods -n falco -o wide
```

Expected output showing one pod per node:
```
NAME          READY   STATUS    RESTARTS   AGE    NODE
falco-7grdt   1/1     Running   0          2m21s  node01
falco-tmq28   1/1     Running   0          2m21s  node02
falco-x9kqz   1/1     Running   0          2m21s  controlplane
```

Confirm the DaemonSet covers all nodes:
```bash
kubectl get daemonset -n falco
NAME    DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
falco   3         3         3       3            3           <none>          5m
```

### 7.2 Check Systemd Service (Node Install)

```bash
# Check service health
systemctl status falco

# View live logs
journalctl -u falco -f

# Check kernel module is loaded
lsmod | grep falco
# Expected: falco_probe   xxx,xxx  0
```

### 7.3 Trigger a Test Alert

The easiest way to verify Falco is working end-to-end is to trigger a rule that ships by default: **reading a sensitive file** (`/etc/shadow`).

```bash
# On the node where Falco is running (or exec into a pod)
cat /etc/shadow

# Immediately check Falco output
journalctl -u falco -n 20
# Or for DaemonSet:
kubectl logs -n falco <falco-pod-name> | tail -20
```

Expected alert:
```
{"output":"12:34:56.789012 Warning Sensitive file opened for reading by non-trusted program
(user=root user_loginuid=0 program=cat command=cat /etc/shadow
file=/etc/shadow parent=bash gparent=sshd ggparent=systemd container_id=host
image=<NA>)","priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["filesystem","mitre_credential_access"],"time":"2024-05-16T12:34:56.789012345Z"}
```

### 7.4 Check Which Rules Are Loaded

```bash
# List all loaded rules with priorities
falco --list-rules

# Validate configuration and rules without starting
falco --validate /etc/falco/falco.yaml

# Check rule file syntax
falco -r /etc/falco/falco_rules.yaml --validate
```

### 7.5 Inspect the Running Probe

```bash
# For kernel module: verify it's loaded
lsmod | grep falco_probe

# For eBPF: check BPF programs are loaded
bpftool prog list | grep falco

# Check which probe type Falco is using
falco --version
```

---

## 8. Falco Output Channels and Alert Routing

Falco can emit alerts to multiple destinations simultaneously. Understanding the options is critical for building a complete detection pipeline.

### 8.1 Standard Output (`stdout`)

```yaml
# /etc/falco/falco.yaml
stdout_output:
  enabled: true
```

Best for: development, testing, and piping to other tools.
```bash
falco 2>&1 | grep -E "Warning|Error|Critical"
```

### 8.2 Syslog

```yaml
syslog_output:
  enabled: true
```

Writes to the system's syslog facility. Viewable via:
```bash
tail -f /var/log/syslog | grep falco
journalctl -t falco -f
```

### 8.3 File Output

```yaml
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/events.log
```

Structured output to a log file that log shippers (Fluent Bit, Filebeat) can tail.

### 8.4 HTTP Webhook Output

```yaml
http_output:
  enabled: true
  url: "http://falcosidekick:2801/"
  user_agent: "falco"
  insecure: false
```

### 8.5 gRPC Output (for Falco Sidekick)

```yaml
grpc:
  enabled: true
  bind_address: "unix:///run/falco/falco.sock"
  threadiness: 8

grpc_output:
  enabled: true
```

### 8.6 Alert Priority Levels

| Priority | Numeric | Use Case |
|---|---|---|
| EMERGENCY | 0 | System is unusable |
| ALERT | 1 | Must act immediately |
| CRITICAL | 2 | Critical condition |
| ERROR | 3 | Error condition |
| WARNING | 4 | Warning (most Falco rules) |
| NOTICE | 5 | Normal but significant |
| INFORMATIONAL | 6 | Informational |
| DEBUG | 7 | Debug-level detail |

In production, set `priority: warning` in `falco.yaml` to suppress debug/info noise and only alert on meaningful events.

---

## 9. As a DevSecOps / K8s Security Engineer

Working with Falco in a real organisation involves much more than installation. Here are the realities of running Falco in production:

### 9.1 Day 1 — Deployment Strategy

Your first decision is the deployment model. In most cloud-managed Kubernetes (GKE, EKS, AKS), you'll use the Helm DaemonSet approach with the eBPF probe — kernel modules are typically not allowed. For self-managed clusters (bare metal, vSphere, on-prem), you have the choice: node service gives better isolation, DaemonSet gives better manageability.

**Interview-ready answer:** "We deploy Falco as a DaemonSet via Helm on GKE with the eBPF probe because GKE Autopilot doesn't allow kernel module insertion. On our bare-metal clusters we install Falco as a systemd service to ensure it survives any Kubernetes-layer compromise."

### 9.2 Day 2 — Noise Reduction

Out-of-the-box, Falco generates a significant amount of noise from legitimate cluster operations — system pods reading sensitive files, monitoring agents executing binaries, etc. Your job is to tune the rules:

```yaml
# falco_rules.local.yaml — suppress known-good processes
- list: known_binaries_reading_sensitive_files
  items: [prometheus, node-exporter, datadog-agent, fluentbit]

- macro: trusted_sensitive_file_access
  condition: proc.name in (known_binaries_reading_sensitive_files)

# Override the built-in rule to exclude trusted processes
- rule: Read sensitive file untrusted
  condition: >
    sensitive_files and open_read
    and not trusted_sensitive_file_access
    and not proc.name in (health_check_binaries)
  override:
    condition: append
```

### 9.3 Day 3 — Alert Pipeline Integration

Raw Falco alerts need to reach the right people through the right channels. A production alert pipeline looks like:

```
Falco → Falcosidekick → Slack (warnings, for triage)
                      → PagerDuty (critical, for on-call)
                      → Elasticsearch (all, for forensics)
                      → JIRA (post-incident, for tickets)
```

### 9.4 Responding to Falco Alerts

When Falco fires an alert in production, the response process:

1. **Acknowledge** the alert (PagerDuty, Slack)
2. **Identify the pod/node** from the alert metadata
3. **Preserve evidence** — capture running processes, network connections, open files:
   ```bash
   kubectl exec -it <pod> -- ps aux
   kubectl exec -it <pod> -- ss -tnp
   kubectl exec -it <pod> -- ls -la /proc/self/fd
   ```
4. **Isolate** the workload if compromised:
   ```bash
   # Apply a deny-all NetworkPolicy
   kubectl label pod <pod> incident=suspected-compromise
   ```
5. **Collect forensic image** of the container filesystem
6. **Terminate** the pod and restart from clean image
7. **Post-mortem** — update Falco rules to improve detection fidelity

### 9.5 Falco in CI/CD Security Gates

Falco can be integrated into deployment pipelines to validate that staging deployments don't trigger security alerts during automated test runs:

```bash
# In CI pipeline: run integration tests while Falco monitors
falco --json-output --one-shot &
FALCO_PID=$!
run_integration_tests
kill $FALCO_PID
# Parse Falco output for any alerts generated during tests
```

### 9.6 Compliance Mapping

Falco alerts map directly to compliance frameworks:

| Framework | Control | Falco Coverage |
|---|---|---|
| CIS Kubernetes Benchmark | 5.7.4 (Runtime Security) | Rule-based syscall monitoring |
| NIST SP 800-190 | 4.4 (Container Runtime) | Image and process monitoring |
| PCI DSS v4.0 | 10.7 (Audit Logging) | syslog output to SIEM |
| SOC 2 Type II | CC7.2 (Monitoring) | Continuous runtime alerting |
| MITRE ATT&CK | Container techniques | Built-in MITRE-tagged rules |

---

## 10. Real Present-Day Scenarios

### Scenario 1: TeamTNT Cryptominer Attack (Real, 2021–2023)

TeamTNT is a threat actor group known for targeting Kubernetes clusters to deploy cryptomining workloads. Their attack pattern: scan for exposed Docker API / kubelet ports → deploy miner container → persist via DaemonSet.

**What Falco would detect:**
```yaml
# TeamTNT typically executes these binaries in containers:
# - masscan, nmap (scanning)
# - xmrig (cryptominer)
# - curl piped to bash (dropper)

- rule: Suspicious Execution in Container
  condition: >
    container and proc.name in (xmrig, masscan, nmap) and
    not proc.pname in (package_managers)
  output: Potential cryptominer detected (container=%container.name proc=%proc.name)
  priority: CRITICAL
```

A Falco rule for `xmrig` execution in any container would have triggered immediately on first execution — stopping the miner before it consumed significant resources.

### Scenario 2: Log4Shell Container Escape Attempt (2021)

After Log4Shell (CVE-2021-44228) was disclosed, attackers immediately targeted any Java application running in containers. The attack involved JNDI injection through a log message, causing the JVM to execute arbitrary code.

Falco detection approach:
- The JVM process suddenly executing `/bin/sh` or `bash` → suspicious child process
- DNS lookup to attacker-controlled server → network detection
- `wget` or `curl` downloading a second-stage payload → file download in container

```yaml
- rule: Java Application Spawning Shell
  desc: Java process spawning a shell — possible RCE
  condition: >
    container and
    proc.pname in (java) and
    proc.name in (sh, bash, dash, ksh, zsh)
  output: >
    Java process spawned shell (pod=%k8s.pod.name ns=%k8s.ns.name
    parent=%proc.pname shell=%proc.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [rce, log4shell, mitre_execution]
```

### Scenario 3: Supply Chain Attack — Malicious Package in Runtime

A popular Node.js library is compromised (similar to `event-stream` in 2018). The malicious package, once running in production pods, opens a reverse shell to an attacker-controlled server.

Falco detection:
```yaml
- rule: Unexpected Outbound Connection from Node.js
  condition: >
    container and
    container.image.repository contains "node" and
    fd.typechar = 4 and   # network socket
    fd.rip not in (allowed_ip_list) and
    proc.name = node
  output: >
    Unexpected outbound connection from Node.js container
    (pod=%k8s.pod.name dst=%fd.rip:%fd.rport)
  priority: WARNING
```

### Scenario 4: Kubernetes Secret Enumeration by Compromised Pod

An attacker who compromises a pod attempts to enumerate secrets from the Kubernetes API:

```bash
# Inside compromised pod:
curl -k https://kubernetes.default.svc/api/v1/namespaces/production/secrets \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

Falco detects this via:
- Access to the service account token file: `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Unexpected `curl` execution in non-debug containers
- K8s audit logging (complementary — Falco handles syscalls, audit log handles API calls)

### Scenario 5: Production Cluster — Falco Deployment at Scale (5,000 Nodes)

A large e-commerce platform running 5,000 Kubernetes nodes deploys Falco via Helm with these learnings:

- **Resource tuning**: 200m CPU, 512Mi memory per node is sufficient; burst allowance to 1 CPU during alert storms
- **Rule tuning**: First month, 60% of alerts are false positives from monitoring agents; after tuning, noise drops to <5%
- **Alert volume**: ~50 real security events per day across 5,000 nodes; 3–5 require human investigation
- **ROI**: Caught 2 cryptominer infections, 1 misconfigured container with exposed credentials, and 4 attempted privilege escalations in the first 6 months

---

## 11. What Happens If You Don't Follow This

### Missing Falco Entirely

Without any runtime security monitoring:

- **You are blind after deployment.** You can harden images and set admission policies, but once a workload is running, you have no visibility into its behaviour.
- **Compromise dwell time increases dramatically.** The industry average dwell time (time between compromise and detection) without active runtime monitoring is measured in **weeks to months**. With Falco, detection can be within **seconds**.
- **Compliance failures.** PCI DSS 4.0 Requirement 10, SOC 2 CC7, and ISO 27001 Annex A.12.4 all require continuous monitoring of runtime activities. "We have admission policies" does not satisfy runtime monitoring requirements.
- **Incident response is guesswork.** Without syscall-level logs, post-incident forensics relies on application logs (which attackers routinely delete or never write to). Falco's kernel-level capture happens below the application layer.

### Installing Without Kernel Headers

```bash
# If you skip: apt-get install -y linux-headers-$(uname -r)
apt install -y falco

# Result during post-install DKMS build:
# ERROR: Cannot find kernel source tree for version 5.15.0-91-generic
# DKMS: build failed
# falco-probe module not installed
# Falco will start but with NO kernel instrumentation — monitoring is silently disabled
```

This is a particularly dangerous failure mode: Falco starts, appears healthy, reports `Running` — but it is not actually monitoring any syscalls because the probe failed to load. Always verify with `lsmod | grep falco_probe` after installation.

### Not Running on Control Plane Nodes

If your DaemonSet uses a toleration that excludes control plane nodes:
```yaml
# BAD: This tolerates only worker nodes
tolerations:
  - key: node-role.kubernetes.io/worker
    operator: Exists
```

The control plane nodes — which run etcd, kube-apiserver, kube-scheduler, kube-controller-manager — are completely unmonitored. These are the highest-value targets in any Kubernetes attack. Always add:
```yaml
tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
```

### Alert Routing Failures

If Falco alerts go only to `stdout` with no routing to a SIEM or alerting system:
- Alerts scroll off terminal history
- No one is paged when a critical event occurs
- Forensic evidence is lost (logs rotate)
- You fail audit requirements for "centralized, tamper-evident log storage"

---

## 12. Most Common Commands and Syntax

### Installation Commands

```bash
# Import Falco GPG key
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -

# Add Falco stable repository
echo "deb https://download.falco.org/packages/deb stable main" \
  | tee -a /etc/apt/sources.list.d/falcosecurity.list

# Install prerequisites + Falco
apt update -y
apt-get install -y linux-headers-$(uname -r)
apt install -y falco

# Service management
systemctl start falco
systemctl stop falco
systemctl restart falco
systemctl enable falco
systemctl status falco
```

### Helm DaemonSet Deployment

```bash
# Add and update Helm repo
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco in falco namespace with eBPF
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=ebpf

# Install with custom values
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --values falco-values.yaml

# Upgrade release
helm upgrade falco falcosecurity/falco --namespace falco --values falco-values.yaml

# Uninstall
helm uninstall falco --namespace falco
```

### Verification Commands

```bash
# DaemonSet: check pod status
kubectl get pods -n falco -o wide
kubectl get daemonset -n falco

# DaemonSet: view logs
kubectl logs -n falco <falco-pod-name> --tail=50 -f
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20

# Node service: view logs
journalctl -u falco -f
journalctl -u falco -n 100
journalctl -u falco --since "10 minutes ago"

# Check kernel module is loaded
lsmod | grep falco
lsmod | grep falco_probe

# Check eBPF programs
bpftool prog list | grep falco
```

### Rule and Config Management

```bash
# Validate configuration file
falco --validate /etc/falco/falco.yaml

# Validate a rules file
falco -r /etc/falco/falco_rules.yaml --validate

# List all loaded rules
falco --list-rules

# Run Falco with a specific rules file (non-default)
falco -r /path/to/custom_rules.yaml

# Run Falco in one-shot mode (exits after reading input)
falco --one-shot

# Run with JSON output to stdout
falco --json-output

# Run in dry-run mode (no actual probing, just rule parsing)
falco --dry-run

# Print Falco version
falco --version
```

### Testing Specific Rules

```bash
# Trigger "Read sensitive file" rule
cat /etc/shadow

# Trigger "Terminal shell in container" rule
kubectl exec -it <pod-name> -- /bin/bash

# Trigger "Write below binary dir" rule
touch /usr/bin/testfile

# Trigger "Create files below dev" rule
touch /dev/testfile
```

### Falco Event Tailing in JSON

```bash
# Tail Falco alerts in JSON format (for parsing)
kubectl logs -n falco <falco-pod> -f | jq '.'

# Filter for WARNING or higher
kubectl logs -n falco <falco-pod> -f | jq 'select(.priority == "Warning" or .priority == "Critical")'

# Filter by rule name
kubectl logs -n falco <falco-pod> -f | jq 'select(.rule == "Terminal shell in container")'
```

---

## 13. Other Tools and Services Available

### 13.1 Runtime Security Alternatives to Falco

| Tool | Vendor | Approach | Strengths | Limitations |
|---|---|---|---|---|
| **Falco** | CNCF (open source) | eBPF/kmod syscall rules | Open source, CNCF, community rules | Rule writing requires expertise |
| **Tetragon** | Isovalent/Cilium | eBPF, kernel-level enforcement | Can block (not just alert), deep eBPF | Requires Cilium CNI |
| **Tracee** | Aqua Security | eBPF + OPA policies | Real-time blocking, OPA integration | Newer, smaller community |
| **Sysdig Secure** | Sysdig | Commercial Falco + cloud platform | Turnkey, multi-cloud, ML-enhanced | Cost, vendor lock-in |
| **NeuVector** | SUSE | Deep packet inspection + syscalls | Full lifecycle, built-in WAF | Complex setup |
| **StackRox/RHACS** | Red Hat | Declarative policies, runtime | OpenShift integration | Resource-heavy |
| **Aqua Security** | Aqua | Commercial, eBPF + ML | Comprehensive, ML threat detection | Cost |

### 13.2 Falco Ecosystem Components

| Component | Purpose |
|---|---|
| **falcosidekick** | Route Falco alerts to 70+ destinations |
| **falcosidekick-ui** | Web dashboard for alert visualization |
| **falcoctl** | CLI for managing Falco artifacts (rules, plugins) |
| **Falco Talon** | Automated response engine (kill pods, isolate, etc.) |
| **falco-exporter** | Prometheus metrics exporter for Falco alerts |
| **event-generator** | Test tool to trigger Falco rules on demand |

### 13.3 Complementary Tools

**For audit log monitoring** (Kubernetes API-level): `kube-bench`, Falco's k8s audit plugin

**For network monitoring**: Cilium Hubble, Pixie

**For forensics**: `crictl`, `nsenter`, `bpftrace`

**For SIEM integration**: Elastic Security, Splunk ES, Microsoft Sentinel (all support Falco JSON ingestion)

### 13.4 Falco Rules Registry (OCI-based)

Starting with Falco 0.35+, rules are distributed through OCI registries:

```bash
# Install falcoctl
falcoctl artifact install falco-rules

# Pull latest community rules
falcoctl artifact pull ghcr.io/falcosecurity/rules/falco-rules:latest

# Configure auto-update in Helm values
falcoctl:
  artifact:
    follow:
      enabled: true
      refs:
        - falco-rules:latest
```

### 13.5 Falco Plugins

Falco's plugin system extends monitoring beyond syscalls:

| Plugin | Data Source | Use Case |
|---|---|---|
| `k8s_audit` | Kubernetes audit logs | API server activity monitoring |
| `cloudtrail` | AWS CloudTrail | AWS API call monitoring |
| `gcp_auditlog` | GCP Audit Logs | GCP API monitoring |
| `okta` | Okta auth events | Identity provider monitoring |
| `github` | GitHub webhook events | Source code repository monitoring |
| `docker` | Docker events | Container lifecycle monitoring |

---

## 14. How AI Is Impacting This Area

### 14.1 ML-Enhanced Threat Detection

Traditional Falco operates on **rule-based detection**: you define what looks suspicious, and Falco alerts when it sees it. This has a fundamental limitation — you can only detect threats you've already thought to define rules for. AI/ML changes this paradigm:

**Behavioural Baselines:** ML models learn "normal" behaviour for each workload — typical CPU usage, network connections, process trees, syscall frequency distributions. Deviations from the baseline trigger alerts, even for previously unseen attack patterns (zero-day detection).

Vendors doing this today:
- **Sysdig Secure** — ML-based anomaly detection on top of Falco's kernel data
- **Aqua Security** — Dynamic threat profiles using ML
- **Datadog Cloud Security** — ML-based cloud workload protection

### 14.2 AI-Assisted Rule Writing

LLMs (including Claude) can help write Falco rules from natural-language threat descriptions:

```
Prompt: "Write a Falco rule to detect if a container spawns more than 
10 child processes in a minute, which could indicate a fork bomb or 
cryptominer multi-threading attack"

Generated Rule:
- rule: Excessive Process Spawning in Container
  desc: Container spawning many child processes
  condition: >
    container and
    proc.is_exe_writable = false and
    evt.type = clone and
    not proc.name in (known_multi_process_apps)
  output: Excessive process spawning (container=%container.name spawned=%proc.name)
  priority: WARNING
```

### 14.3 AI-Driven Automatic Response

Emerging tools combine Falco with AI-powered response:

```
Falco Alert: "Cryptominer detected in pod X"
     ↓
AI Response Engine (Falco Talon + LLM)
     ↓
Decision: Kill pod, preserve forensic snapshot, notify on-call, open JIRA ticket
     ↓
Automated actions executed in <5 seconds
```

### 14.4 LLM-Powered Alert Triage

Raw Falco alerts are noisy. AI can classify and prioritise:
- **False positive suppression**: "This `cat /etc/passwd` is from a legitimate health check — confidence 94%"
- **Attack chain correlation**: "These 3 separate alerts (recon + privilege escalation + network connection) likely belong to the same attack campaign"
- **Context enrichment**: Automatically pull CVE data, threat intelligence, and suggest remediation steps for each alert

### 14.5 AI-Generated Anomaly Descriptions

Instead of cryptic log lines, AI translates alerts into human-readable incident reports:
```
Raw Alert: proc.name=bash evt.type=execve proc.pname=node container.name=api-server

AI Generated: "A bash shell was unexpectedly launched by a Node.js process inside 
the 'api-server' container in namespace 'production'. This could indicate a 
command injection vulnerability or a supply chain compromise. Recommended action: 
isolate the pod and examine recent deployments."
```

### 14.6 Threat Intelligence Integration

AI models trained on threat intelligence feeds can automatically update Falco rules in response to newly disclosed attack techniques:

```
New TTP disclosed → ML model maps to Falco rule conditions → 
PR automatically created to rules repo → Human review → Deploy
```

---

## 15. CKS Exam Tips

The CKS exam tests your practical ability to deploy and work with Falco. Here are the exact competencies you need to demonstrate:

### What the Exam Tests

| Competency | Weight |
|---|---|
| Understanding Falco's architecture (kernel module vs eBPF) | High |
| Installing Falco on a node (the exact commands) | High |
| Verifying Falco installation (`kubectl get pods`, `systemctl status`) | High |
| Reading Falco alerts and identifying what triggered them | High |
| Understanding Falco rules structure | Medium |
| DaemonSet deployment concept | Medium |

### The Five Commands You Must Know Cold

```bash
# 1. Import GPG key
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -

# 2. Add repository
echo "deb https://download.falco.org/packages/deb stable main" \
  | tee -a /etc/apt/sources.list.d/falcosecurity.list

# 3. Install kernel headers (CRITICAL — forget this and Falco has no probe)
apt-get install -y linux-headers-$(uname -r)

# 4. Install Falco
apt install -y falco

# 5. Start the service
systemctl start falco
```

### Exam Traps and How to Avoid Them

**Trap 1: Forgetting kernel headers**
```bash
# WRONG — installs Falco without probe
apt install -y falco

# RIGHT — always install headers first
apt-get install -y linux-headers-$(uname -r) && apt install -y falco
```

**Trap 2: Not verifying the probe loaded**
After installation, always run:
```bash
lsmod | grep falco_probe
# If this returns nothing, the probe did not load — kernel headers were wrong
```

**Trap 3: Wrong namespace for DaemonSet**
```bash
# If you installed Falco with Helm into the `falco` namespace:
kubectl get pods -n falco   # CORRECT
kubectl get pods            # WRONG — shows nothing
```

**Trap 4: Confusing alert sources**
- Syscall events → Falco logs (`journalctl -u falco` or `kubectl logs`)
- Kubernetes API events → K8s audit logs (`/var/log/audit/audit.log`)
- These are different! The exam may ask you to distinguish them.

**Trap 5: systemctl vs kubectl**
- Node-installed Falco: `systemctl start falco`
- DaemonSet Falco: managed by Kubernetes — you CANNOT `systemctl start` a DaemonSet pod

### Key Exam Concepts to Memorise

| Concept | Answer |
|---|---|
| What does Falco monitor? | System calls (syscalls) from user-space to Linux kernel |
| Two probe methods? | Kernel module (intrusive) and eBPF (preferred) |
| Why eBPF is preferred? | Non-intrusive, kernel-verified, works on managed K8s |
| Where are rules stored? | `/etc/falco/falco_rules.yaml` (built-in), `/etc/falco/falco_rules.local.yaml` (custom) |
| Main config file? | `/etc/falco/falco.yaml` |
| How to check if Falco is running (node)? | `systemctl status falco` |
| How to check if Falco is running (DaemonSet)? | `kubectl get pods -n falco` |
| What is a DaemonSet? | Ensures one pod runs on every node |
| Why install Falco as a service (not pod)? | Survives Kubernetes-layer compromise |
| Alert output channels? | syslog, stdout, file, HTTP, gRPC |

### Practice Exercises Before the Exam

```bash
# Exercise 1: Install Falco on a node from scratch (no notes)
# Time yourself — should take <5 minutes

# Exercise 2: After installing, trigger and read an alert
kubectl exec -it <any-pod> -- bash
# Check Falco logs and explain what rule fired

# Exercise 3: Install Falco via Helm DaemonSet
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=ebpf

# Exercise 4: Verify all nodes are covered
kubectl get pods -n falco -o wide
kubectl get daemonset -n falco

# Exercise 5: Check Falco is reading from a specific probe type
falco --version
lsmod | grep falco
```

### Time Management

On the CKS exam, Falco-related tasks typically appear as 4–8% of the total score. Common question patterns:
- "Install Falco on node01 and verify it is running"
- "Falco is installed but not detecting events — troubleshoot and fix"
- "What Falco rule would trigger if a container reads /etc/shadow?"

Budget 6–10 minutes maximum for any single Falco task. If you're spending more than 10 minutes, move on and return.

---

## 16. Links and References

- [Falco Official Documentation](https://falco.org/docs/)
- [Falco GitHub Repository](https://github.com/falcosecurity/falco)
- [Falco Rules Repository](https://github.com/falcosecurity/rules)
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick)
- [Falco Helm Chart (ArtifactHub)](https://artifacthub.io/packages/helm/falcosecurity/falco)
- [eBPF Overview — kernel.org](https://ebpf.io/)
- [Kubernetes DaemonSet Documentation](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)
- [CNCF Falco Project Page](https://www.cncf.io/projects/falco/)
- [Falco Talon — Automated Response](https://github.com/falco-talon/falco-talon)
- [MITRE ATT&CK Container Techniques](https://attack.mitre.org/matrices/enterprise/containers/)
- [libscap / libsinsp Documentation](https://falco.org/docs/reference/libs/)
- [Falco CO-RE Modern Probe](https://falco.org/blog/falco-modern-bpf-0-35/)

---

*Chapter 2 of 6 — Monitoring, Logging and Runtime Security*
*Next: Chapter 3 — Use Falco to Detect Threats*
