# Falco Configuration Files

> **Module:** Monitoring, Logging and Runtime Security
> **Chapter:** 4 of 6
> **Scope:** Complete reference for `falco.yaml`, rule file loading order and precedence, output channel configuration, rule overriding, hot-reload with SIGHUP, and production configuration hardening.

---

## Table of Contents

1. [Configuration Architecture Overview](#1-configuration-architecture-overview)
2. [Main Configuration File — `/etc/falco/falco.yaml`](#2-main-configuration-file--etcfalcofalcoyaml)
3. [Rule File Loading — `rules_file` and Precedence](#3-rule-file-loading--rules_file-and-precedence)
4. [Logging and Output Format Settings](#4-logging-and-output-format-settings)
5. [Output Channel Configuration](#5-output-channel-configuration)
6. [Built-in Rules File — `/etc/falco/falco_rules.yaml`](#6-built-in-rules-file--etcfalcofalco_rulesyaml)
7. [Local Overrides File — `/etc/falco/falco_rules.local.yaml`](#7-local-overrides-file--etcfalcofalco_rules_localyaml)
8. [Overriding Rules — Changing Priority and Conditions](#8-overriding-rules--changing-priority-and-conditions)
9. [Writing Application-Specific Custom Rules](#9-writing-application-specific-custom-rules)
10. [Hot Reloading Configuration with SIGHUP](#10-hot-reloading-configuration-with-sighup)
11. [Complete Production `falco.yaml` Reference](#11-complete-production-falcoyaml-reference)
12. [As a DevSecOps / K8s Security Engineer](#12-as-a-devsecops--k8s-security-engineer)
13. [Real Present-Day Scenarios](#13-real-present-day-scenarios)
14. [What Happens If You Don't Follow This](#14-what-happens-if-you-dont-follow-this)
15. [Most Common Commands and Syntax](#15-most-common-commands-and-syntax)
16. [Other Tools and Services Available](#16-other-tools-and-services-available)
17. [How AI Is Impacting This Area](#17-how-ai-is-impacting-this-area)
18. [CKS Exam Tips](#18-cks-exam-tips)
19. [Links and References](#19-links-and-references)

---

## 1. Configuration Architecture Overview

Falco's configuration system is split across multiple files with a deliberate separation of concerns. Understanding this architecture prevents the most common production mistakes: custom rules being lost on upgrades, config changes not taking effect, and rules silently shadowing each other.

```
/etc/falco/
│
├── falco.yaml                    ← Main config: controls engine, output, and which rule files to load
│
├── falco_rules.yaml              ← Built-in ruleset (Falco-maintained, DO NOT EDIT)
│                                   Overwritten on every `apt upgrade falco`
│
├── falco_rules.local.yaml        ← Your custom rules and overrides (EDIT THIS FILE)
│                                   Preserved across upgrades
│
├── k8s_audit_rules.yaml          ← Kubernetes audit log rules (optional)
│
└── rules.d/                      ← Directory of additional rule files (all loaded automatically)
    ├── my-company-rules.yaml
    ├── compliance-rules.yaml
    └── application-rules.yaml
```

**The golden rule of Falco configuration:**
- `falco.yaml` controls the engine
- `falco_rules.yaml` is managed by the Falco project — never edit it
- `falco_rules.local.yaml` and `rules.d/` are yours — always edit these

### Configuration Evaluation Order

```
Falco starts
     │
     ▼
Reads /etc/falco/falco.yaml
     │
     ├── Loads engine settings (probe type, buffers, threads)
     ├── Loads output channel settings
     └── Reads rules_file list in ORDER:
              │
              ▼
         1. /etc/falco/falco_rules.yaml      (loaded first — baseline)
              │
              ▼
         2. /etc/falco/falco_rules.local.yaml (loaded second — overrides baseline)
              │
              ▼
         3. /etc/falco/k8s_audit_rules.yaml   (optional — audit log rules)
              │
              ▼
         4. /etc/falco/rules.d/               (any .yaml files in dir, alphabetical)
              │
              ▼
         RULE: Last definition of any rule/list/macro wins
```

---

## 2. Main Configuration File — `/etc/falco/falco.yaml`

The primary Falco configuration file at `/etc/falco/falco.yaml` is a YAML document that controls every aspect of the Falco engine's behaviour: which rule files to load, how to format output, which output channels to use, how the kernel probe behaves, and performance tuning parameters.

### 2.1 Verifying Which Config File Is In Use

When Falco starts, it logs the configuration file it's using. Verify this in the startup logs:

```bash
journalctl -u falco | grep "configuration file"
```

Expected output:
```
Apr 13 21:45:36 node01 falco[9817]: Falco initialized with configuration file /etc/falco/falco.yaml
```

You can also inspect the systemd unit file to see how Falco is invoked:

```bash
systemctl cat falco | grep "\-c"
# ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --pidfile=/var/run/falco.pid
```

The `-c` flag specifies the configuration file. If you need to run Falco with a different config (e.g., for testing), you can override it:

```bash
falco -c /path/to/custom-falco.yaml
```

### 2.2 Complete Startup Log Sequence

The KodeKloud lesson shows the full startup log:

```
-- Logs begin at Tue 2021-04-13 21:45:35 UTC, end at Tue 2021-04-13 21:51:31 UTC. --
Apr 13 21:45:36 node01 systemd[1]: Starting Falco: Container Native Runtime Security...
Apr 13 21:45:36 node01 systemd[1]: Started Falco: Container Native Runtime Security.
Apr 13 21:45:36 node01 falco[9817]: Falco version 0.28.0 (driver version 5c0b863ddade7a45568c0ac97d037422c9efb750)
Apr 13 21:45:36 node01 falco[9817]: Falco initialized with configuration file /etc/falco/falco.yaml
```

Reading the startup log tells you:
- Falco version (`0.28.0`)
- Driver version (the kernel probe build hash)
- Which config file is active
- Which rule files were loaded (look for `Loading rules from file` entries that follow)

A complete healthy startup sequence looks like:
```
falco[PID]: Falco version X.Y.Z
falco[PID]: Falco initialized with configuration file /etc/falco/falco.yaml
falco[PID]: Loading rules from file /etc/falco/falco_rules.yaml: ...
falco[PID]: Loading rules from file /etc/falco/falco_rules.local.yaml: ...
falco[PID]: Starting internal webserver, listening on port 8765
falco[PID]: eBPF probe loaded
```

If any rule file fails to load, you'll see an error here — making startup log review a critical first step in troubleshooting.

### 2.3 Editing the Config File

```bash
# View current config
cat /etc/falco/falco.yaml

# Edit with your preferred editor
vi /etc/falco/falco.yaml
nano /etc/falco/falco.yaml

# Validate configuration before restarting
falco --validate /etc/falco/falco.yaml

# Restart to apply changes
systemctl restart falco
# Or hot-reload (see Section 10)
kill -1 $(cat /var/run/falco.pid)
```

---

## 3. Rule File Loading — `rules_file` and Precedence

The `rules_file` key in `falco.yaml` is a YAML list that specifies which files Falco loads as rule sources. This is one of the most important configuration settings because it controls the entire detection surface.

### 3.1 Default Configuration

```yaml
# /etc/falco/falco.yaml (relevant excerpt)
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/k8s_audit_rules.yaml
  - /etc/falco/rules.d/
```

Falco processes this list **in order from top to bottom**. Each file is parsed and its rules, macros, and lists are merged into Falco's internal rule database.

### 3.2 The Override Precedence Rule

**The definition that appears last wins.**

This is the key mechanic that enables the entire override pattern. If `falco_rules.yaml` defines rule `Terminal shell in container` with `priority: NOTICE`, and `falco_rules.local.yaml` also defines `Terminal shell in container` with `priority: WARNING`, the WARNING definition wins because `falco_rules.local.yaml` is later in the list.

```
File loading order:
  1. falco_rules.yaml          → defines "Terminal shell in container" (NOTICE)
  2. falco_rules.local.yaml    → redefines "Terminal shell in container" (WARNING)

Result: Falco uses WARNING
        (the later definition completely replaces the earlier one)
```

This means:
- You never need to edit `falco_rules.yaml` to change a rule's priority, condition, or output
- Any rule can be overridden by repeating it in a later file
- New rules can be added by defining them in a later file

### 3.3 Directory Support (`rules.d/`)

When a path ending in `/` (or pointing to a directory) is listed in `rules_file`, Falco loads **all `.yaml` files in that directory** in alphabetical order.

```yaml
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d/          # Loads all .yaml files alphabetically
```

```
/etc/falco/rules.d/
├── 01-company-baseline.yaml     (loaded 1st)
├── 02-compliance-pci.yaml       (loaded 2nd)
├── 03-compliance-soc2.yaml      (loaded 3rd)
├── 10-team-backend.yaml         (loaded 4th)
└── 20-team-frontend.yaml        (loaded 5th)
```

Numbering files with prefixes (`01-`, `02-`) ensures deterministic loading order — critical when rules in later files intentionally override rules in earlier files.

### 3.4 Custom Rules File Structure (Recommended Pattern)

```yaml
# Recommended rules_file configuration for a production cluster
rules_file:
  - /etc/falco/falco_rules.yaml           # 1. Official built-in rules (never edit)
  - /etc/falco/falco_rules.local.yaml     # 2. Override file (your customisations)
  - /etc/falco/k8s_audit_rules.yaml       # 3. K8s API audit log rules (if enabled)
  - /etc/falco/rules.d/                   # 4. Per-team or per-app rule files
```

### 3.5 Adding Additional Custom Rule Directories

For large organisations with multiple teams:

```yaml
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d/
  - /etc/falco/rules.d.compliance/        # Compliance-team managed rules
  - /etc/falco/rules.d.applications/      # App-team managed rules
```

Each directory can be owned by a different team, managed by different Git repositories, and deployed independently — while all rules run in a single Falco engine.

### 3.6 Verifying Which Rules Were Loaded

```bash
# Check startup log for rule file loading
journalctl -u falco --since "5 minutes ago" | grep "Loading rules"

# Expected output:
# falco[9817]: Loading rules from file /etc/falco/falco_rules.yaml
# falco[9817]: Loading rules from file /etc/falco/falco_rules.local.yaml
# falco[9817]: Loading rules from file /etc/falco/rules.d/

# List all active rules
falco --list-rules

# Count rules per source
falco --list-rules | wc -l
```

---

## 4. Logging and Output Format Settings

The `falco.yaml` file controls how Falco formats its own internal logs (distinct from alert output) and which format alert events use.

### 4.1 JSON vs. Plain Text Output

```yaml
# /etc/falco/falco.yaml

# JSON output: false = plain text (default), true = JSON format
json_output: false
```

**Plain text output (json_output: false):**
```
May 16 12:34:56.789 Warning Sensitive file opened for reading by non-trusted program
(user=root program=cat command=cat /etc/shadow file=/etc/shadow container_id=abc123 image=nginx)
```

**JSON output (json_output: true):**
```json
{
  "output": "Sensitive file opened for reading by non-trusted program ...",
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": ["filesystem", "mitre_credential_access"],
  "time": "2024-05-16T12:34:56.789012345Z",
  "output_fields": {
    "container.id": "abc123def456",
    "fd.name": "/etc/shadow",
    "k8s.pod.name": "nginx",
    "proc.cmdline": "cat /etc/shadow",
    "user.name": "root"
  }
}
```

**When to use each:**
- `json_output: false` — Human reading logs directly via `journalctl`
- `json_output: true` — SIEM integration, Falcosidekick, automated parsing, Elasticsearch

```yaml
# Additional JSON option: include the "output" field in JSON events
json_include_output_property: true   # Default: true
```

### 4.2 Falco's Internal Log Settings

These control Falco's **own** log messages (startup messages, errors, debug info) — distinct from alert output:

```yaml
# Log Falco's own messages to stderr
log_stderr: true

# Log Falco's own messages to syslog
log_syslog: true

# Minimum log level for Falco's internal messages
# Options: emergency, alert, critical, error, warning, notice, info, debug
log_level: info
```

**Important distinction:**
- `log_level` controls the verbosity of Falco's own operational messages
- `priority` in a rule controls which alert levels get reported

Setting `log_level: debug` gives you verbose Falco internals (rule evaluation details, engine state) — useful for troubleshooting but very noisy in production. Use `log_level: info` or `log_level: warning` in production.

### 4.3 Priority Filter

```yaml
# Minimum priority for alert output
# Rules below this priority are loaded but alerts are suppressed
priority: debug      # Show all alerts (development)
priority: warning    # Show WARNING and above (production recommended)
priority: error      # Show ERROR and above (quieter, high-confidence only)
```

This is a global filter — it overrides individual rule priorities at the output level. A rule with `priority: NOTICE` will never produce output if `falco.yaml` has `priority: warning`.

```yaml
# Typical production config:
priority: warning

# This means:
# DEBUG rules    → no output
# INFORMATIONAL  → no output
# NOTICE         → no output
# WARNING        → output ✓
# ERROR          → output ✓
# CRITICAL       → output ✓
# ALERT          → output ✓
# EMERGENCY      → output ✓
```

### 4.4 Full Logging Configuration Section

```yaml
# /etc/falco/falco.yaml — logging section
json_output: true
json_include_output_property: true
log_stderr: true
log_syslog: true
log_level: info
priority: warning
buffered_outputs: false   # false = flush immediately (lower latency, recommended for security)
```

---

## 5. Output Channel Configuration

Falco supports multiple output channels simultaneously. All enabled channels receive every alert — they are not exclusive. In production, you typically enable 2–3 channels: `stdout` for local debugging, a file for log shippers, and HTTP for Falcosidekick.

### 5.1 Standard Output (`stdout_output`)

```yaml
stdout_output:
  enabled: true
```

Prints alerts to the process's standard output, captured by systemd and visible via `journalctl`. The simplest output channel — always enabled during development and testing.

### 5.2 File Output (`file_output`)

```yaml
file_output:
  enabled: true
  keep_alive: false     # true = keep file handle open; false = open/close per event
  filename: /opt/falco/events.txt
```

Writes alerts to a file. Used with log shippers (Fluent Bit, Filebeat, Logstash) that tail the file and forward events to Elasticsearch, Splunk, or Loki.

```yaml
# Production example: JSON file for Fluent Bit
file_output:
  enabled: true
  keep_alive: true      # Better performance for high-alert-volume environments
  filename: /var/log/falco/falco-events.json
```

**Important:** The directory must exist and be writable by the Falco process:
```bash
mkdir -p /var/log/falco
chown falco:falco /var/log/falco  # Or root if Falco runs as root
```

### 5.3 Program Output (`program_output`)

```yaml
program_output:
  enabled: true
  keep_alive: false
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/XXXX"
```

Pipes each alert to an external program or shell command. The alert text is passed on stdin. This enables arbitrary integrations:

```yaml
# Send to Slack via jq + curl
program_output:
  enabled: true
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/T00/B00/xxx"

# Send to a custom script
program_output:
  enabled: true
  program: "/usr/local/bin/falco-handler.sh"

# Send to a Python script for enrichment
program_output:
  enabled: true
  program: "python3 /opt/falco/enrich-and-route.py"
```

**Performance note:** `program_output` spawns a new process for each alert. At high alert rates this is expensive. Prefer `http_output` or `grpc_output` for high-volume environments.

### 5.4 HTTP Output (`http_output`)

```yaml
http_output:
  enabled: true
  url: "http://falcosidekick:2801/"    # Falcosidekick endpoint
  user_agent: "falco"
  insecure: false                       # Set true only in dev (skips TLS verification)
```

Sends alerts as JSON HTTP POST requests to a webhook endpoint. This is the primary integration method for Falcosidekick:

```
Falco → HTTP POST → Falcosidekick:2801 → Slack, PagerDuty, Datadog, JIRA, etc.
```

```yaml
# Production: TLS to a remote Falcosidekick
http_output:
  enabled: true
  url: "https://falcosidekick.monitoring.company.internal:2801/"
  user_agent: "falco/0.37.1"
  insecure: false
  ca_cert: /etc/ssl/company-ca.crt
```

### 5.5 syslog Output (`syslog_output`)

```yaml
syslog_output:
  enabled: true
```

Writes to the system syslog facility. Viewable via `journalctl` alongside other system logs, and automatically forwarded to any syslog aggregator (`rsyslog`, `syslog-ng`) configured on the host.

### 5.6 gRPC Output (`grpc_output`)

```yaml
grpc:
  enabled: true
  bind_address: "unix:///run/falco/falco.sock"  # Unix socket (preferred)
  # Or TCP:
  # bind_address: "0.0.0.0:5060"
  threadiness: 8                                  # Parallel gRPC worker threads

grpc_output:
  enabled: true
```

The gRPC interface is used by Falcosidekick and custom consumers that need the highest-performance, lowest-latency alert delivery. Recommended for production environments with >100 alerts/second.

### 5.7 Complete Output Section Example

```yaml
# /etc/falco/falco.yaml — output section
stdout_output:
  enabled: true             # Always on for journalctl access

syslog_output:
  enabled: true             # For syslog-based log aggregation

file_output:
  enabled: true
  keep_alive: true          # Better for high-volume
  filename: /var/log/falco/events.json

http_output:
  enabled: true
  url: "http://falcosidekick:2801/"
  user_agent: "falco"
  insecure: false

# Disable program output in production (performance)
program_output:
  enabled: false
```

---

## 6. Built-in Rules File — `/etc/falco/falco_rules.yaml`

The file `/etc/falco/falco_rules.yaml` is the **official Falco community ruleset**. It ships with Falco and contains hundreds of rules, macros, and lists covering common attack patterns.

### 6.1 What's Inside

```bash
# How many rules are in the default ruleset?
grep -c "^- rule:" /etc/falco/falco_rules.yaml

# How many macros?
grep -c "^- macro:" /etc/falco/falco_rules.yaml

# How many lists?
grep -c "^- list:" /etc/falco/falco_rules.yaml
```

A typical Falco installation has:
- ~100+ rules covering MITRE ATT&CK container techniques
- ~200+ macros for condition reuse
- ~50+ lists for item collections

### 6.2 The Terminal Shell in Container Rule (KodeKloud Example)

One of the most important built-in rules:

```yaml
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal
    (user=%user.name user_loginuid=%user.loginuid %container.info
     shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline
     terminal=%proc.tty container_id=%container.id
     image=%container.image.repository)
  priority: NOTICE
```

Dissecting this rule:

| Component | Value | Meaning |
|---|---|---|
| `spawned_process` | macro | `evt.type=execve and evt.dir=<` — a new process was created |
| `container` | macro | `container.id != host` — event is from inside a container |
| `shell_procs` | macro | `proc.name in (shell_binaries)` — the process is a shell |
| `proc.tty != 0` | condition | The process has an attached terminal (interactive) |
| `container_entrypoint` | macro | The shell was started directly (not by another shell) |
| `not user_expected_...` | macro | Excludes known-good cases (CI runners, debug sidecars) |
| `priority: NOTICE` | priority | Lower severity — shells are suspicious, not definitely malicious |

The `not user_expected_terminal_shell_in_container_conditions` macro is intentionally left flexible so organisations can add their own exceptions without overriding the whole rule.

### 6.3 The CRITICAL Rule — Never Edit This File

```yaml
# /etc/falco/falco_rules.yaml is managed by the Falco project.
# It is OVERWRITTEN on every:
#   apt upgrade falco
#   apt install falco (fresh install)
#   helm upgrade falco falcosecurity/falco

# Any direct edits are PERMANENTLY LOST on upgrade.
# Use /etc/falco/falco_rules.local.yaml instead.
```

### 6.4 Browsing Rules Without Opening the File

```bash
# List all rule names
falco --list-rules | grep "Rule:"

# Find rules related to a topic
grep -n "shell" /etc/falco/falco_rules.yaml | grep "^- rule:"

# View a specific rule and its surrounding context
grep -A 15 "Terminal shell in container" /etc/falco/falco_rules.yaml

# Find the definition of a specific macro
grep -A 3 "^- macro: container$" /etc/falco/falco_rules.yaml
```

---

## 7. Local Overrides File — `/etc/falco/falco_rules.local.yaml`

This file is **your workspace**. It ships empty (or with minimal examples) and is never overwritten by Falco upgrades. All custom rules, all overrides to built-in rules, all new lists and macros should live here.

### 7.1 File Location and Default Contents

```bash
# View the default file
cat /etc/falco/falco_rules.local.yaml
```

Default content (usually just a comment):
```yaml
# Add customizations for rules here.
# Note: These customizations will be applied AFTER the main falco_rules.yaml.
# This means any rule, list, or macro defined here with the same name as one
# in falco_rules.yaml will override the previous definition.
```

### 7.2 What To Put in This File

```
falco_rules.local.yaml should contain:
├── Overridden built-in rules (changed priority, condition, or output)
├── Exceptions to built-in rules (via macro override + append)
├── New lists for your environment (approved registries, trusted processes)
├── New macros for your condition patterns
└── New custom rules for your specific threat model
```

### 7.3 Structure of a Well-Organised Local Rules File

```yaml
# /etc/falco/falco_rules.local.yaml
#
# Organisation: Company Name
# Last updated: 2024-05-16
# Owner: Security Team <security@company.com>
#
# SECTION 1: Override built-in lists (add trusted processes)
# SECTION 2: Override built-in macros (add exceptions)
# SECTION 3: Override built-in rules (change priority/condition)
# SECTION 4: Custom lists for this environment
# SECTION 5: Custom macros for this environment
# SECTION 6: Custom rules for this environment

# =============================================================
# SECTION 1: Override built-in lists
# =============================================================

# Add our monitoring agent to trusted processes that read sensitive files
- list: sensitive_file_readers
  items: [datadog-agent, prometheus-exporter, node-exporter]
  override:
    items: append

# =============================================================
# SECTION 2: Override built-in macros (exceptions)
# =============================================================

# Allow our configuration management system to write to /etc
- macro: user_known_write_etc_conditions
  condition: proc.name in (chef-client, puppet, ansible-playbook)
  override:
    condition: append

# =============================================================
# SECTION 3: Override built-in rules (priority changes)
# =============================================================

- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal
    (user=%user.name user_loginuid=%user.loginuid %container.info
     shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline
     terminal=%proc.tty container_id=%container.id
     image=%container.image.repository)
  priority: WARNING    # Upgraded from NOTICE to WARNING

# =============================================================
# SECTION 4–6: Custom rules (see Section 9)
# =============================================================
```

---

## 8. Overriding Rules — Changing Priority and Conditions

The most common customisation task is modifying a built-in rule without editing the official rules file. The mechanism is simple: redefine the entire rule in `falco_rules.local.yaml`. Because it's loaded later, it replaces the built-in definition.

### 8.1 Changing a Rule's Priority (KodeKloud Example)

The built-in `Terminal shell in container` rule has `priority: NOTICE`. For a production cluster, you may want this to be `WARNING` so it gets routed to the on-call pager.

**In `falco_rules.local.yaml`:**

```yaml
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal (user=%user.name user_loginuid=%user.loginuid %container.info
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: WARNING
```

The entire rule definition is repeated with `priority: WARNING` changed. All other fields are identical to the original — you're only changing the priority.

**Result:** Falco loads the NOTICE version from `falco_rules.yaml`, then loads the WARNING version from `falco_rules.local.yaml`. The WARNING version wins. Shells in containers now generate WARNING-priority alerts.

### 8.2 Adding a Condition Exception (Safer Pattern)

Instead of repeating the entire rule, add an exception through the macro that the rule already uses:

```yaml
# The built-in rule uses this macro:
# "not user_expected_terminal_shell_in_container_conditions"

# Add your exceptions to that macro:
- macro: user_expected_terminal_shell_in_container_conditions
  condition: >
    container.image.repository in (
      "company/debug-container",
      "company/bastion",
      "tooling/kubectl-debug"
    )
  override:
    condition: append    # Append to the macro, don't replace it
```

This is cleaner than repeating the full rule because:
- When Falco upgrades and improves the rule condition, your exception still works
- The override is minimal and self-documenting
- You only maintain the exception logic, not the entire rule

### 8.3 Disabling a Rule Entirely

```yaml
# Method 1: Override with a condition that is never true
- rule: Unexpected outbound connection destination
  condition: never_true  # Built-in macro that evaluates to false
  override:
    condition: replace

# Method 2: Use the enabled field (Falco 0.28+)
- rule: Unexpected outbound connection destination
  enabled: false
```

Be cautious when disabling rules — document why each rule is disabled, and review periodically whether the reason still applies.

### 8.4 The Override Key (Modern Falco)

Modern Falco (0.28+) supports a cleaner `override` syntax:

```yaml
# Override the condition (replace or append)
- rule: My Rule
  condition: new_condition
  override:
    condition: replace    # Replace the whole condition

- rule: My Rule
  condition: and extra_condition
  override:
    condition: append     # Append to existing condition

# Override the output
- rule: My Rule
  output: "New output format (pod=%k8s.pod.name)"
  override:
    output: replace

# Override priority only
- rule: Terminal shell in container
  priority: WARNING
  override:
    priority: replace
```

---

## 9. Writing Application-Specific Custom Rules

Custom rules targeting specific application images or directories are among the most powerful Falco capabilities. The KodeKloud example introduces this pattern with a webapp-specific rule.

### 9.1 KodeKloud Example: Anomalous File Read Detection

```yaml
- rule: Anomalous read in kodekloud/webapp pod
  desc: Detect suspicious file reads in a custom webapp container.
  condition: >
    open_read and container
    and container.image.repository == "kodekloud/simple-webapp"
    and fd.directory != "/opt/app"
  output: >
    A file was opened and read outside the /opt/app directory
    (user=%user.name user_loginuid=%user.loginuid
     container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
```

**Rule Logic:** Any file read (`open_read`) inside a container running the `kodekloud/simple-webapp` image where the file is NOT in `/opt/app` triggers a CRITICAL alert.

This is a **whitelist-based detection** approach: instead of blacklisting known-bad paths, it defines the known-good path (`/opt/app`) and alerts on anything outside it. This is more comprehensive because you catch unknown-unknown reads — files the attacker accesses that you didn't specifically anticipate.

**Why this rule is powerful:**
- If an attacker gains RCE in this webapp and reads `/etc/shadow`, it's outside `/opt/app` → CRITICAL alert
- If they read `/proc/1/environ` (env vars, credentials) → CRITICAL alert
- If they access `/var/run/secrets/kubernetes.io` (service account) → CRITICAL alert
- Only files in `/opt/app` are allowed without alerting

### 9.2 Extending the Pattern — Adding Context

```yaml
- rule: Anomalous read in kodekloud/webapp pod
  desc: Detect suspicious file reads in a custom webapp container.
  condition: >
    open_read and container
    and container.image.repository = "kodekloud/simple-webapp"
    and fd.directory != "/opt/app"
    and fd.directory != "/proc/self"     # Exclude self-inspection (normal)
    and fd.directory != "/dev/null"      # Exclude /dev/null
    and not fd.name startswith "/proc/self/fd"
  output: >
    Anomalous file read in webapp container
    (user=%user.name uid=%user.uid
     container_id=%container.id container_name=%container.name
     image=%container.image.repository
     file=%fd.name directory=%fd.directory
     cmd=%proc.cmdline parent=%proc.pname
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [webapp, data_access, anomaly]
```

### 9.3 Complete Combined Example (Both Rules from KodeKloud)

The KodeKloud lesson shows placing both the overridden Terminal Shell rule AND the custom webapp rule in `falco_rules.local.yaml`:

```yaml
# /etc/falco/falco_rules.local.yaml

# Override 1: Upgrade "Terminal shell in container" from NOTICE to WARNING
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal (user=%user.name user_loginuid=%user.loginuid %container.info
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: WARNING

# Custom Rule: Detect anomalous file reads in webapp container
- rule: Anomalous read in kodekloud/webapp pod
  desc: Detect suspicious file reads in a custom webapp container.
  condition: >
    open_read and container
    and container.image.repository == "kodekloud/simple-webapp"
    and fd.directory != "/opt/app"
  output: >
    A file was opened and read outside the /opt/app directory (user=%user.name user_loginuid=%user.loginuid
    container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
```

### 9.4 More Custom Rule Patterns by Threat Type

**Pattern: Database container — alert on unexpected process execution**
```yaml
- rule: Unexpected process in database container
  desc: A process other than the database binary ran in a DB container
  condition: >
    container and
    spawned_process and
    container.image.repository in (mysql, postgres, mariadb, mongo) and
    proc.name not in (mysql, mysqld, postgres, mongod, mongos, pg_ctl, sh)
  output: >
    Unexpected process in DB container
    (proc=%proc.name image=%container.image.repository
     pod=%k8s.pod.name cmdline=%proc.cmdline)
  priority: ERROR
```

**Pattern: Secrets file access from application container**
```yaml
- list: secret_paths
  items:
    - /etc/shadow
    - /etc/sudoers
    - /root/.ssh
    - /var/run/secrets

- rule: Sensitive path accessed in application container
  condition: >
    open_read and container and
    fd.name pmatch (secret_paths)
  output: >
    Sensitive path accessed
    (file=%fd.name proc=%proc.name container=%container.name
     image=%container.image.repository pod=%k8s.pod.name)
  priority: ERROR
```

**Pattern: Namespace-specific monitoring**
```yaml
- rule: Any shell in production namespace
  desc: Interactive shells in production are prohibited
  condition: >
    container and spawned_process and
    shell_procs and
    k8s.ns.name = "production"
  output: >
    Shell in production namespace
    (user=%user.name shell=%proc.name pod=%k8s.pod.name
     container=%container.name image=%container.image.repository)
  priority: CRITICAL
```

---

## 10. Hot Reloading Configuration with SIGHUP

Restarting Falco completely (`systemctl restart falco`) causes a brief period where no monitoring occurs — the kernel probe is unloaded and reloaded. For high-security environments, this gap is unacceptable. Hot reloading solves this.

### 10.1 How Hot Reloading Works

Sending a `SIGHUP` (Signal Hang-Up, signal number 1) to the Falco process causes it to:
1. Re-read `/etc/falco/falco.yaml`
2. Reload all rule files listed in `rules_file`
3. Rebuild the internal rule database
4. Resume monitoring with the new configuration

**The kernel probe stays loaded throughout** — there is no monitoring gap.

### 10.2 The PID File

Falco writes its process ID to `/var/run/falco.pid` when it starts:

```bash
# View the current Falco PID
cat /var/run/falco.pid
7183
```

This file is what the hot-reload command uses to find the Falco process without having to use `pgrep`.

### 10.3 The Hot Reload Command

```bash
# Hot reload in one command (from KodeKloud):
kill -1 $(cat /var/run/falco.pid)
```

Breaking this down:
- `cat /var/run/falco.pid` → outputs the PID (e.g., `7183`)
- `kill -1 7183` → sends SIGHUP to PID 7183
- Falco receives SIGHUP → reloads config → continues monitoring without gap

### 10.4 Alternative Reload Methods

```bash
# Method 1: Direct PID (most reliable)
kill -1 $(cat /var/run/falco.pid)

# Method 2: Signal by name
kill -SIGHUP $(cat /var/run/falco.pid)

# Method 3: Using pkill (finds by process name)
pkill -SIGHUP falco

# Method 4: systemctl reload (wraps the SIGHUP)
systemctl reload falco

# Method 5: Full restart (causes monitoring gap — avoid if possible)
systemctl restart falco
```

### 10.5 Verifying the Reload Worked

After sending SIGHUP, check the logs for reload confirmation:

```bash
journalctl -u falco -n 30
```

Expected entries after reload:
```
May 16 12:45:00 node01 falco[7183]: Received signal 1 (SIGHUP), restarting...
May 16 12:45:00 node01 falco[7183]: Falco initialized with configuration file /etc/falco/falco.yaml
May 16 12:45:00 node01 falco[7183]: Loading rules from file /etc/falco/falco_rules.yaml
May 16 12:45:00 node01 falco[7183]: Loading rules from file /etc/falco/falco_rules.local.yaml
May 16 12:45:00 node01 falco[7183]: Reload complete. Monitoring resuming.
```

If your new custom rule was added correctly, it will appear in the `Loading rules` output.

### 10.6 When Reload Fails

If `falco_rules.local.yaml` has a syntax error, the reload will fail and Falco will log an error:

```
May 16 12:45:00 node01 falco[7183]: Error loading rules from /etc/falco/falco_rules.local.yaml:
                                     1 error(s) loading rules. Aborting rule reload.
```

In this case, **Falco keeps running with the previous (pre-reload) rules** — it does not crash. This is a safety mechanism: a broken config file doesn't take down monitoring.

**Always validate before reloading:**
```bash
# Validate BEFORE sending SIGHUP
falco --validate /etc/falco/falco.yaml && kill -1 $(cat /var/run/falco.pid)
```

---

## 11. Complete Production `falco.yaml` Reference

A heavily annotated, production-ready `falco.yaml`:

```yaml
# /etc/falco/falco.yaml
# Production configuration for a Kubernetes cluster

# =============================================================
# RULE FILES
# =============================================================
rules_file:
  - /etc/falco/falco_rules.yaml           # Official rules — do not edit
  - /etc/falco/falco_rules.local.yaml     # Local overrides and custom rules
  - /etc/falco/k8s_audit_rules.yaml       # K8s API audit rules (if enabled)
  - /etc/falco/rules.d/                   # Additional rule directories

# =============================================================
# ENGINE / PROBE SETTINGS
# =============================================================
# Which kernel instrumentation to use: "ebpf", "module", or "modern_ebpf"
# engine:
#   kind: ebpf

# =============================================================
# OUTPUT FORMAT
# =============================================================
# false = plain text, true = JSON (recommended for SIEM/Falcosidekick)
json_output: true

# Include the "output" string field in JSON events
json_include_output_property: true

# Include raw tags in JSON output
json_include_tags_property: true

# Minimum severity for alert output
# Options: debug, informational, notice, warning, error, critical, alert, emergency
priority: warning

# Flush output buffers immediately (lower latency, recommended for security)
buffered_outputs: false

# =============================================================
# FALCO'S OWN LOGGING (not alerts — Falco's internal messages)
# =============================================================
log_stderr: true         # Log to stderr (captured by journalctl)
log_syslog: true         # Log to syslog
log_level: info          # Internal log verbosity: debug, info, warning, error

# =============================================================
# OUTPUT CHANNELS
# =============================================================
stdout_output:
  enabled: true

syslog_output:
  enabled: true

file_output:
  enabled: true
  keep_alive: true
  filename: /var/log/falco/falco-events.json

http_output:
  enabled: true
  url: "http://falcosidekick:2801/"
  user_agent: "falco"
  insecure: false

program_output:
  enabled: false          # Disabled in production (performance)

# gRPC for programmatic consumers
grpc:
  enabled: false          # Enable if using Falcosidekick via gRPC
  bind_address: "unix:///run/falco/falco.sock"
  threadiness: 8

grpc_output:
  enabled: false

# =============================================================
# SYSCALL BUFFERING (PERFORMANCE TUNING)
# =============================================================
syscall_event_drops:
  actions:
    - log
    - alert
  rate: 0.03333           # 1 alert per 30 seconds for drops
  max_burst: 10

# Buffer size for syscall events (increase if drops are frequent)
# syscall_buf_size_preset: 4   # 0-8, higher = more memory, fewer drops

# =============================================================
# WEBSERVER (for liveness/health checks)
# =============================================================
webserver:
  enabled: true
  listen_port: 8765
  k8s_healthz_endpoint: /healthz
  ssl_enabled: false

# =============================================================
# FALCO METRICS (Prometheus)
# =============================================================
metrics:
  enabled: true
  interval: 15s
  output_rule: true
  resource_utilization_enabled: true
```

---

## 12. As a DevSecOps / K8s Security Engineer

### 12.1 Configuration Management Strategy

In production, Falco configuration files should be managed as infrastructure code:

```
Git Repository: falco-config/
├── base/
│   ├── falco.yaml                      # Base config
│   └── falco_rules.local.yaml          # Base overrides
├── overlays/
│   ├── production/
│   │   ├── falco.yaml                  # Prod-specific (WARNING+ priority, JSON output)
│   │   └── falco_rules.local.yaml      # Prod-specific exceptions
│   └── staging/
│       ├── falco.yaml                  # Staging (DEBUG priority, verbose)
│       └── falco_rules.local.yaml      # Staging-specific exceptions
└── rules.d/
    ├── compliance-pci.yaml
    ├── compliance-soc2.yaml
    └── team-backend-rules.yaml
```

Deploy via:
- **Helm values** for DaemonSet (rules in ConfigMaps)
- **Ansible/Chef/Puppet** for node-installed Falco
- **Kustomize** for environment-specific overlays

### 12.2 Rule Review Process

Every custom rule addition should go through a review process:

```
Developer proposes rule →
  Security team reviews for:
    ├── False positive risk (is the condition too broad?)
    ├── Performance impact (does the condition hit every event?)
    ├── Coverage gaps (does it miss variants of the attack?)
    └── MITRE mapping (which technique does this cover?)
  Test in staging (event-generator + manual testing) →
  Measure false positive rate (first 48 hours) →
  Tune if >10% FP rate →
  Promote to production
```

### 12.3 Operational Runbook for Config Changes

```bash
# Standard procedure for adding/changing Falco rules:

# 1. Edit the local rules file
nano /etc/falco/falco_rules.local.yaml

# 2. Validate before reloading (critical — don't skip)
falco --validate /etc/falco/falco.yaml
echo "Exit code: $?"  # 0 = valid, non-zero = errors

# 3. Hot-reload (no monitoring gap)
kill -1 $(cat /var/run/falco.pid)

# 4. Verify reload succeeded
journalctl -u falco -n 20 | grep -E "(Loading|Error|Reload)"

# 5. Test the new rule
# (perform the action the rule should detect)

# 6. Confirm alert appeared
journalctl -fu falco | grep "your-rule-name"
```

### 12.4 Debugging Rule Not Firing

If a rule you wrote isn't generating alerts when you expect it to:

```bash
# Step 1: Confirm the rule is loaded
falco --list-rules | grep "your rule name"

# Step 2: Check for syntax errors in the log
journalctl -u falco --since "5 minutes ago" | grep "Error"

# Step 3: Run Falco in verbose/debug mode temporarily
falco -c /etc/falco/falco.yaml --debug 2>&1 | grep "your rule name"

# Step 4: Check if the condition is correct
# Use strace/bpftrace to verify the syscall is being generated
strace -e trace=openat cat /the/file/in/question

# Step 5: Check if priority filter is suppressing it
grep "priority" /etc/falco/falco.yaml
# If priority: error, a WARNING rule won't output

# Step 6: Trace event through the system
falco --print-base64 -r /tmp/test-rule.yaml
```

---

## 13. Real Present-Day Scenarios

### Scenario 1: Priority Escalation — PCI DSS Compliance

A financial services company needs their Falco deployment to page on-call immediately for any container reading sensitive financial data files, but the default rule fires at NOTICE (which isn't routed to PagerDuty in their setup).

**Solution in `falco_rules.local.yaml`:**
```yaml
# Upgrade Read sensitive file from NOTICE to CRITICAL for PCI compliance
- rule: Read sensitive file untrusted
  condition: >
    sensitive_files and open_read
    and not proc.name in (trusted_processes)
    and container
  output: >
    [PCI-DSS] Sensitive file accessed in container
    (user=%user.name file=%fd.name container=%container.name
     image=%container.image.repository pod=%k8s.pod.name
     ns=%k8s.ns.name cmdline=%proc.cmdline)
  priority: CRITICAL    # Upgraded from WARNING to CRITICAL
  tags: [pci-dss, sensitive-data, mitre_credential_access]
```

**Falcosidekick routes CRITICAL → PagerDuty → on-call engineer paged within 30 seconds.**

### Scenario 2: Multi-Team Environment — Per-Team Rules

A platform team supports 5 product teams, each with different security profiles:

```
/etc/falco/rules.d/
├── 00-platform-baseline.yaml       # Platform team: base rules
├── 10-team-payments.yaml           # Payments team: strict PCI rules
├── 20-team-analytics.yaml          # Analytics: allow more data access
├── 30-team-infrastructure.yaml     # Infra: allow system tools
└── 40-team-ml.yaml                 # ML team: GPU/compute access patterns
```

Each team owns their file via GitOps. Changes go through PR review by the security team. The platform baseline can't be overridden by team files (controlled by numerical prefix order).

### Scenario 3: Application Image Whitelisting

A company's production cluster should only run images from their internal registry (`registry.company.internal`). Any container from Docker Hub or other registries indicates either a misconfiguration or a supply chain attack.

```yaml
# In falco_rules.local.yaml
- list: approved_image_prefixes
  items:
    - "registry.company.internal"
    - "gcr.io/company-project"

- rule: Unapproved container image in production
  desc: A container is running from an unapproved registry
  condition: >
    container and
    container.image.repository not in (approved_image_prefixes) and
    not container.image.repository startswith "registry.company.internal" and
    k8s.ns.name != "kube-system" and
    k8s.ns.name != "falco"
  output: >
    Unapproved image running in production
    (image=%container.image.repository:%container.image.tag
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
```

### Scenario 4: Hot Reload in a Change Freeze Window

During a production change freeze, a new CVE is disclosed that allows remote code execution in a popular container base image. The security team needs to add a Falco rule to detect exploitation attempts — but they cannot do a full Falco restart (change freeze prohibits service restarts).

**Solution:** Hot reload via SIGHUP — no systemd service restart, no monitoring gap, zero downtime. Rule added, validated, and live within 2 minutes of the CVE being disclosed.

```bash
# During change freeze:
echo "New rule added for CVE-2024-XXXXX" >> /etc/falco/falco_rules.local.yaml
cat >> /etc/falco/falco_rules.local.yaml << 'EOF'
- rule: Detect CVE-2024-XXXXX Exploitation
  desc: Detects command injection via vulnerable library
  condition: container and proc.name = sh and proc.pname = java
  output: Possible CVE-2024-XXXXX exploitation (pod=%k8s.pod.name)
  priority: CRITICAL
EOF

falco --validate /etc/falco/falco.yaml && \
  kill -1 $(cat /var/run/falco.pid) && \
  echo "Rule deployed without service restart"
```

---

## 14. What Happens If You Don't Follow This

### Editing `falco_rules.yaml` Directly

```bash
# You do this:
vi /etc/falco/falco_rules.yaml
# Add 20 custom rules

# Three months later:
apt upgrade falco
# Falco package manager overwrites /etc/falco/falco_rules.yaml
# Your 20 custom rules are GONE
# You won't notice until an attack occurs that those rules would have caught
```

The package upgrade doesn't warn you. The file is simply replaced with the new version. This is not a Falco bug — it's the expected behaviour of package management.

### Wrong File Order in `rules_file`

```yaml
# WRONG: Local file before official rules
rules_file:
  - /etc/falco/falco_rules.local.yaml    # Loaded first
  - /etc/falco/falco_rules.yaml          # Loaded second — OVERRIDES your local file

# Result: Your overrides in falco_rules.local.yaml are REPLACED by
# the built-in definitions from falco_rules.yaml.
# Your priority change from NOTICE to WARNING is silently reverted.
```

### Not Validating Before Reload

```bash
# You add a rule with a syntax error:
echo "- rule: Bad Rule" >> /etc/falco/falco_rules.local.yaml
echo "  condition: [this is not valid YAML or condition syntax" >> /etc/falco/falco_rules.local.yaml

# You reload without validating:
kill -1 $(cat /var/run/falco.pid)

# Falco tries to reload, fails on the bad rule file,
# and KEEPS THE PREVIOUS RULE SET active.
# Your new rule is not loaded.
# You might not notice for hours.
# During that time, the threat you were trying to detect goes undetected.
```

Always validate: `falco --validate /etc/falco/falco.yaml` before reloading.

### `json_output: false` in a Multi-Node SIEM Environment

```yaml
# falco.yaml with plain text output:
json_output: false

# Consequence: Filebeat/Fluent Bit trying to parse structured fields
# gets unstructured text instead.
# SIEM dashboards show garbled data.
# Alert correlation fails (can't join on container_id across events).
# Compliance reports can't be generated automatically.
```

In any environment with log aggregation, always set `json_output: true`.

### Not Using `program_output` Slack Integration at Scale

```yaml
# You configure program_output to post to Slack:
program_output:
  enabled: true
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/..."

# In a high-alert environment (500 alerts/minute):
# Each alert spawns a new process (fork + exec)
# 500 fork+exec per minute = significant CPU overhead
# Shell rate-limits kick in
# curl requests get throttled
# Slack webhook rate limits (1 message/second) cause most alerts to be DROPPED
```

Use Falcosidekick with `http_output` instead — it buffers, batches, and respects rate limits correctly.

---

## 15. Most Common Commands and Syntax

### Config File Management

```bash
# View main config
cat /etc/falco/falco.yaml

# View built-in rules (read-only reference)
cat /etc/falco/falco_rules.yaml | head -100

# Edit local rules (your workspace)
vi /etc/falco/falco_rules.local.yaml
nano /etc/falco/falco_rules.local.yaml

# Check file sizes
wc -l /etc/falco/falco_rules.yaml
wc -l /etc/falco/falco_rules.local.yaml

# Count rules in each file
grep -c "^- rule:" /etc/falco/falco_rules.yaml
grep -c "^- rule:" /etc/falco/falco_rules.local.yaml
```

### Validation

```bash
# Validate falco.yaml and all rule files
falco --validate /etc/falco/falco.yaml

# Validate a specific rules file in isolation
falco -r /etc/falco/falco_rules.local.yaml --validate

# Validate with detailed error messages
falco --validate /etc/falco/falco.yaml 2>&1 | grep -E "Error|Warning|OK"

# Safe reload (validate before hot-reload)
falco --validate /etc/falco/falco.yaml && kill -1 $(cat /var/run/falco.pid) \
  || echo "Validation failed — NOT reloading"
```

### Hot Reload

```bash
# View PID
cat /var/run/falco.pid

# Hot reload (primary method)
kill -1 $(cat /var/run/falco.pid)

# Alternative with SIGHUP name
kill -SIGHUP $(cat /var/run/falco.pid)

# Using pkill
pkill -SIGHUP falco

# Via systemctl
systemctl reload falco

# Full restart (causes monitoring gap)
systemctl restart falco

# Verify reload succeeded
journalctl -u falco -n 20 | grep -E "(Loading rules|Reload|Error)"
```

### Checking Configuration Settings

```bash
# Which config file is in use?
journalctl -u falco | grep "configuration file"

# Which rule files are loaded?
journalctl -u falco | grep "Loading rules"

# What priority filter is active?
grep "^priority:" /etc/falco/falco.yaml

# Is JSON output enabled?
grep "^json_output:" /etc/falco/falco.yaml

# Which output channels are enabled?
grep -A 2 "_output:" /etc/falco/falco.yaml | grep "enabled:"
```

### Priority Change Template

```yaml
# Change any rule's priority in falco_rules.local.yaml:
- rule: <Exact Rule Name From falco_rules.yaml>
  desc: <Copy desc from original>
  condition: >
    <Copy condition from original exactly>
  output: >
    <Copy output from original exactly>
  priority: <NEW_PRIORITY>    # Change only this line
```

### Application-Specific Rule Template

```yaml
- rule: Anomalous access in <application> container
  desc: Detect unexpected file/process activity in <application>
  condition: >
    open_read and container
    and container.image.repository = "<your-image>"
    and fd.directory != "<allowed-directory>"
  output: >
    Unexpected file access in <application>
    (user=%user.name file=%fd.name container=%container.name
     pod=%k8s.pod.name ns=%k8s.ns.name cmdline=%proc.cmdline)
  priority: CRITICAL
```

---

## 16. Other Tools and Services Available

### 16.1 Configuration Management Integration

**Ansible role for Falco config deployment:**
```yaml
- name: Deploy Falco local rules
  template:
    src: falco_rules.local.yaml.j2
    dest: /etc/falco/falco_rules.local.yaml
    validate: "falco -r %s --validate"
  notify: reload falco

handlers:
  - name: reload falco
    shell: kill -1 $(cat /var/run/falco.pid)
```

**Helm ConfigMap for DaemonSet:**
```yaml
# In Helm values.yaml
customRules:
  company-rules.yaml: |
    - rule: Terminal shell in container
      priority: WARNING
      override:
        priority: replace
    - rule: Custom App Rule
      ...
```

### 16.2 Falcosidekick UI — Visual Config Inspector

```bash
# Deploy Falcosidekick UI alongside Falcosidekick
helm upgrade falco falcosecurity/falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --namespace falco

# Access the UI
kubectl port-forward svc/falco-falcosidekick-ui 2802:2802 -n falco
# Browser: http://localhost:2802
```

The UI shows:
- Real-time alert stream with filtering
- Alert volume over time
- Rule hit frequency (shows which rules are firing most)
- Priority distribution

### 16.3 `falcoctl` — Rule Artifact Management

```bash
# List available rule artifact versions
falcoctl artifact search falco-rules

# Install the latest community rules
falcoctl artifact install falco-rules

# Pull rules from a custom OCI registry
falcoctl artifact pull ghcr.io/company/falco-rules:v1.2.0

# Configure auto-update (in falco.yaml for Helm deployments)
falcoctl:
  artifact:
    follow:
      enabled: true
      refs:
        - falco-rules:latest
      every: 6h              # Check for updates every 6 hours
```

### 16.4 Open Policy Agent (OPA) vs Falco

| Aspect | OPA Gatekeeper | Falco |
|---|---|---|
| When it runs | Admission time (before pod creates) | Runtime (during pod execution) |
| What it sees | Pod spec, CRD definitions | Actual syscalls, process trees |
| Can block? | Yes (deny admission) | Alert only (unless using Talon) |
| Config format | Rego policies | YAML + condition language |
| Kubernetes CVEs | Admission-time enforcement | Runtime behaviour anomalies |
| Complementary? | Yes — use both |

They are complementary, not competitive. OPA prevents misconfigured workloads from deploying. Falco detects unexpected behaviour once they're running.

---

## 17. How AI Is Impacting This Area

### 17.1 AI-Generated falco.yaml Configurations

LLMs can generate environment-specific `falco.yaml` configurations from requirements:

```
Prompt: "Generate a production Falco config for a PCI-DSS environment 
        running on GKE with 200 nodes. We need JSON output to 
        Elasticsearch, Slack alerting for CRITICAL+, PagerDuty for 
        EMERGENCY. Priority filter at WARNING."

Output: Complete falco.yaml with all output channels, priority settings,
        and appropriate performance tuning for 200 nodes.
```

### 17.2 AI-Powered Rule Validation

Beyond syntax checking, AI can validate rule logic:
- "This condition will trigger on every process start in every container — performance issue"
- "This condition uses `fd.name = /etc/shadow` but should use `contains` for variants like `/etc/shadow-`"
- "This rule duplicates the built-in `Read sensitive file untrusted` — consider overriding instead"

### 17.3 Auto-Generated Rule Exceptions

After deploying Falco, ML models analyze the false positive patterns and auto-generate exception lists:

```
Observed: prometheus-exporter reading /proc/PID/status → False positive
Observed: node-exporter reading /sys/class/net/* → False positive
Observed: datadog-agent reading /etc/hostname → False positive

AI generates:
- list: monitoring_agent_processes
  items: [prometheus, node-exporter, datadog-agent, ...]

- macro: monitoring_agent_activity
  condition: proc.name in (monitoring_agent_processes)
```

These suggested exceptions are presented for human review before deployment.

### 17.4 Natural Language Rule Search

Instead of `grep`-ing through rule files, AI enables natural language queries:

```
"Which rules would fire if an attacker ran netcat inside a container?"
→ AI searches rule conditions for network-related process detection
→ Returns: ["Netcat Remote Code Execution in Container", "Launch Remote File Copy Tools in Container", "Outbound Connection from Shell Process"]
```

### 17.5 Continuous Configuration Drift Detection

AI monitors the Falco config across the fleet and alerts on drift:

```
Node01: falco_rules.local.yaml SHA256 = abc123
Node02: falco_rules.local.yaml SHA256 = abc123
Node03: falco_rules.local.yaml SHA256 = xyz789  ← DRIFT DETECTED

AI Alert: "Node03's local rules file differs from the fleet baseline.
          3 rules are missing, 1 rule has a modified condition.
          This could indicate an unauthorized change or a failed deployment."
```

---

## 18. CKS Exam Tips

Falco configuration is one of the most directly tested areas in the CKS. The exam presents practical scenarios where you must edit config files, reload Falco, and verify results.

### Highest-Probability Exam Tasks

1. **"Change the priority of rule X from NOTICE to WARNING"**
2. **"Add a custom rule to detect file reads outside /opt/app in a specific container"**
3. **"Reload Falco without a full restart after making rule changes"**
4. **"Enable JSON output for Falco"**
5. **"Add a custom output channel (file output)"**

### The Critical File Paths (Memorise These)

| File | Purpose | Edit? |
|---|---|---|
| `/etc/falco/falco.yaml` | Main config | Yes — output channels, priority, rules_file |
| `/etc/falco/falco_rules.yaml` | Built-in rules | **NEVER** |
| `/etc/falco/falco_rules.local.yaml` | Custom rules / overrides | **Always use this** |
| `/var/run/falco.pid` | Falco's PID for hot-reload | Read only |
| `/etc/falco/rules.d/` | Additional rule directory | Add files here |

### The Exam Priority Change Workflow

```bash
# Step 1: Check the current priority in the built-in file
grep -A 10 "Terminal shell in container" /etc/falco/falco_rules.yaml | grep priority
# priority: NOTICE

# Step 2: Open the local file
vi /etc/falco/falco_rules.local.yaml

# Step 3: Add the override (copy entire rule, change only priority)
# (paste from falco_rules.yaml, change NOTICE to WARNING)

# Step 4: Validate
falco --validate /etc/falco/falco.yaml

# Step 5: Hot-reload
kill -1 $(cat /var/run/falco.pid)

# Step 6: Verify
journalctl -u falco -n 10 | grep "Loading rules"
```

### The Exam Custom Rule Workflow

```bash
# Step 1: Open local file
vi /etc/falco/falco_rules.local.yaml

# Step 2: Add rule (use the template)
cat >> /etc/falco/falco_rules.local.yaml << 'EOF'
- rule: Anomalous read in webapp container
  desc: Detect file reads outside allowed directory in webapp
  condition: >
    open_read and container
    and container.image.repository = "kodekloud/simple-webapp"
    and fd.directory != "/opt/app"
  output: >
    File read outside allowed dir
    (user=%user.name file=%fd.name container=%container.name
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
EOF

# Step 3: Validate
falco --validate /etc/falco/falco.yaml

# Step 4: Reload
kill -1 $(cat /var/run/falco.pid)
```

### Exam Traps

**Trap 1: Editing falco_rules.yaml (then the exam asks you to verify it survives upgrade)**
→ Always use `falco_rules.local.yaml`

**Trap 2: Forgetting that later files override earlier files**
→ Your override in `falco_rules.local.yaml` must come AFTER `falco_rules.yaml` in the `rules_file` list

**Trap 3: Using `systemctl restart` when the question asks for "no monitoring gap"**
→ Use `kill -1 $(cat /var/run/falco.pid)` for hot-reload

**Trap 4: Not validating before reloading**
→ Always run `falco --validate /etc/falco/falco.yaml` first

**Trap 5: Priority filter blocking your new rule**
→ If `priority: error` is set in falco.yaml, a `priority: WARNING` rule will never output alerts
→ Check: `grep "^priority:" /etc/falco/falco.yaml`

### Key Facts for the Exam

| Question | Answer |
|---|---|
| Where are built-in rules? | `/etc/falco/falco_rules.yaml` |
| Where should custom rules go? | `/etc/falco/falco_rules.local.yaml` |
| Why not edit falco_rules.yaml? | Overwritten on apt upgrade |
| How to reload without restart? | `kill -1 $(cat /var/run/falco.pid)` |
| What does SIGHUP do to Falco? | Reloads config and rules without stopping the probe |
| How to enable JSON output? | `json_output: true` in falco.yaml |
| How to add file output? | Add `file_output.enabled: true` + `filename:` |
| Which file takes precedence? | The LATER file in the rules_file list |
| How to validate before reload? | `falco --validate /etc/falco/falco.yaml` |

---

## 19. Links and References

- [Falco Configuration Reference](https://falco.org/docs/reference/daemon/config-options/)
- [Falco Rules Reference](https://falco.org/docs/rules/)
- [falco_rules.yaml Source on GitHub](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [Falco Hot Reload Documentation](https://falco.org/docs/faq/)
- [Falcosidekick Output Integrations](https://github.com/falcosecurity/falcosidekick)
- [Falco Rule Override Mechanism](https://falco.org/docs/rules/overriding/)
- [Falco Helm Chart Configuration](https://github.com/falcosecurity/charts/tree/master/charts/falco)
- [falcoctl Artifact Management](https://github.com/falcosecurity/falcoctl)
- [Falco JSON Output Schema](https://falco.org/docs/alerts/)

---

*Chapter 4 of 6 — Monitoring, Logging and Runtime Security*
*Next: Chapter 5 — Mutable vs Immutable Infrastructure*
