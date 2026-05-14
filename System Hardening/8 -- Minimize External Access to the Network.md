# 8 — Minimize External Access to the Network

> **What you'll learn:** What "external access" means in a Kubernetes context, how to verify what is exposed on your servers, the two primary approaches to network security (perimeter vs host-based), how layered defence-in-depth works, the key tools available at each layer, and how to systematically reduce your cluster's network attack surface.

---

## Table of Contents

1. [What is External Network Access?](#1-what-is-external-network-access)
2. [Why Minimising External Access Matters](#2-why-minimising-external-access-matters)
3. [Verifying What Your Server Exposes](#3-verifying-what-your-server-exposes)
4. [Understanding Network Exposure — 0.0.0.0 vs 127.0.0.1](#4-understanding-network-exposure--0000-vs-127001)
5. [Analysing a Real netstat Output](#5-analysing-a-real-netstat-output)
6. [Two Approaches to Network Security](#6-two-approaches-to-network-security)
7. [Layer 1 — Network-Wide Security (Perimeter Firewalls)](#7-layer-1--network-wide-security-perimeter-firewalls)
8. [Layer 2 — Server-Level Security (Host-Based Firewalls)](#8-layer-2--server-level-security-host-based-firewalls)
9. [Layer 3 — Cloud Security Groups](#9-layer-3--cloud-security-groups)
10. [Layer 4 — Kubernetes Network Policies](#10-layer-4--kubernetes-network-policies)
11. [Defence-in-Depth: All Four Layers Together](#11-defence-in-depth-all-four-layers-together)
12. [Scoping Services to the Right Interface](#12-scoping-services-to-the-right-interface)
13. [Real-World Scenarios](#13-real-world-scenarios)
14. [Common Mistakes & Gotchas](#14-common-mistakes--gotchas)
15. [CKS Exam Tips](#15-cks-exam-tips)

---

## 1. What is External Network Access?

"External access" means any network connection that originates from **outside a defined trust boundary**. What counts as "external" depends on your context:

```mermaid
flowchart LR
    subgraph INTERNET["🌍 Internet (Untrusted)"]
        EXT["External Users\nAttackers\nBots & Scanners"]
    end

    subgraph CORP["🏢 Corporate Network (Semi-trusted)"]
        CORP_USER["Developers\nAdmin Laptops"]
        VPN["VPN Gateway"]
    end

    subgraph CLUSTER["☸️ Kubernetes Cluster (Trusted)"]
        subgraph CP["Control Plane"]
            API["kube-apiserver :6443"]
            ETCD["etcd :2379"]
        end
        subgraph WORKER["Worker Nodes"]
            KL["kubelet :10250"]
            PODS["Pods"]
        end
    end

    EXT -->|"Should be blocked\nfor most K8s ports"| CLUSTER
    CORP_USER -->|"VPN → SSH :22\nkubectl → :6443"| CLUSTER
    EXT -->|"Scanners probe\nopen ports"| CLUSTER
    CORP_USER --> VPN --> CLUSTER

    style INTERNET fill:#ff6b6b,color:#fff
    style CLUSTER fill:#6bcb77,color:#fff
    style CORP fill:#ffd93d,color:#333
```

### Three Zones to Protect

| Zone Boundary | "External" Means | Enforcement Tool |
|---|---|---|
| **Internet → Network** | Any traffic from the public internet | Perimeter firewall, cloud security groups |
| **Network → Server** | Any traffic from the corporate LAN | Host-based firewall (UFW, iptables) |
| **Node → Pod** | Traffic from outside the pod's namespace | Kubernetes NetworkPolicy |
| **Pod → Pod** | Cross-namespace or cross-service traffic | Kubernetes NetworkPolicy |

---

## 2. Why Minimising External Access Matters

```mermaid
mindmap
  root((Why Minimise\nExternal Access?))
    Reduce Attack Surface
      Every open port reachable from internet is a target
      Unpatched services = immediate exploit
      Unknown open ports = forgotten vulnerabilities
    Prevent Reconnaissance
      Attackers scan ports to map infrastructure
      Open ports reveal what software you run
      Service banners reveal versions and CVEs
    Limit Blast Radius
      Breach of one exposed service
      Should not reach internal services
      Segmentation contains the damage
    Compliance Requirements
      PCI-DSS Req 1 — firewall between internet and card data
      HIPAA — network access controls required
      SOC 2 CC6.6 — external network access restricted
    Kubernetes Specific
      etcd must never be internet-accessible
      kubelet API must be restricted
      Dashboard must never be public
      kubectl proxy must not run persistently
```

### What Happens Without Network Restriction

```mermaid
sequenceDiagram
    participant ATK as 🔴 Attacker (Internet)
    participant SCAN as Port Scanner
    participant NODE as Kubernetes Node
    participant ETCD as etcd :2379
    participant CLUSTER as Full Cluster

    ATK->>SCAN: Run nmap -sT -p 1-65535 <node-ip>
    SCAN-->>ATK: PORT 2379/tcp OPEN (etcd!)
    ATK->>ETCD: curl http://node-ip:2379/v2/keys/?recursive=true
    ETCD-->>ATK: All cluster secrets, tokens, configs
    ATK->>CLUSTER: Use cluster-admin token to kubectl
    CLUSTER-->>ATK: Full cluster access 💀
```

This is not theoretical — this exact attack happened repeatedly with exposed etcd instances in 2018.

---

## 3. Verifying What Your Server Exposes

Before you can restrict external access, you need to know exactly what is currently exposed.

### Check SSH Service Status

```bash
# Is SSH running and on which address?
systemctl status ssh

# What port is SSH registered for?
cat /etc/services | grep ssh
# ssh    22/tcp    # SSH Remote Login Protocol
# ssh    22/udp    # SSH Remote Login Protocol

# Verify actual listening address
ss -tlpn | grep sshd
# tcp  LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234))
# 0.0.0.0 = all interfaces = reachable from anywhere on the network!
```

### Full Port Exposure Audit

```bash
# Method 1 — netstat (classic)
netstat -an | grep -w LISTEN

# Method 2 — ss (modern, preferred)
sudo ss -tulpn

# Method 3 — lsof (verbose, shows file descriptors)
sudo lsof -i -P -n | grep LISTEN

# Method 4 — scan yourself from outside perspective
sudo nmap -sT -p 1-65535 $(hostname -I | awk '{print $1}')

# Method 5 — scan from another node in the cluster
# This shows what is ACTUALLY reachable, accounting for all firewall rules
nmap -sT 10.0.1.10   # From worker node to control plane
```

---

## 4. Understanding Network Exposure — 0.0.0.0 vs 127.0.0.1

The **binding address** of a service is the most important field to understand when assessing exposure:

```mermaid
flowchart TD
    subgraph ADDR["Listening Address Meanings"]
        A1["127.0.0.1:port\nLoopback only\nOnly processes on THIS machine\ncan connect — NOT network accessible"]

        A2["10.x.x.x:port (specific IP)\nOnly clients reaching THIS interface\nCan be internal-only if IP is private\nBut reachable from network"]

        A3["0.0.0.0:port\nAll IPv4 interfaces\nAny machine on ANY network\ncan try to connect"]

        A4[":::port (IPv6 all interfaces)\nAll IPv6 interfaces\nEquivalent to 0.0.0.0 for IPv6\nRisky if IPv6 is enabled"]
    end

    A1 -->|"Safe — no external access"| SAFE["✅ Not network accessible"]
    A2 -->|"Depends on network scope\nand firewall rules"| PARTIAL["⚠️ Partially exposed"]
    A3 -->|"Accessible from anywhere\nif no firewall"| RISK["🔴 Fully exposed"]
    A4 -->|"Same risk as 0.0.0.0"| RISK

    style SAFE fill:#6bcb77,color:#fff
    style PARTIAL fill:#ffd93d,color:#333
    style RISK fill:#ff6b6b,color:#fff
```

### Quick Exposure Classification

```bash
# Classify all listening ports by exposure level
sudo ss -tulpn | grep LISTEN | while read line; do
    addr=$(echo $line | awk '{print $5}')
    port=$(echo $addr | rev | cut -d: -f1 | rev)
    ip=$(echo $addr | rev | cut -d: -f2- | rev)

    if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]]; then
        echo "✅ LOCALHOST: $addr"
    elif [[ "$ip" == "0.0.0.0" || "$ip" == "::" || "$ip" == "*" ]]; then
        echo "🔴 ALL INTERFACES: $addr"
    else
        echo "⚠️  SPECIFIC IP: $addr"
    fi
done
```

---

## 5. Analysing a Real netstat Output

Let's analyse the output from the KodeKloud lesson in detail:

```bash
netstat -an | grep -w LISTEN
```

```
tcp  0  0  127.0.0.1:10248   0.0.0.0:*  LISTEN  ← kubelet healthz      ✅ localhost only
tcp  0  0  127.0.0.1:10249   0.0.0.0:*  LISTEN  ← kube-proxy metrics   ✅ localhost only
tcp  0  0  127.0.0.1:2379    0.0.0.0:*  LISTEN  ← etcd (loopback)      ✅ localhost only
tcp  0  0  10.53.64.6:2379   0.0.0.0:*  LISTEN  ← etcd (node IP)       ⚠️ internal network
tcp  0  0  10.53.64.6:2380   0.0.0.0:*  LISTEN  ← etcd peer            ⚠️ internal network
tcp  0  0  127.0.0.1:42893   0.0.0.0:*  LISTEN  ← dynamic port         ✅ localhost only
tcp  0  0  127.0.0.1:2381    0.0.0.0:*  LISTEN  ← etcd metrics         ✅ localhost only
tcp  0  0  127.0.0.11:46607  0.0.0.0:*  LISTEN  ← Docker DNS           ✅ Docker internal
tcp  0  0  0.0.0.0:80        0.0.0.0:*  LISTEN  ← HTTP (apache?)       🔴 ALL INTERFACES
tcp  0  0  0.0.0.0:8080      0.0.0.0:*  LISTEN  ← Unknown service      🔴 ALL INTERFACES
tcp  0  0  127.0.0.1:10257   0.0.0.0:*  LISTEN  ← controller-manager   ✅ localhost only
tcp  0  0  127.0.0.1:10259   0.0.0.0:*  LISTEN  ← kube-scheduler       ✅ localhost only
tcp  0  0  0.0.0.0:53        0.0.0.0:*  LISTEN  ← DNS                  ⚠️ Investigate
tcp  0  0  0.0.0.0:22        0.0.0.0:*  LISTEN  ← SSH                  ⚠️ Restrict source IPs
tcp6 0  0  :::10250          :::*        LISTEN  ← kubelet API          ⚠️ all interfaces
tcp6 0  0  :::6443           :::*        LISTEN  ← kube-apiserver       ⚠️ Needs firewall rule
tcp6 0  0  :::10256          :::*        LISTEN  ← kube-proxy healthz   ⚠️ restrict to local
tcp6 0  0  :::22             :::*        LISTEN  ← SSH (IPv6)           ⚠️ Restrict source IPs
tcp6 0  0  :::8888           :::*        LISTEN  ← kubectl proxy!       🔴 CRITICAL — remove!
```

### Prioritised Remediation List

| Priority | Port | Issue | Action |
|---|---|---|---|
| 🔴 Critical | `:::8888` | kubectl proxy — unauthenticated K8s API | Stop immediately |
| 🔴 Critical | `0.0.0.0:8080` | Unknown service on all interfaces | Identify and remove |
| 🔴 Critical | `0.0.0.0:80` | Web server — not needed on K8s node | Remove apache/nginx |
| 🟠 High | `0.0.0.0:53` | DNS on all interfaces — is this a DNS server? | Scope to internal only |
| 🟡 Medium | `:::6443` | API server all interfaces — add firewall rules | UFW allow only admin IPs |
| 🟡 Medium | `:::10250` | Kubelet all interfaces — restrict to cluster | UFW allow only apiserver IP |
| 🟡 Medium | `0.0.0.0:22` | SSH all interfaces — restrict source | UFW allow from admin networks |
| ✅ OK | `127.0.0.1:*` | All localhost-only bindings | No action needed |

---

## 6. Two Approaches to Network Security

```mermaid
flowchart TD
    subgraph APPROACH["Two Complementary Approaches"]
        NET["1️⃣ Network-Wide Security\n(Perimeter / External Firewalls)\nCisco ASA, Juniper NGFW\nFortigate, Barracuda\nCloud Security Groups\n\nControls traffic BETWEEN networks\nCentrally managed\nProtects all servers behind it"]

        HOST["2️⃣ Server-Level Security\n(Host-Based Firewalls)\niptables, firewalld, UFW (Linux)\nWindows Firewall\n\nControls traffic TO/FROM this server\nConfigured per-server\nDefence if network firewall is bypassed"]
    end

    BOTH["✅ Best Practice:\nUse BOTH together\nDefence-in-Depth\nNetwork firewall blocks external\nHost firewall is a backstop"]

    NET --> BOTH
    HOST --> BOTH
```

### Why You Need Both

```mermaid
flowchart LR
    INTERNET["Internet"]
    PERIM["Perimeter Firewall\nBlocks port 2379 (etcd)\nBlocks port 10250 (kubelet)"]
    INTERNAL["Internal Network\nDeveloper laptops\nCI/CD servers\nOther services"]
    HOST["Host Firewall (UFW)\nBlocks same ports\nfrom internal network\nunless explicitly allowed"]
    NODE["K8s Node\netcd, kubelet"]

    INTERNET -->|"Port 2379 blocked"| PERIM
    PERIM -->|"Only port 22, 6443 allowed"| NODE
    INTERNAL -->|"Even internal traffic\ngoes through host firewall"| HOST
    HOST -->|"Only kube-apiserver IP\nallowed to :10250"| NODE

    style PERIM fill:#4d96ff,color:#fff
    style HOST fill:#6bcb77,color:#fff
```

If a developer's laptop is compromised, the perimeter firewall won't help — the laptop is "inside" the network. The host firewall on each node provides the second layer of protection.

---

## 7. Layer 1 — Network-Wide Security (Perimeter Firewalls)

Perimeter firewalls operate at the **network edge** — controlling what traffic can enter or leave entire network segments.

### Enterprise Firewall Products

| Vendor | Product | Key Feature |
|---|---|---|
| **Cisco** | ASA (Adaptive Security Appliance) | Stateful inspection, VPN, IPS |
| **Juniper** | SRX Series (NextGen Firewall) | Zone-based policies, AppSecure |
| **Fortinet** | FortiGate | NGFW with SSL inspection, SD-WAN |
| **Barracuda** | CloudGen Firewall | Cloud-native, zero-trust |
| **Palo Alto** | PA Series | App-ID, User-ID, threat prevention |
| **Check Point** | Quantum Security Gateway | Unified threat management |

### What Perimeter Firewalls Do

```mermaid
flowchart LR
    INTERNET["🌍 Internet"]

    subgraph FIREWALL["Perimeter Firewall Rules"]
        R1["ALLOW: TCP :443 from ANY → Load Balancer"]
        R2["ALLOW: TCP :22 from VPN CIDR → K8s Nodes"]
        R3["ALLOW: TCP :6443 from Developers → Control Plane"]
        R4["DENY: TCP :2379 from ANY → All Nodes"]
        R5["DENY: TCP :10250 from ANY → All Nodes"]
        R6["DENY: ALL other → Internal Network"]
    end

    INTERNAL["☸️ Internal K8s Network"]

    INTERNET --> FIREWALL --> INTERNAL
    style FIREWALL fill:#4d96ff,color:#fff
```

### Cloud-Native Perimeter Controls

In cloud environments, security groups and network ACLs serve as the perimeter firewall:

```bash
# AWS Security Group — restrict etcd to internal only
aws ec2 authorize-security-group-ingress \
  --group-id sg-control-plane \
  --protocol tcp \
  --port 2379 \
  --source-group sg-control-plane   # Only from other control plane nodes

# Block etcd from internet
aws ec2 revoke-security-group-ingress \
  --group-id sg-control-plane \
  --protocol tcp \
  --port 2379 \
  --cidr 0.0.0.0/0   # Remove any internet rule

# GCP Firewall Rule — allow kubelet only from apiserver
gcloud compute firewall-rules create allow-kubelet \
  --direction=INGRESS \
  --priority=1000 \
  --network=k8s-vpc \
  --action=ALLOW \
  --rules=tcp:10250 \
  --source-tags=control-plane \
  --target-tags=worker-node
```

---

## 8. Layer 2 — Server-Level Security (Host-Based Firewalls)

Host-based firewalls protect each individual server, regardless of what the network firewall allows. The three main tools on Linux:

```mermaid
flowchart TD
    subgraph TOOLS["Linux Host Firewall Options"]
        IPT["iptables\nLow-level — direct kernel netfilter rules\nVery powerful, complex syntax\nFull control over every packet"]
        FWD["firewalld\nDynamic — rules applied without restart\nZone-based concept\nUsed on RHEL/CentOS/Fedora"]
        UFW["UFW — Uncomplicated Firewall\nSimplified iptables frontend\nHuman-readable commands\nDefault on Ubuntu/Debian\nCovered in next chapter"]
    end

    KERN["Linux Kernel\nnetfilter subsystem"]

    IPT --> KERN
    FWD -->|"uses iptables/nftables"| KERN
    UFW -->|"uses iptables"| KERN
```

### iptables — The Foundation

Everything else (UFW, firewalld) builds on top of `iptables`. Understanding it helps you understand what the higher-level tools are doing:

```bash
# View current iptables rules
sudo iptables -L -v -n

# Allow established connections (important — don't lock yourself out!)
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from specific CIDR only
sudo iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP   # Drop SSH from everywhere else

# Allow kube-apiserver from cluster network only
sudo iptables -A INPUT -p tcp --dport 6443 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 6443 -j DROP

# Block a specific port entirely
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP

# Block all other incoming (default deny)
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Save rules (persist across reboots)
sudo iptables-save > /etc/iptables/rules.v4
sudo apt install iptables-persistent  # Loads saved rules at boot
```

> **Note:** In the next chapter (Chapter 9), we cover UFW in detail — which is a friendlier interface to iptables and the primary tool you'll use on Ubuntu-based Kubernetes nodes.

---

## 9. Layer 3 — Cloud Security Groups

When Kubernetes runs on a cloud provider, **Security Groups** (AWS) or **Firewall Rules** (GCP) act as the network-level firewall before traffic even reaches the host firewall.

```mermaid
flowchart LR
    INTERNET["🌍 Internet"]
    SG["☁️ Cloud Security Group\n(Stateful — tracks connections)"]
    UFW["🖥 Host UFW\n(Second layer)"]
    SERVICE["Service on Port"]

    INTERNET -->|"Packet arrives"| SG
    SG -->|"Allowed by SG rule"| UFW
    UFW -->|"Allowed by UFW rule"| SERVICE
    SG -->|"Blocked by SG"| DROPPED1["❌ Dropped"]
    UFW -->|"Blocked by UFW"| DROPPED2["❌ Dropped"]

    style DROPPED1 fill:#ff6b6b,color:#fff
    style DROPPED2 fill:#ff6b6b,color:#fff
    style SG fill:#4d96ff,color:#fff
    style UFW fill:#6bcb77,color:#fff
```

### Recommended Security Group Rules for K8s

```bash
# Control Plane Security Group
# Allow from internet: only 6443 (kubectl)
# Allow from VPN/admin: 22 (SSH)
# Allow from worker nodes: 2379, 2380 (etcd)
# Deny everything else

# Worker Node Security Group
# Allow from control plane: 10250 (kubelet)
# Allow from VPN/admin: 22 (SSH)
# Allow from internet (via LB): 30000-32767 (NodePort) — only if needed
# Deny everything else

# AWS example — control plane SG
aws ec2 create-security-group \
  --group-name k8s-control-plane \
  --description "Kubernetes control plane"

# Allow kubectl from admin CIDR
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp --port 6443 \
  --cidr 10.0.0.0/8

# Allow etcd from worker nodes only (using SG reference)
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp --port 2379 \
  --source-group sg-worker-nodes   # Only from worker SG

# Block everything else (SGs are default-deny for ingress)
```

---

## 10. Layer 4 — Kubernetes Network Policies

Even inside the cluster, traffic between pods should be restricted. This is the job of **Kubernetes NetworkPolicy** (covered in depth in the Cluster Setup section, Ch. 14).

```mermaid
flowchart TD
    subgraph CLUSTER["Inside K8s Cluster"]
        subgraph NS_PROD["namespace: production"]
            FRONT["frontend pod\n:8080"]
            BACK["backend pod\n:3000"]
            DB["database pod\n:5432"]
        end
        subgraph NS_DEV["namespace: development"]
            DEVPOD["dev pod"]
        end
    end

    FRONT -->|"NetworkPolicy: Allow"| BACK
    BACK -->|"NetworkPolicy: Allow"| DB
    DEVPOD -->|"NetworkPolicy: DENY\nDev namespace cannot\nreach production"| BACK
    DEVPOD -->|"NetworkPolicy: DENY"| DB

    style DEVPOD fill:#ff6b6b,color:#fff
```

```yaml
# Default deny all in production namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow frontend → backend only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - port: 3000
```

---

## 11. Defence-in-Depth: All Four Layers Together

The full security model combines all layers — each one catches what the previous one misses:

```mermaid
flowchart LR
    ATTK["🔴 Attacker"]

    subgraph L1["Layer 1\nPerimeter Firewall\nor Cloud Security Group"]
        L1R["Blocks:\n• etcd from internet\n• kubelet from internet\n• kubectl proxy\n• Unknown services"]
    end

    subgraph L2["Layer 2\nHost Firewall (UFW)"]
        L2R["Blocks:\n• Same ports if SG misconfigured\n• Internal traffic from wrong source IPs\n• Dynamic ports from wrong services"]
    end

    subgraph L3["Layer 3\nService Binding"]
        L3R["Services bound to:\n• 127.0.0.1 (localhost only)\n• Internal IP (not 0.0.0.0)\n• Reduces what reaches firewall"]
    end

    subgraph L4["Layer 4\nK8s NetworkPolicy"]
        L4R["Blocks:\n• Cross-namespace pod traffic\n• Pod-to-IMDS (169.254.169.254)\n• East-west lateral movement"]
    end

    ATTK --> L1 --> L2 --> L3 --> L4

    style L1 fill:#4d96ff,color:#fff
    style L2 fill:#6bcb77,color:#fff
    style L3 fill:#ffd93d,color:#333
    style L4 fill:#a855f7,color:#fff
```

### What Each Layer Catches

| Threat | Layer 1 (Perimeter) | Layer 2 (Host FW) | Layer 3 (Binding) | Layer 4 (NetPol) |
|---|---|---|---|---|
| Internet → etcd | ✅ Blocks | ✅ Backstop | ✅ Localhost-only | — |
| Internet → kubelet | ✅ Blocks | ✅ Backstop | — | — |
| Compromised dev laptop → etcd | ❌ Misses (inside network) | ✅ Catches | — | — |
| Pod → IMDS | ❌ Misses | ❌ Misses | — | ✅ Catches |
| Pod → other namespace | ❌ Misses | ❌ Misses | — | ✅ Catches |
| kubectl proxy exposed | ✅ Blocks | ✅ Backstop | ✅ Bind to 127.0.0.1 | — |

---

## 12. Scoping Services to the Right Interface

The best network security is to bind services to the most restrictive address possible in the first place — before firewall rules even come into play.

### Configuring Services to Bind Correctly

```bash
# ── SSH — restrict to specific interface ─────────────────────────
# /etc/ssh/sshd_config
ListenAddress 10.0.1.10    # Only on internal IP — not all interfaces
# Or for admin VPN interface only:
ListenAddress 172.16.0.1

# ── kubelet — bind to node IP only ───────────────────────────────
# In kubelet config: /var/lib/kubelet/config.yaml
address: 10.0.1.10         # Not 0.0.0.0

# ── kube-proxy — metrics localhost only ──────────────────────────
# In kube-proxy ConfigMap
metricsBindAddress: "127.0.0.1:10249"   # Not 0.0.0.0

# ── etcd — bind only to required interfaces ──────────────────────
# In /etc/kubernetes/manifests/etcd.yaml
# --listen-client-urls=https://127.0.0.1:2379,https://NODE_IP:2379
# NOT: --listen-client-urls=https://0.0.0.0:2379

# ── kubectl proxy — localhost only when needed ───────────────────
kubectl proxy --address='127.0.0.1' --port=8001
# Note: NEVER bind to 0.0.0.0 and NEVER run as a persistent service
```

### Service Binding Decision Tree

```mermaid
flowchart TD
    Q1{"Does any machine\nOUTSIDE this server\nneed to connect?"}
    Q2{"Does any machine\nOUTSIDE the cluster\nneed to connect?"}
    Q3{"Can you restrict\nto specific IPs?"}

    BIND_LO["Bind to 127.0.0.1\nLoopback only"]
    BIND_SPECIFIC["Bind to specific IP\n(node IP, VPN IP)\n+ Firewall rule for source IPs"]
    BIND_ALL["Bind to 0.0.0.0\nBut MUST have firewall rules\nBlocking all except required sources"]

    Q1 -->|No| BIND_LO
    Q1 -->|Yes| Q2
    Q2 -->|No, cluster-internal only| BIND_SPECIFIC
    Q2 -->|Yes, external access needed| Q3
    Q3 -->|Yes| BIND_SPECIFIC
    Q3 -->|No — truly public| BIND_ALL

    style BIND_LO fill:#6bcb77,color:#fff
    style BIND_SPECIFIC fill:#ffd93d,color:#333
    style BIND_ALL fill:#ff6b6b,color:#fff
```

---

## 13. Real-World Scenarios

### Scenario 1 — The 2018 etcd Exposure Epidemic

**What happened:** Security researchers using Shodan (an internet port scanner) discovered over **2,000 etcd clusters** exposed on port 2379 to the public internet with no authentication. Many were Kubernetes etcd instances. Data from these clusters — including secrets, service account tokens, TLS certificates, and application configs — was freely readable.

```bash
# How the researcher found them (Shodan query)
# shodan search 'product:"etcd"'

# What was accessible
curl http://<public-ip>:2379/v2/keys/?recursive=true | python3 -m json.tool
# Returned: complete etcd database, all K8s secrets in plaintext

# Root cause
netstat -an | grep 2379
# tcp  0  0  0.0.0.0:2379  0.0.0.0:*  LISTEN  ← etcd bound to ALL interfaces!

# No authentication configured:
# --listen-client-urls=http://0.0.0.0:2379  (HTTP not HTTPS!)
# --trusted-ca-file not set
```

**Prevention — three controls needed:**

```bash
# 1. Bind etcd to internal IP only
# In /etc/kubernetes/manifests/etcd.yaml:
# --listen-client-urls=https://127.0.0.1:2379,https://10.0.1.10:2379

# 2. UFW blocks port 2379 from internet
sudo ufw deny 2379/tcp
sudo ufw allow from 10.0.0.0/8 to any port 2379

# 3. Cloud security group — no internet → port 2379
aws ec2 revoke-security-group-ingress \
  --group-id sg-control-plane \
  --protocol tcp --port 2379 --cidr 0.0.0.0/0
```

---

### Scenario 2 — Kubernetes Dashboard Publicly Exposed

**Situation:** A startup's DevOps team deployed the Kubernetes dashboard using `kubectl proxy --address=0.0.0.0 --disable-filter=true` — the `--disable-filter=true` flag removes the security check that requires requests to come from localhost. The dashboard was then accessible from any machine. The `--address=0.0.0.0` made it network-accessible. Within a week, automated tools discovered the open dashboard and used it to deploy malicious workloads.

```bash
# The dangerous command used
kubectl proxy --address='0.0.0.0' --port=8001 --disable-filter=true
# Now ANYONE can reach the K8s API via http://node-ip:8001

# Detection
ss -tulpn | grep 8001
# tcp  LISTEN  0  128  0.0.0.0:8001  ...  users:(("kubectl"))
# 0.0.0.0 = accessible from network!

# Prevention
# Option 1: Localhost only (correct way to use kubectl proxy)
kubectl proxy --address='127.0.0.1' --port=8001
# Then use SSH tunnelling: ssh -L 8001:localhost:8001 user@node
# Access dashboard at http://localhost:8001 from your laptop

# Option 2: Block at UFW level
sudo ufw deny 8001/tcp
```

---

### Scenario 3 — Lateral Movement via Unrestricted Internal Port

**Situation:** A developer's laptop is compromised with malware. The attacker uses the laptop (which has VPN access to the corporate network) to scan and probe internal Kubernetes nodes. They discover that the kubelet API (port 10250) is reachable from the developer's network segment with no authentication (anonymous auth enabled on kubelet). They use the kubelet API to exec into pods and steal secrets.

```bash
# Attacker from compromised laptop
curl -sk https://k8s-worker-01:10250/pods | jq .items[].metadata.name
# Lists all pods on the worker — no auth needed!

curl -sk https://k8s-worker-01:10250/run/default/web-app/web-app \
  -d "cmd=cat /run/secrets/kubernetes.io/serviceaccount/token"
# Runs command in container — retrieves service account token!
```

**Dual fix — kubelet auth AND host firewall:**

```bash
# Fix 1: Enable kubelet authentication (Ch. 10 — Kubelet Security)
# /var/lib/kubelet/config.yaml
# authentication:
#   anonymous:
#     enabled: false

# Fix 2: UFW restricts port 10250 to only the kube-apiserver IP
sudo ufw allow from 10.0.1.10 to any port 10250 proto tcp comment 'kubelet from apiserver'
sudo ufw deny 10250/tcp comment 'block kubelet from all others'
```

---

## 14. Common Mistakes & Gotchas

| Mistake | Consequence | Fix |
|---|---|---|
| Relying only on perimeter firewall | Compromised internal machine bypasses it | Always add host-based firewall (UFW) |
| Services bound to `0.0.0.0` without firewall | Any network access = any machine can connect | Bind to specific IP or add UFW rules |
| Thinking `127.0.0.1` services are totally safe | SSH tunnelling can expose them remotely | Audit who has SSH access, disable TCP forwarding |
| No default-deny firewall policy | Any new service that starts is immediately accessible | `ufw default deny incoming` always |
| Firewall allows port but service is removed | Port is still "open" according to firewall rules — confusing | Clean up firewall rules when services are removed |
| Security group on cloud but no host firewall | Cloud SG is misconfigured → all exposed | Both layers always |
| Kubernetes NetworkPolicy not deployed | All pods can talk to all pods | Deploy CNI plugin + default-deny NetworkPolicy |
| DNS port 53 open to internet | DNS amplification DDoS attack vector | Scope DNS to internal CIDR only |
| Not auditing after every deployment | New services introduce new ports | Scan after every change |

---

## 15. CKS Exam Tips

```mermaid
mindmap
  root((CKS Exam\nExternal Access))
    Understand the exposure model
      0.0.0.0 = all interfaces = dangerous
      127.0.0.1 = localhost only = safe
      Specific IP = partially exposed
    Know the two approaches
      Network-wide perimeter firewalls
      Server-level host firewalls
      Both needed — defence in depth
    Know the verification commands
      netstat -an | grep LISTEN
      ss -tulpn
      lsof -i -P -n | grep LISTEN
    K8s specific ports
      etcd 2379 never internet
      kubelet 10250 only from apiserver
      kubectl proxy never persistent
      Dashboard never public
    Next chapter preview
      UFW is the host firewall for Ubuntu
      Covered in depth in Ch. 9
```

### Quick Reference — The External Access Checklist

```bash
# 1. Audit all open ports
sudo ss -tulpn

# 2. Flag all 0.0.0.0 listeners (exposed to all interfaces)
sudo ss -tulpn | grep '0.0.0.0'
sudo ss -tulpn | grep ':::'

# 3. Identify owners of unexpected ports
sudo ss -tulpn | grep ':8080'   # Who owns this?

# 4. Stop and remove unknown services
sudo systemctl stop <service>
sudo apt remove --purge <package>

# 5. Restrict SSH source IPs (UFW — next chapter)
sudo ufw allow from 10.0.0.0/8 to any port 22

# 6. Block K8s-internal ports from internet
sudo ufw deny 2379/tcp   # etcd
sudo ufw deny 10250/tcp  # kubelet — allow only from apiserver IP

# 7. Verify no internet access to sensitive ports
nmap -p 2379,10250,6443 <public-ip>   # From external machine
```

---

## Summary

```mermaid
flowchart TD
    AUDIT["1. Audit\nss -tulpn\nWhat is exposed?"]
    CLASSIFY["2. Classify\n0.0.0.0 = risky\n127.0.0.1 = safe\nSpecific IP = review"]
    REMEDIATE["3. Remediate\nStop/remove unexpected services\nBind services to correct interfaces\nRemove kubectl proxy as service"]
    LAYER["4. Layer Defences\nPerimeter FW blocks internet\nHost UFW blocks internal misuse\nCloud SG as outer layer\nNetworkPolicy inside cluster"]
    VERIFY["5. Verify\nnmap from external host\nss -tulpn after changes\nConfirm no unintended exposure"]
    MAINTAIN["6. Maintain\nAudit after every change\nAlert on new listening ports\nReview firewall rules quarterly"]

    AUDIT --> CLASSIFY --> REMEDIATE --> LAYER --> VERIFY --> MAINTAIN

    style AUDIT fill:#4d96ff,color:#fff
    style LAYER fill:#a855f7,color:#fff
    style VERIFY fill:#6bcb77,color:#fff
```

| Concept | Key Point |
|---|---|
| **0.0.0.0:port** | Service reachable from any network — highest risk |
| **127.0.0.1:port** | Localhost only — no external access |
| **Two approaches** | Perimeter (network-wide) + Host-based (per-server) — use both |
| **Perimeter tools** | Cisco ASA, Juniper NGFW, Fortinet, cloud security groups |
| **Host-based tools** | UFW, iptables, firewalld — covered in detail in Ch. 9 |
| **Critical K8s ports** | etcd (:2379) must never reach internet; kubelet (:10250) only from apiserver |
| **kubectl proxy** | Never bind to 0.0.0.0, never run as a persistent service |
| **Defence-in-depth** | Each layer catches what the previous one misses |
| **Verify exposure** | `ss -tulpn` + `nmap` from external perspective after every change |
