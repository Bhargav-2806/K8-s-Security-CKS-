# Chapter 15 — Different Types of Multi-Tenancy in Kubernetes

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 14 — Overview of Multi-Tenancy in Kubernetes](./14%20---%20Overview%20of%20Multi%20Tenancy%20in%20Kubernetes.md)
> **Next:** [Chapter 16 — Levels of Isolation — Namespace, Pod, Node](./16%20---%20Levels%20of%20Isolation%20Namespace%20Pod%20Node.md)

---

## Why This Matters for CKS

Kubernetes multi-tenancy is not one-size-fits-all. The isolation controls appropriate for an internal engineering team sharing a dev cluster are completely inadequate for a SaaS provider hosting untrusted customer workloads. The CKS exam expects you to reason about the *type* of tenancy before prescribing controls — because the wrong controls leave gaps, and the right controls depend entirely on the trust model.

Understanding the two primary tenancy types gives you a framework for answering questions like:
- "Should external customers be able to use `kubectl` against this cluster?"
- "Is namespace-level RBAC sufficient here, or do we need node-level isolation?"
- "What regulatory compliance requirements change the security posture?"
- "Which isolation controls are mandatory vs. optional given this scenario?"

This chapter maps out the terrain. Every subsequent chapter in the multi-tenancy series (16–25) is a deep-dive into one specific isolation control — and which controls you deploy depends on which tenancy type you're operating.

---

## The Two Primary Tenancy Models

Kubernetes multi-tenancy splits cleanly into two categories, each with a fundamentally different trust model, access pattern, and isolation requirement:

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Multi-Tenancy Type Spectrum                        │
│                                                                      │
│  MULTI-TEAM TENANCY              MULTI-CUSTOMER TENANCY             │
│  (Internal Tenants)              (External Tenants)                  │
│                                                                      │
│  ┌───────────┐                   ┌───────────┐                      │
│  │ Team: Eng │  Same org,        │ Customer A│  Different orgs,     │
│  │ Team: HR  │  trusted,         │ Customer B│  untrusted,          │
│  │ Team: Data│  known users      │ Customer C│  anonymous or        │
│  └───────────┘                   └───────────┘  contractual         │
│                                                                      │
│  Trust: HIGH ◄──────────────────────────────────► Trust: LOW        │
│  Isolation: Soft                                  Isolation: Hard    │
│  Access: Direct (kubectl)                         Access: Indirect   │
│  Compliance: Internal policy                      Compliance: GDPR,  │
│                                                   HIPAA, SOC2, PCI  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Type 1 — Multi-Team Tenancy

### What It Is

Multi-team tenancy is the practice of sharing a Kubernetes cluster among **multiple internal teams** within a single organization. Each team gets their own namespace (or set of namespaces), with RBAC controlling who can access what, ResourceQuotas preventing resource hogging, and NetworkPolicies segmenting traffic.

```
Multi-Team Cluster Architecture
════════════════════════════════

                  Kubernetes Cluster
    ┌─────────────────────────────────────────────┐
    │                                             │
    │  ns: engineering        ns: data-science    │
    │  ┌──────────────────┐   ┌─────────────────┐ │
    │  │ deploy: backend  │   │ deploy: jupyter  │ │
    │  │ deploy: frontend │   │ deploy: spark    │ │
    │  │ svc: api         │   │ pvc: datasets    │ │
    │  └──────────────────┘   └─────────────────┘ │
    │                                             │
    │  ns: platform           ns: finance         │
    │  ┌──────────────────┐   ┌─────────────────┐ │
    │  │ deploy: prometheus│  │ deploy: billing  │ │
    │  │ deploy: grafana  │   │ deploy: reports  │ │
    │  └──────────────────┘   └─────────────────┘ │
    │                                             │
    │         Shared Worker Nodes                 │
    │   ┌─────────┐  ┌─────────┐  ┌─────────┐    │
    │   │ Node 1  │  │ Node 2  │  │ Node 3  │    │
    │   └─────────┘  └─────────┘  └─────────┘    │
    └─────────────────────────────────────────────┘

Access Pattern:
  Engineers → kubectl (direct API access)
  Platform team → GitOps controllers (ArgoCD, Flux)
  CI/CD → dedicated ServiceAccounts with scoped permissions
```

### Characteristics of Multi-Team Tenancy

| Characteristic | Detail |
|---|---|
| **Tenant type** | Internal teams, projects, environments (dev/staging/prod) |
| **Trust level** | High — all tenants belong to the same organization |
| **API access** | Direct — teams use `kubectl`, Helm, GitOps controllers |
| **Identity source** | Corporate SSO, OIDC provider (Okta, Azure AD, Google) |
| **Isolation strength** | Soft — namespace + RBAC + quota usually sufficient |
| **Compliance driver** | Internal policy, cost allocation, security best practices |
| **Typical scale** | 5–50 teams in one cluster |
| **Data sensitivity** | Low to medium — rarely regulated data in dev/staging |

### Typical RBAC Structure for Multi-Team Tenancy

Each team gets a namespace-scoped Role, never cluster-wide ClusterRole bindings:

```yaml
# namespace: engineering — Role for the backend team
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: backend-developer
  namespace: engineering
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["pods", "pods/log", "pods/exec", "deployments",
              "services", "configmaps", "jobs", "cronjobs"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]          # Can read but not write secrets
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch", "create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: backend-team-binding
  namespace: engineering
subjects:
- kind: Group
  name: engineering-backend     # Mapped from OIDC group claim
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: backend-developer
  apiGroup: rbac.authorization.k8s.io
```

Platform administrators (SRE/DevOps) may have a ClusterRole, but team developers never should.

### Common Multi-Team Tenancy Patterns

**Pattern A: One namespace per team**
```
ns: team-frontend → frontend team owns it entirely
ns: team-backend  → backend team owns it entirely
ns: team-data     → data team owns it entirely
```
Simple, clean. Works for small organizations. Risk: cross-team dependencies require shared namespaces or explicit NetworkPolicies.

**Pattern B: One namespace per team per environment**
```
ns: frontend-dev     → frontend developers
ns: frontend-staging → CI/CD pipeline only
ns: frontend-prod    → read-only for developers, SRE for writes
```
More namespaces to manage, but clean environment separation. Good for RBAC: developers can't accidentally modify prod.

**Pattern C: GitOps-managed namespaces**
```
ns: app-foo-dev    → ArgoCD creates and manages
ns: app-foo-prod   → ArgoCD creates and manages
# Teams interact via Git PRs, not kubectl in prod
```
Developers never touch production directly. RBAC on the cluster is simpler because only the GitOps SA needs write access.

### What's NOT Needed for Multi-Team Tenancy

Multi-team tenancy operating with trusted internal users typically does **not** need:
- VM-level isolation (Kata Containers) — container escapes are a theoretical risk but not the primary concern for trusted colleagues
- Dedicated node pools per team — too expensive and operationally complex for the trust level
- Separate etcd instances — one etcd is fine
- Air-gapped network segments — NetworkPolicy within the cluster is sufficient

The guiding principle: **match isolation strength to threat level**. Over-isolating wastes resources and creates friction; under-isolating creates risk.

---

## Type 2 — Multi-Customer Tenancy

### What It Is

Multi-customer tenancy means hosting **multiple external, untrusted customers** on a shared Kubernetes cluster. This is the SaaS model: each customer is logically isolated from every other customer, but they all share the same underlying infrastructure. The customers have no direct access to Kubernetes — they interact with the application through its API or UI, not through `kubectl`.

```
Multi-Customer Cluster Architecture
════════════════════════════════════

                  Kubernetes Cluster
    ┌──────────────────────────────────────────────────┐
    │                                                  │
    │  ns: customer-acme          ns: customer-globex  │
    │  ┌───────────────────┐   ┌───────────────────┐  │
    │  │ deploy: app-acme  │   │ deploy: app-globex │  │
    │  │ secret: acme-db   │   │ secret: globex-db  │  │
    │  │ pvc: acme-data    │   │ pvc: globex-data   │  │
    │  └───────────────────┘   └───────────────────┘  │
    │                                                  │
    │  ns: customer-initech       ns: customer-xyz     │
    │  ┌───────────────────┐   ┌───────────────────┐  │
    │  │ deploy: app-init  │   │ deploy: app-xyz   │  │
    │  │ secret: init-db   │   │ secret: xyz-db    │  │
    │  └───────────────────┘   └───────────────────┘  │
    │                                                  │
    └──────────────────────────────────────────────────┘
          ▲                             ▲
          │                             │
    ┌─────────────┐             ┌─────────────┐
    │ ACME Corp   │             │ Globex Corp  │
    │ (customer)  │             │ (customer)  │
    │             │             │             │
    │ Accesses    │             │ Accesses    │
    │ via browser │             │ via API     │
    │ NOT kubectl │             │ NOT kubectl │
    └─────────────┘             └─────────────┘

Kubernetes is invisible to the customer — they only see the application.
```

### Characteristics of Multi-Customer Tenancy

| Characteristic | Detail |
|---|---|
| **Tenant type** | External customers, clients, end-users |
| **Trust level** | Low — tenants may be malicious, competitive, or regulated |
| **API access** | Indirect — customers interact with the **application**, never `kubectl` |
| **Identity source** | Per-application auth (OAuth, SAML), not cluster auth |
| **Isolation strength** | Hard — namespace + RBAC + quota + NetworkPolicy + PSA minimum |
| **Compliance driver** | GDPR, HIPAA, PCI-DSS, SOC 2, ISO 27001 — legally binding |
| **Typical scale** | Tens to thousands of customers per cluster |
| **Data sensitivity** | High — customer data, PII, financial records, health records |

### Why Stricter Isolation Is Mandatory

The threat model changes completely when customers are external:

```
Multi-Team Threat: Accidental access, misconfiguration
Multi-Customer Threat: Deliberate, adversarial exploitation

A malicious customer might:
• Deploy a container designed to escape to the host kernel
• Flood the API server or DNS to degrade other customers (DoS)
• Attempt to read other customers' secrets via misconfigured RBAC
• Exfiltrate data from adjacent pods via network attacks
• Violate data residency by having their data land on wrong region nodes
```

For regulated industries, the consequences of a data breach between customers are not just operational — they're legal. GDPR fines can reach 4% of global annual revenue. HIPAA violations can result in criminal charges.

### The "Kubernetes Is Invisible" Principle

The most important architectural principle for multi-customer tenancy: **customers must not interact with Kubernetes directly**. All cluster operations happen behind the scenes, managed by the SaaS provider's platform team.

```
Multi-Team Access Pattern:
  Developer → kubectl → Kubernetes API Server
  (Direct, authenticated, scoped)

Multi-Customer Access Pattern:
  Customer → Application UI/API → Application Code → Kubernetes (backend)
  (Indirect, through application layer, no cluster credentials)
```

This means:
- Customers have **no kubeconfig**, no service account tokens, no API access
- All provisioning (creating customer namespaces, deploying workloads) is done by the platform's **control plane application** (often itself a Kubernetes controller)
- Customer-facing RBAC is **application-level**, not cluster-level

### The Control Plane Application Pattern

SaaS providers typically have a dedicated "platform controller" that manages customer namespaces:

```
┌─────────────────────────────────────────────────────────────────┐
│                   SaaS Control Plane Architecture               │
│                                                                 │
│  Customer signs up → Platform API → Platform Controller         │
│                                          │                      │
│                                          ▼                      │
│                               Creates:                          │
│                               • Namespace (customer-{id})       │
│                               • ResourceQuota                   │
│                               • LimitRange                      │
│                               • NetworkPolicy                   │
│                               • RBAC (SA + Role + Binding)      │
│                               • PVC for customer data           │
│                               Deploys:                          │
│                               • Application pods                │
│                               • Monitoring sidecars             │
│                                                                 │
│  Platform Controller's ServiceAccount needs ClusterRole:        │
│  • create/delete namespaces                                     │
│  • create/delete ResourceQuotas, LimitRanges                    │
│  • create/delete Deployments, Services (any namespace)          │
│  • manage NetworkPolicies                                       │
└─────────────────────────────────────────────────────────────────┘
```

This controller is a significant security surface: it has cluster-wide write access. It must be:
- Deployed in a dedicated privileged namespace
- Secured with strict network policies
- Protected by Pod Security Admission (restricted or at least baseline)
- Running with least-privilege service accounts

---

## Side-by-Side Comparison

```
┌──────────────────────────┬──────────────────────────┬──────────────────────────┐
│ Dimension                │ Multi-Team               │ Multi-Customer           │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Who are the tenants?     │ Internal teams, projects │ External customers       │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Trust level              │ High (same org)          │ Low (unknown/adversarial)│
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Cluster access           │ Direct kubectl / GitOps  │ None (app UI/API only)  │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Identity management      │ Corporate SSO, OIDC      │ App-level (not cluster) │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Namespace management     │ Manual or GitOps         │ Automated controller     │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ RBAC complexity          │ Medium                   │ High (all managed by     │
│                          │                          │ platform controller)     │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Network isolation        │ NetworkPolicy            │ NetworkPolicy + strict   │
│                          │ (recommended)            │ default-deny (mandatory) │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Resource isolation       │ ResourceQuota +          │ ResourceQuota + LimitRng │
│                          │ LimitRange               │ + PriorityClass          │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Pod security             │ PSA baseline or          │ PSA restricted           │
│                          │ restricted               │ (mandatory)              │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Node isolation           │ Optional                 │ Recommended for high-    │
│                          │                          │ sensitivity customers    │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Compliance burden        │ Internal policies        │ GDPR, HIPAA, PCI, SOC2  │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Data breach impact       │ Operational, reputational│ Legal (fines), criminal  │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Typical # of tenants     │ 5–50                     │ 50–100,000               │
├──────────────────────────┼──────────────────────────┼──────────────────────────┤
│ Monitoring strategy      │ Shared Prometheus/Loki   │ Per-tenant metrics with  │
│                          │                          │ strict data isolation    │
└──────────────────────────┴──────────────────────────┴──────────────────────────┘
```

---

## Isolation Requirements by Tenancy Type

### Multi-Team: Minimum Viable Isolation

```yaml
# For each team namespace, this baseline is required:

# 1. ResourceQuota — prevent noisy neighbors
apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-quota
  namespace: team-engineering
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    pods: "40"
---
# 2. LimitRange — ensure all pods have resource requests
apiVersion: v1
kind: LimitRange
metadata:
  name: team-limits
  namespace: team-engineering
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
---
# 3. NetworkPolicy — default deny + allow intra-namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: team-engineering
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: team-engineering
spec:
  podSelector: {}
  ingress:
  - from:
    - podSelector: {}
  egress:
  - to:
    - podSelector: {}
  - ports:               # Allow DNS
    - port: 53
      protocol: UDP
```

### Multi-Customer: Enhanced Isolation Requirements

Everything from multi-team plus:

```yaml
# 4. Pod Security Admission — restrict pod capabilities
# Applied via namespace label (Ch. 5)
# pod-security.kubernetes.io/enforce: restricted

# 5. Stricter NetworkPolicy — no egress to other namespaces
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: strict-egress
  namespace: customer-acme
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector: {}       # Only to pods in same namespace
  - ports:
    - port: 53
      protocol: UDP          # DNS only for external
    - port: 53
      protocol: TCP
  # No egress to other customer namespaces
  # No egress to Kubernetes API (customers don't need it)
---
# 6. OPA Gatekeeper — custom policy for customer isolation
# Enforce that all pods have a customer label
# Prevent pods from using hostPath, hostNetwork, hostPID
# Enforce approved image registries

# 7. Audit policy — log all access to customer namespaces
# (See System Hardening — Audit Logging chapter)
```

---

## The Compliance Dimension

One of the most important practical differences between the two models: **regulatory compliance requirements**.

### Multi-Customer Compliance Matrix

| Regulation | Key Requirement | Kubernetes Control |
|---|---|---|
| **GDPR** | Data residency (EU data stays in EU) | Node labels + nodeAffinity per customer |
| **GDPR** | Right to erasure | PV deletion policy, etcd key rotation |
| **HIPAA** | PHI isolation | Namespace isolation, encryption at rest |
| **HIPAA** | Access audit trails | Kubernetes audit logging, per-namespace |
| **PCI-DSS** | Network segmentation | NetworkPolicy strict default-deny |
| **PCI-DSS** | Encrypt cardholder data | Secrets encryption at rest + mTLS |
| **SOC 2** | Change management | RBAC, GitOps, no direct prod access |
| **SOC 2** | Availability | ResourceQuota, PodDisruptionBudget |
| **ISO 27001** | Asset inventory | Resource labeling, namespace tagging |

For multi-team tenancy (internal), compliance is simpler — internal security policies rather than external legal mandates. For multi-customer tenancy, a data leak between customers is not just a security incident; it's potentially a regulatory violation with severe consequences.

### Data Residency Example

A customer in Germany under GDPR may require their data to only be processed on EU nodes:

```yaml
# Node label on EU-region nodes
kubectl label node eu-node-1 eu-node-2 eu-node-3 region=eu

# Customer namespace uses nodeAffinity
apiVersion: v1
kind: Pod
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: region
            operator: In
            values:
            - eu   # Only schedule on EU nodes
  containers:
  - name: app
    image: my-saas-app:latest
```

---

## Hybrid and Intermediate Tenancy Models

Real-world clusters often fall between the two pure types:

### Developer Platform (Hybrid)
Internal developers get namespace access, but non-engineering staff (e.g., managers, customers with trial access) go through a front-end application. The cluster uses both patterns simultaneously.

### Environment Separation as Tenancy
Many organizations treat dev/staging/prod as "tenants":
```
Production namespace → strict, PSA restricted, no dev access
Staging namespace → moderate, PSA baseline, CI/CD access
Development namespace → relaxed, PSA baseline, developer access
```
The "tenants" here are environments, not teams. RBAC ensures developers can't touch production.

### Customer-Facing Developer Tools
Some SaaS products (e.g., managed database services, ML platforms) give customers limited `kubectl` or API access to their own namespace. This is the hardest multi-tenancy scenario — customers have direct API access but must be contained to their namespace. This requires:
- Virtual clusters (vcluster) for strong API isolation
- Or extremely tight RBAC with regular audits
- And definitely node-level isolation for the most sensitive customers

---

## Choosing the Right Model

Use this decision tree when designing a multi-tenant cluster:

```
Are the tenants internal to your organization?
├── YES → Multi-Team Tenancy
│         • Namespace per team
│         • RBAC via corporate SSO
│         • ResourceQuota + LimitRange
│         • NetworkPolicy (recommended)
│         • PSA baseline (minimum)
│         └── Is data regulated (HIPAA, PCI)?
│               ├── YES → Add: PSA restricted, audit logging,
│               │          encryption at rest, dedicated node pools
│               └── NO  → Namespace isolation is sufficient
│
└── NO  → Multi-Customer Tenancy
          • Namespace per customer (automated)
          • No direct cluster access for customers
          • RBAC managed by platform controller
          • ResourceQuota + LimitRange + PriorityClass
          • NetworkPolicy strict default-deny
          • PSA restricted (mandatory)
          • Audit logging (mandatory)
          └── Are customers regulated or high-security?
                ├── YES → Add: dedicated node pools (Ch. 22),
                │          node-level isolation, gVisor/Kata (Ch. 10-12),
                │          data residency nodeAffinity, GDPR controls
                └── NO  → Namespace + network + resource isolation
                           is the baseline; add controls as needed
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Using the same isolation controls regardless of tenant type

Applying multi-team-level controls to a multi-customer cluster is dangerous. External tenants cannot be trusted the same way internal colleagues are. Always start from the trust model.

### ❌ Mistake 2: Giving external customers kubectl access

If a multi-customer SaaS operator gives customers cluster credentials "for convenience," they've broken the fundamental security model. Customers interacting with Kubernetes APIs directly can potentially escape their namespace through RBAC misconfiguration or Kubernetes API vulnerabilities.

### ❌ Mistake 3: Treating all multi-customer scenarios as equal

A B2B SaaS with 20 known enterprise customers under NDA is very different from a public platform with thousands of anonymous users. The threat level scales with anonymity and scale.

### ❌ Mistake 4: Forgetting that compliance is a customer-tenancy concern, not a team-tenancy one

Internal teams rarely trigger GDPR, HIPAA, or PCI-DSS requirements at the Kubernetes layer. External customers almost always do if they're in regulated industries. This is a key distinguishing factor in exam scenarios.

### ❌ Mistake 5: Assuming namespace = full isolation

In both tenancy models, namespaces alone are insufficient. The exam often presents scenarios where all the right namespaces exist, but the Network Policies, ResourceQuotas, or RBAC controls are missing.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│           Multi-Tenancy Types — Quick Reference                  │
├────────────────────┬────────────────────┬───────────────────────┤
│                    │ Multi-Team         │ Multi-Customer        │
├────────────────────┼────────────────────┼───────────────────────┤
│ Tenants are        │ Internal teams     │ External customers    │
├────────────────────┼────────────────────┼───────────────────────┤
│ Trust level        │ High               │ Low                   │
├────────────────────┼────────────────────┼───────────────────────┤
│ Cluster access     │ Direct (kubectl)   │ None (app only)       │
├────────────────────┼────────────────────┼───────────────────────┤
│ Isolation strength │ Soft               │ Hard                  │
├────────────────────┼────────────────────┼───────────────────────┤
│ RBAC managed by    │ Admins / GitOps    │ Platform controller   │
├────────────────────┼────────────────────┼───────────────────────┤
│ Compliance         │ Internal policy    │ GDPR, HIPAA, PCI...   │
├────────────────────┼────────────────────┼───────────────────────┤
│ Data breach impact │ Operational        │ Legal liability       │
├────────────────────┼────────────────────┼───────────────────────┤
│ Node isolation?    │ Rarely needed      │ Often needed          │
├────────────────────┼────────────────────┼───────────────────────┤
│ gVisor/Kata?       │ Rarely             │ For high-risk tenants │
├────────────────────┼────────────────────┼───────────────────────┤
│ Namespace mgmt     │ Manual / GitOps    │ Automated controller  │
└────────────────────┴────────────────────┴───────────────────────┘

Key Rules:
1. Match isolation strength to trust level
2. External tenants never get kubectl access
3. Compliance requirements (GDPR/HIPAA) almost always mean multi-customer
4. Namespaces alone are never sufficient for either model
5. Default-deny NetworkPolicy is mandatory for both, critical for multi-customer
```

---

## CKS Exam Tips

**Read the scenario carefully for trust signals.** The exam will describe a situation — "a SaaS company hosting multiple enterprise customers" vs. "several development teams sharing a cluster." These clue you into which tenancy type applies, which then tells you which controls are mandatory.

**The "no kubectl access" rule is a CKS gotcha.** If the exam asks about multi-customer tenancy and presents an option of "create a kubeconfig for each customer," that is categorically wrong. Multi-customer tenants never get direct cluster access.

**Compliance keywords signal multi-customer:** GDPR, HIPAA, PCI-DSS, data residency, data sovereignty — any of these in the scenario description mean you're in multi-customer territory with mandatory stricter controls.

**Exam tasks likely to appear:**
- Given a namespace, determine if the isolation controls are appropriate for multi-team or multi-customer tenancy
- Add missing controls to a multi-customer namespace (NetworkPolicy, ResourceQuota, PSA label)
- Explain why a team namespace RBAC setup would be insufficient for a customer namespace
- Design the RBAC for a platform controller that manages customer namespaces

---

## Summary

Kubernetes multi-tenancy divides into two fundamentally different models based on the trust relationship between tenants and the cluster operator. Multi-team tenancy manages internal organizational teams who have direct API access to the cluster, where namespace isolation combined with RBAC, ResourceQuota, and NetworkPolicy provides sufficient security. The trust is high, the compliance requirements are internal, and the threat model is primarily accidental misconfiguration rather than deliberate attack.

Multi-customer tenancy hosts external, potentially untrusted customers who never interact with Kubernetes directly — they only see the application. This model demands much stricter isolation: mandatory default-deny NetworkPolicies, PSA restricted profiles, automated namespace provisioning, comprehensive audit logging, and often node-level isolation for regulated customers. The compliance stakes are legal rather than just operational.

The practical decision between the two models comes down to trust. Ask: "Are these tenants part of my organization, and do I trust them with API access?" If yes, multi-team controls are your baseline. If no — if the tenants are external, unknown, or potentially adversarial — multi-customer controls are mandatory regardless of the added complexity.

---

## What's Next

**[Chapter 16 — Levels of Isolation — Namespace, Pod, Node →](./16%20---%20Levels%20of%20Isolation%20Namespace%20Pod%20Node.md)**

With the two tenancy models defined, Chapter 16 maps out the three levels at which isolation can be implemented in Kubernetes: the namespace level (RBAC, NetworkPolicy, ResourceQuota), the pod level (security contexts, PSA, runtime sandboxes), and the node level (taints, tolerations, dedicated node pools). Understanding which threats are mitigated at which level is essential for designing multi-tenant clusters that don't over- or under-isolate.
