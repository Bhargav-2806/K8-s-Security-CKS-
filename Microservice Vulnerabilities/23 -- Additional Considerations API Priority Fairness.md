# Chapter 23 — Additional Considerations: API Priority and Fairness

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 22 — Using Node Pools and Taints/Tolerations for Isolation](./22%20---%20Using%20Node%20Pools%20and%20Taints%20Tolerations%20for%20Isolation.md)
> **Next:** [Chapter 24 — Quality of Service](./24%20---%20Quality%20of%20Service.md)

---

## Why This Matters for CKS

The Kubernetes API server is the single control point for all cluster operations. Every `kubectl` command, every controller reconciliation loop, every webhook call, every service account token request — all of these are API server requests. In a multi-tenant cluster, if one tenant's workload or controller generates a flood of API requests, it can degrade the API server's responsiveness for all other tenants and for system components like the scheduler and controller-manager.

This chapter covers two distinct but complementary prioritisation mechanisms:

1. **API Priority and Fairness (APF)**: Prevents API server overload by classifying, queuing, and rate-limiting API requests per flow — ensuring that critical system operations aren't starved by heavy tenant traffic.
2. **Pod Priority and Preemption**: Ensures critical pods get scheduled onto nodes even under resource pressure, by allowing them to evict lower-priority pods.

Understanding both is important for the CKS exam because they address different resource contention planes — the control plane (API server) and the data plane (node CPU/memory) respectively.

---

## Part 1 — API Priority and Fairness (APF)

### The Problem: API Server as a Shared Resource

```
Multi-tenant API Server Abuse Scenario
════════════════════════════════════════

Tenant B's application has a bug:
  - Controller stuck in reconciliation loop
  - Sends 5,000 LIST requests/second to the API server

Effect on the cluster:
  - API server request queue fills up
  - Tenant A's HPA (Horizontal Pod Autoscaler) can't get pod metrics
  - Scheduler can't list pending pods
  - System controllers can't update status
  - kubectl commands time out for all users

Result: A buggy (or malicious) tenant effectively DoS's the API server
for all other tenants and system components.
```

### How APF Works

API Priority and Fairness (graduated to stable in Kubernetes 1.29) introduces a two-object model to the API server's request handling:

```
APF Architecture
══════════════════

Incoming API Request
      │
      ▼
┌─────────────────────────────────────────────────┐
│              FlowSchema Matching                │
│  (which priority level does this request get?) │
│                                                 │
│  Request properties matched against:           │
│  • User / Group / ServiceAccount               │
│  • Verb (get, list, create, delete...)         │
│  • API group and resource type                 │
│  • Namespace                                   │
│  • Non-resource URL (e.g., /healthz)          │
│                                                 │
│  Matched FlowSchema → assigned PriorityLevel   │
└─────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────┐
│         PriorityLevelConfiguration              │
│   (how many concurrent requests allowed?)       │
│                                                 │
│  type: Limited → queue with concurrency shares │
│  type: Exempt  → never queued, always admitted  │
│                                                 │
│  assuredConcurrencyShares: N                   │
│    → proportional share of server concurrency  │
│  limitResponse:                                │
│    type: Queue → excess requests wait          │
│    type: Reject → excess requests get 429      │
└─────────────────────────────────────────────────┘
      │
      ▼
  Request admitted or queued
```

### Step 1 — Define PriorityLevelConfiguration

PriorityLevelConfigurations define concurrency "buckets". The `assuredConcurrencyShares` is a proportional weight — a level with 10 shares gets 10x the concurrency of a level with 1 share when the server is under load.

```yaml
# High-priority level: critical tenant gets significant concurrency
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: PriorityLevelConfiguration
metadata:
  name: high-priority
spec:
  type: Limited
  limited:
    assuredConcurrencyShares: 10   # 10x more concurrency than low-priority
    limitResponse:
      type: Queue                   # Queue excess requests (don't drop)
      queuing:
        queues: 64                  # Number of independent queues
        handSize: 6                 # Shuffle sharding — requests assigned to 6/64 queues
        queueLengthLimit: 50        # Max requests per queue before rejection
---
# Low-priority level: non-critical workloads get limited concurrency
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: PriorityLevelConfiguration
metadata:
  name: low-priority
spec:
  type: Limited
  limited:
    assuredConcurrencyShares: 1    # 10x less concurrency than high-priority
    limitResponse:
      type: Queue
      queuing:
        queues: 64
        handSize: 6
        queueLengthLimit: 50
```

**`type: Exempt`** is for levels that bypass all limiting — used for cluster-admin operations and health checks:

```yaml
# Exempt level — never queued, never rate-limited
# Pre-built in Kubernetes: "exempt" level for cluster-admin
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: PriorityLevelConfiguration
metadata:
  name: exempt
spec:
  type: Exempt    # No limiting — used for health checks, cluster-admin
```

### Step 2 — Define FlowSchemas

FlowSchemas map API requests to PriorityLevelConfigurations. The `matchingPrecedence` determines which FlowSchema wins when multiple match — lower number = higher precedence.

```yaml
# High-priority FlowSchema: Namespace A (critical tenant)
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: FlowSchema
metadata:
  name: high-priority-namespace-a
spec:
  priorityLevelConfiguration:
    name: high-priority           # Maps to the high-priority PriorityLevel
  matchingPrecedence: 1000        # Lower number = evaluated first (wins ties)
  distinguisherMethod:
    type: ByUser                  # Each user gets their own flow (fair per-user)
  rules:
  - subjects:
    - kind: ServiceAccount
      name: "system-account"
      namespace: "namespace-a"   # Namespace A's service account gets high priority
    resourceRules:
    - verbs: ["*"]
      apiGroups: ["*"]
      resources: ["*"]
---
# Low-priority FlowSchema: Namespace B (regular tenant)
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: FlowSchema
metadata:
  name: low-priority-namespace-b
spec:
  priorityLevelConfiguration:
    name: low-priority            # Maps to low-priority PriorityLevel
  matchingPrecedence: 2000        # Evaluated after high-priority-namespace-a
  distinguisherMethod:
    type: ByUser
  rules:
  - subjects:
    - kind: Group
      name: "regular-users"      # All members of this group
    - kind: ServiceAccount
      name: "default"
      namespace: "namespace-b"
    resourceRules:
    - verbs: ["*"]
      apiGroups: ["*"]
      resources: ["*"]
```

### Built-in FlowSchemas and PriorityLevels

Kubernetes ships with default FlowSchemas that handle common cases. Check them before adding custom ones to avoid conflicts:

```bash
# List all FlowSchemas
kubectl get flowschemas
# NAME                           PRIORITYLEVEL     MATCHINGPRECEDENCE
# exempt                         exempt            1
# probes                         exempt            2
# system-leader-election         leader-election   100
# kube-system-service-accounts   workload-high     900
# system-nodes                   system            500
# system-node-high               node-high         400
# cluster-admin                  exempt            100
# global-default                 global-default    9999

# List all PriorityLevelConfigurations
kubectl get prioritylevelconfigurations
# NAME             TYPE      ASSUREDCONCURRENCYSHARES
# catch-all        Limited   5
# exempt           Exempt    <none>
# global-default   Limited   20
# leader-election  Limited   10
# node-high        Limited   40
# system           Limited   30
# workload-high    Limited   40
# workload-low     Limited   100

# Check if APF is enabled (default in 1.20+)
kubectl get apiservices | grep flowcontrol
```

### Monitoring APF — Detecting Throttling

```bash
# View API server metrics for APF (if Prometheus is available)
kubectl get --raw /metrics | grep apiserver_flowcontrol

# Key metrics:
# apiserver_flowcontrol_rejected_requests_total — requests rejected (429)
# apiserver_flowcontrol_dispatched_requests_total — requests handled
# apiserver_flowcontrol_current_inqueue_requests — current queue depth
# apiserver_flowcontrol_request_wait_duration_seconds — time spent in queue

# Check if a request was throttled (look for 429 in kubectl)
kubectl get pods -n namespace-b
# Error from server (TooManyRequests): the server has received too many requests
# Retry-After: 1
```

### Flow Distinguisher: ByUser vs. ByNamespace

The `distinguisherMethod` determines how requests within the same FlowSchema are separated into distinct flows for fair-queuing:

```yaml
# ByUser: each user/SA gets their own sub-flow
# Prevents one user from monopolising the priority level's queue
distinguisherMethod:
  type: ByUser

# ByNamespace: each namespace gets its own sub-flow
# Prevents one namespace from monopolising the priority level's queue
distinguisherMethod:
  type: ByNamespace

# No distinguisher: all requests share one flow
# Less fair — one heavy user blocks all others at same priority level
# (omit distinguisherMethod entirely)
```

---

## Part 2 — Pod Priority and Preemption

### The Problem: Node Resource Contention

APF protects the API server. But once pods are scheduled and running, node resources (CPU, memory) are the scarce commodity. Without priority controls:

```
Node Resource Contention Scenario
═══════════════════════════════════

Node has 8 CPU, 32 GiB RAM. Current usage: 7.5 CPU / 28 GiB RAM.
Tenant A needs to scale a critical production database — needs 2 CPU, 4 GiB.
Tenant B has 10 development job pods consuming 6 CPU, 20 GiB.

Without pod priority:
  → Scheduler can't fit the Tenant A database pod
  → Pod stays Pending indefinitely
  → Tenant A's production service is degraded

With pod priority + preemption:
  → Scheduler sees high-priority Tenant A pod needs resources
  → Scheduler identifies low-priority Tenant B job pods to evict
  → Evicts enough Tenant B pods to make room
  → Tenant A database pod is scheduled immediately
  → Tenant B jobs restart later (when resources are available)
```

### PriorityClass Objects

`PriorityClass` is a cluster-scoped object that defines a priority value (integer). Higher value = higher priority. Kubernetes uses this value for scheduling decisions and preemption.

```yaml
# Critical production workloads — highest tenant priority
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: high-priority
value: 1000                    # Higher value = higher priority
globalDefault: false           # Not the default for unlabelled pods
preemptionPolicy: PreemptLowerPriority   # Can preempt lower-priority pods
description: "Critical production workloads — databases, core services"
---
# Standard tenant workloads
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: standard-priority
value: 500
globalDefault: true            # Applied to pods that don't specify a class
preemptionPolicy: PreemptLowerPriority
description: "Standard production workloads"
---
# Development / batch jobs — lowest priority, first to be preempted
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: low-priority
value: 100
globalDefault: false
preemptionPolicy: PreemptLowerPriority
description: "Non-critical dev and batch workloads"
---
# Never-preempt class: important but should not displace others
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: non-preempting
value: 750
globalDefault: false
preemptionPolicy: Never         # Cannot preempt other pods to get scheduled
description: "Medium-priority workloads that should not evict others"
```

**Built-in system PriorityClasses:**

```bash
kubectl get priorityclasses
# NAME                      VALUE        GLOBAL-DEFAULT
# system-cluster-critical   2000000000   false   ← kube-dns, CNI, metrics-server
# system-node-critical      2000001000   false   ← kube-proxy, kubelet-related
# high-priority             1000         false   ← our custom class
# standard-priority         500          true    ← our custom class
# low-priority              100          false   ← our custom class
```

Never set your tenant priority values above `system-cluster-critical` (2,000,000,000) or `system-node-critical` (2,000,001,000) — those classes protect infrastructure pods that must never be evicted.

### Assigning PriorityClass to Pods

```yaml
# Critical application pod in namespace-a
apiVersion: v1
kind: Pod
metadata:
  name: critical-app
  namespace: namespace-a
spec:
  priorityClassName: high-priority   # References the PriorityClass
  containers:
  - name: app-container
    image: nginx
    resources:
      requests:
        memory: "500Mi"
        cpu: "500m"
      limits:
        memory: "500Mi"
        cpu: "500m"
---
# Low-priority batch job in namespace-b
apiVersion: batch/v1
kind: Job
metadata:
  name: data-processing-job
  namespace: namespace-b
spec:
  template:
    spec:
      priorityClassName: low-priority  # Will be preempted first under pressure
      restartPolicy: OnFailure
      containers:
      - name: processor
        image: batch-processor:latest
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
```

### Preemption Flow

```
Preemption Sequence
════════════════════

1. High-priority pod submitted → scheduler can't find a fitting node
2. Scheduler identifies victim pods (lower priority) to evict
3. Victims must release enough resources to fit the high-priority pod
4. Scheduler sends graceful termination signal to victims
   → Pods get their terminationGracePeriodSeconds to clean up
5. Resources freed → high-priority pod is scheduled
6. Evicted pods restart on available nodes (if Deployment/Job manages them)

Key constraint: Only pods with lower priority value are evicted.
               A pod will NEVER preempt pods of equal or higher priority.
               System-critical pods (2B+ priority) are effectively unpreemptable.
```

### Controlling Preemption with ResourceQuota

You can use ResourceQuota to limit which PriorityClass a namespace can use, preventing tenants from creating high-priority pods without authorisation:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: priority-quota
  namespace: namespace-b
spec:
  hard:
    # Allow standard workloads but not high-priority
    pods: "50"
    requests.cpu: "8"
    requests.memory: 16Gi
  scopeSelector:
    matchExpressions:
    - operator: In
      scopeName: PriorityClass
      values:
      - low-priority
      - standard-priority
      # high-priority not listed → namespace-b cannot use high-priority class
```

Without this, any tenant who can create pods can assign any PriorityClass to their pods — potentially preempting other tenants' critical workloads.

---

## Part 3 — Comparing APF and Pod Priority

These two mechanisms address different scarcity problems:

```
┌────────────────────────────────────────────────────────────────────────┐
│              API Priority vs. Pod Priority — Comparison                │
├──────────────────────────┬─────────────────────────┬───────────────────┤
│ Dimension                │ API Priority & Fairness  │ Pod Priority &    │
│                          │                          │ Preemption        │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ Resource protected       │ API server request        │ Node CPU, memory  │
│                          │ processing capacity       │ (scheduling)      │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ Kubernetes objects       │ FlowSchema               │ PriorityClass     │
│                          │ PriorityLevelConfig       │ (pod field:       │
│                          │                          │ priorityClassName) │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ Scope                    │ Control plane            │ Data plane        │
│                          │ (API server)             │ (nodes)           │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ Effect of priority       │ High-priority requests   │ High-priority pods│
│                          │ get more concurrency     │ preempt lower-    │
│                          │ and shorter queue wait   │ priority pods     │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ Effect of throttling     │ Low-priority requests    │ Low-priority pods │
│                          │ queued or rejected (429) │ evicted to free   │
│                          │                          │ node resources    │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ When activated           │ API server under heavy   │ Scheduler can't   │
│                          │ request load             │ fit a pod without │
│                          │                          │ evicting others   │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ Can replace each other?  │ NO — they address        │ NO — complemen-   │
│                          │ completely different      │ tary mechanisms  │
│                          │ bottlenecks              │                   │
└──────────────────────────┴─────────────────────────┴───────────────────┘
```

A cluster under load needs both:
- APF prevents the API server from being overwhelmed by one tenant's controllers
- Pod Priority prevents critical pods from waiting while low-priority batch jobs consume all node resources

---

## Real-World Multi-Tenant Priority Architecture

```yaml
# ── Production SaaS cluster priority design ───────────────────────

# Tier 1: Platform infrastructure (highest)
PriorityClass: system-cluster-critical  (built-in, value: 2B)
  → kube-dns, CNI agent, metrics-server, ingress controller

# Tier 2: Critical tenant production services
PriorityClass: tenant-production  (value: 10000)
  → Production databases, API services, payment processors

# Tier 3: Standard tenant services
PriorityClass: tenant-standard  (value: 1000)
  → Web frontends, background workers, caches

# Tier 4: Batch / development jobs
PriorityClass: tenant-batch  (value: 100)
  → ETL jobs, report generation, dev pods

# Tier 5: Best-effort workloads
PriorityClass: (none / cluster default)  (value: 0)
  → Experimental workloads, canary deployments
```

Enforced via ResourceQuota scopeSelector: each tenant namespace can only use the PriorityClasses appropriate for their tier.

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Confusing APF and Pod Priority (they're unrelated)

APF controls API server request handling. Pod Priority controls pod scheduling. They use completely different objects and operate at different layers. Setting a pod's `priorityClassName` does nothing to protect the API server. Setting APF FlowSchemas does nothing to ensure a pod gets scheduled.

### ❌ Mistake 2: Setting tenant priority values above system-critical

If a tenant's `high-priority` PriorityClass has `value: 3000000000` (above `system-node-critical`), their pods can preempt `kube-dns` or `kube-proxy` — breaking cluster networking for all tenants. Always cap tenant priority values far below the system built-in values.

### ❌ Mistake 3: Lower `matchingPrecedence` means lower priority — it doesn't

In FlowSchemas, **lower `matchingPrecedence` number = evaluated first = higher precedence in matching**. This is the opposite of PriorityClass values where higher number = higher priority. Don't confuse the two.

```
FlowSchema matchingPrecedence: 100  → Matched FIRST (highest priority in matching)
FlowSchema matchingPrecedence: 9999 → Matched LAST (lowest priority in matching)

PriorityClass value: 2000  → HIGH priority pod
PriorityClass value: 100   → LOW priority pod
```

### ❌ Mistake 4: Not restricting PriorityClass access via ResourceQuota

Without ResourceQuota scopeSelector restrictions, any tenant that can create pods can use `system-cluster-critical` as their priorityClassName — making their pods unpreemptable and giving them scheduling preference over everything else. Always restrict PriorityClass access per namespace.

### ❌ Mistake 5: Forgetting that `globalDefault: true` applies to pods with no priorityClassName

If `globalDefault: true` is set on a PriorityClass, all pods without an explicit `priorityClassName` get that priority value. Having multiple PriorityClasses with `globalDefault: true` is invalid — only one can be global default.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│       API Priority and Fairness — Quick Reference               │
├─────────────────┬───────────────────────────────────────────────┤
│ Objects         │ PriorityLevelConfiguration + FlowSchema        │
│                 │ API: flowcontrol.apiserver.k8s.io/v1beta3      │
├─────────────────┼───────────────────────────────────────────────┤
│ Priority Level  │ type: Limited (with shares) or Exempt          │
│ Config          │ assuredConcurrencyShares: proportional weight   │
│                 │ limitResponse: Queue or Reject                  │
├─────────────────┼───────────────────────────────────────────────┤
│ FlowSchema      │ priorityLevelConfiguration: name               │
│                 │ matchingPrecedence: lower = matched first       │
│                 │ rules: subjects (User/Group/SA) + verbs/groups  │
│                 │ distinguisherMethod: ByUser or ByNamespace      │
├─────────────────┼───────────────────────────────────────────────┤
│ Key commands    │ kubectl get flowschemas                         │
│                 │ kubectl get prioritylevelconfigurations         │
│                 │ kubectl get --raw /metrics | grep flowcontrol  │
└─────────────────┴───────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│         Pod Priority and Preemption — Quick Reference            │
├─────────────────┬───────────────────────────────────────────────┤
│ Objects         │ PriorityClass (cluster-scoped)                 │
│                 │ API: scheduling.k8s.io/v1                      │
├─────────────────┼───────────────────────────────────────────────┤
│ PriorityClass   │ value: integer (higher = more priority)        │
│ fields          │ globalDefault: true/false (one per cluster)    │
│                 │ preemptionPolicy: PreemptLowerPriority / Never  │
│                 │ description: human-readable label              │
├─────────────────┼───────────────────────────────────────────────┤
│ Pod field       │ spec.priorityClassName: <name>                 │
├─────────────────┼───────────────────────────────────────────────┤
│ System classes  │ system-cluster-critical: 2,000,000,000        │
│                 │ system-node-critical: 2,000,001,000           │
│                 │ Never exceed these with tenant classes         │
├─────────────────┼───────────────────────────────────────────────┤
│ Restrict via    │ ResourceQuota + scopeSelector + PriorityClass  │
│ ResourceQuota   │ matchExpressions to limit which classes a NS   │
│                 │ can use                                        │
├─────────────────┼───────────────────────────────────────────────┤
│ Key commands    │ kubectl get priorityclasses                     │
│                 │ kubectl describe priorityclass <name>          │
│                 │ kubectl describe pod <name> | grep Priority     │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**Know the two different priority mechanisms and don't confuse them.** The exam may describe an API server performance problem (APF) or a pod scheduling problem (Pod Priority) — the solution is completely different in each case. Read the scenario carefully.

**The FlowSchema `matchingPrecedence` trap:** lower number = higher precedence (evaluated first). This is counter-intuitive. The number 100 beats 9999 in FlowSchema matching — but a PriorityClass value of 9999 beats 100 in pod scheduling.

**Know the built-in system PriorityClasses.** `system-cluster-critical` and `system-node-critical` protect kube-dns, kube-proxy, etc. Tenant priority values must stay well below 2,000,000,000.

**ResourceQuota PriorityClass scoping is a security control.** Without it, any tenant can set `priorityClassName: system-cluster-critical` on their pod — giving it effectively infinite priority. The exam may ask you to restrict this.

**Likely exam tasks:**
- Create a PriorityClass for a critical workload and assign it to a pod spec
- Identify why a pod is stuck Pending (and determine if preemption would help)
- Create a FlowSchema to assign a namespace's service account to a priority level
- Restrict a namespace from using high-priority classes via ResourceQuota

---

## Summary

API Priority and Fairness and Pod Priority address two different resource scarcity problems in multi-tenant Kubernetes clusters. APF protects the API server — the control plane's single most critical component — from being overwhelmed by any one tenant's request flood. It classifies API requests into flows via FlowSchemas, assigns them to concurrency-limited PriorityLevelConfigurations, and queues excess requests fairly. High-priority tenants get more concurrency; low-priority tenants get throttled first when the server is under load.

Pod Priority and Preemption addresses node-level resource allocation. When a high-priority pod cannot be scheduled due to insufficient node resources, the scheduler can evict lower-priority pods to make room. PriorityClasses define integer priority values; pods reference these classes via `spec.priorityClassName`. Crucially, tenant PriorityClass values must never exceed the built-in system classes (`system-cluster-critical`, `system-node-critical`) which protect infrastructure pods from being evicted. ResourceQuota with `scopeSelector` restricts which PriorityClasses a namespace can use — preventing tenant privilege escalation through priority assignment.

The two mechanisms are complementary and neither can replace the other: APF protects the control plane, Pod Priority protects the data plane. In a well-configured multi-tenant cluster, both are deployed together.

---

## What's Next

**[Chapter 24 — Quality of Service →](./24%20---%20Quality%20of%20Service.md)**

Chapter 24 examines Kubernetes Quality of Service (QoS) classes — Guaranteed, Burstable, and BestEffort — which emerge automatically from pod resource requests and limits. QoS determines which pods are evicted first under memory pressure, creating another layer of implicit priority that interacts with the explicit Pod Priority mechanism covered in this chapter.
