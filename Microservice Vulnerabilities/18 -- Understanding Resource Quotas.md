# Chapter 18 — Understanding Resource Quotas

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 17 — Control Plane Isolation](./17%20---%20Control%20Plane%20Isolation.md)
> **Next:** [Chapter 19 — Data Plane Isolation](./19%20---%20Data%20Plane%20Isolation.md)

---

## Why This Matters for CKS

Resource isolation is as important as access control in multi-tenant clusters. A perfectly secured namespace — with tight RBAC, NetworkPolicy, and PSA — is still vulnerable if one tenant can exhaust the cluster's CPU or memory, crashing other tenants' workloads. The CKS exam tests this layer directly.

Exam tasks in this area include:
- Creating a ResourceQuota with specific CPU, memory, pod count, and object limits for a namespace
- Creating a LimitRange that enforces per-container defaults and maximums
- Diagnosing why a pod fails to schedule due to quota exhaustion
- Understanding the interaction between ResourceQuota and LimitRange
- Recognising the "quota bypass" when LimitRange is missing

ResourceQuota and LimitRange are conceptually simple but have subtle mechanics around `requests` vs `limits`, how they interact with each other, and what happens when either is missing. This chapter covers all of those.

---

## The Noisy Neighbor Problem

Without resource controls, a single tenant's workload can consume all available cluster resources:

```
Cluster with 16 CPU, 64 GiB RAM — no ResourceQuota
═══════════════════════════════════════════════════

Time 0:  All tenants running normally (CPU ~4/tenant)
Time 1:  Tenant A deploys a memory leak — slowly consuming more RAM
Time 2:  Tenant A's pods now using 40 GiB of the cluster's 64 GiB
Time 3:  Kubernetes can't schedule new Tenant B/C pods — no memory left
Time 4:  Node memory pressure → kubelet starts evicting pods
Time 5:  Tenant B's production workload gets evicted
         Tenant A's bug has taken down Tenant B's service

ResourceQuota prevents this: Tenant A's namespace has a hard ceiling.
Once they hit the quota, their pods fail — not other tenants' pods.
```

---

## What Is a ResourceQuota?

A `ResourceQuota` is a namespace-level object that enforces hard limits on the aggregate resource consumption within a namespace. Once a namespace's quota is exhausted, new resource creation that would exceed the quota is rejected by the API server — existing resources are unaffected.

```
ResourceQuota enforcement flow:
═════════════════════════════════

User creates Pod → API Server →
  Admission Controller: ResourceQuota
    "Would this pod push namespace usage over quota?"
    ├── No  → Allow pod creation
    └── Yes → Reject with 403 Forbidden:
               exceeded quota: cpu-memory-quota,
               requested: requests.cpu=2, used: requests.cpu=3,
               limited: requests.cpu=4
```

ResourceQuota covers three categories of limits:
1. **Compute resources** — CPU and memory requests/limits
2. **Storage resources** — PersistentVolumeClaim size and count
3. **Object count** — maximum number of specific Kubernetes objects

---

## ResourceQuota Anatomy

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: cpu-memory-quota
  namespace: namespace_a
spec:
  hard:
    # ── Compute Resources ─────────────────────────────────────────
    requests.cpu: "4"          # Sum of all pod CPU requests ≤ 4 cores
    requests.memory: 16Gi      # Sum of all pod memory requests ≤ 16 GiB
    limits.cpu: "8"            # Sum of all pod CPU limits ≤ 8 cores
    limits.memory: 32Gi        # Sum of all pod memory limits ≤ 32 GiB

    # ── Storage Resources ─────────────────────────────────────────
    requests.storage: 100Gi    # Sum of all PVC storage requests ≤ 100 GiB
    persistentvolumeclaims: "10"  # Max 10 PVCs in namespace

    # ── Object Count ─────────────────────────────────────────────
    pods: "50"                 # Max 50 pods
    services: "20"             # Max 20 services
    secrets: "30"              # Max 30 secrets
    configmaps: "30"           # Max 30 ConfigMaps
    replicationcontrollers: "0"  # Disabled (legacy resource)
    services.loadbalancers: "2"  # Max 2 LoadBalancer services
    services.nodeports: "0"    # No NodePort services (security control)
    count/deployments.apps: "20"  # Max 20 Deployments
    count/jobs.batch: "30"    # Max 30 Jobs
```

### Compute Quota: Requests vs. Limits

The distinction between `requests` and `limits` is critical:

```
requests.cpu: "4"   → The SCHEDULER sees this. Admission is based on the
                       pod's spec.resources.requests.cpu, not limits.
                       Total requested CPU across all pods ≤ 4 cores.

limits.cpu: "8"     → The KUBELET enforces this at runtime.
                       Total CPU limits across all pods ≤ 8 cores.

A pod with requests.cpu: 250m and limits.cpu: 500m
  → counts 250m toward the requests.cpu quota
  → counts 500m toward the limits.cpu quota

Why have both?
  requests controls scheduling (what's actually reserved)
  limits controls the burst ceiling (max the namespace can use)
  The ratio limits/requests is the "burstability" headroom
```

### The Critical Interaction with LimitRange

When a ResourceQuota is applied to a namespace, **every pod must specify both resource requests AND limits**. If a pod spec has no resource section, the API server rejects it with a quota error:

```bash
# Creating a pod with no resource spec in a quota-enforced namespace:
kubectl run bare-pod --image=nginx -n namespace_a
# Error from server (Forbidden): pods "bare-pod" is forbidden:
# [failed quota: cpu-memory-quota: must specify limits.cpu,
#  limits.memory, requests.cpu, requests.memory]
```

This is where `LimitRange` becomes essential — it provides defaults so that pods without explicit resource specs still get values that satisfy the quota.

---

## Pod Spec Compliant with ResourceQuota

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: resource-limited-pod
  namespace: namespace_a
spec:
  containers:
  - name: resource-limited-container
    image: nginx
    resources:
      requests:
        cpu: "250m"       # 0.25 cores reserved by scheduler
        memory: "64Mi"    # 64 MiB reserved
      limits:
        cpu: "500m"       # Container throttled above 0.5 cores
        memory: "128Mi"   # Container OOM-killed above 128 MiB
```

This pod consumes from the quota as follows:
- `requests.cpu` usage: +250m (of the 4000m = 4 core limit)
- `requests.memory` usage: +64Mi (of the 16Gi limit)
- `limits.cpu` usage: +500m (of the 8000m = 8 core limit)
- `limits.memory` usage: +128Mi (of the 32Gi limit)
- `pods` count: +1 (of the 50 limit)

---

## LimitRange — The Essential Companion

`LimitRange` enforces per-Pod or per-Container resource bounds and provides defaults. It solves two problems:

1. **Default injection**: When a container doesn't specify resources, LimitRange injects defaults — satisfying the ResourceQuota requirement automatically
2. **Individual ceiling**: Prevents a single container from claiming an outsized share of the namespace quota

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: namespace-a-limits
  namespace: namespace_a
spec:
  limits:
  # ── Per-Container limits ──────────────────────────────────────
  - type: Container
    default:           # Injected if container omits 'limits'
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:    # Injected if container omits 'requests'
      cpu: "100m"
      memory: "128Mi"
    max:               # Hard ceiling per container — cannot exceed
      cpu: "2"
      memory: "4Gi"
    min:               # Minimum per container — must specify at least
      cpu: "50m"
      memory: "64Mi"
    maxLimitRequestRatio:  # limits/requests ratio ceiling
      cpu: "4"             # limits.cpu ≤ 4 × requests.cpu
      memory: "4"          # limits.memory ≤ 4 × requests.memory

  # ── Per-Pod limits (sum of all containers in the pod) ─────────
  - type: Pod
    max:
      cpu: "4"
      memory: "8Gi"

  # ── Per-PersistentVolumeClaim limits ─────────────────────────
  - type: PersistentVolumeClaim
    max:
      storage: "50Gi"
    min:
      storage: "1Gi"
```

### How LimitRange Default Injection Works

```
Scenario: Pod has no resource spec, namespace has both LimitRange and ResourceQuota

Step 1: User submits pod with no resource section
Step 2: LimitRange admission controller runs
        → Injects defaultRequest: {cpu: 100m, memory: 128Mi}
        → Injects default:        {cpu: 500m, memory: 512Mi}
Step 3: ResourceQuota admission controller runs
        → Pod now has both requests AND limits (from LimitRange injection)
        → Checks: would 100m CPU request push namespace over 4-core quota?
        → No → Allow

Without LimitRange:
Step 1: User submits pod with no resource section
Step 2: ResourceQuota admission controller runs
        → No resource requests found
        → REJECT: "must specify requests.cpu, requests.memory..."
```

### LimitRange Without ResourceQuota

LimitRange alone prevents any single container from being too large, but doesn't cap the namespace total. A tenant could run 1000 minimal pods, each consuming the minimum, overwhelming the cluster.

### ResourceQuota Without LimitRange

ResourceQuota alone requires every pod to have explicit resources, or it will be rejected — this creates friction for developers. Without LimitRange defaults, every pod spec needs a full resources block.

The correct production pattern: **always deploy both together**.

---

## Checking Quota Usage

```bash
# View current quota usage (most important command)
kubectl describe resourcequota cpu-memory-quota -n namespace_a
# Output:
# Name:            cpu-memory-quota
# Namespace:       namespace_a
# Resource         Used    Hard
# --------         ----    ----
# limits.cpu       2500m   8
# limits.memory    2560Mi  32Gi
# pods             5       50
# requests.cpu     1250m   4
# requests.memory  640Mi   16Gi

# Short form
kubectl get resourcequota -n namespace_a

# Check LimitRange defaults
kubectl describe limitrange namespace-a-limits -n namespace_a

# See what's consuming quota — check all pods' resource specs
kubectl get pods -n namespace_a -o json | \
  jq '.items[] | {name: .metadata.name, 
      cpu_req: .spec.containers[].resources.requests.cpu,
      mem_req: .spec.containers[].resources.requests.memory}'

# Quota at a glance across all namespaces
kubectl get resourcequota --all-namespaces
```

---

## Storage Quotas

ResourceQuota also governs storage consumption:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: storage-quota
  namespace: namespace_a
spec:
  hard:
    # Total storage across all PVCs
    requests.storage: 100Gi

    # Total number of PVCs
    persistentvolumeclaims: "10"

    # Per-StorageClass quotas (prevents one class from being exhausted)
    gold.storageclass.storage.k8s.io/requests.storage: 50Gi
    gold.storageclass.storage.k8s.io/persistentvolumeclaims: "5"
    silver.storageclass.storage.k8s.io/requests.storage: 50Gi
    silver.storageclass.storage.k8s.io/persistentvolumeclaims: "5"
```

StorageClass-scoped quotas are powerful for multi-tenant environments where expensive storage classes (SSDs, high-IOPS) should be rationed, while cheaper storage classes can have more generous quotas.

---

## Object Count Quotas

Beyond compute and storage, you can limit how many Kubernetes objects a tenant can create:

```yaml
spec:
  hard:
    # Prevent namespace sprawl and API server overload
    pods: "50"
    services: "20"
    secrets: "30"
    configmaps: "30"
    persistentvolumeclaims: "10"

    # Prevent expensive cloud resources
    services.loadbalancers: "2"     # Each LB = cloud load balancer $$$
    services.nodeports: "0"         # No NodePort — use Ingress instead

    # Count by resource group (more granular)
    count/deployments.apps: "20"
    count/statefulsets.apps: "5"
    count/jobs.batch: "30"
    count/cronjobs.batch: "10"
    count/ingresses.networking.k8s.io: "10"
```

Setting `services.nodeports: "0"` is a common multi-tenant security control — NodePort services expose cluster ports on every node's external IP, which can be a security risk in shared environments. Forcing tenants to use Ingress instead gives the platform team control over external exposure.

---

## Scoped ResourceQuota

`ResourceQuota` can be scoped to apply only to pods matching certain criteria — specifically the QoS class or priority class:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: best-effort-quota
  namespace: namespace_a
spec:
  hard:
    pods: "5"           # Max 5 BestEffort pods
  scopes:
  - BestEffort          # Only applies to BestEffort-class pods
```

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: priority-quota
  namespace: namespace_a
spec:
  hard:
    pods: "10"
    requests.cpu: "2"
    requests.memory: 4Gi
  scopeSelector:
    matchExpressions:
    - operator: In
      scopeName: PriorityClass
      values:
      - high-priority     # Only pods with this PriorityClass
```

Scope values: `Terminating`, `NotTerminating`, `BestEffort`, `NotBestEffort`, `PriorityClass`.

---

## Multi-Tenant ResourceQuota Strategy

In a multi-tenant cluster, each tenant namespace should have its own ResourceQuota sized to their allocation:

```
Cluster resources: 64 CPU, 256 GiB RAM
════════════════════════════════════════

Tenant A (production SaaS): 
  requests.cpu: 20, requests.memory: 80Gi, pods: 100

Tenant B (internal tools):
  requests.cpu: 8, requests.memory: 32Gi, pods: 50

Tenant C (dev/staging):
  requests.cpu: 4, requests.memory: 16Gi, pods: 40

Platform (kube-system, monitoring):
  Reserved: 32 CPU, 128 GiB RAM (not quota-controlled — privileged)

Total allocated: 32 CPU tenant + 32 CPU platform = 64 CPU
                 128 GiB tenant + 128 GiB platform = 256 GiB

Note: Sum of tenant quotas (32 CPU) = available tenant capacity (32 CPU)
If you over-allocate quotas (e.g., 80 CPU across tenants), tenants can
"reserve" more than exists — quota is a ceiling, not a guarantee.
For guaranteed resources, use PriorityClasses and node reservations.
```

---

## Real-World Example — Complete Namespace Setup

Combining everything into a production-ready multi-tenant namespace configuration:

```yaml
# ── 1. Namespace with PSA labels ─────────────────────────────────
apiVersion: v1
kind: Namespace
metadata:
  name: namespace_a
  labels:
    team: platform
    environment: production
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
---
# ── 2. LimitRange — per-container defaults and bounds ─────────────
apiVersion: v1
kind: LimitRange
metadata:
  name: namespace-a-limits
  namespace: namespace_a
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    max:
      cpu: "2"
      memory: "4Gi"
    min:
      cpu: "50m"
      memory: "64Mi"
  - type: PersistentVolumeClaim
    max:
      storage: "20Gi"
    min:
      storage: "1Gi"
---
# ── 3. ResourceQuota — namespace-wide ceilings ────────────────────
apiVersion: v1
kind: ResourceQuota
metadata:
  name: cpu-memory-quota
  namespace: namespace_a
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 16Gi
    limits.cpu: "8"
    limits.memory: 32Gi
    pods: "50"
    services: "15"
    persistentvolumeclaims: "10"
    requests.storage: 100Gi
    secrets: "30"
    configmaps: "30"
    services.loadbalancers: "1"
    services.nodeports: "0"
    count/deployments.apps: "20"
```

```yaml
# ── 4. Pod that fits within this namespace's constraints ──────────
apiVersion: v1
kind: Pod
metadata:
  name: resource-limited-pod
  namespace: namespace_a
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: resource-limited-container
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      requests:
        cpu: "250m"      # Within LimitRange min (50m) and max (2)
        memory: "64Mi"   # Within LimitRange min (64Mi) and max (4Gi)
      limits:
        cpu: "500m"      # Within LimitRange max (2)
        memory: "128Mi"  # Within LimitRange max (4Gi)
```

---

## Diagnosing Quota and LimitRange Issues

```bash
# ── Pod rejected due to quota exhaustion ─────────────────────────
kubectl run test-pod --image=nginx -n namespace_a
# Error from server (Forbidden): pods "test-pod" is forbidden:
# exceeded quota: cpu-memory-quota,
# requested: requests.cpu=100m, used: requests.cpu=3900m,
# limited: requests.cpu=4

# Fix: either scale down existing pods or request quota increase
kubectl describe resourcequota cpu-memory-quota -n namespace_a

# ── Pod rejected because no resource spec and no LimitRange ───────
# Error: "must specify limits.cpu for: namespace_a"
# Fix: Add a LimitRange with defaults, or add resources to pod spec

# ── Container violates LimitRange max ─────────────────────────────
kubectl apply -f big-pod.yaml
# Error: maximum cpu usage per Container is 2, but limit is 4.

# ── Container below LimitRange min ────────────────────────────────
# Error: minimum memory usage per Container is 64Mi, but request is 32Mi.

# ── Check if LimitRange is injecting defaults ─────────────────────
# Create a pod with no resource spec, then describe it
kubectl run test --image=nginx -n namespace_a --dry-run=server -o yaml | \
  grep -A10 resources
# Should show the LimitRange-injected defaults
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Deploying ResourceQuota without LimitRange

Without LimitRange, every pod must explicitly specify resource requests and limits. In practice this breaks many deployments that rely on defaults. Always pair them.

### ❌ Mistake 2: Setting `requests` quota but not `limits` quota (or vice versa)

If you set `requests.cpu` but not `limits.cpu`, pods can set unlimited CPU limits. A tenant could set `limits.cpu: 1000` on their pods, which the scheduler ignores for placement but which the kubelet considers — this creates unpredictable behaviour. Always set both.

### ❌ Mistake 3: Not accounting for system overhead in quota math

Setting `requests.cpu: 64` in a cluster with 64 CPU cores leaves no headroom for system pods (kube-proxy, CoreDNS, CNI plugins, monitoring agents). System pods run in `kube-system` which typically has no quota — but they still consume real CPU and memory. Size tenant quotas to leave 15-20% capacity for system components.

### ❌ Mistake 4: Forgetting object count quotas for expensive resources

LoadBalancer services and NodePort services have real infrastructure costs. Without `services.loadbalancers: "0"` or `"1"` in a quota, a tenant could create 100 load balancers and run up a massive cloud bill.

### ❌ Mistake 5: Reading `kubectl describe quota` wrong

The output shows `Used` vs. `Hard`. **Used** is what's currently consuming the quota — the sum of all running pods' resource specs. **Hard** is the ceiling. If `Used` equals `Hard`, the next pod creation will fail.

```bash
kubectl describe resourcequota -n namespace_a
# Resource         Used    Hard
# --------         ----    ----
# requests.cpu     4       4      ← FULL — next pod will fail!
# pods             48      50     ← Nearly full
```

### ❌ Mistake 6: Setting quota but allowing pods without `requests` via `BestEffort` scope

BestEffort pods (no resource requests or limits) don't consume compute quota — they have no resources to count. If you don't add a `BestEffort` scope quota limiting pod count, tenants can create unlimited BestEffort pods that bypass your compute quota.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│              Resource Quotas — Quick Reference                   │
├─────────────────┬───────────────────────────────────────────────┤
│ ResourceQuota   │ Namespace-level hard ceiling on:               │
│ controls        │  • Compute: requests/limits CPU + memory       │
│                 │  • Storage: PVC count + total size             │
│                 │  • Objects: pod count, service count, etc.     │
├─────────────────┼───────────────────────────────────────────────┤
│ LimitRange      │ Per-container/pod defaults and bounds:         │
│ controls        │  • default: injected if container omits limits │
│                 │  • defaultRequest: injected if no requests     │
│                 │  • max: hard ceiling per container             │
│                 │  • min: minimum per container                  │
├─────────────────┼───────────────────────────────────────────────┤
│ Always deploy   │ ResourceQuota alone → pods without resource    │
│ both together   │ specs get rejected                             │
│                 │ LimitRange alone → no namespace ceiling        │
│                 │ Both together → defaults injected + ceiling    │
├─────────────────┼───────────────────────────────────────────────┤
│ Key commands    │ kubectl describe resourcequota -n <ns>         │
│                 │ kubectl describe limitrange -n <ns>            │
│                 │ kubectl get resourcequota --all-namespaces     │
├─────────────────┼───────────────────────────────────────────────┤
│ Quota fields    │ requests.cpu / requests.memory                 │
│                 │ limits.cpu / limits.memory                     │
│                 │ pods / services / secrets / configmaps         │
│                 │ persistentvolumeclaims / requests.storage      │
│                 │ services.loadbalancers / services.nodeports    │
│                 │ count/<resource>.<group>                       │
├─────────────────┼───────────────────────────────────────────────┤
│ LimitRange      │ Container / Pod / PersistentVolumeClaim        │
│ types           │                                                │
├─────────────────┼───────────────────────────────────────────────┤
│ Security use    │ services.nodeports: "0" — block NodePort       │
│                 │ services.loadbalancers: "1" — control cloud LB │
│                 │ pods: "N" — limit blast radius from runaway    │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**Create from scratch rapidly.** The exam often asks you to create a ResourceQuota or LimitRange for a namespace. Know the YAML structure cold or use `kubectl create quota`:

```bash
# Imperative ResourceQuota creation
kubectl create quota tenant-quota \
  --hard=requests.cpu=4,requests.memory=16Gi,limits.cpu=8,limits.memory=32Gi,pods=50 \
  --namespace=namespace_a

# Verify immediately
kubectl describe resourcequota tenant-quota -n namespace_a
```

**LimitRange has no imperative command** — you must write YAML. Practice writing the structure with `type: Container`, `default`, `defaultRequest`, `max`, and `min`.

**Read the quota output carefully.** The exam may ask "why is this pod failing?" and the answer is visible in `kubectl describe resourcequota` — the Used field is at or near the Hard limit.

**Remember the security controls:** `services.nodeports: "0"` and `services.loadbalancers: "0"` are quota-enforced security policies, not just cost controls. The exam may ask you to prevent NodePort service creation — ResourceQuota is the right tool.

**Know the relationship between `requests` and scheduling.** ResourceQuota tracks `requests`, not `limits`. The scheduler uses requests to decide placement. A pod with no requests bypasses quota tracking (and that's the BestEffort scope exception).

---

## Summary

ResourceQuota and LimitRange are the resource isolation layer of multi-tenant Kubernetes. ResourceQuota sets namespace-wide hard ceilings on compute (CPU/memory requests and limits), storage (PVC count and total size), and object counts (pods, services, load balancers). Once the ceiling is hit, new resource creation is rejected at the API server — protecting other tenants' capacity.

LimitRange is the essential companion that injects default resource requests and limits into pods that don't specify them, ensuring ResourceQuota enforcement doesn't break deployments that rely on defaults. It also sets per-container bounds, preventing any single container from claiming an unfair share of the namespace quota.

Together, they form the "noisy neighbor" prevention layer: a misbehaving or runaway tenant is contained within their quota, unable to starve other tenants of CPU or memory regardless of how many pods they try to spawn. Combined with the RBAC and namespace isolation from Chapter 17, they complete the control plane isolation picture — access is controlled by RBAC, and resource consumption is bounded by quota.

---

## What's Next

**[Chapter 19 — Data Plane Isolation →](./19%20---%20Data%20Plane%20Isolation.md)**

With the control plane secured (RBAC in Chapter 17, ResourceQuota here), the focus shifts to the data plane — what happens at runtime between running workloads. Chapter 19 introduces data plane isolation: the mechanisms that prevent tenant pods from talking to each other, accessing each other's storage, or escaping their scheduled nodes.
