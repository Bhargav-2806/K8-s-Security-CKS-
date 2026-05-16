# Chapter 24 — Quality of Service

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 23 — Additional Considerations — API Priority and Fairness](./23%20---%20Additional%20Considerations%20API%20Priority%20Fairness.md)
> **Next:** [Chapter 25 — DNS in Multi-Tenant Environments](./25%20---%20DNS%20in%20Multi%20Tenant%20Environments.md)

---

## Why This Matters for CKS

Quality of Service (QoS) is the implicit priority system that Kubernetes derives from your resource configuration. Unlike Pod Priority (Chapter 23) which is explicit and intentional, QoS emerges automatically from how you write your resource requests and limits — and it directly determines which pods get evicted first when a node runs low on memory. Getting QoS wrong has real consequences in multi-tenant clusters: a misconfigured tenant pod in the BestEffort class will be the first victim of memory pressure, even if it's running a critical workload.

The CKS exam tests QoS through:
- Identifying the QoS class of a pod from its resource spec
- Understanding the eviction order under memory pressure
- Knowing how QoS interacts with Pod Priority from Chapter 23
- Recognising that network and storage QoS are external mechanisms, not built-in Kubernetes primitives

---

## What Is QoS in Kubernetes?

Kubernetes Quality of Service is the mechanism by which the kubelet determines **eviction priority** when a node runs out of memory. Unlike CPU (which is compressible — processes can be throttled), memory is incompressible: when it runs out, processes must be killed.

The kubelet assigns every pod to one of three QoS classes:

```
QoS Class Assignment Rules
════════════════════════════

Guaranteed:
  ALL containers in the pod must have:
  • requests.cpu == limits.cpu (exactly equal, both set)
  • requests.memory == limits.memory (exactly equal, both set)
  Result: Kubernetes reserves exactly what the pod needs, nothing more.

Burstable:
  At least ONE container has requests OR limits set,
  AND the pod does NOT qualify for Guaranteed.
  Result: Pod is guaranteed its requests, can burst to limits.

BestEffort:
  NO container has ANY resource requests OR limits.
  Result: Pod gets whatever is leftover after all others are served.
```

The QoS class is not a field you set — it's computed and stored by Kubernetes:

```bash
kubectl get pod critical-app -o jsonpath='{.status.qosClass}'
# Guaranteed

kubectl describe pod critical-app | grep "QoS Class"
# QoS Class:  Guaranteed
```

---

## QoS Class 1 — Guaranteed

### What It Means

A pod gets the `Guaranteed` QoS class when every container's resource requests equal its limits. Kubernetes treats this pod as if it has reserved, dedicated resources:

- The **scheduler** places it on a node with exactly enough capacity for its requests (which equal its limits)
- The **kubelet** does not attempt to evict it under memory pressure unless the node itself is critically unstable
- The **cgroups** give it a predictable CPU and memory allocation

### Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: critical-app
  namespace: namespace-a
spec:
  containers:
  - name: critical-container
    image: nginx
    resources:
      requests:
        memory: "500Mi"
        cpu: "500m"
      limits:
        memory: "500Mi"     # ← Must equal requests.memory
        cpu: "500m"         # ← Must equal requests.cpu
  # QoS class: Guaranteed
  # Every container must meet this requirement
  # If initContainers exist, they must also meet it
```

### When to Use

```
Guaranteed QoS is appropriate for:
  ✅ Production databases — cannot tolerate unexpected eviction
  ✅ Stateful services with in-memory state (Redis, Kafka brokers)
  ✅ Payment processing, authentication services — must be always available
  ✅ Any workload where performance must be consistent and predictable
  ✅ Multi-tenant environments: critical tenant SLAs requiring uptime guarantees

Trade-off:
  → Wastes resources if the workload doesn't consistently use all its requested resources
  → requests = limits means NO burst capacity — always allocated, never scaled
```

### Multi-Container Pod — All Must Be Guaranteed

If a pod has multiple containers (including sidecars), **every container** must have matching requests and limits for the pod to be `Guaranteed`:

```yaml
spec:
  containers:
  - name: main-app
    resources:
      requests: {cpu: "500m", memory: "512Mi"}
      limits:   {cpu: "500m", memory: "512Mi"}   # Guaranteed
  - name: log-sidecar
    resources:
      requests: {cpu: "100m", memory: "64Mi"}
      limits:   {cpu: "100m", memory: "64Mi"}    # Also Guaranteed
  # Pod QoS: Guaranteed ✅ (both containers qualify)
```

If even one container is Burstable (different requests vs. limits), the whole pod drops to `Burstable`.

---

## QoS Class 2 — Burstable

### What It Means

`Burstable` pods have at least one container with resource requests set, but requests and limits are not equal (or limits are unset). The pod is guaranteed its requests, but can consume more if available. Under memory pressure, Burstable pods are evicted after BestEffort pods but before Guaranteed pods.

### Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: burstable-app
  namespace: namespace-b
spec:
  containers:
  - name: burstable-container
    image: nginx
    resources:
      requests:
        memory: "200Mi"    # Guaranteed minimum
        cpu: "200m"
      limits:
        memory: "16Gi"     # Can burst up to 16 GiB when resources are available
        cpu: "1"           # Can burst up to 1 CPU core
  # QoS class: Burstable
  # requests < limits → not Guaranteed
```

### Common Burstable Patterns

```yaml
# Pattern 1: Requests set, no limits (risky — unlimited burst)
resources:
  requests:
    cpu: "200m"
    memory: "256Mi"
  # No limits → Burstable, but can consume unlimited memory (OOM risk)

# Pattern 2: Only limits, no requests
resources:
  limits:
    cpu: "500m"
    memory: "512Mi"
  # No explicit requests → Kubernetes copies limits as requests
  # Actually becomes Guaranteed! (requests = limits after injection)

# Pattern 3: Requests and limits both set but unequal
resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "500m"     # limits > requests → Burstable
    memory: "512Mi"
```

### When to Use

```
Burstable QoS is appropriate for:
  ✅ Web frontends — typical load is predictable, spike-tolerant
  ✅ Background workers — variable workload, can burst during peak
  ✅ Development workloads — want decent defaults but allow flexibility
  ✅ When resource usage is bursty and you want to balance cost and performance
  ✅ Most "standard" tenant workloads in multi-tenant clusters

Trade-off:
  → Evicted before Guaranteed pods under memory pressure
  → Burst consumption can affect other co-resident pods (noisy neighbor)
  → Unlimited burst (no limits set) creates OOM risk for the node
```

---

## QoS Class 3 — BestEffort

### What It Means

`BestEffort` pods have **no resource requests or limits** on any container. They get whatever resources happen to be available on the node. Under any memory pressure, they are the **first to be evicted** — the kubelet targets them before Burstable or Guaranteed pods.

### Configuration

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: besteffort-app
  namespace: namespace-b
spec:
  containers:
  - name: besteffort-container
    image: nginx
    # No resources block at all → BestEffort
  # QoS class: BestEffort
```

### When to Use

```
BestEffort QoS is appropriate for:
  ✅ Development and testing — acceptable to be evicted
  ✅ Short-lived batch jobs — restart on failure is acceptable
  ✅ Non-critical analytics — can retry if evicted
  ✅ Canary deployments — can be sacrificed during pressure

When NOT to use:
  ❌ Any production workload
  ❌ Multi-tenant environments where tenant SLA requires availability
  ❌ Stateful workloads (data loss on eviction)
  ❌ Workloads that run LimitRange-enforced namespaces
       (LimitRange default injection makes them Burstable/Guaranteed automatically)
```

---

## Eviction Order Under Memory Pressure

When a node runs out of memory, the kubelet evicts pods in this order:

```
Eviction Priority (evicted FIRST to LAST)
══════════════════════════════════════════

1. BestEffort pods
   → No reservation, first sacrifice

2. Burstable pods whose usage exceeds their requests
   → Using more than they reserved — fair to evict first
   → Eviction target: pod with the highest (usage - request) / limit ratio

3. Burstable pods whose usage is within their requests
   → Unlikely to be evicted unless pressure is severe
   → Eviction target: pod with the highest usage / request ratio

4. Guaranteed pods
   → Only evicted if the node itself is unstable (kernel OOM killer)
   → The kubelet does NOT evict Guaranteed pods under normal pressure

Note: Pod Priority (Chapter 23) can override this order.
      A high-priority BestEffort pod is evicted before a low-priority Guaranteed pod.
      QoS and Priority work together: Priority is the primary sort key,
      QoS is the secondary sort key within the same priority level.
```

### The Interaction Between QoS and Pod Priority

```
Combined eviction scoring (simplified):
  Primary key:   Pod Priority value (higher priority = evicted last)
  Secondary key: QoS class (Guaranteed evicted last within same priority)

Example: Four pods under memory pressure
  Pod A: priority=1000, Guaranteed     → Evicted LAST
  Pod B: priority=1000, BestEffort     → Evicted 3rd
  Pod C: priority=100,  Guaranteed     → Evicted 2nd
  Pod D: priority=100,  BestEffort     → Evicted FIRST

Low-priority BestEffort pod D is always the first victim.
High-priority Guaranteed pod A is the last resort.
```

---

## Network QoS

Unlike compute QoS, Kubernetes does not natively provide network bandwidth Quality of Service. Pod network interfaces all share the same underlying node network stack without built-in bandwidth control. Network QoS requires external mechanisms:

### Option 1 — CNI Plugin Bandwidth Limiting (Kubernetes-native annotation)

The `bandwidth` CNI plugin (supported by most major CNIs) allows per-pod bandwidth limiting via annotations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bandwidth-limited-pod
  namespace: namespace-a
  annotations:
    kubernetes.io/ingress-bandwidth: "10M"    # Max 10 Mbps inbound
    kubernetes.io/egress-bandwidth: "10M"     # Max 10 Mbps outbound
spec:
  containers:
  - name: app
    image: nginx
```

This uses Linux **Traffic Control (tc)** under the hood — the `tbf` (Token Bucket Filter) queuing discipline is applied to the pod's veth interface.

### Option 2 — Calico Network Policy with Rate Limits

Calico (used in the KodeKloud source example) extends standard Kubernetes NetworkPolicy with rate-limit actions:

```yaml
# Calico-specific NetworkPolicy (not standard Kubernetes NetworkPolicy)
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: tenant-a-network-policy
  namespace: namespace-a
spec:
  selector: all()         # Apply to all pods in namespace-a
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [80]
    # Note: rate limiting in Calico is via packet rate, not bandwidth
    # Actual bandwidth shaping requires CNI bandwidth plugin
  egress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [80]
```

### Option 3 — Linux tc (Traffic Control) via Init Containers

For fine-grained bandwidth control outside of CNI plugins:

```yaml
# InitContainer applies tc rules before main container starts
initContainers:
- name: set-bandwidth
  image: alpine
  command: ["/bin/sh", "-c"]
  args:
  - |
    # Apply traffic shaping to eth0 (pod's primary interface)
    tc qdisc add dev eth0 root tbf rate 10mbit burst 10kb latency 70ms
  securityContext:
    capabilities:
      add: ["NET_ADMIN"]   # Required for tc commands
```

### Network QoS Comparison

```
┌──────────────────────────────────┬────────────────────────────────────────┐
│ Approach                         │ Use Case                               │
├──────────────────────────────────┼────────────────────────────────────────┤
│ kubernetes.io/ingress-bandwidth  │ Simple per-pod bandwidth cap.          │
│ annotation (CNI bandwidth plugin)│ Works with most CNIs. Simple, reliable.│
├──────────────────────────────────┼────────────────────────────────────────┤
│ Calico NetworkPolicy with limits │ Packet rate limiting + traffic policy  │
│                                  │ combined. Calico-specific.             │
├──────────────────────────────────┼────────────────────────────────────────┤
│ Linux tc via init container      │ Maximum control. Complex, privileged.  │
│                                  │ Requires NET_ADMIN capability.         │
├──────────────────────────────────┼────────────────────────────────────────┤
│ Service mesh (Istio/Linkerd)     │ Application-level traffic shaping,     │
│                                  │ retry budgets, circuit breaking.       │
└──────────────────────────────────┴────────────────────────────────────────┘
```

---

## Storage QoS

Like network QoS, Kubernetes does not directly control storage I/O rates. Storage QoS is implemented through:

### StorageClass IOPS Configuration

```yaml
# High-IOPS StorageClass for critical tenant (Namespace A)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: high-performance
provisioner: kubernetes.io/aws-ebs
parameters:
  type: io1           # Provisioned IOPS SSD
  iopsPerGB: "50"     # 50 IOPS per GB (50 × 20GB = 1000 IOPS)
  fsType: ext4
reclaimPolicy: Delete
allowVolumeExpansion: true
volumeBindingMode: Immediate
---
# Standard StorageClass for regular tenants (Namespace B)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: standard-performance
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3           # General Purpose SSD (lower IOPS, cheaper)
  iopsPerGB: "3"      # 3 IOPS per GB baseline
  throughput: "125"   # 125 MiB/s throughput
  fsType: ext4
reclaimPolicy: Delete
allowVolumeExpansion: true
```

### Storage QoS at the Platform Level

For on-premises clusters with Ceph or NFS:

```yaml
# Ceph RBD storage class with QoS settings
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ceph-high-iops
provisioner: rbd.csi.ceph.com
parameters:
  clusterID: <ceph-cluster-id>
  pool: high-iops-pool           # Dedicated Ceph pool with QoS settings
  # Ceph supports per-pool IOPS limits via:
  # ceph osd pool set high-iops-pool rbd_qos_iops_limit 5000
  imageFeatures: layering
reclaimPolicy: Delete
```

---

## Full QoS Strategy for Multi-Tenant Clusters

Putting all QoS mechanisms together into a coherent multi-tenant strategy:

```
┌─────────────────────────────────────────────────────────────────────┐
│              Multi-Tenant QoS Architecture                          │
├──────────────────┬───────────────────┬──────────────────────────────┤
│ Tenant Tier      │ Compute QoS       │ Storage / Network QoS        │
├──────────────────┼───────────────────┼──────────────────────────────┤
│ Critical         │ Guaranteed        │ high-performance StorageClass│
│ (namespace-a)    │ req = limits      │ 10Mbps+ bandwidth allocation │
│                  │ PriorityClass:    │ io1/gp3-with-high-iops       │
│                  │ high-priority     │                              │
├──────────────────┼───────────────────┼──────────────────────────────┤
│ Standard         │ Burstable         │ standard-performance class   │
│ (namespace-b     │ req < limits      │ Default bandwidth (shared)   │
│  production)     │ PriorityClass:    │ gp3 standard IOPS            │
│                  │ standard-priority │                              │
├──────────────────┼───────────────────┼──────────────────────────────┤
│ Development /    │ BestEffort or     │ Standard class               │
│ Batch            │ Burstable         │ Bandwidth limited (1Mbps)    │
│ (namespace-c)    │ PriorityClass:    │ Low-priority storage pool    │
│                  │ low-priority      │                              │
└──────────────────┴───────────────────┴──────────────────────────────┘
```

Enforced via:
- **LimitRange** (auto-injects resource defaults — prevents unintended BestEffort)
- **ResourceQuota** (caps total namespace consumption)
- **PriorityClass + ResourceQuota scopeSelector** (restricts which priority classes a namespace can use)
- **StorageClass + per-class ResourceQuota** (isolates storage tiers)
- **NetworkPolicy + CNI bandwidth annotations** (isolates network usage)

---

## QoS and LimitRange Interaction

An important behaviour: when a namespace has a `LimitRange` with defaults, pods without resource specs get the LimitRange defaults injected. This means they are no longer BestEffort:

```
Namespace with LimitRange:
  defaultRequest: {cpu: 100m, memory: 128Mi}
  default: {cpu: 500m, memory: 512Mi}

Pod with NO resource spec submitted:
  LimitRange injects:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {cpu: 500m, memory: 512Mi}

Result: Pod is Burstable (req < limits)
NOT BestEffort!

Without LimitRange:
  Pod with no resource spec → BestEffort
  Pod is first to be evicted under memory pressure
```

This is why deploying a LimitRange in every tenant namespace is important — it prevents tenant pods from accidentally landing in BestEffort and getting killed during memory pressure events.

---

## Diagnosing QoS Class

```bash
# Check QoS class of a specific pod
kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.qosClass}'
# Guaranteed, Burstable, or BestEffort

# Check QoS class in pod describe output
kubectl describe pod <pod-name> -n <namespace> | grep "QoS Class"

# List all pods with their QoS classes across all namespaces
kubectl get pods --all-namespaces -o json | jq '
  .items[] | {
    namespace: .metadata.namespace,
    name: .metadata.name,
    qos: .status.qosClass,
    requests: [.spec.containers[].resources.requests],
    limits: [.spec.containers[].resources.limits]
  }'

# Find all BestEffort pods (eviction risk)
kubectl get pods --all-namespaces -o json | jq '
  .items[] | select(.status.qosClass == "BestEffort") |
  {namespace: .metadata.namespace, name: .metadata.name}'

# Check kubelet eviction thresholds (default: evict at 100Mi available memory)
cat /var/lib/kubelet/config.yaml | grep -A5 eviction
# or
systemctl cat kubelet | grep eviction
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Thinking only limits set = Guaranteed

Setting only `limits` (no explicit `requests`) does NOT automatically make the pod Guaranteed. Kubernetes copies `limits` as `requests` when requests are unset — making them equal — which would technically be Guaranteed. But this is fragile: any LimitRange defaultRequest might override this. Explicitly set both requests and limits to the same value for true Guaranteed intent.

### ❌ Mistake 2: Believing BestEffort pods use no resources

BestEffort pods CAN consume resources — they just have no reservations. A BestEffort pod can spike to use all available CPU or fill all available memory, triggering eviction of itself AND potentially impacting co-resident pods by causing memory pressure on the node.

### ❌ Mistake 3: Confusing Pod Priority with QoS class

Pod Priority (Chapter 23) is an explicit integer value set on a PriorityClass. QoS is an implicit class derived from resource configuration. They interact in eviction: Priority is the primary key, QoS is the tiebreaker within the same priority level.

### ❌ Mistake 4: Assuming Guaranteed pods are never evicted

Guaranteed pods are the last to be evicted under kubelet-managed memory pressure. But the Linux kernel's **OOM killer** operates independently — if the kernel runs out of physical memory, it can kill any process, including processes in Guaranteed pods, without following Kubernetes eviction order. This is a last-resort kernel mechanism that bypasses the kubelet.

### ❌ Mistake 5: Setting limits much higher than requests without understanding burst risk

A Burstable pod with `requests: 200Mi, limits: 16Gi` is guaranteed 200Mi but can burst to 16GB. If the node has 16GB total and the pod actually uses 15GB, it effectively starves all other pods. Always set reasonable limits relative to actual expected usage.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│              Quality of Service — Quick Reference                │
├─────────────────┬───────────────────────────────────────────────┤
│ Guaranteed      │ requests == limits for ALL containers          │
│                 │ Both CPU and memory must match exactly         │
│                 │ Last evicted (except kernel OOM)               │
│                 │ Use for: critical, latency-sensitive workloads │
├─────────────────┼───────────────────────────────────────────────┤
│ Burstable       │ At least one container has requests OR limits  │
│                 │ Requests ≠ limits OR mixed containers          │
│                 │ Evicted 2nd (after BestEffort)                 │
│                 │ Use for: standard production workloads         │
├─────────────────┼───────────────────────────────────────────────┤
│ BestEffort      │ NO requests OR limits on ANY container         │
│                 │ First evicted under any memory pressure        │
│                 │ Use for: dev, test, batch (never production)   │
├─────────────────┼───────────────────────────────────────────────┤
│ Eviction order  │ BestEffort → Burstable (over request) →       │
│                 │ Burstable (within request) → Guaranteed        │
│                 │ Pod Priority overrides this as primary key     │
├─────────────────┼───────────────────────────────────────────────┤
│ Network QoS     │ Not built-in — use CNI bandwidth annotations  │
│                 │ kubernetes.io/ingress-bandwidth: "10M"          │
│                 │ kubernetes.io/egress-bandwidth: "10M"          │
├─────────────────┼───────────────────────────────────────────────┤
│ Storage QoS     │ Not built-in — use StorageClass parameters     │
│                 │ io1/iopsPerGB (AWS), gp3/iops (AWS)           │
│                 │ Per-tenant StorageClasses isolate IOPS pools   │
├─────────────────┼───────────────────────────────────────────────┤
│ Check QoS class │ kubectl get pod <name> -o jsonpath            │
│                 │   '{.status.qosClass}'                        │
│                 │ kubectl describe pod <name> | grep QoS        │
├─────────────────┼───────────────────────────────────────────────┤
│ LimitRange      │ Injects defaults → prevents accidental         │
│ interaction     │ BestEffort classification                      │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**Identify QoS class from resource spec instantly.** Given a pod spec, you should immediately know the QoS class:
- Both `requests == limits` for all containers → Guaranteed
- Any requests or limits set, but `requests ≠ limits` → Burstable
- No resources at all → BestEffort

**The "only limits" trap.** If a pod has limits but no requests, Kubernetes copies limits as requests, making `requests == limits` → Guaranteed. The exam may use this to test whether you understand the rule.

**LimitRange prevents BestEffort.** In a namespace with a LimitRange defining `defaultRequest`, pods without resource specs get Burstable (injected request < injected limit) or Guaranteed (if defaultRequest == default). BestEffort only happens when no LimitRange exists AND no resources are specified.

**Network and storage QoS are NOT Kubernetes primitives.** They're implemented via CNI plugins and StorageClasses respectively. If the exam asks about network bandwidth limits, the answer involves CNI annotations or Calico policies — not a built-in Kubernetes QoS field.

**Know the eviction order cold:** BestEffort → Burstable → Guaranteed. This ordering, combined with Pod Priority, determines which pods survive memory pressure.

---

## Summary

Kubernetes Quality of Service classifies pods into three compute tiers based entirely on how their resource requests and limits are configured. Guaranteed pods — where every container's requests equal its limits — receive stable, predictable resource allocation and are the last to be evicted under memory pressure. Burstable pods have minimum resource guarantees but can scale up when resources are available; they're evicted after BestEffort pods but before Guaranteed. BestEffort pods, with no resource specifications, are the first eviction candidates and should never be used for production workloads.

The QoS class interacts with Pod Priority (Chapter 23): Priority is the primary eviction sort key, and QoS is the tiebreaker within the same priority level. LimitRange in every tenant namespace prevents accidental BestEffort classification by injecting resource defaults into pods that don't specify them.

Network and storage QoS are not Kubernetes-native constructs. Network bandwidth control requires CNI plugin support (via `kubernetes.io/ingress-bandwidth` annotations) or Calico-specific policies. Storage IOPS isolation is achieved through StorageClass parameter configuration at the provisioner level, with per-class ResourceQuota restrictions ensuring each tenant uses only their designated storage tier.

---

## What's Next

**[Chapter 25 — DNS in Multi-Tenant Environments →](./25%20---%20DNS%20in%20Multi%20Tenant%20Environments.md)**

Chapter 25 closes the multi-tenancy section by addressing DNS — the service discovery layer that every pod uses to communicate. In multi-tenant clusters, DNS is a potential information disclosure vector: a pod in one tenant namespace can enumerate services in other namespaces by querying the cluster DNS. Chapter 25 covers DNS isolation strategies including NetworkPolicy-based DNS egress control, per-tenant CoreDNS configurations, and the risks of cross-namespace service discovery.
