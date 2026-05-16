# Chapter 22 — Using Node Pools and Taints/Tolerations for Isolation

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 21 — Data Plane Isolation — Storage](./21%20---%20Data%20Plane%20Isolation%20Storage.md)
> **Next:** [Chapter 23 — Additional Considerations — API Priority and Fairness](./23%20---%20Additional%20Considerations%20API%20Priority%20Fairness.md)

---

## Why This Matters for CKS

Node-level isolation is the final and most powerful data plane isolation mechanism — and the one that closes the shared-kernel attack surface that namespace, network, and storage isolation cannot address. Even with perfect RBAC, NetworkPolicy, and storage controls, pods sharing a physical node share the same Linux kernel. A kernel exploit or container escape from one tenant can potentially reach another tenant's processes if they co-reside on the same node.

The CKS exam tests node isolation through hands-on tasks:
- Applying taints to nodes with specific effects (NoSchedule, PreferNoSchedule, NoExecute)
- Writing pod specs with matching tolerations
- Combining tolerations with `nodeSelector` and `nodeAffinity` for guaranteed placement
- Understanding why tolerations alone are insufficient without also attracting pods to the right nodes
- Recognising the difference between soft and hard scheduling constraints

---

## Why Node-Level Isolation Is Necessary

Network and storage isolation address runtime communication and data access. They don't address **co-location** — the fact that two tenant pods may run side-by-side on the same physical machine, sharing:

```
Shared Resources When Pods Co-Reside on the Same Node
══════════════════════════════════════════════════════

1. LINUX KERNEL
   All pods on a node make system calls to the SAME kernel.
   A kernel exploit (e.g., a container breakout via a CVE like
   runc CVE-2019-5736 or overlayfs CVE-2021-3493) gives the
   attacker root on the host — affecting ALL co-resident pods.

2. CPU CACHES (L1/L2/L3)
   Modern CPUs share cache between cores. Side-channel attacks
   (Spectre, Meltdown) allow a process to infer data from another
   process's cache activity. Tenant A can potentially read Tenant B's
   encryption keys or memory via timing attacks.

3. MEMORY (with NUMA effects)
   Memory bandwidth is shared. A memory-intensive tenant slows
   all other pods (even with cgroup memory limits, cache thrashing
   still affects neighbours).

4. HOST FILESYSTEM (/proc, /sys, /dev)
   Even without hostPath volumes, the host's /proc filesystem
   can reveal process information of other containers.
   /proc/<pid>/environ, /proc/<pid>/mem, /proc/<pid>/fd
   can leak secrets from co-resident containers.

5. NETWORK INTERFACES
   All pods on a node share the host's network interfaces.
   ARP spoofing or raw socket attacks target the physical NIC,
   not the virtual pod interface.
```

Node isolation eliminates these risks by ensuring tenant pods never co-locate.

---

## The Taint/Toleration Mechanism

Kubernetes uses **taints** on nodes and **tolerations** on pods as a push-pull scheduling mechanism:

```
Taint on Node:  "Only pods that explicitly tolerate this may run here"
                → REPELS pods without matching toleration

Toleration on Pod: "I can tolerate this taint"
                   → ALLOWS the pod to run on tainted nodes
                   → Does NOT force the pod onto tainted nodes

Together:
  Taint repels unwanted pods
  Toleration permits wanted pods

But you still need nodeSelector or nodeAffinity to ATTRACT pods
to the right nodes — toleration alone is not sufficient!
```

### Taint Syntax

```bash
# kubectl taint nodes <node-name> <key>=<value>:<effect>

# Apply a taint
kubectl taint nodes nodeA customer=customerA:NoSchedule

# Remove a taint (append -)
kubectl taint nodes nodeA customer=customerA:NoSchedule-

# View taints on a node
kubectl describe node nodeA | grep -A5 Taints
```

### Taint Effects

```
┌──────────────────────────────────────────────────────────────────┐
│                    Taint Effects                                  │
├─────────────────────┬────────────────────────────────────────────┤
│ NoSchedule          │ New pods without matching toleration will   │
│                     │ NOT be scheduled on this node.             │
│                     │ Existing pods are NOT affected.            │
│                     │ Use for: dedicated node pools              │
├─────────────────────┼────────────────────────────────────────────┤
│ PreferNoSchedule    │ Scheduler TRIES to avoid placing pods       │
│                     │ without matching toleration here.           │
│                     │ If no other node is available, pod may     │
│                     │ still land here.                           │
│                     │ Use for: soft preference (best-effort)     │
├─────────────────────┼────────────────────────────────────────────┤
│ NoExecute           │ New pods without toleration are not         │
│                     │ scheduled AND existing pods without        │
│                     │ toleration are EVICTED.                    │
│                     │ Tolerations can include tolerationSeconds  │
│                     │ to delay eviction.                         │
│                     │ Use for: node quarantine, urgent isolation  │
└─────────────────────┴────────────────────────────────────────────┘
```

---

## Step 1 — Apply Taints to Nodes

Reserve nodes for specific tenants by tainting them:

```bash
# Reserve nodeA exclusively for Customer A workloads
kubectl taint nodes nodeA customer=customerA:NoSchedule

# Reserve nodeB exclusively for Customer B workloads
kubectl taint nodes nodeB customer=customerB:NoSchedule

# Reserve nodeC exclusively for Customer C workloads
kubectl taint nodes nodeC customer=customerC:NoSchedule

# Label nodes for nodeSelector targeting
kubectl label nodes nodeA dedicated=customerA
kubectl label nodes nodeB dedicated=customerB
kubectl label nodes nodeC dedicated=customerC

# Verify taints applied
kubectl describe node nodeA | grep Taints
# Taints: customer=customerA:NoSchedule

# Verify labels applied
kubectl get node nodeA --show-labels
```

After this, any pod WITHOUT the `customer=customerA` toleration will be refused by nodeA. System pods (kube-proxy, CoreDNS) need to be handled — see the system pods section below.

---

## Step 2 — Configure Pods with Tolerations

Pods belonging to Customer A need the matching toleration to be scheduled on nodeA:

```yaml
# Customer A pod — can schedule on tainted nodeA
apiVersion: v1
kind: Pod
metadata:
  name: customer-a-pod
  namespace: customer_a
spec:
  containers:
  - name: customer-a-container
    image: nginx
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
      limits:
        cpu: "500m"
        memory: "256Mi"
  tolerations:
  - key: "customer"
    operator: "Equal"
    value: "customerA"
    effect: "NoSchedule"
```

**Important:** This toleration only means the pod CAN run on nodeA — it doesn't force it there. Without a `nodeSelector` or `nodeAffinity`, the pod could also schedule on any untainted node in the cluster.

---

## Step 3 — Add nodeSelector for Guaranteed Placement

To complete node isolation, attract the pod to the dedicated node:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: customer-a-pod
  namespace: customer_a
spec:
  containers:
  - name: customer-a-container
    image: nginx
  tolerations:
  - key: "customer"
    operator: "Equal"
    value: "customerA"
    effect: "NoSchedule"
  nodeSelector:
    dedicated: customerA    # Pod ONLY schedules on nodes with this label
```

Now the pod:
1. Is repelled from nodeB and nodeC (wrong toleration)
2. Is attracted to nodeA (matching nodeSelector)
3. Cannot schedule on any other node (untainted nodes lack the label)

**Result: guaranteed co-location of Customer A pods on Customer A's dedicated nodes, with zero possibility of Customer B or C pods being on the same node.**

---

## Step 4 — Using nodeAffinity for More Complex Rules

`nodeAffinity` is the more powerful alternative to `nodeSelector`. It supports `In`, `NotIn`, `Exists`, `DoesNotExist`, `Gt`, `Lt` operators and both required (hard) and preferred (soft) constraints:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: customer-a-pod
  namespace: customer_a
spec:
  containers:
  - name: app
    image: nginx
  tolerations:
  - key: "customer"
    operator: "Equal"
    value: "customerA"
    effect: "NoSchedule"
  affinity:
    nodeAffinity:
      # REQUIRED — hard constraint (same as nodeSelector)
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: dedicated
            operator: In
            values:
            - customerA                # Must be on a customerA node
          - key: topology.kubernetes.io/zone
            operator: In
            values:
            - us-east-1a
            - us-east-1b              # AND in these AZs

      # PREFERRED — soft constraint (scheduler tries but not guaranteed)
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        preference:
          matchExpressions:
          - key: node-type
            operator: In
            values:
            - ssd-backed              # Prefer SSD nodes but not required
```

### nodeAffinity vs. nodeSelector

```
nodeSelector:
  + Simple syntax, easy to understand
  + Sufficient for basic tenant isolation
  - Binary (matches or doesn't) — no soft preferences
  - Only equality matching (key=value)

nodeAffinity:
  + Supports In, NotIn, Exists, DoesNotExist operators
  + Required (hard) + Preferred (soft) constraints
  + Can express complex multi-condition requirements
  - More verbose YAML
  + Required for complex scheduling scenarios
```

---

## Toleration Operators

```yaml
tolerations:
# Exact match — key=value with specific effect
- key: "customer"
  operator: "Equal"
  value: "customerA"
  effect: "NoSchedule"

# Key exists with any value, specific effect
- key: "dedicated"
  operator: "Exists"
  effect: "NoSchedule"

# Match all taints (DANGEROUS — do not use for tenant isolation)
- operator: "Exists"  # No key specified — tolerates ALL taints
  # Use ONLY for system-critical pods like kube-proxy

# NoExecute with tolerationSeconds (grace period before eviction)
- key: "node.kubernetes.io/not-ready"
  operator: "Exists"
  effect: "NoExecute"
  tolerationSeconds: 300   # Wait 300s before evicting from not-ready node
```

---

## Full Multi-Tenant Node Isolation Setup

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Multi-Tenant Node Pool Architecture                │
│                                                                      │
│  System Nodes (untainted — platform components)                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ node-sys-1 │ node-sys-2                                      │   │
│  │ [kube-proxy][coredns][prometheus][ingress-nginx]             │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Customer A Pool (taint: customer=customerA:NoSchedule)            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ nodeA-1 │ nodeA-2 │ nodeA-3                                  │   │
│  │ [pod-a-1][pod-a-2]  [pod-a-3][pod-a-4]  [pod-a-5]           │   │
│  │ (all pods have customer=customerA toleration + nodeSelector) │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Customer B Pool (taint: customer=customerB:NoSchedule)            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ nodeB-1 │ nodeB-2                                            │   │
│  │ [pod-b-1][pod-b-2]  [pod-b-3][pod-b-4]                      │   │
│  │ (all pods have customer=customerB toleration + nodeSelector) │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Customer C Pool (taint: customer=customerC:NoSchedule)            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ nodeC-1                                                       │   │
│  │ [pod-c-1][pod-c-2]                                           │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Complete Setup Script

```bash
# ── Step 1: Taint all customer nodes ─────────────────────────────
kubectl taint nodes nodeA-1 nodeA-2 nodeA-3 customer=customerA:NoSchedule
kubectl taint nodes nodeB-1 nodeB-2 customer=customerB:NoSchedule
kubectl taint nodes nodeC-1 customer=customerC:NoSchedule

# ── Step 2: Label all customer nodes ─────────────────────────────
kubectl label nodes nodeA-1 nodeA-2 nodeA-3 dedicated=customerA
kubectl label nodes nodeB-1 nodeB-2 dedicated=customerB
kubectl label nodes nodeC-1 dedicated=customerC

# ── Step 3: Verify — no Customer A pods can run on nodeB ─────────
# Try creating a Customer A pod without Customer A toleration
kubectl run test-pod --image=nginx -n customer_a \
  --overrides='{"spec":{"nodeSelector":{"dedicated":"customerB"}}}'
# Should fail: 0/2 nodes are available: 2 node(s) had untolerated taint {customer: customerB}

# ── Step 4: Verify Customer A pod lands on correct node ───────────
kubectl get pod customer-a-pod -n customer_a -o wide
# NAME              NODE    READY   STATUS
# customer-a-pod    nodeA-1  1/1    Running   ← Correct!
```

### Deployment with Node Isolation

```yaml
# Production: Customer A Deployment with full node isolation
apiVersion: apps/v1
kind: Deployment
metadata:
  name: customer-a-app
  namespace: customer_a
spec:
  replicas: 3
  selector:
    matchLabels:
      app: customer-a-app
  template:
    metadata:
      labels:
        app: customer-a-app
    spec:
      # ── Node isolation ────────────────────────────────────────
      tolerations:
      - key: "customer"
        operator: "Equal"
        value: "customerA"
        effect: "NoSchedule"
      nodeSelector:
        dedicated: customerA

      # ── Pod anti-affinity (spread across Customer A nodes) ────
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: customer-a-app
              topologyKey: kubernetes.io/hostname   # Spread across different nodes

      # ── Security context ──────────────────────────────────────
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault

      containers:
      - name: app
        image: customer-a-app:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        resources:
          requests:
            cpu: "250m"
            memory: "256Mi"
          limits:
            cpu: "1"
            memory: "512Mi"
```

---

## Handling System Pods on Tainted Nodes

DaemonSet pods (kube-proxy, CNI agents, monitoring agents) must run on every node, including tainted ones. They use broad tolerations to achieve this:

```yaml
# kube-proxy DaemonSet (Kubernetes default) — tolerates all taints
# This is necessary — kube-proxy must run everywhere for networking
tolerations:
- operator: Exists   # Matches ANY taint key/value/effect

# Custom monitoring DaemonSet — tolerate specific customer taints
tolerations:
- key: "customer"
  operator: "Exists"    # Matches any customer=X:NoSchedule taint
  effect: "NoSchedule"
```

This is expected behaviour — DaemonSets need to bypass tenant taints. The important constraint is that *application* pods from other tenants cannot bypass them.

### Reserving System Nodes

To prevent tenant pods from landing on system/platform nodes, taint those nodes too:

```bash
# Taint system nodes — platform components only
kubectl taint nodes node-sys-1 node-sys-2 \
  node-role.kubernetes.io/control-plane:NoSchedule

# Or a custom taint for platform workloads
kubectl taint nodes node-sys-1 node-sys-2 \
  dedicated=platform:NoSchedule

kubectl label nodes node-sys-1 node-sys-2 dedicated=platform
```

Platform components (Prometheus, Ingress Controller, cert-manager) are then deployed with the matching toleration to land on system nodes, keeping them off customer nodes entirely.

---

## Node Isolation + OPA Gatekeeper — Enforcing Toleration Requirements

With manual taint/toleration setups, a misconfigured tenant pod that accidentally lacks a `nodeSelector` might land on an untainted node — sharing it with other tenants. OPA Gatekeeper can enforce that all pods in a customer namespace must have the correct toleration and nodeSelector:

```yaml
# ConstraintTemplate: require specific toleration in namespace
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredtoleration
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredToleration
      validation:
        openAPIV3Schema:
          type: object
          properties:
            requiredTolerationKey:
              type: string
            requiredTolerationValue:
              type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8srequiredtoleration

      violation[{"msg": msg}] {
        pod := input.review.object
        key := input.parameters.requiredTolerationKey
        val := input.parameters.requiredTolerationValue
        not has_toleration(pod, key, val)
        msg := sprintf("Pod must have toleration key=%v value=%v", [key, val])
      }

      has_toleration(pod, key, val) {
        toleration := pod.spec.tolerations[_]
        toleration.key == key
        toleration.value == val
      }
---
# Constraint: every pod in customer_a namespace must have Customer A toleration
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredToleration
metadata:
  name: customer-a-toleration-required
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    namespaces:
    - customer_a
  parameters:
    requiredTolerationKey: customer
    requiredTolerationValue: customerA
```

This admission webhook prevents any Customer A pod from being admitted without the correct toleration, ensuring no pod accidentally lands on a shared node.

---

## NoExecute Taint — Emergency Node Isolation

`NoExecute` goes further than `NoSchedule` — it evicts existing pods that don't have a matching toleration:

```bash
# Emergency: isolate a node immediately, evicting non-Customer-A pods
kubectl taint nodes nodeA-1 emergency=isolation:NoExecute

# Pods without this toleration are evicted immediately
# Pods with: tolerationSeconds determines grace period

# For planned maintenance: cordon + drain instead
kubectl cordon nodeA-1     # Prevent new pods from scheduling
kubectl drain nodeA-1 --ignore-daemonsets --delete-emptydir-data
# Gracefully evicts all pods, then you can maintain the node
```

`NoExecute` is useful for:
- Emergency node quarantine (suspected compromise)
- Kubernetes node condition taints (node not ready, memory pressure, disk pressure)
- Temporary isolation for maintenance

Kubernetes itself applies `NoExecute` taints automatically:
```
node.kubernetes.io/not-ready:NoExecute
node.kubernetes.io/unreachable:NoExecute
node.kubernetes.io/memory-pressure:NoSchedule
node.kubernetes.io/disk-pressure:NoSchedule
node.kubernetes.io/pid-pressure:NoSchedule
node.kubernetes.io/unschedulable:NoSchedule
```

---

## Cost and Operational Considerations

```
┌─────────────────────────────────────────────────────────────────┐
│           Node Isolation: Cost vs. Security Analysis             │
├──────────────────────────────────┬──────────────────────────────┤
│ SECURITY BENEFIT                 │ OPERATIONAL COST             │
├──────────────────────────────────┼──────────────────────────────┤
│ Eliminates shared-kernel risk    │ Lower node utilisation —     │
│ between tenants                  │ idle capacity per tenant     │
├──────────────────────────────────┼──────────────────────────────┤
│ Prevents side-channel attacks    │ Each tenant needs minimum    │
│ (Spectre/Meltdown) across tenants│ viable nodes (HA = 3+)      │
├──────────────────────────────────┼──────────────────────────────┤
│ Limits blast radius from kernel  │ Cluster autoscaler must      │
│ exploits to own node pool        │ manage per-pool scaling      │
├──────────────────────────────────┼──────────────────────────────┤
│ Physical data separation for     │ More complex taint/label     │
│ compliance (GDPR, HIPAA)         │ management as tenants grow   │
├──────────────────────────────────┼──────────────────────────────┤
│ Node failure only affects one    │ Less burst capacity sharing  │
│ tenant                           │ — cannot pool spare capacity  │
└──────────────────────────────────┴──────────────────────────────┘

When to use dedicated node pools:
  ✅ Multi-customer tenancy with contractual isolation guarantees
  ✅ Regulated industries (HIPAA, PCI-DSS, GDPR data residency)
  ✅ Tenants with significantly different security profiles
  ✅ When shared-kernel risk is unacceptable (financial, healthcare)
  ✅ High-value or high-sensitivity customer workloads

When NOT to use dedicated node pools:
  ❌ Internal team multi-tenancy (trusted users)
  ❌ Dev/staging environments (cost waste)
  ❌ Small tenant count where HA node minimum is prohibitively expensive
  ❌ When gVisor/Kata can provide sufficient sandbox isolation instead
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Tolerations without nodeSelector (the most common error)

A pod with a toleration can run on the tainted node — but without a `nodeSelector` or `nodeAffinity`, it can also run on any other untainted node in the cluster. Toleration = permission, not requirement. Always pair with `nodeSelector` or `requiredDuringScheduling` nodeAffinity.

```bash
# Symptom: Customer A pod landed on a shared node
kubectl get pod customer-a-pod -o wide
# NODE: shared-node-5   ← Not a Customer A node!

# Fix: Add nodeSelector to force placement
spec:
  nodeSelector:
    dedicated: customerA
```

### ❌ Mistake 2: nodeSelector without toleration

Without the matching toleration, the pod can never schedule on the tainted target node — it will be stuck in Pending:

```bash
kubectl get pod customer-a-pod
# STATUS: Pending

kubectl describe pod customer-a-pod | grep -A5 Events
# Warning  FailedScheduling  0/5 nodes are available:
# 3 node(s) had untolerated taint {customer: customerA}
# 2 node(s) didn't match Pod's node affinity/selector
```

### ❌ Mistake 3: Getting the toleration `effect` wrong

The taint has a specific effect (`NoSchedule`, `PreferNoSchedule`, `NoExecute`). The toleration must match — a toleration for `NoSchedule` does NOT override a `NoExecute` taint:

```yaml
# Taint: customer=customerA:NoSchedule
# Toleration must match effect:
tolerations:
- key: "customer"
  operator: "Equal"
  value: "customerA"
  effect: "NoSchedule"    # Must match taint effect exactly
                          # OR omit effect to match ALL effects
```

### ❌ Mistake 4: Forgetting that DaemonSets need broad tolerations

If you deploy a new DaemonSet (monitoring agent, log forwarder) after adding customer taints, it won't run on customer nodes unless you add appropriate tolerations. Check your monitoring coverage when adding node pools.

### ❌ Mistake 5: Using `PreferNoSchedule` for security isolation

`PreferNoSchedule` is a hint, not a guarantee. If the scheduler can't find a better option, it will place pods on preferred-but-not-required-to-avoid nodes. For actual security isolation, always use `NoSchedule` (hard requirement).

### ❌ Mistake 6: Not labeling nodes after tainting

Tainting blocks wrong pods; labeling attracts right pods. Both steps are required. Missing the label means pods with the correct toleration might still schedule on untainted nodes if no `nodeSelector` is set.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│      Node Pools and Taints/Tolerations — Quick Reference         │
├─────────────────┬───────────────────────────────────────────────┤
│ Apply taint     │ kubectl taint nodes <node> <key>=<value>:<effect>│
│ Remove taint    │ kubectl taint nodes <node> <key>=<value>:<effect>-│
│ View taints     │ kubectl describe node <name> | grep Taints     │
├─────────────────┼───────────────────────────────────────────────┤
│ Taint effects   │ NoSchedule: blocks new pods                    │
│                 │ PreferNoSchedule: soft block (not for security) │
│                 │ NoExecute: blocks + evicts existing pods       │
├─────────────────┼───────────────────────────────────────────────┤
│ Toleration      │ key, operator (Equal/Exists), value, effect    │
│ fields          │ Omit effect to match all effects               │
│                 │ operator: Exists + no key = tolerate all taints│
├─────────────────┼───────────────────────────────────────────────┤
│ Complete        │ 1. Taint node with NoSchedule                  │
│ isolation       │ 2. Label node (dedicated=tenantX)              │
│ setup           │ 3. Add matching toleration to pod spec         │
│                 │ 4. Add nodeSelector matching label             │
│                 │ → Taint REPELS, nodeSelector ATTRACTS          │
├─────────────────┼───────────────────────────────────────────────┤
│ nodeSelector    │ Simple key=value label matching (hard rule)    │
│ vs nodeAffinity │ nodeAffinity: In/NotIn/Exists + weight(soft)   │
├─────────────────┼───────────────────────────────────────────────┤
│ DaemonSets      │ Need: operator: Exists (no key) to run on all  │
│                 │ tainted nodes — this is expected and necessary  │
├─────────────────┼───────────────────────────────────────────────┤
│ When to use     │ Multi-customer tenancy, regulated industries,  │
│                 │ hard isolation requirement                     │
│ When to skip    │ Internal teams, dev/staging, trusted tenants   │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**Write it from memory: 4 steps.** The exam frequently asks you to set up node isolation for a tenant. Know the 4 steps by heart: (1) `kubectl taint`, (2) `kubectl label`, (3) add `tolerations` to pod spec, (4) add `nodeSelector` to pod spec.

**The toleration syntax is the most error-prone part.** Mistakes: wrong operator (`Equal` vs `Exists`), wrong effect (must match the taint effect or be omitted), wrong indentation (it's a list item under `spec.tolerations`).

```yaml
# Memorise this pattern cold:
tolerations:
- key: "customer"
  operator: "Equal"
  value: "customerA"
  effect: "NoSchedule"
nodeSelector:
  dedicated: customerA
```

**Toleration without nodeSelector = incomplete isolation.** The exam may present a scenario where a Customer A pod landed on a shared node — the diagnosis is always "toleration present but nodeSelector missing."

**The `NoExecute` effect evicts running pods** — this matters if the exam asks about immediately enforcing isolation on a node that already has running pods. `NoSchedule` only affects future scheduling.

**`PreferNoSchedule` is never the right answer for security isolation** — it's a scheduling hint, not a security control.

---

## Summary

Node pools with taints and tolerations provide the third and final data plane isolation pillar: physical separation of tenant workloads at the node level. While namespace isolation controls the Kubernetes API and NetworkPolicy controls runtime network traffic, node isolation eliminates the shared-kernel risk — the fact that all pods on a node use the same Linux kernel and can be affected by kernel exploits, side-channel attacks, and host filesystem exposure.

The mechanism requires both halves to work: taints on nodes **repel** pods without the matching toleration, and node labels with `nodeSelector` or `nodeAffinity` **attract** pods to the right nodes. Toleration alone is insufficient — without a `nodeSelector`, a tolerating pod may still schedule on an untainted shared node. Both directions of scheduling control must be applied together.

The three taint effects — `NoSchedule`, `PreferNoSchedule`, and `NoExecute` — provide different levels of enforcement: `NoSchedule` blocks future pods, `NoExecute` additionally evicts existing pods, and `PreferNoSchedule` is a hint unsuitable for security isolation. DaemonSets legitimately need broad tolerations to run on all nodes including tainted ones.

Node isolation is most appropriate for multi-customer tenancy with contractual isolation guarantees, regulated industries with compliance requirements, and scenarios where the shared-kernel risk is unacceptable. For internal team tenancy with trusted users, the overhead of dedicated node pools typically isn't justified — namespace isolation with NetworkPolicy and ResourceQuota provides sufficient protection.

---

## What's Next

**[Chapter 23 — Additional Considerations — API Priority and Fairness →](./23%20---%20Additional%20Considerations%20API%20Priority%20Fairness.md)**

With all three data plane isolation pillars covered (network, storage, node), Chapter 23 addresses a subtler multi-tenancy concern: API server fairness. A tenant that floods the API server with requests can degrade its performance for all other tenants and system components. Kubernetes's API Priority and Fairness (APF) mechanism prevents this by queuing and prioritising API requests per flow — the API server equivalent of ResourceQuota.
