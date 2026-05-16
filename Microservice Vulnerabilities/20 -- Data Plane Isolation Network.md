# Chapter 20 — Data Plane Isolation: Network

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 19 — Data Plane Isolation](./19%20---%20Data%20Plane%20Isolation.md)
> **Next:** [Chapter 21 — Data Plane Isolation — Storage](./21%20---%20Data%20Plane%20Isolation%20Storage.md)

---

## Why This Matters for CKS

NetworkPolicy is one of the most tested topics in the CKS exam. The exam regularly requires you to write NetworkPolicy manifests from scratch — default-deny policies, intra-namespace allowlists, cross-namespace rules, port-specific restrictions, and egress controls. Mistakes in selector syntax are easy to make under time pressure, and a subtle error (an `and` when you need an `or`, or a missing namespaceSelector label) means the policy silently fails to enforce.

This chapter covers the complete NetworkPolicy model: how it works under the hood, every selector type, the critical `and` vs `or` distinction in from/to blocks, default-deny patterns, and multi-tenant network segmentation strategies. After this chapter you should be able to write any NetworkPolicy the exam asks for without referencing documentation.

---

## How Kubernetes Networking Works Without Policies

Kubernetes uses a flat network model by default:

```
Default (no NetworkPolicy): Every pod can reach every other pod
═══════════════════════════════════════════════════════════════

Cluster CIDR: 10.244.0.0/16

Pod A (10.244.1.5) in namespace: tenant-a
Pod B (10.244.2.8) in namespace: tenant-b
Pod C (10.244.1.9) in namespace: tenant-a

A → B: ✅ Allowed (cross-namespace)
B → C: ✅ Allowed (cross-namespace)
A → C: ✅ Allowed (same namespace)
Any pod → Internet (8.8.8.8): ✅ Allowed
```

Every pod gets a unique IP address routable within the cluster. There's no firewall between them. This is intentional for single-tenant clusters — simplicity and ease of service discovery. For multi-tenancy, it's a security gap: any tenant can probe any other tenant's services.

---

## What NetworkPolicy Does

A NetworkPolicy is a namespaced Kubernetes object that instructs the CNI plugin to install kernel-level traffic rules (iptables, nftables, or eBPF depending on the CNI) that enforce the policy:

```
NetworkPolicy enforcement model:
══════════════════════════════════

1. Policy created via kubectl → stored in API server / etcd
2. CNI plugin (Calico/Cilium/Weave) watches for NetworkPolicy objects
3. CNI translates policy into kernel rules on each node:
   • iptables rules (Calico legacy, Weave)
   • eBPF programs (Cilium, Calico eBPF mode)
4. Traffic hitting a pod's veth interface is evaluated against these rules
5. Non-matching traffic is dropped at kernel level — no TCP RST, just DROP

Key property: enforcement is at the kernel, not the application.
The container cannot bypass it (no iptables in container, no SO_BYPASS).
```

### CNI Plugin Requirement

**NetworkPolicy only works with a CNI plugin that supports it.** This is a critical exam trap:

```
CNI plugins that SUPPORT NetworkPolicy:
  ✅ Calico (most common in CKS labs)
  ✅ Cilium (eBPF-based, very powerful)
  ✅ Weave Net
  ✅ Antrea
  ✅ Canal (Calico policy + Flannel networking)

CNI plugins that do NOT support NetworkPolicy:
  ❌ Flannel (accepts the object but enforces NOTHING)
  ❌ Kubenet (basic, no policy support)

Symptom of missing CNI support:
  NetworkPolicy objects exist, kubectl apply succeeds, but traffic
  is not blocked. Everything still communicates freely.
```

---

## NetworkPolicy Anatomy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: my-policy
  namespace: tenant-a        # Policy lives in this namespace
spec:
  podSelector:               # Which pods this policy applies TO (ingress target / egress source)
    matchLabels:
      app: backend           # Selects pods with label app=backend in tenant-a
                             # Empty podSelector {} selects ALL pods in namespace

  policyTypes:               # Which traffic directions this policy governs
  - Ingress                  # Controls inbound traffic TO selected pods
  - Egress                   # Controls outbound traffic FROM selected pods
                             # If Ingress only → egress is unrestricted
                             # If Egress only → ingress is unrestricted

  ingress:                   # List of allowed inbound traffic rules
  - from:                    # Source selectors (who can send traffic in)
    - podSelector:           # Pods matching this label
        matchLabels:
          role: frontend
    - namespaceSelector:     # Pods in namespaces matching this label
        matchLabels:
          tenant: tenant-b
    ports:                   # Which ports/protocols are allowed
    - protocol: TCP
      port: 8080

  egress:                    # List of allowed outbound traffic rules
  - to:                      # Destination selectors
    - podSelector:
        matchLabels:
          role: database
    ports:
    - protocol: TCP
      port: 5432
```

### The `policyTypes` Interaction

```
policyTypes determines what gets restricted:

policyTypes: [Ingress]
  → Ingress is restricted by the ingress rules below
  → Egress is UNRESTRICTED (no egress rules apply)

policyTypes: [Egress]
  → Egress is restricted by the egress rules below
  → Ingress is UNRESTRICTED

policyTypes: [Ingress, Egress]
  → Both are restricted by their respective rule sections

No policyTypes specified, but ingress rules present:
  → Defaults to [Ingress] only
  → Egress is unrestricted

IMPORTANT: If policyTypes: [Ingress, Egress] but NO rules listed,
this is a DEFAULT DENY for both directions — all traffic blocked.
```

---

## The `and` vs. `or` Distinction — The Most Tested Trap

This is the most common source of exam and production bugs in NetworkPolicy. The behaviour of multiple selectors within a single `from` element vs. multiple `from` elements is completely different.

### OR Logic — Multiple Elements in the `from` Array

```yaml
ingress:
- from:
  - podSelector:           # Element 1 in the from array
      matchLabels:
        role: frontend
  - namespaceSelector:     # Element 2 in the from array (separate -)
      matchLabels:
        tenant: tenant-b
```

**This is OR logic.** Traffic is allowed from:
- ANY pod with `role: frontend` in the same namespace, **OR**
- ANY pod in any namespace labeled `tenant: tenant-b`

A frontend pod from namespace `tenant-c` would be allowed through because it matches the `podSelector` rule. A completely unrelated pod in `tenant-b` would also be allowed.

### AND Logic — Single Element Combining Both Selectors

```yaml
ingress:
- from:
  - podSelector:           # Both selectors on the same element (no - before namespaceSelector)
      matchLabels:
        role: frontend
    namespaceSelector:     # Note: no dash — same list item as podSelector above
      matchLabels:
        tenant: tenant-b
```

**This is AND logic.** Traffic is allowed only from:
- Pods with `role: frontend` label **AND** in a namespace labeled `tenant: tenant-b`

A frontend pod from `tenant-a` is NOT allowed (wrong namespace). A non-frontend pod from `tenant-b` is NOT allowed (wrong pod label). Only pods satisfying both conditions are allowed.

### Side-by-Side Comparison

```
OR (two from-elements):              AND (one from-element with both selectors):

ingress:                             ingress:
- from:                              - from:
  - podSelector:                       - podSelector:
      matchLabels:                         matchLabels:
        role: frontend                       role: frontend
  - namespaceSelector:                   namespaceSelector:
      matchLabels:                           matchLabels:
        tenant: tenant-b                       tenant: tenant-b

Allows:                              Allows ONLY:
  • frontend pods in ANY namespace     • frontend pods in tenant-b namespace
  • ANY pod in tenant-b namespace
```

The YAML indentation is the only visual difference — the dash (`-`) before `namespaceSelector` determines whether it's a new element (OR) or part of the same element (AND).

---

## Default Deny Patterns

The foundation of multi-tenant network isolation is always **default-deny first, then explicitly allow**.

### Default Deny All Ingress (for selected pods)

```yaml
# Any pod targeted by a NetworkPolicy has its ingress denied
# by default — this policy explicitly targets ALL pods with
# an empty podSelector and no ingress rules = deny all ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-a
spec:
  podSelector: {}    # All pods in tenant-a
  policyTypes:
  - Ingress
  # No ingress rules = deny all ingress
```

### Default Deny All Egress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
  # No egress rules = deny all egress (including DNS!)
```

> **Warning:** Denying all egress also blocks DNS (port 53). If pods need to resolve service names, you must explicitly allow DNS egress.

### Default Deny All (Ingress + Egress) — Recommended for Multi-Tenancy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  # No rules = deny everything in both directions
```

Apply this as the **first policy** in every tenant namespace. Then add specific allow policies on top.

---

## Multi-Tenant Network Segmentation Patterns

### Pattern 1: Allow Intra-Namespace Only

Pods within a namespace can talk to each other, but nothing from outside:

```yaml
# Allow all pods within tenant-a to communicate
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-intra-namespace
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}    # Any pod in THIS namespace (no namespaceSelector = same NS)
  egress:
  - to:
    - podSelector: {}    # Any pod in THIS namespace
  # Also allow DNS (essential for service name resolution)
  - ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### Pattern 2: Allow Specific Cross-Namespace Traffic (KodeKloud example expanded)

The KodeKloud source shows Tenant B calling Tenant A's backend. Expanded with the AND selector for precision:

```yaml
# Allow pods labeled app=backend in tenant_a to receive TCP 8080
# from ANY pod in namespace labeled tenant=tenant_b
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-tenant-b-to-backend
  namespace: tenant_a
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          tenant: tenant_b   # Namespace must have this label
    ports:
    - protocol: TCP
      port: 8080
```

For more precision — only specific pods in tenant_b can call the backend:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-tenant-b-frontend-to-backend
  namespace: tenant_a
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:         # AND logic — both must match
        matchLabels:
          app: frontend
      namespaceSelector:
        matchLabels:
          tenant: tenant_b
    ports:
    - protocol: TCP
      port: 8080
```

### Pattern 3: Allow Egress to Kubernetes API Server

Some tenant applications need to call the Kubernetes API (e.g., operators, controllers):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-k8s-api-egress
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      needs-api-access: "true"   # Only specific pods get API access
  policyTypes:
  - Egress
  egress:
  - ports:
    - protocol: TCP
      port: 6443    # API server port (kubeadm default)
    - protocol: TCP
      port: 443     # API server alternative port
```

### Pattern 4: Allow Egress to Specific External IP Range

For tenant applications that need to reach an external service:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-db-egress
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 203.0.113.0/24          # External DB server range
        except:
        - 203.0.113.0/25              # Exclude part of the range
    ports:
    - protocol: TCP
      port: 5432
```

### Pattern 5: Block All Cross-Namespace Traffic (Pure Namespace Isolation)

The most common multi-tenant pattern — enforce complete namespace isolation except for explicitly allowed cross-namespace flows:

```yaml
# Apply to every tenant namespace
# Step 1: Default deny all
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Step 2: Allow intra-namespace + DNS
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}
  egress:
  - to:
    - podSelector: {}
  - ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
---
# Step 3: Add specific allowed cross-namespace flows as needed
# (only add what's actually required)
```

### Pattern 6: Allow Monitoring / Ingress Controller Access

Platform-level pods (Prometheus scraping, nginx-ingress, cert-manager) need access to tenant namespaces:

```yaml
# Allow Prometheus in monitoring namespace to scrape metrics
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-prometheus-scrape
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      app: my-app    # Pods exposing metrics
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring   # Built-in namespace name label
      podSelector:
        matchLabels:
          app: prometheus    # AND: must be Prometheus pods
    ports:
    - protocol: TCP
      port: 9090    # Prometheus metrics port
---
# Allow ingress controller to forward traffic to tenant pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-controller
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      app: my-app
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
      podSelector:
        matchLabels:
          app.kubernetes.io/name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
```

---

## NetworkPolicy Selector Reference

```
┌──────────────────────────────────────────────────────────────────┐
│              NetworkPolicy Selector Types                         │
├─────────────────────┬────────────────────────────────────────────┤
│ Selector            │ Matches                                     │
├─────────────────────┼────────────────────────────────────────────┤
│ podSelector: {}     │ All pods in the same namespace as the       │
│                     │ NetworkPolicy object                        │
├─────────────────────┼────────────────────────────────────────────┤
│ podSelector:        │ Pods with matching labels in the same       │
│   matchLabels:      │ namespace (or combined with               │
│     key: value      │ namespaceSelector for cross-NS AND logic)   │
├─────────────────────┼────────────────────────────────────────────┤
│ namespaceSelector:{}│ All namespaces (effectively all pods in     │
│                     │ any namespace) — use carefully!            │
├─────────────────────┼────────────────────────────────────────────┤
│ namespaceSelector:  │ Pods in namespaces matching these labels    │
│   matchLabels:      │ Note: namespace must have the label         │
│     key: value      │ Use kubernetes.io/metadata.name for exact   │
│                     │ namespace name matching                     │
├─────────────────────┼────────────────────────────────────────────┤
│ ipBlock:            │ IP addresses in the CIDR range (minus       │
│   cidr: x.x.x.x/n  │ except ranges). For external traffic only — │
│   except: [...]     │ pod IPs change; use pod/NS selectors for    │
│                     │ intra-cluster traffic                       │
└─────────────────────┴────────────────────────────────────────────┘
```

### Namespace Name Matching

A common requirement: target a specific namespace by name. Kubernetes automatically adds a `kubernetes.io/metadata.name` label to every namespace equal to its name:

```yaml
namespaceSelector:
  matchLabels:
    kubernetes.io/metadata.name: monitoring   # Exact namespace name match
```

This is more reliable than custom labels which might not be applied consistently.

---

## Verifying NetworkPolicy Enforcement

```bash
# ── Apply policies and verify ─────────────────────────────────────
kubectl apply -f default-deny-all.yaml
kubectl apply -f allow-same-namespace.yaml

# ── Check policies in a namespace ────────────────────────────────
kubectl get networkpolicy -n tenant-a
kubectl describe networkpolicy default-deny-all -n tenant-a

# ── Test connectivity (create debug pods) ─────────────────────────
# Pod within tenant-a → should reach other tenant-a pods
kubectl run debug-a --image=busybox -n tenant-a --rm -it -- \
  wget -qO- --timeout=3 http://backend-svc.tenant-a.svc.cluster.local

# Pod in tenant-b → should NOT reach tenant-a backend (unless explicitly allowed)
kubectl run debug-b --image=busybox -n tenant-b --rm -it -- \
  wget -qO- --timeout=3 http://backend-svc.tenant-a.svc.cluster.local
# Should time out: wget: download timed out

# Test DNS still works (after default-deny egress)
kubectl run debug --image=busybox -n tenant-a --rm -it -- \
  nslookup kubernetes.default.svc.cluster.local
# Should resolve if DNS egress is allowed

# Test blocked egress to internet
kubectl run debug --image=busybox -n tenant-a --rm -it -- \
  wget -qO- --timeout=3 http://example.com
# Should time out if egress internet is blocked

# ── Cilium-specific: inspect policy enforcement ───────────────────
# If using Cilium
kubectl exec -n kube-system -it $(kubectl get pod -n kube-system \
  -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}') \
  -- cilium policy get
```

---

## Network Isolation in Multi-Tenant Architecture

### Full Multi-Tenant Network Setup (Both Namespaces)

```bash
# Label namespaces so NetworkPolicy selectors work
kubectl label namespace tenant-a tenant=tenant-a
kubectl label namespace tenant-b tenant=tenant-b

# Apply the same base policies to EACH tenant namespace
for ns in tenant-a tenant-b tenant-c; do
  # Default deny all
  kubectl apply -f - -n $ns <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: $ns
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
  namespace: $ns
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}
  egress:
  - to:
    - podSelector: {}
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
EOF
done
```

### Visualising the Resulting Network Topology

```
After applying default-deny + allow-same-namespace to both tenant-a and tenant-b:

namespace: tenant-a                    namespace: tenant-b
┌─────────────────────┐               ┌─────────────────────┐
│ pod-a-1 ←→ pod-a-2  │               │ pod-b-1 ←→ pod-b-2  │
│ pod-a-1 ←→ pod-a-3  │   ✗ blocked   │ pod-b-1 ←→ pod-b-3  │
│ (free intra-NS      │ ◄────────────► │ (free intra-NS      │
│  communication)     │               │  communication)     │
└─────────────────────┘               └─────────────────────┘
        │                                       │
        │ ✗ blocked (unless allow policy)        │ ✗ blocked
        ▼                                       ▼
     Internet                                Internet
```

To then allow Tenant B's frontend pods to reach Tenant A's backend:

```yaml
# Add to tenant-a namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-tenant-a-to-tenant-b     # Allow tenant-b's frontend into tenant-a's backend
  namespace: tenant_a
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          tenant: tenant_b
    ports:
    - protocol: TCP
      port: 8080
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: The `and` vs `or` selector confusion (most common)

Already covered above, but worth repeating: a `-` before `namespaceSelector` means it's a separate `from` element (OR logic). Without a `-`, it's combined with the adjacent `podSelector` in the same element (AND logic). Draw it out if needed during the exam.

### ❌ Mistake 2: Forgetting to label namespaces

`namespaceSelector` matches against namespace labels. A freshly created namespace with no labels won't match any `namespaceSelector`. Always label namespaces when setting up multi-tenant environments.

```bash
# Check if namespace has required labels
kubectl get namespace tenant-b --show-labels
# If no labels: kubectl label namespace tenant-b tenant=tenant-b
```

### ❌ Mistake 3: Forgetting DNS egress

Default-deny egress blocks UDP port 53. Pod service name resolution stops working. Always include a DNS allow rule when applying egress policies.

```yaml
egress:
- ports:           # This must be a separate egress rule (not inside a 'to' block)
  - protocol: UDP
    port: 53
  - protocol: TCP
    port: 53
```

### ❌ Mistake 4: Using Flannel and wondering why NetworkPolicy doesn't work

If the cluster uses Flannel as the CNI, NetworkPolicy objects are accepted but not enforced. Test with a debug pod before relying on policies for security.

### ❌ Mistake 5: Applying NetworkPolicy to pods that don't exist yet

NetworkPolicy selects pods by label at the time traffic flows, not at the time the policy is created. If you mistype a pod selector label, the policy simply doesn't match any pods and traffic flows unimpeded. Always verify with `kubectl describe networkpolicy` and a connectivity test.

### ❌ Mistake 6: Thinking `podSelector: {}` means "all pods in cluster"

An empty `podSelector` means all pods **in the same namespace as the NetworkPolicy**. NetworkPolicy is always namespace-scoped. To select pods in other namespaces, use `namespaceSelector`.

### ❌ Mistake 7: Omitting `policyTypes`

If you write ingress rules but forget `policyTypes: [Ingress]`, the default applies (ingress is restricted, egress is not). If you write both ingress and egress rules but only declare `policyTypes: [Ingress]`, the egress rules are silently ignored. Always be explicit.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│              NetworkPolicy — Quick Reference                     │
├─────────────────┬───────────────────────────────────────────────┤
│ podSelector     │ Which pods the policy applies TO              │
│                 │ {} = all pods in namespace                    │
├─────────────────┼───────────────────────────────────────────────┤
│ policyTypes     │ [Ingress] / [Egress] / [Ingress, Egress]      │
│                 │ Must be declared to activate each direction   │
├─────────────────┼───────────────────────────────────────────────┤
│ from / to       │ List of source/destination selectors          │
│ elements        │ Multiple - items = OR logic                   │
│                 │ Combined podSelector+namespaceSelector         │
│                 │ in one item = AND logic                       │
├─────────────────┼───────────────────────────────────────────────┤
│ Default deny    │ podSelector: {}, policyTypes listed,          │
│ pattern         │ no rules = deny all in that direction         │
├─────────────────┼───────────────────────────────────────────────┤
│ DNS allow       │ Always add egress to port 53 UDP+TCP          │
│                 │ when applying egress default-deny             │
├─────────────────┼───────────────────────────────────────────────┤
│ Namespace name  │ namespaceSelector:                            │
│ exact match     │   matchLabels:                                │
│                 │     kubernetes.io/metadata.name: my-ns        │
├─────────────────┼───────────────────────────────────────────────┤
│ CNI requirement │ Calico, Cilium, Weave = enforced              │
│                 │ Flannel, Kubenet = NOT enforced               │
├─────────────────┼───────────────────────────────────────────────┤
│ Key commands    │ kubectl get networkpolicy -n <ns>             │
│                 │ kubectl describe networkpolicy <name> -n <ns> │
│                 │ kubectl run debug --image=busybox --rm -it    │
│                 │   -- wget -qO- --timeout=3 <url>             │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**The `and` vs `or` selector trap will appear.** Before writing a policy with both `podSelector` and `namespaceSelector`, ask yourself: "Do I need both conditions to be true (AND), or is either one sufficient (OR)?" AND = combine in one list item. OR = separate list items with their own `-`.

**Write default-deny first, then allow.** The exam often asks you to "restrict communication between these namespaces" — the answer is always: default-deny policy first, then add explicit allow policies for what's needed.

**Label your namespaces before applying namespaceSelector policies.** If the exam asks you to allow traffic from a specific namespace, check if that namespace has the label you're targeting in your `namespaceSelector`. Add it if not: `kubectl label namespace <name> key=value`.

**Memorise the default-deny pattern:**
```yaml
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  # No rules — deny all
```

**Don't forget DNS egress:**
```yaml
egress:
- ports:
  - protocol: UDP
    port: 53
  - protocol: TCP
    port: 53
```

**Always test:** `kubectl run debug --image=busybox -n <ns> --rm -it -- wget -qO- --timeout=3 <url>` is the exam connectivity test command. Know it.

---

## Summary

NetworkPolicy is the primary network data plane isolation mechanism in Kubernetes. By default, Kubernetes allows all pods to communicate with all other pods cluster-wide — this flat network model is a security gap in multi-tenant environments. NetworkPolicy objects, enforced by CNI plugins at the kernel level, replace this open model with explicit allowlisting.

The core pattern for multi-tenant network isolation is: apply a default-deny-all NetworkPolicy to every tenant namespace first, then add explicit allow policies for only the traffic that's actually required. Intra-namespace traffic is typically allowed with an empty `podSelector` and same-namespace `from` selector. Cross-namespace traffic is allowed with precise `namespaceSelector` and optionally `podSelector` combinations. DNS egress (port 53 UDP/TCP) must always be explicitly allowed when egress default-deny is applied.

The most critical technical detail is the AND vs. OR selector distinction: multiple list elements in a `from` block use OR logic, while combining `podSelector` and `namespaceSelector` in a single list element uses AND logic. This single YAML indentation difference is the source of the most common NetworkPolicy misconfiguration.

NetworkPolicy requires a CNI plugin that supports it — Calico and Cilium are the standard choices. Flannel silently ignores NetworkPolicy objects. Always verify enforcement with connectivity tests, not just by checking that the policy object was accepted by the API server.

---

## What's Next

**[Chapter 21 — Data Plane Isolation — Storage →](./21%20---%20Data%20Plane%20Isolation%20Storage.md)**

With network traffic isolated, the next data plane concern is storage. Chapter 21 covers how PersistentVolumes and PersistentVolumeClaims can create cross-tenant data exposure risks, how StorageClass design and reclaim policies prevent data leakage between tenants, and how Pod Security Admission (by blocking hostPath volumes) closes the most dangerous storage-based attack vector.
