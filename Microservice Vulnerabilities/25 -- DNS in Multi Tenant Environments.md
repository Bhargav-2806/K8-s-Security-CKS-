# Chapter 25 — DNS in Multi-Tenant Environments

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 24 — Quality of Service](./24%20---%20Quality%20of%20Service.md)
> **Next:** [Chapter 26 — Pod-to-Pod Encryption](./26%20---%20Pod%20to%20Pod%20Encryption.md)

---

## Why This Matters for CKS

DNS is the foundation of service discovery in Kubernetes. Every time a pod communicates with a service by name, it performs a DNS lookup against CoreDNS. In a multi-tenant cluster, this creates a subtle but significant information disclosure risk: by default, a pod in `namespace-b` can look up services in `namespace-a` using the fully qualified domain name (FQDN), discovering which services exist, what ports they listen on, and potentially mapping the entire tenant topology without sending a single packet of application traffic.

The CKS exam tests DNS in multi-tenancy through:
- Understanding the Kubernetes DNS naming hierarchy (FQDN structure)
- Knowing that default CoreDNS configuration allows cross-namespace resolution
- Modifying the CoreDNS ConfigMap to restrict DNS scope
- Using NetworkPolicy to restrict DNS egress as an alternative or complementary control
- Testing DNS isolation with `nslookup` and `dig` from debug pods

This chapter closes the multi-tenancy section by addressing the one remaining isolation gap that RBAC, NetworkPolicy, ResourceQuota, and node isolation all leave open: the DNS service discovery layer.

---

## How Kubernetes DNS Works

Kubernetes deploys **CoreDNS** as the cluster DNS service, running in `kube-system` namespace. Every pod gets `/etc/resolv.conf` configured to point to CoreDNS:

```bash
# Inside any pod:
cat /etc/resolv.conf
# nameserver 10.96.0.10        ← CoreDNS cluster IP
# search default.svc.cluster.local svc.cluster.local cluster.local
# options ndots:5
```

The `search` domains mean pods can use short names within their namespace:

```bash
# Inside a pod in namespace-a, these all resolve the same service:
nslookup backend              # Short name → appends search domains
nslookup backend.namespace-a  # Partial FQDN
nslookup backend.namespace-a.svc.cluster.local   # Full FQDN
```

### The Kubernetes DNS Naming Hierarchy

```
FQDN format: <service-name>.<namespace>.svc.<cluster-domain>

Examples:
  backend.namespace-a.svc.cluster.local
  postgres.tenant-b.svc.cluster.local
  redis.payments.svc.cluster.local

Pod DNS (when pod hostname/subdomain is configured):
  <pod-ip-dashes>.<namespace>.pod.cluster.local
  10-244-1-5.namespace-a.pod.cluster.local

  # Or with headless service:
  <hostname>.<subdomain>.<namespace>.svc.cluster.local
```

### What CoreDNS Resolves

```
Query                                           Resolution
════════════════════════════════════════════════════════════════
backend (from pod in namespace-a)              namespace-a/backend Service ClusterIP
backend.namespace-b.svc.cluster.local         namespace-b/backend Service ClusterIP
kubernetes.default.svc.cluster.local          API server Service ClusterIP (10.96.0.1)
google.com                                    Forwarded to upstream resolver (/etc/resolv.conf)
```

---

## The Multi-Tenancy DNS Problem

By default, every pod in the cluster can resolve every service in every namespace — just by knowing the FQDN format:

```
Default cluster (no DNS isolation):
══════════════════════════════════

Pod in namespace-b:
  nslookup backend.namespace-a.svc.cluster.local
  # Resolves to: 10.98.45.23
  ✅ Successfully resolves Tenant A's backend service

  nslookup payments.namespace-a.svc.cluster.local
  # Resolves to: 10.98.46.11
  ✅ Successfully resolves Tenant A's payment service

  nslookup database.namespace-a.svc.cluster.local
  # Resolves to: 10.98.47.88
  ✅ Successfully resolves Tenant A's database

This is SERVICE ENUMERATION — discovering the topology of other tenants.
Even with NetworkPolicy blocking actual connections, DNS reveals:
  • What services exist in each namespace
  • The service names (revealing architecture)
  • That DNS resolution is possible (connection attempt happens next)
```

DNS resolution itself isn't a connection to the service — it's just a UDP query to CoreDNS. NetworkPolicy rules (Chapter 20) that block TCP connections to `namespace-a` don't automatically block DNS queries about `namespace-a` services. The attack surface has two layers:

1. **Information disclosure**: Learning service names and IPs across tenants
2. **Stepping stone for connection attempts**: Once IP is known, probe other vectors

---

## Solution 1 — CoreDNS `fallthrough in-namespace`

The KodeKloud source shows the `fallthrough in-namespace` directive in the CoreDNS Kubernetes plugin. This modifies how CoreDNS responds to queries that don't match the local namespace:

### Step 1 — Edit the CoreDNS ConfigMap

```bash
kubectl edit configmap coredns -n kube-system
```

### Step 2 — Add `fallthrough in-namespace` to the Kubernetes Block

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
            lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
            pods verified
            fallthrough in-namespace   # ← Add this directive
        }
        prometheus :9153
        forward . /etc/resolv.conf
        cache 30
        loop
        reload
        loadbalance
    }
```

### What `fallthrough in-namespace` Does

The `fallthrough` directive in CoreDNS's Kubernetes plugin controls what happens when a query doesn't match the configured zone. With `in-namespace`, CoreDNS only resolves names that belong to the querying pod's namespace:

```
Without fallthrough in-namespace:
  Pod in namespace-b queries: backend.namespace-a.svc.cluster.local
  CoreDNS: Resolves it → returns IP of namespace-a's backend
  Result: Cross-namespace discovery ENABLED

With fallthrough in-namespace:
  Pod in namespace-b queries: backend.namespace-a.svc.cluster.local
  CoreDNS: "This isn't in namespace-b, fallthrough to next handler"
  Next handler: forward . /etc/resolv.conf (external DNS)
  External DNS: NXDOMAIN (doesn't know about k8s services)
  Result: Cross-namespace resolution BLOCKED
```

> **Important caveat:** The exact behaviour of `fallthrough in-namespace` depends on the CoreDNS version and configuration. In some versions, this may not completely prevent cross-namespace resolution — test thoroughly in your environment before relying on it for security. NetworkPolicy-based DNS control (Solution 2) is often more reliable.

### CoreDNS Reloads Automatically

After saving the ConfigMap, CoreDNS detects the change and reloads its configuration within a few seconds (via the `reload` plugin in the Corefile). No pod restart required:

```bash
# Watch CoreDNS logs to confirm reload
kubectl logs -n kube-system -l k8s-app=kube-dns -f
# [INFO] Reloading
# [INFO] plugin/reload: Running configuration...
# [INFO] Reloading complete
```

---

## Step 3 — Test DNS Isolation

After applying the configuration, verify the isolation works as intended:

```bash
# ── Test 1: Cross-namespace resolution should FAIL ────────────────
kubectl run test-pod \
  --rm -i --tty \
  --image=busybox \
  --restart=Never \
  --namespace=namespace-a \
  -- nslookup backend.namespace-b.svc.cluster.local

# Expected result with isolation:
# Server:    10.96.0.10
# Address 1: 10.96.0.10 kube-dns.kube-system.svc.cluster.local
# nslookup: can't resolve 'backend.namespace-b.svc.cluster.local'
# ← CORRECT: cross-namespace lookup blocked

# ── Test 2: Same-namespace resolution should WORK ─────────────────
kubectl run test-pod \
  --rm -i --tty \
  --image=busybox \
  --restart=Never \
  --namespace=namespace-a \
  -- nslookup backend.namespace-a.svc.cluster.local

# Expected result:
# Server:    10.96.0.10
# Name:      backend.namespace-a.svc.cluster.local
# Address 1: 10.98.45.23 backend.namespace-a.svc.cluster.local
# ← CORRECT: same-namespace lookup works

# ── Test 3: External DNS should still work ────────────────────────
kubectl run test-pod \
  --rm -i --tty \
  --image=busybox \
  --restart=Never \
  --namespace=namespace-a \
  -- nslookup google.com

# Expected result:
# Server:    10.96.0.10
# Name:      google.com
# Address 1: 142.250.x.x
# ← CORRECT: external DNS forwarding still works

# ── Test 4: Kubernetes API server should still resolve ────────────
kubectl run test-pod \
  --rm -i --tty \
  --image=busybox \
  --restart=Never \
  --namespace=namespace-a \
  -- nslookup kubernetes.default.svc.cluster.local
# ← This should still work (same cluster.local zone)
```

---

## Solution 2 — NetworkPolicy for DNS Egress Control

A complementary (and often more reliable) approach: use NetworkPolicy to control which pods can reach CoreDNS, and what they can query. This operates at the network layer rather than the DNS application layer.

### Restrict DNS Egress to Same-Namespace Pods Only

NetworkPolicy can't filter by DNS query content, but you can control which pods can reach CoreDNS at all. For stricter environments, you can route DNS queries through a per-namespace DNS proxy:

```yaml
# Block all DNS egress (tight default-deny already in place from Ch. 20)
# Then explicitly allow DNS only to the cluster DNS service
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: namespace-a
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  # Allow UDP/TCP to CoreDNS (kube-dns service in kube-system)
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow all other same-namespace egress
  - to:
    - podSelector: {}
```

This doesn't prevent cross-namespace DNS resolution by itself (pods can still query CoreDNS for other-namespace services), but combined with the `fallthrough in-namespace` CoreDNS configuration, it adds defence in depth.

### Per-Namespace CoreDNS Policy Using NodeLocal DNSCache

A more advanced approach: deploy NodeLocal DNSCache and configure per-namespace resolution policies. This allows fine-grained control over which namespaces' services are resolvable from a given namespace:

```yaml
# NodeLocal DNSCache ConfigMap — restrict namespace-b from resolving namespace-a
apiVersion: v1
kind: ConfigMap
metadata:
  name: node-local-dns
  namespace: kube-system
data:
  Corefile: |
    cluster.local:53 {
        errors
        cache {
            success 9984 30
            denial 9984 5
        }
        reload
        loop
        bind 169.254.20.10
        forward . __PILLAR__CLUSTER__DNS__ {
            force_tcp
        }
        prometheus :9253
        health 169.254.20.10:8080
    }
    # Per-namespace policy can be added here
    # (advanced configuration, beyond default NodeLocal DNSCache)
```

---

## Understanding the FQDN Structure for Exam Scenarios

The exam frequently requires you to construct or interpret FQDNs. Know this structure completely:

```
Service FQDN:
  <service-name>.<namespace>.svc.<cluster-domain>

Default cluster domain: cluster.local

Examples:
  backend.namespace-a.svc.cluster.local
  └─────┘ └──────────┘ └──┘ └──────────────┘
  service  namespace  type  cluster domain

Headless Service Pod FQDN (StatefulSet):
  <pod-name>.<service-name>.<namespace>.svc.<cluster-domain>
  postgres-0.postgres-headless.database.svc.cluster.local

Pod FQDN (with subdomain):
  <hostname>.<subdomain>.<namespace>.svc.<cluster-domain>
  myhost.mysubdomain.namespace-a.svc.cluster.local
```

### Short Name Resolution via Search Domains

The `search` domains in `/etc/resolv.conf` enable short-name lookups. The `ndots:5` option means: if a name has fewer than 5 dots, try appending search domains before trying it as-is:

```
Pod in namespace-a resolves "backend":
  1. Try: backend.namespace-a.svc.cluster.local → found! Return IP
  (stops here if resolved)

Pod in namespace-a resolves "backend.namespace-b":
  1. Try: backend.namespace-b.namespace-a.svc.cluster.local → not found
  2. Try: backend.namespace-b.svc.cluster.local → found! Return IP
  (returns namespace-b's backend)
  
This is why even "short" cross-namespace names can resolve!
```

---

## DNS Policy Options for Pods

Individual pods can override how DNS resolution works via `spec.dnsPolicy`:

```yaml
spec:
  dnsPolicy: ClusterFirst    # Default — use CoreDNS, fall back to node resolver
                             # Most pods use this

  dnsPolicy: ClusterFirstWithHostNet
                             # For hostNetwork pods — still use CoreDNS

  dnsPolicy: Default         # Use the node's resolver (/etc/resolv.conf on host)
                             # Bypasses CoreDNS entirely

  dnsPolicy: None            # Ignore all cluster DNS settings
                             # Must provide dnsConfig manually
  dnsConfig:                 # Used with dnsPolicy: None
    nameservers:
    - 8.8.8.8
    searches:
    - namespace-a.svc.cluster.local
    options:
    - name: ndots
      value: "5"
```

For multi-tenant isolation, you generally don't want tenant pods to use `dnsPolicy: Default` or `dnsPolicy: None` unless you've configured a custom resolver that also enforces isolation — otherwise they bypass CoreDNS policies entirely.

---

## CoreDNS Plugins Relevant to Multi-Tenancy

Understanding the full CoreDNS Corefile plugin chain helps when modifying it:

```
.:53 {
    errors                   # Log errors
    health { lameduck 5s }   # Health check endpoint (:8080/health)
    ready                    # Readiness endpoint (:8181/ready)

    kubernetes cluster.local in-addr.arpa ip6.arpa {
        # Kubernetes plugin — answers queries for .cluster.local
        pods verified        # Validate pod IP against actual pods
        fallthrough in-namespace   # Restrict to namespace queries
        ttl 30               # Cache TTL for successful responses
    }

    prometheus :9153         # Expose metrics for Prometheus scraping

    forward . /etc/resolv.conf {
        # Forward non-cluster queries to upstream (node's resolver)
        max_concurrent 1000
    }

    cache 30                 # Cache responses for 30 seconds
    loop                     # Detect forwarding loops
    reload                   # Watch ConfigMap and auto-reload
    loadbalance              # Round-robin load balancing for responses
}
```

### Adding a Per-Namespace Resolution Block

For very fine-grained control, you can add a dedicated server block per namespace:

```yaml
data:
  Corefile: |
    .:53 {
        errors
        health { lameduck 5s }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
            pods verified
            fallthrough in-namespace
        }
        prometheus :9153
        forward . /etc/resolv.conf
        cache 30
        loop
        reload
        loadbalance
    }

    # Dedicated block: allow only specific services to be resolvable cross-namespace
    # (advanced usage — add explicit allow rules for known cross-tenant services)
    # This technique requires a custom CoreDNS plugin or rewrite rules
```

---

## DNS and NetworkPolicy — Defence in Depth

The two DNS isolation approaches complement each other:

```
┌─────────────────────────────────────────────────────────────────┐
│         DNS Isolation Layered Defence                           │
├──────────────────────────────────┬──────────────────────────────┤
│ Layer 1: NetworkPolicy           │ Controls WHICH pods can send  │
│ (DNS egress control)             │ DNS queries to CoreDNS        │
│                                  │ Does not filter query content │
├──────────────────────────────────┼──────────────────────────────┤
│ Layer 2: CoreDNS config          │ Controls WHAT CoreDNS answers │
│ (fallthrough in-namespace)       │ Can block cross-NS resolution │
│                                  │ Operates at application layer │
├──────────────────────────────────┼──────────────────────────────┤
│ Layer 3: NetworkPolicy           │ Even if DNS resolves an IP,   │
│ (connection blocking)            │ the actual TCP connection is  │
│                                  │ blocked by NetworkPolicy      │
│                                  │ (defence in depth)            │
└──────────────────────────────────┴──────────────────────────────┘

Attack that defeats only one layer:
  Without CoreDNS restriction: Pod discovers service IPs via DNS
  → NetworkPolicy blocks connection attempts
  → Information still disclosed (service exists + IP known)

  Without NetworkPolicy: CoreDNS blocks cross-NS resolution
  → Pod hardcodes IP or uses /etc/hosts
  → Connects directly to service IP (bypasses DNS)

With both layers: Neither IP discovery nor connection is possible.
```

---

## Monitoring CoreDNS for Multi-Tenant DNS Queries

CoreDNS exposes Prometheus metrics that reveal DNS query patterns — useful for detecting cross-tenant enumeration attempts:

```bash
# Check CoreDNS metrics endpoint
kubectl port-forward -n kube-system svc/kube-dns 9153:9153
curl -s localhost:9153/metrics | grep coredns_dns_request

# Key metrics for multi-tenant DNS monitoring:
# coredns_dns_requests_total{server,zone,proto,family,type}
# coredns_dns_responses_total{server,zone,rcode}
# coredns_dns_request_duration_seconds

# Look for NXDOMAIN responses — indicates failed cross-NS lookups
# (after isolation is applied, cross-NS queries should return NXDOMAIN)
curl -s localhost:9153/metrics | grep 'rcode="NXDOMAIN"'
```

You can also enable CoreDNS query logging (verbose — use sparingly in production):

```yaml
data:
  Corefile: |
    .:53 {
        errors
        log                  # Enable query logging (all requests logged)
        health { lameduck 5s }
        ...
    }
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Thinking NetworkPolicy alone prevents DNS-based service enumeration

A NetworkPolicy that blocks TCP connections to `namespace-a` does not prevent a pod from querying CoreDNS about `namespace-a` services. DNS uses UDP port 53 — if your default-deny egress policy allows UDP/53 to kube-dns (which it must, for any DNS to work), cross-namespace DNS queries still reach CoreDNS.

### ❌ Mistake 2: Assuming `fallthrough in-namespace` completely blocks cross-namespace DNS

`fallthrough in-namespace` redirects unmatched queries to the next plugin (usually the upstream forwarder). The upstream forwarder won't know about internal cluster services, so the query effectively fails — but this relies on the upstream resolver not having cached or alternate routes. Always test this in your environment.

### ❌ Mistake 3: Breaking kube-dns resolution for system components

If you misconfigure CoreDNS, pods across the entire cluster lose DNS resolution. This breaks service discovery for everyone — including system components. Always test CoreDNS changes in a non-production environment first, and keep a working configuration backup.

```bash
# Quickly revert CoreDNS to a known-good state
kubectl get configmap coredns -n kube-system -o yaml > coredns-backup.yaml
# After testing, if broken:
kubectl apply -f coredns-backup.yaml
```

### ❌ Mistake 4: Forgetting CoreDNS runs in kube-system — RBAC implications

Editing the CoreDNS ConfigMap requires ClusterAdmin or cluster-admin-equivalent access. Tenant users should never be able to modify `kube-system` ConfigMaps — this is a privilege escalation path. Verify RBAC:

```bash
kubectl auth can-i update configmap -n kube-system --as tenant-user
# Should return: no
```

### ❌ Mistake 5: Using `dnsPolicy: Default` to bypass CoreDNS without planning

Pods with `dnsPolicy: Default` use the node's `/etc/resolv.conf`, bypassing CoreDNS entirely. This means they don't get cluster service discovery (can't resolve `backend.namespace-a.svc.cluster.local`) but also bypass any CoreDNS-level isolation policies. In a multi-tenant cluster, monitor for pods using `dnsPolicy: Default` unless intentional.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│         DNS in Multi-Tenant Environments — Quick Reference       │
├─────────────────┬───────────────────────────────────────────────┤
│ FQDN format     │ <svc>.<namespace>.svc.cluster.local           │
│                 │ <pod-ip-dashes>.<namespace>.pod.cluster.local  │
├─────────────────┼───────────────────────────────────────────────┤
│ Default         │ Any pod can resolve any service in any NS      │
│ behaviour       │ using FQDN — cross-tenant enumeration possible │
├─────────────────┼───────────────────────────────────────────────┤
│ CoreDNS         │ kubectl edit configmap coredns -n kube-system  │
│ restriction     │ Add: fallthrough in-namespace                  │
│ (primary tool)  │ Inside: kubernetes cluster.local { } block     │
├─────────────────┼───────────────────────────────────────────────┤
│ CoreDNS reload  │ Automatic after ConfigMap save (reload plugin) │
│                 │ Check: kubectl logs -n kube-system -l k8s-app=kube-dns│
├─────────────────┼───────────────────────────────────────────────┤
│ NetworkPolicy   │ Allow DNS egress to kube-dns pods only         │
│ DNS control     │ Namespace: kube-system, pod: k8s-app=kube-dns  │
│                 │ Ports: UDP/53 + TCP/53                         │
├─────────────────┼───────────────────────────────────────────────┤
│ Test commands   │ kubectl run test-pod --rm -i --tty             │
│                 │   --image=busybox --restart=Never -n <ns>      │
│                 │   -- nslookup <fqdn>                           │
│                 │ kubectl run test-pod ... -- dig <fqdn>         │
├─────────────────┼───────────────────────────────────────────────┤
│ dnsPolicy       │ ClusterFirst (default) → uses CoreDNS          │
│ options         │ Default → uses node resolver (bypasses CoreDNS)│
│                 │ None → manual config via dnsConfig             │
├─────────────────┼───────────────────────────────────────────────┤
│ CoreDNS metrics │ Port 9153 → Prometheus scrape endpoint         │
│                 │ coredns_dns_responses_total{rcode="NXDOMAIN"}  │
│                 │ indicates blocked cross-namespace lookups      │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**Know the FQDN format.** The exam will ask you to look up a service across namespaces or to verify isolation. You must know `<service>.<namespace>.svc.cluster.local` without hesitation.

**The CoreDNS ConfigMap edit is a hands-on task.** Know: `kubectl edit configmap coredns -n kube-system` and where to add `fallthrough in-namespace` (inside the `kubernetes cluster.local` block, same indentation as `pods verified`). Getting the indentation wrong silently breaks the directive.

**Always test after editing CoreDNS.** The exam may ask you to verify the change works. Use the `nslookup` command from a debug pod in the right namespace. Know that successful isolation = NXDOMAIN for cross-NS lookups, successful resolution for same-NS lookups.

**The `reload` plugin means no restart needed.** After editing the ConfigMap, CoreDNS auto-reloads. You don't need to `kubectl rollout restart` the CoreDNS deployment.

**DNS isolation is the last mile of multi-tenancy.** The exam may present a scenario where RBAC, NetworkPolicy, and ResourceQuota are all in place — but a tenant can still enumerate another tenant's services. The missing control is DNS isolation (CoreDNS `fallthrough in-namespace`).

---

## Summary

DNS is both the backbone of Kubernetes service discovery and a potential information disclosure vector in multi-tenant clusters. By default, CoreDNS answers any query for any service in any namespace using the fully qualified domain name format — enabling a pod in `namespace-b` to discover services in `namespace-a` without ever attempting a connection that would be blocked by NetworkPolicy.

DNS isolation is achieved primarily by modifying the CoreDNS ConfigMap in `kube-system` to add the `fallthrough in-namespace` directive inside the Kubernetes plugin block. This causes CoreDNS to refuse to resolve service names outside the querying pod's namespace, forwarding unmatched queries to the upstream resolver where they receive NXDOMAIN. CoreDNS automatically reloads the configuration after the ConfigMap is saved via the `reload` plugin.

NetworkPolicy provides a complementary layer: even if DNS resolution succeeds (or is attempted by hardcoding an IP), NetworkPolicy blocks the actual network connection. Both layers together — DNS name resolution control and connection blocking — implement true defence-in-depth DNS isolation for multi-tenant Kubernetes environments.

This chapter closes the multi-tenancy section. The complete isolation stack — namespaces (Ch. 16), RBAC (Ch. 17), ResourceQuota (Ch. 18), NetworkPolicy (Ch. 20), storage controls (Ch. 21), node pools (Ch. 22), API Priority (Ch. 23), QoS (Ch. 24), and DNS isolation (this chapter) — provides a comprehensive, layered defence for shared Kubernetes clusters.

---

## What's Next

**[Chapter 26 — Pod-to-Pod Encryption →](./26%20---%20Pod%20to%20Pod%20Encryption.md)**

With multi-tenancy fully covered, the next topic shifts to in-transit encryption between pods. Chapter 26 introduces the concept of pod-to-pod encryption: why encrypting traffic inside the cluster matters even with NetworkPolicy in place, how the threat model for in-cluster traffic differs from external-facing traffic, and the options available — from application-level TLS to service mesh mTLS to CNI-level transparent encryption with Cilium.
