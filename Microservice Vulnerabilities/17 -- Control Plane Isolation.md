# Chapter 17 — Control Plane Isolation

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 16 — Levels of Isolation: Namespace, Pod, Node](./16%20---%20Levels%20of%20Isolation%20Namespace%20Pod%20Node.md)
> **Next:** [Chapter 18 — Understanding Resource Quotas](./18%20---%20Understanding%20Resource%20Quotas.md)

---

## Why This Matters for CKS

Control plane isolation is the first layer of the multi-tenancy stack — and the most fundamental. If a tenant can interact with the Kubernetes control plane beyond their allowed scope, every other isolation mechanism can be undermined. A tenant with excessive API server access can delete NetworkPolicies protecting other tenants, escalate their own RBAC permissions, or read Secrets belonging to other namespaces.

The CKS exam tests control plane isolation through hands-on tasks like:
- Creating namespace-scoped Roles and RoleBindings for specific users or teams
- Auditing existing RBAC configurations to find over-privileged bindings
- Identifying when a ClusterRole should be a Role instead
- Verifying that the principle of least privilege is applied correctly
- Understanding what namespaces provide and what they don't

This chapter covers the two pillars of control plane isolation — namespaces and RBAC — in the depth the exam requires, including the common misconfigurations that create control plane isolation gaps.

---

## What Is the Control Plane?

The Kubernetes **control plane** is the set of components that manage the cluster's desired state:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Kubernetes Control Plane                      │
│                                                                  │
│  ┌─────────────────┐   ┌─────────────────┐  ┌───────────────┐  │
│  │   API Server     │   │ Controller Mgr  │  │   Scheduler   │  │
│  │ (kube-apiserver) │   │(kube-controller │  │(kube-scheduler│  │
│  │                  │   │   -manager)     │  │               │  │
│  │ Entry point for  │   │ Reconciliation  │  │ Pod placement │  │
│  │ all cluster ops  │   │ loops           │  │ decisions     │  │
│  └────────┬─────────┘   └────────┬────────┘  └───────┬───────┘  │
│           │                      │                    │          │
│           └──────────────┬───────┘────────────────────┘          │
│                          │                                        │
│                   ┌──────▼──────┐                                 │
│                   │    etcd     │                                 │
│                   │ (cluster    │                                 │
│                   │ state store)│                                 │
│                   └─────────────┘                                │
└─────────────────────────────────────────────────────────────────┘

Control Plane Isolation asks:
  "Who can make requests to the API server, and what can they do?"
```

All cluster operations — creating pods, applying policies, reading secrets, modifying RBAC — go through the API server. Control plane isolation means ensuring that each tenant's API server interactions are strictly scoped to their own resources.

---

## Pillar 1 — Namespaces as Isolation Boundaries

### What Namespaces Provide to the Control Plane

Namespaces partition the Kubernetes API into logical sections. Within the API server, namespaces enable:

**1. Resource name scoping**
The same resource name can exist in multiple namespaces without collision. A `Secret` named `db-password` in `namespace: team-a` is a completely separate API object from a `Secret` named `db-password` in `namespace: team-b`. The API server treats them as distinct objects: `secrets/team-a/db-password` vs. `secrets/team-b/db-password` in etcd.

**2. Policy scoping**
Most Kubernetes security resources (Roles, RoleBindings, NetworkPolicies, ResourceQuotas, LimitRanges) are namespace-scoped. A NetworkPolicy in `team-a` only applies to pods in `team-a`. An RBAC Role in `team-b` only governs access to `team-b`'s resources.

**3. API filtering**
When a user is bound to a namespace-scoped Role, the API server's authorization layer filters all responses. `kubectl get pods -n team-a` for a user who only has access to `team-a` will never return pods from `team-b` — the API server enforces this regardless of the user's `--namespace` flag.

### Namespace Hierarchy and Naming Conventions

```
Effective namespace naming for control plane isolation:

By team:       ns: team-frontend, ns: team-backend, ns: team-data
By customer:   ns: customer-acme, ns: customer-globex, ns: cust-{uuid}
By environment:ns: prod-frontend, ns: staging-frontend, ns: dev-frontend
By service:    ns: payments, ns: notifications, ns: identity

Anti-patterns to avoid:
❌ Using "default" namespace for workloads (no isolation)
❌ Mixing environments in the same namespace (prod + staging)
❌ Using one namespace for an entire cluster (defeats the purpose)
❌ Naming namespaces after nodes or cluster resources (confusing)
```

### Creating and Configuring Namespaces

```bash
# Basic namespace creation
kubectl create namespace team-a
kubectl create namespace team-b

# With labels (essential for NetworkPolicy selectors and PSA)
kubectl create namespace development
kubectl label namespace development \
  team=backend \
  environment=development \
  cost-center=engineering \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted

# Declarative (preferred for GitOps)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: development
  labels:
    team: backend
    environment: development
    cost-center: engineering
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: latest
  annotations:
    contact: backend-team@example.com
    slack-channel: "#backend-alerts"
EOF

# List namespaces with labels
kubectl get namespaces --show-labels

# Describe a namespace to see all configuration
kubectl describe namespace development
```

### Namespace-Scoped vs. Cluster-Scoped Resources

Understanding which resources are namespace-scoped is critical — you can only isolate namespace-scoped resources at the namespace level:

```
NAMESPACE-SCOPED (isolated by namespace):
  Core:   Pod, Service, Endpoints, ConfigMap, Secret, ServiceAccount,
          PersistentVolumeClaim, ResourceQuota, LimitRange, Event
  Apps:   Deployment, ReplicaSet, StatefulSet, DaemonSet
  Batch:  Job, CronJob
  Net:    Ingress, NetworkPolicy
  RBAC:   Role, RoleBinding
  Auto:   HorizontalPodAutoscaler
  Policy: PodDisruptionBudget

CLUSTER-SCOPED (NOT isolated by namespace):
  Infrastructure: Node, PersistentVolume, StorageClass, IngressClass
  RBAC:           ClusterRole, ClusterRoleBinding
  Scheduling:     PriorityClass, RuntimeClass
  Admission:      ValidatingWebhookConfiguration, MutatingWebhookConfiguration
  Auth:           CertificateSigningRequest, TokenReview
  Meta:           Namespace itself, CustomResourceDefinition
```

Cluster-scoped resources require separate strategies (ClusterRole restrictions, OPA policies) since namespaces can't contain them.

---

## Pillar 2 — RBAC for Control Plane Isolation

### The Principle of Least Privilege

The core RBAC philosophy for multi-tenancy: **every user and service account should have only the permissions they need to do their job, and nothing more**.

Violations of this principle are the most common control plane isolation failures:
- Developers given `cluster-admin` "for convenience"
- Service accounts with `ClusterRole` bindings when namespace `Roles` suffice
- Wildcard permissions (`resources: ["*"]`, `verbs: ["*"]`)
- `edit` or `view` ClusterRole bindings that expose all namespaces

### Role vs. ClusterRole — The Critical Distinction

```
Role (namespace-scoped):
  • Permissions apply ONLY within one namespace
  • Bound via RoleBinding (also namespace-scoped)
  • Cannot grant access to cluster-scoped resources
  • ALWAYS prefer for tenant users

ClusterRole (cluster-scoped):
  • Permissions apply cluster-wide when bound via ClusterRoleBinding
  • CAN be bound via RoleBinding to scope permissions to one namespace
  • Necessary for cluster-scoped resources (Nodes, PVs, StorageClasses)
  • Should be restricted to cluster administrators / platform team

Common misuse: Binding a ClusterRole with ClusterRoleBinding for tenant users
→ Tenant can suddenly see ALL namespaces' resources
```

### The Four Binding Combinations

```
┌──────────────────────┬──────────────────────┬──────────────────────────┐
│ Role Type            │ Binding Type         │ Effective Scope           │
├──────────────────────┼──────────────────────┼──────────────────────────┤
│ Role                 │ RoleBinding          │ ONE namespace only        │
│                      │                      │ ← CORRECT for tenants    │
├──────────────────────┼──────────────────────┼──────────────────────────┤
│ ClusterRole          │ RoleBinding          │ ONE namespace only        │
│                      │ (in specific NS)     │ (reuse ClusterRole defs  │
│                      │                      │  but scoped to NS)       │
├──────────────────────┼──────────────────────┼──────────────────────────┤
│ ClusterRole          │ ClusterRoleBinding   │ ALL namespaces            │
│                      │                      │ ← DANGEROUS for tenants  │
├──────────────────────┼──────────────────────┼──────────────────────────┤
│ Role                 │ ClusterRoleBinding   │ Not valid — ClusterRole  │
│                      │                      │ Binding requires a        │
│                      │                      │ ClusterRole              │
└──────────────────────┴──────────────────────┴──────────────────────────┘
```

### Complete RBAC Example — Development Namespace

```yaml
# ── Developer Role for the development namespace ─────────────────
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: developer-role
rules:
  # Full control over workload resources
  - apiGroups: ["", "apps", "batch"]
    resources: ["pods", "pods/log", "pods/exec", "pods/portforward",
                "deployments", "replicasets", "services", "jobs",
                "cronjobs", "configmaps"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  # Read-only on secrets (no create/delete — managed by platform)
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
  # Scale deployments
  - apiGroups: ["apps"]
    resources: ["deployments/scale"]
    verbs: ["update", "patch"]
  # Read events for debugging
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch"]
  # HPA management
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
# ── RoleBinding: bind developer-role to user pranjal ────────────
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-rolebinding
  namespace: development
subjects:
  - kind: User
    name: pranjal
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
```

**What this configuration enables:**
- `pranjal` can manage all workload resources in the `development` namespace
- `pranjal` cannot create, update, or delete secrets (managed externally)
- `pranjal` has zero access to any other namespace
- `pranjal` cannot list Nodes, PersistentVolumes, or other cluster-scoped resources

### RBAC for Multiple Teams — Side by Side

```yaml
# ── Team Alpha: full development namespace access ─────────────────
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: alpha-dev-binding
  namespace: alpha-dev
subjects:
- kind: Group
  name: team-alpha
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role        # Same Role definition, different namespace
  apiGroup: rbac.authorization.k8s.io
---
# ── Team Beta: full development namespace access ──────────────────
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: beta-dev-binding
  namespace: beta-dev
subjects:
- kind: Group
  name: team-beta
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role        # Same Role definition, different namespace
  apiGroup: rbac.authorization.k8s.io
```

Team Alpha can do anything in `alpha-dev`, nothing in `beta-dev`. Team Beta is the inverse. The `developer-role` Role definition is reused across namespaces — each namespace has its own copy of the Role object, or you can bind a ClusterRole via namespace-scoped RoleBindings to reuse the definition.

### Service Account RBAC

Every pod in Kubernetes has an associated ServiceAccount. By default, the `default` ServiceAccount in most namespaces has no permissions — but it's easy to accidentally grant it too much.

```yaml
# Dedicated ServiceAccount per application (best practice)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-service-sa
  namespace: payments
automountServiceAccountToken: false    # Opt-out of automatic token mounting
                                        # (unless the pod needs API access)
---
# Minimal Role for the payment service
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payment-service-role
  namespace: payments
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["payment-config"]   # Only THIS specific ConfigMap
  verbs: ["get", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["payment-api-key"]  # Only THIS specific Secret
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payment-service-binding
  namespace: payments
subjects:
- kind: ServiceAccount
  name: payment-service-sa
  namespace: payments
roleRef:
  kind: Role
  name: payment-service-role
  apiGroup: rbac.authorization.k8s.io
```

Key practices:
- `automountServiceAccountToken: false` on the ServiceAccount prevents automatic token injection into every pod (tokens that don't get mounted can't be stolen)
- `resourceNames` restricts access to specific named resources, not all resources of that type
- Never use the `default` ServiceAccount for application workloads

---

## Control Plane Isolation Architecture

Putting namespaces and RBAC together into a complete multi-tenant control plane picture:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Control Plane Isolation Architecture             │
│                                                                      │
│  kubectl (User: pranjal)           kubectl (User: bob)              │
│       │                                  │                          │
│       │ Bearer token / cert              │ Bearer token / cert      │
│       ▼                                  ▼                          │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │                   kube-apiserver                           │     │
│  │                                                            │     │
│  │  1. AuthN: Who is this? (cert CN / OIDC token)            │     │
│  │  2. AuthZ: What can they do? (RBAC check)                 │     │
│  │  3. Admission: Is this request valid? (webhooks/PSA)       │     │
│  │                                                            │     │
│  │  RBAC Check for pranjal requesting pods in development:    │     │
│  │  • Is there a RoleBinding in 'development' for pranjal?   │     │
│  │  • Does the bound Role allow 'list' on 'pods'?            │     │
│  │  • Yes → ALLOW                                            │     │
│  │                                                            │     │
│  │  RBAC Check for pranjal requesting pods in production:     │     │
│  │  • Is there a RoleBinding in 'production' for pranjal?    │     │
│  │  • No → DENY (Forbidden)                                  │     │
│  └────────────────────────────────────────────────────────────┘     │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  etcd  (cluster state)                                       │   │
│  │                                                              │   │
│  │  /namespaces/development/pods/...    ← pranjal can access   │   │
│  │  /namespaces/production/pods/...    ← pranjal CANNOT access │   │
│  │  /namespaces/staging/secrets/...    ← pranjal CANNOT access │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## RBAC Audit — Finding Control Plane Isolation Gaps

The CKS exam often presents a cluster where you need to audit RBAC for isolation gaps. Key commands:

```bash
# ── List all roles in a namespace ────────────────────────────────
kubectl get roles -n development
kubectl describe role developer-role -n development

# ── List all role bindings in a namespace ─────────────────────────
kubectl get rolebindings -n development
kubectl describe rolebinding developer-rolebinding -n development

# ── DANGER: Check for ClusterRoleBindings that grant broad access ─
# Anyone bound to cluster-admin, edit, or view via ClusterRoleBinding
# can access ALL namespaces
kubectl get clusterrolebindings -o wide
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name | test("admin|edit|view")) | 
      {name: .metadata.name, role: .roleRef.name, subjects: .subjects}'

# ── Check what a specific user can do ─────────────────────────────
kubectl auth can-i list pods -n development --as pranjal
# yes
kubectl auth can-i list pods -n production --as pranjal
# no
kubectl auth can-i list pods --all-namespaces --as pranjal
# no

# ── Check ALL permissions for a user (verbose audit) ──────────────
kubectl auth can-i --list --namespace development --as pranjal
# Lists every resource/verb combination allowed for pranjal in dev

# ── Find service accounts with excessive permissions ───────────────
# Look for ClusterRoleBindings pointing to ServiceAccounts
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]?.kind == "ServiceAccount") |
      {binding: .metadata.name, role: .roleRef.name, 
       sa: [.subjects[] | select(.kind=="ServiceAccount") | "\(.namespace)/\(.name)"]}'
```

### Red Flags in RBAC Audits

```
🚨 Critical isolation violations:
   • User bound to cluster-admin ClusterRole
   • Tenant ServiceAccount with ClusterRoleBinding to 'edit' or 'view'
   • Wildcard resources: ["*"] or verbs: ["*"] in a tenant Role
   • ServiceAccount token mounted in pod that doesn't need API access
   • 'default' ServiceAccount with any permissions

⚠️  Warnings (potential violations):
   • ClusterRole used where a Role would suffice
   • RBAC for cross-namespace secret access
   • Secrets resource with 'create' and 'delete' verbs for tenant users
   • Missing 'resourceNames' restriction on sensitive resource access
```

---

## Scoping ClusterRoles via RoleBindings

A powerful but often underused pattern: reuse a ClusterRole definition but scope its permissions to a single namespace via a namespace-scoped RoleBinding:

```yaml
# Instead of creating duplicate Role definitions in each namespace,
# define a ClusterRole once and bind it namespace-by-namespace

# ── ClusterRole definition (reusable template) ────────────────────
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-developer-template
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["pods", "pods/log", "deployments", "services",
              "configmaps", "jobs"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
# ── RoleBinding in namespace-a: scopes ClusterRole to namespace-a ─
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-a-binding
  namespace: namespace-a          # RoleBinding scopes the permissions here
subjects:
- kind: Group
  name: team-a
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole               # References a ClusterRole...
  name: tenant-developer-template
  apiGroup: rbac.authorization.k8s.io
  # ...but the RoleBinding (not ClusterRoleBinding) scopes it to namespace-a
---
# ── RoleBinding in namespace-b: scopes ClusterRole to namespace-b ─
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-b-binding
  namespace: namespace-b
subjects:
- kind: Group
  name: team-b
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: tenant-developer-template
  apiGroup: rbac.authorization.k8s.io
```

Result: `team-a` has developer access in `namespace-a` only. `team-b` has developer access in `namespace-b` only. Neither can access the other's namespace. No duplicate Role definitions — just one ClusterRole + one RoleBinding per namespace.

---

## Control Plane Isolation for Kubernetes System Components

System components themselves must be isolated from tenant workloads. The control plane runs in `kube-system` namespace — tenants must not be able to interfere with it:

```bash
# Verify tenant users cannot access kube-system
kubectl auth can-i get pods -n kube-system --as pranjal
# no — correct

kubectl auth can-i get secrets -n kube-system --as pranjal
# no — correct

# If a tenant can read kube-system secrets, they might get cluster credentials
# This would be a critical isolation failure
```

### Protecting etcd

etcd stores all cluster state including all Secrets (even if base64-encoded). etcd access bypasses the API server's RBAC entirely — if someone can read etcd directly, they can read everything.

```bash
# etcd should only be accessible from the API server
# Verify etcd listen address is NOT 0.0.0.0
ps aux | grep etcd | grep listen-client-urls
# Should show: --listen-client-urls=https://127.0.0.1:2379
# NOT: --listen-client-urls=https://0.0.0.0:2379

# etcd mTLS — only the API server has the client cert
ls /etc/kubernetes/pki/etcd/
# ca.crt     ← etcd CA
# server.crt ← etcd server cert
# server.key
# peer.crt   ← etcd peer cert (for cluster communication)
# peer.key

# The API server's etcd client cert
ls /etc/kubernetes/pki/apiserver-etcd-client.crt
# Only the API server holds this client cert — nothing else can authenticate to etcd
```

### API Server Hardening Flags for Control Plane Isolation

```bash
# View current API server flags
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -A1 "\-\-"

# Key flags for control plane isolation:
--anonymous-auth=false              # Reject unauthenticated requests
--authorization-mode=Node,RBAC     # Use RBAC (must include Node for kubelet)
--enable-admission-plugins=NodeRestriction,PodSecurity,...
--audit-log-path=/var/log/kube-audit.log     # Log all API requests
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--service-account-issuer=https://kubernetes.default.svc
--service-account-signing-key-file=/etc/kubernetes/pki/sa.key
--tls-cert-file=/etc/kubernetes/pki/apiserver.crt
--tls-private-key-file=/etc/kubernetes/pki/apiserver.key
--client-ca-file=/etc/kubernetes/pki/ca.crt  # Verify client certs (mTLS)
```

---

## Audit Logging as a Control Plane Isolation Verification

Audit logging captures every API server request, making it possible to detect isolation violations even after the fact. This is a control plane-level tool:

```yaml
# /etc/kubernetes/audit-policy.yaml
# Capture all writes and privilege-sensitive reads per namespace
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log secret reads — isolation failure if wrong namespace
- level: Metadata
  verbs: ["get", "list", "watch"]
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]

# Log all writes (modifications) with full request body
- level: Request
  verbs: ["create", "update", "patch", "delete"]
  resources:
  - group: ""
    resources: ["pods", "services", "secrets"]
  - group: "apps"
    resources: ["deployments"]

# Log RBAC changes — someone modifying roles is a privilege escalation risk
- level: RequestResponse
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

# Default: only metadata for everything else
- level: Metadata
```

Audit log entries for RBAC violations look like this:
```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "verb": "list",
  "user": {"username": "pranjal"},
  "objectRef": {
    "resource": "secrets",
    "namespace": "production",   ← Not pranjal's namespace!
    "apiVersion": "v1"
  },
  "responseStatus": {
    "code": 403,                 ← Forbidden — RBAC worked correctly
    "message": "secrets is forbidden"
  }
}
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Binding a ClusterRole with a ClusterRoleBinding for tenant users

The single most common control plane isolation mistake. A tenant user who is ClusterRoleBinding'd to the built-in `view` ClusterRole can list Secrets in every namespace — including other tenants'. Use a namespace-scoped RoleBinding instead.

```bash
# Dangerous — pranjal can see ALL namespaces
kubectl create clusterrolebinding pranjal-view \
  --clusterrole=view \
  --user=pranjal

# Safe — pranjal can only see development namespace
kubectl create rolebinding pranjal-view \
  --clusterrole=view \
  --user=pranjal \
  --namespace=development
```

### ❌ Mistake 2: Leaving the `default` ServiceAccount unmounted and unused but still permissioned

Even if no pod explicitly uses the `default` ServiceAccount, if it has permissions granted, any pod that doesn't specify a `serviceAccountName` will automatically use it. Always audit default SA permissions:

```bash
kubectl get rolebindings,clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]? | .kind == "ServiceAccount" and .name == "default")'
```

### ❌ Mistake 3: Forgetting that `pods/exec` and `pods/portforward` are separate resources

A developer Role that allows `pods` doesn't automatically allow `kubectl exec` or `kubectl port-forward`. But a Role that does include these gives significant access — a developer can exec into any pod in their namespace and potentially extract secrets or credentials. Be deliberate about including these.

```yaml
# pods/exec grants: kubectl exec -n namespace pod-name -- /bin/sh
# pods/portforward grants: kubectl port-forward -n namespace pod-name 8080:80
# pods/log grants: kubectl logs -n namespace pod-name
# Each is a separate sub-resource that must be explicitly granted
```

### ❌ Mistake 4: Granting RBAC write permissions to tenants

Allowing a tenant to create/modify Roles or RoleBindings in their namespace is a privilege escalation path. They could create a binding that grants them more access than intended. RBAC management should be reserved for cluster admins.

### ❌ Mistake 5: Not validating with `kubectl auth can-i`

Writing RBAC YAML correctly is hard. Always verify with `kubectl auth can-i` after applying — test both what should be allowed and what should be denied.

```bash
# The exam will likely ask you to verify RBAC — know this command cold
kubectl auth can-i <verb> <resource> --namespace <ns> --as <user>
kubectl auth can-i --list --namespace <ns> --as <user>
```

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│              Control Plane Isolation — Quick Reference           │
├─────────────────┬───────────────────────────────────────────────┤
│ Namespaces      │ Logical partition of API resources             │
│ provide         │ Name scoping: same name, different namespaces  │
│                 │ Policy scoping: RBAC, NetPol, RQ are NS-scoped │
├─────────────────┼───────────────────────────────────────────────┤
│ Namespaces do   │ Runtime network isolation (need NetworkPolicy) │
│ NOT provide     │ Resource limits (need ResourceQuota)           │
│                 │ Access to cluster-scoped resources             │
├─────────────────┼───────────────────────────────────────────────┤
│ Role vs         │ Role: scoped to ONE namespace                  │
│ ClusterRole     │ ClusterRole: cluster-wide (dangerous for       │
│                 │ tenants unless bound via RoleBinding not CRB)  │
├─────────────────┼───────────────────────────────────────────────┤
│ Tenant RBAC     │ Role + RoleBinding (namespace-scoped only)     │
│ pattern         │ ServiceAccount per app, not default SA         │
│                 │ resourceNames to restrict specific objects     │
│                 │ automountServiceAccountToken: false if unused  │
├─────────────────┼───────────────────────────────────────────────┤
│ Audit commands  │ kubectl auth can-i <verb> <res> -n <ns> --as  │
│                 │ kubectl auth can-i --list -n <ns> --as <user>  │
│                 │ kubectl get rolebindings -n <ns>               │
│                 │ kubectl get clusterrolebindings -o wide        │
│                 │ kubectl describe role <name> -n <ns>           │
├─────────────────┼───────────────────────────────────────────────┤
│ Red flags       │ ClusterRoleBinding for tenant users            │
│                 │ Wildcard resources ["*"] or verbs ["*"]        │
│                 │ default ServiceAccount with permissions        │
│                 │ RBAC write access for tenants                  │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**The most common exam task:** Create a Role + RoleBinding for a specific user in a specific namespace. Know this cold — write it from memory without checking syntax.

```bash
# Imperative (fastest in exam)
kubectl create role developer-role \
  --verb=get,list,watch,create,update,patch,delete \
  --resource=pods,services \
  --namespace=development

kubectl create rolebinding developer-rolebinding \
  --role=developer-role \
  --user=pranjal \
  --namespace=development

# Then verify
kubectl auth can-i list pods -n development --as pranjal    # yes
kubectl auth can-i list pods -n production --as pranjal     # no
```

**Second most common:** Audit a ClusterRoleBinding and determine if it violates least privilege. Look for: tenant users or SAs bound to ClusterRoles via ClusterRoleBindings.

**Know the difference:** `kubectl create role` creates a namespace-scoped Role. `kubectl create clusterrole` creates a cluster-scoped ClusterRole. Accidentally using the wrong one is a common exam error.

**Sub-resources matter:** `pods` ≠ `pods/log` ≠ `pods/exec`. If the task says "allow viewing logs," you need both `pods` (get/list/watch) and `pods/log` (get).

---

## Summary

Control plane isolation in Kubernetes rests on two pillars: namespaces and RBAC. Namespaces partition the API into logical sections, giving each tenant a private space where their resources don't collide with others' and where security policies (RBAC, NetworkPolicy, ResourceQuota) are scoped. This means the same resource names can coexist across namespaces, and a policy in one namespace never affects another.

RBAC enforces the access boundary within and between namespaces. The critical rule for multi-tenancy is to use namespace-scoped Roles bound via namespace-scoped RoleBindings — never ClusterRoles bound via ClusterRoleBindings for tenant users, as this grants cluster-wide visibility. The principle of least privilege demands that each user and service account has only the permissions required for their specific function, restricted further with `resourceNames` where applicable.

Together, namespace partitioning and RBAC access control form the control plane isolation layer — the API-level guarantee that tenant A cannot see, modify, or interfere with tenant B's resources through the Kubernetes API. The data plane (NetworkPolicy, ResourceQuota, node isolation) then extends this isolation to runtime behaviour, forming the complete multi-tenancy isolation stack.

---

## What's Next

**[Chapter 18 — Understanding Resource Quotas →](./18%20---%20Understanding%20Resource%20Quotas.md)**

With control plane access locked down via namespaces and RBAC, the next resource management question is: how do you prevent one tenant from consuming all available cluster resources? Chapter 18 dives deep into ResourceQuota and LimitRange — the tools that enforce per-namespace resource ceilings and prevent noisy neighbors from starving other tenants.
