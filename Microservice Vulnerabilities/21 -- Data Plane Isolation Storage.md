# Chapter 21 — Data Plane Isolation: Storage

> **Section:** Microservice Vulnerabilities
> **Previous:** [Chapter 20 — Data Plane Isolation — Network](./20%20---%20Data%20Plane%20Isolation%20Network.md)
> **Next:** [Chapter 22 — Using Node Pools and Taints/Tolerations for Isolation](./22%20---%20Using%20Node%20Pools%20and%20Taints%20Tolerations%20for%20Isolation.md)

---

## Why This Matters for CKS

Storage isolation is the most invisible of the data plane isolation mechanisms — when it fails, it fails silently. A pod mounting the wrong PersistentVolume, or reading a previous tenant's data from a recycled volume, won't produce an error. The data is simply there. This makes storage isolation a high-stakes configuration domain: mistakes are easy to make and hard to detect.

The CKS exam tests storage isolation through:
- Configuring StorageClasses with appropriate reclaim policies
- Understanding how PVC namespace scoping prevents cross-tenant volume access
- Recognising when `hostPath` volumes defeat all other isolation controls
- Applying ResourceQuota restrictions on storage to prevent tenant overconsumption
- Understanding access modes (`ReadWriteOnce` vs `ReadWriteMany`) and their isolation implications

---

## The Storage Isolation Problem

Kubernetes storage has several vectors through which tenant data can leak:

```
Storage Data Leakage Scenarios
════════════════════════════════

1. VOLUME REUSE (Reclaim Policy: Retain)
   Tenant A creates PVC → PV bound → Tenant A deletes PVC
   PV status: Released (still holds Tenant A's data)
   Admin manually rebinds PV → Tenant B gets a PVC bound to Tenant A's PV
   Result: Tenant B can read Tenant A's old data from the volume

2. SHARED VOLUMES (ReadWriteMany access mode)
   PV with ReadWriteMany can be mounted by multiple pods simultaneously
   If two pods in different tenant namespaces both request and bind to
   the same PV, they share the same filesystem — full data access

3. HOST PATH VOLUMES (privileged access to node filesystem)
   A pod with hostPath volume mounts arbitrary paths on the host:
   hostPath: /etc/kubernetes → reads cluster certificates
   hostPath: /var/lib/kubelet/pods → reads other pods' volumes!
   hostPath: / → full root filesystem access

4. CROSS-NAMESPACE PV BINDING (unbound PV reuse)
   A PV with status Available can be claimed by any PVC in any namespace
   A PVC in tenant-b could bind to a PV that was "meant" for tenant-a
   if the PV has no namespace-specific binding policy

5. STORAGE CLASS SHARING (performance contention)
   All tenants using the same StorageClass share the same storage pool
   A tenant writing 10,000 IOPS saturates the shared pool
   Other tenants' database writes slow to a crawl — noisy neighbor in storage
```

---

## PersistentVolume Architecture Review

Before diving into isolation controls, a brief review of the PV/PVC binding model:

```
StorageClass → PersistentVolume → PersistentVolumeClaim → Pod

Dynamic provisioning flow:
  1. Admin creates StorageClass (provisioner + parameters)
  2. Tenant creates PVC referencing the StorageClass
  3. StorageClass provisioner creates a PV in the cloud/storage backend
  4. PV binds to the PVC (1:1 binding)
  5. Pod mounts the PVC as a volume

Static provisioning flow:
  1. Admin creates PV (pre-provisioned storage)
  2. Tenant creates PVC matching the PV's capacity + access mode + storageClass
  3. PV binds to the PVC
  4. Pod mounts the PVC

Key property: PVC is namespace-scoped. PV is cluster-scoped.
              A PVC can only be mounted by pods in its own namespace.
              But two PVCs in different namespaces could (misconfiguration) bind to
              the same PV if using static provisioning or Retain reclaim policy.
```

---

## The Primary Isolation Control: StorageClass Per Tenant

The central tool for storage data plane isolation is the **StorageClass**. By giving each tenant type its own StorageClass:
- Tenants can only provision volumes via their permitted class
- Performance characteristics are isolated (IOPS pool segregation)
- The provisioner can create volumes in a tenant-specific storage pool or account
- ResourceQuota can restrict which StorageClass a namespace can use

### High-Performance StorageClass (Critical Tenant — Namespace A)

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: high-performance
  labels:
    tier: critical
    tenant-type: premium
provisioner: kubernetes.io/aws-ebs      # AWS EBS provisioner
parameters:
  type: io1                             # Provisioned IOPS SSD
  iopsPerGB: "50"                       # 50 IOPS/GB — high performance
  fsType: ext4
  encrypted: "true"                     # Encryption at rest (important for multi-tenancy)
  kmsKeyId: arn:aws:kms:us-east-1:123456789012:key/premium-tenant-key
reclaimPolicy: Delete                   # PV deleted when PVC deleted — no data residue
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer # Binds when pod is scheduled (AZ-aware)
```

### Standard StorageClass (Regular Tenant — Namespace B)

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: standard-performance
  labels:
    tier: standard
    tenant-type: regular
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3                             # General Purpose SSD (lower IOPS)
  throughput: "125"                     # 125 MiB/s throughput (gp3 default)
  fsType: ext4
  encrypted: "true"
reclaimPolicy: Delete
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
```

### On-Premises StorageClass Examples

```yaml
# NFS-backed StorageClass (on-prem)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-standard
provisioner: nfs.csi.k8s.io
parameters:
  server: nfs-server.example.com
  share: /exports/tenant-standard
reclaimPolicy: Delete
volumeBindingMode: Immediate

---
# Local SSD StorageClass (for latency-sensitive workloads)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-ssd
provisioner: kubernetes.io/no-provisioner   # Manual — no dynamic provisioning
volumeBindingMode: WaitForFirstConsumer     # Requires pod placement first
reclaimPolicy: Delete
```

---

## Reclaim Policies — The Most Critical Security Setting

The `reclaimPolicy` controls what happens to a PV when its bound PVC is deleted. This is the most important storage security setting for multi-tenancy:

```
┌─────────────────────────────────────────────────────────────────┐
│              PV Reclaim Policies                                 │
├───────────────┬─────────────────────────────────────────────────┤
│ Delete        │ PV and its underlying storage are DELETED when   │
│ (recommended  │ the PVC is deleted. No data residue. Safe for    │
│  for MT)      │ multi-tenancy — next tenant gets a fresh volume. │
├───────────────┼─────────────────────────────────────────────────┤
│ Retain        │ PV is kept with status "Released" after PVC      │
│ (DANGEROUS    │ deletion. Data persists on the volume. Admin     │
│  for MT)      │ must manually clean up before re-use. If admin   │
│               │ accidentally re-binds, next tenant sees old data.│
├───────────────┼─────────────────────────────────────────────────┤
│ Recycle       │ DEPRECATED. Basic scrub (rm -rf /mountpoint/*). │
│ (deprecated)  │ Not secure — only does surface-level deletion.   │
│               │ Removed in modern Kubernetes.                    │
└───────────────┴─────────────────────────────────────────────────┘
```

**Rule for multi-tenancy: always use `reclaimPolicy: Delete`** on StorageClasses used by tenant workloads. The `Retain` policy is appropriate only for data that must survive PVC deletion (e.g., database backups managed by admins), never for general tenant storage.

```bash
# Check reclaim policy on existing storage classes
kubectl get storageclass -o custom-columns='NAME:.metadata.name,PROVISIONER:.provisioner,RECLAIM:.reclaimPolicy'
# NAME                PROVISIONER             RECLAIM
# high-performance    kubernetes.io/aws-ebs   Delete     ✅
# standard-perf       kubernetes.io/aws-ebs   Delete     ✅
# manual-backup       kubernetes.io/aws-ebs   Retain     ⚠️  Admin-managed only

# Check PV reclaim policy
kubectl get pv -o custom-columns='NAME:.metadata.name,RECLAIM:.spec.persistentVolumeReclaimPolicy,STATUS:.status.phase'
# If you see Released PVs with Retain policy — check for data before rebinding
```

---

## Access Modes and Isolation

PV access modes control how many nodes/pods can mount a volume simultaneously:

```
┌──────────────────────────────────────────────────────────────────┐
│              PersistentVolume Access Modes                        │
├──────────────────────┬───────────────────────────────────────────┤
│ ReadWriteOnce (RWO)  │ Mounted read-write by ONE node at a time  │
│                      │ Most cloud block storage (EBS, Azure Disk) │
│                      │ Safe for single-tenant pods               │
│                      │ Multiple pods on SAME node can all mount  │
├──────────────────────┼───────────────────────────────────────────┤
│ ReadOnlyMany (ROX)   │ Mounted read-only by MANY nodes           │
│                      │ Safe for shared reference data            │
│                      │ No write conflict; reads are safe to share│
├──────────────────────┼───────────────────────────────────────────┤
│ ReadWriteMany (RWX)  │ Mounted read-write by MANY nodes          │
│                      │ NFS, CephFS, Azure Files, EFS             │
│                      │ ⚠️ Can be shared across namespaces if not  │
│                      │ carefully controlled                       │
├──────────────────────┼───────────────────────────────────────────┤
│ ReadWriteOncePod     │ Mounted read-write by ONE POD only        │
│ (RWOP) — K8s 1.22+  │ Strictest isolation mode                  │
│                      │ Even multiple pods on same node blocked    │
└──────────────────────┴───────────────────────────────────────────┘
```

For multi-tenant storage isolation, prefer:
- **RWO** for database volumes and stateful application data (one pod writes, clear ownership)
- **RWOP** for the strictest single-pod isolation (Kubernetes 1.22+)
- **Avoid RWX** unless you specifically need shared storage, and only for data that's intentionally shared

---

## PVC Namespace Scoping

PVCs are namespace-scoped — a pod in `namespace-a` can only mount PVCs that exist in `namespace-a`. This is a built-in isolation property:

```bash
# PVC in namespace-a
kubectl get pvc -n namespace-a
# NAME        STATUS   VOLUME    CAPACITY   ACCESS MODES   STORAGECLASS
# my-data     Bound    pvc-xxx   10Gi       RWO            high-performance

# A pod in namespace-b CANNOT mount this PVC
# This is rejected at admission — cross-namespace PVC mounting is not possible
```

However, PVs are cluster-scoped, which creates the static provisioning risk:

```yaml
# DANGEROUS: Static PV that any PVC in any namespace can claim
apiVersion: v1
kind: PersistentVolume
metadata:
  name: shared-pv          # No namespace — cluster-scoped
spec:
  capacity:
    storage: 10Gi
  accessModes:
  - ReadWriteOnce
  storageClassName: manual  # A PVC in ANY namespace requesting "manual" + 10Gi can bind here
  hostPath:
    path: /data/tenant-a    # Tenant A's data path
```

A PVC in `namespace-b` requesting `storageClassName: manual` and `10Gi` could bind to this PV and access Tenant A's data. Mitigations:
1. Use **dynamic provisioning** exclusively — no pre-created PVs
2. Use `claimRef` on static PVs to lock them to a specific PVC:

```yaml
spec:
  claimRef:
    name: my-pvc         # Only this specific PVC can bind
    namespace: namespace-a  # In this specific namespace
```

---

## StorageClass Restrictions via ResourceQuota

ResourceQuota can restrict which StorageClass a namespace can use and how much storage it can consume from each class:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: storage-quota
  namespace: namespace-a
spec:
  hard:
    # Total storage across ALL classes
    requests.storage: 200Gi
    persistentvolumeclaims: "20"

    # Per-StorageClass quotas — enforces class segregation
    high-performance.storageclass.storage.k8s.io/requests.storage: 100Gi
    high-performance.storageclass.storage.k8s.io/persistentvolumeclaims: "10"

    # Prevent namespace-a from using the standard class (different tier)
    # Simply don't list it as allowed — or set to "0"
    standard-performance.storageclass.storage.k8s.io/requests.storage: "0"
    standard-performance.storageclass.storage.k8s.io/persistentvolumeclaims: "0"
```

Setting a StorageClass quota to `"0"` effectively bans that class from the namespace. Combined with OPA Gatekeeper policies, this creates a robust StorageClass access control system.

---

## hostPath Volumes — The Ultimate Storage Isolation Failure

A `hostPath` volume mounts a path from the **node's filesystem** directly into the container. This is the most dangerous storage configuration in a multi-tenant cluster:

```yaml
# DO NOT use in multi-tenant clusters
spec:
  volumes:
  - name: host-vol
    hostPath:
      path: /var/lib/kubelet/pods    # Reads other pods' volumes on this node!
      # OR
      path: /etc/kubernetes/pki     # Reads cluster certificates
      # OR
      path: /proc                   # Access to host kernel interfaces
      # OR
      path: /                       # Full root filesystem
```

What a tenant with `hostPath` access can do:
- Read any file on the host: `/etc/kubernetes/pki/ca.key` = full cluster compromise
- Read environment variables and secrets of other pods via `/proc/<pid>/environ`
- Read other pods' mounted secrets via `/var/lib/kubelet/pods/<uid>/volumes/`
- Write to the host filesystem, modifying configurations or injecting malicious code

### Blocking hostPath with Pod Security Admission

The `restricted` PSA profile disallows all `hostPath` volumes (only certain volume types are permitted):

```yaml
# Namespace label enforcing PSA restricted — blocks hostPath
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

Under `restricted`, the only allowed volume types are:
- `configMap`, `downwardAPI`, `emptyDir`, `projected`, `secret`
- `persistentVolumeClaim` (the safe way to use persistent storage)
- `csi` (with restrictions)
- `ephemeral`

Any pod that specifies a `hostPath` volume in a `restricted`-enforced namespace will be rejected at admission.

### Blocking hostPath with OPA Gatekeeper

For finer-grained control or when PSA is not sufficient:

```yaml
# ConstraintTemplate: block specific volume types
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockvolumetypes
spec:
  crd:
    spec:
      names:
        kind: K8sBlockVolumeTypes
      validation:
        openAPIV3Schema:
          type: object
          properties:
            blockedVolumeTypes:
              type: array
              items:
                type: string
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sblockvolumetypes

      violation[{"msg": msg}] {
        vol := input.review.object.spec.volumes[_]
        blocked := input.parameters.blockedVolumeTypes[_]
        vol[blocked]
        msg := sprintf("Volume type %v is not allowed", [blocked])
      }
---
# Constraint: apply to all namespaces
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockVolumeTypes
metadata:
  name: block-host-volumes
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  parameters:
    blockedVolumeTypes:
    - hostPath
    - nfs           # Also block direct NFS mounts if not managed
```

---

## Multi-Tenant Storage Architecture — Full Pattern

### Namespace A (Critical / Premium Tenant)

```yaml
# ── StorageClass (admin creates, cluster-scoped) ──────────────────
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: high-performance
provisioner: kubernetes.io/aws-ebs
parameters:
  type: io1
  iopsPerGB: "50"
  encrypted: "true"
reclaimPolicy: Delete
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
---
# ── ResourceQuota (namespace-scoped) ─────────────────────────────
apiVersion: v1
kind: ResourceQuota
metadata:
  name: storage-quota-a
  namespace: namespace-a
spec:
  hard:
    requests.storage: 200Gi
    persistentvolumeclaims: "20"
    high-performance.storageclass.storage.k8s.io/requests.storage: 200Gi
    high-performance.storageclass.storage.k8s.io/persistentvolumeclaims: "20"
    standard-performance.storageclass.storage.k8s.io/requests.storage: "0"
---
# ── PVC in namespace-a ────────────────────────────────────────────
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: critical-db-data
  namespace: namespace-a
spec:
  accessModes:
  - ReadWriteOnce              # Single-pod access — isolated
  storageClassName: high-performance
  resources:
    requests:
      storage: 50Gi
```

### Namespace B (Standard / Regular Tenant)

```yaml
# ── ResourceQuota (namespace-scoped) ─────────────────────────────
apiVersion: v1
kind: ResourceQuota
metadata:
  name: storage-quota-b
  namespace: namespace-b
spec:
  hard:
    requests.storage: 50Gi
    persistentvolumeclaims: "5"
    standard-performance.storageclass.storage.k8s.io/requests.storage: 50Gi
    standard-performance.storageclass.storage.k8s.io/persistentvolumeclaims: "5"
    high-performance.storageclass.storage.k8s.io/requests.storage: "0"  # Blocked!
---
# ── PVC in namespace-b ────────────────────────────────────────────
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: regular-app-data
  namespace: namespace-b
spec:
  accessModes:
  - ReadWriteOnce
  storageClassName: standard-performance
  resources:
    requests:
      storage: 10Gi
```

---

## Encryption at Rest — The Storage Security Baseline

In multi-tenant environments, all tenant storage should be encrypted at rest (covered in depth in Chapter 9 for etcd, same principle applies here):

```yaml
# StorageClass with encryption (AWS KMS example)
parameters:
  type: gp3
  encrypted: "true"
  kmsKeyId: arn:aws:kms:us-east-1:123456789012:key/tenant-a-key

# Per-tenant KMS keys provide cryptographic isolation:
# Even if storage volumes are co-located on the same physical disk,
# Tenant A's key cannot decrypt Tenant B's data.
```

For on-premises clusters, consider:
- **LUKS** (Linux Unified Key Setup) at the block device level
- **CSI encryption plugins** (e.g., Rook/Ceph with encryption enabled)
- **Application-level encryption** as a defence-in-depth layer

---

## Diagnosing Storage Isolation Issues

```bash
# ── Check PVCs and their bound PVs ───────────────────────────────
kubectl get pvc -n namespace-a
kubectl get pvc -n namespace-b
# Verify each PVC is in its own namespace and bound to a distinct PV

# ── Check PV status (look for Released PVs — data residue risk!) ──
kubectl get pv
# STATUS: Released = was used by a PVC that got deleted
# With Retain policy, data still present — DO NOT rebind to new tenant

# ── Check StorageClass reclaim policies ───────────────────────────
kubectl get storageclass
kubectl describe storageclass high-performance | grep ReclaimPolicy
# Should be: Delete (not Retain)

# ── Verify storage quota is enforced ─────────────────────────────
kubectl describe resourcequota storage-quota-a -n namespace-a
# Check: high-performance class requests.storage Used vs. Hard

# ── Look for dangerous volume types in running pods ───────────────
kubectl get pods -A -o json | jq '
  .items[] |
  select(.spec.volumes[]? | has("hostPath")) |
  {ns: .metadata.namespace, pod: .metadata.name,
   hostPaths: [.spec.volumes[] | select(has("hostPath")) | .hostPath.path]}'

# ── Check PSA enforcement on namespace ───────────────────────────
kubectl get namespace namespace-a -o jsonpath='{.metadata.labels}' | \
  python3 -m json.tool | grep pod-security
# Should show: "pod-security.kubernetes.io/enforce": "restricted"
# restricted profile blocks hostPath
```

---

## Common Mistakes and Exam Traps

### ❌ Mistake 1: Using `reclaimPolicy: Retain` on shared storage classes

Retain is appropriate for admin-managed backups, not for tenant-facing storage. If a tenant deletes their PVC and the PV enters "Released" state with their data intact, the next tenant bound to that PV gets the old data. Always use `Delete` for tenant StorageClasses.

### ❌ Mistake 2: Assuming PVC namespace scoping prevents all cross-tenant storage access

It prevents pod-level cross-namespace PVC mounting. But static PVs (cluster-scoped) can be bound by any matching PVC in any namespace unless protected with `claimRef`. Use dynamic provisioning exclusively for tenant storage.

### ❌ Mistake 3: Using ReadWriteMany without access controls

A PV with `ReadWriteMany` can be simultaneously mounted by pods across the cluster. If two tenant namespaces both have PVCs binding to the same shared NFS export, they share the filesystem. Always treat RWX volumes with the same care as shared databases.

### ❌ Mistake 4: Allowing hostPath volumes

Even with "just for testing" intent, a `hostPath` volume in a tenant pod is a full cluster compromise waiting to happen. Enforce `restricted` PSA on all tenant namespaces to block hostPath at admission. No exceptions.

### ❌ Mistake 5: Forgetting to restrict StorageClass access via ResourceQuota

Without quota restrictions on StorageClass, any tenant can request any StorageClass. A regular tenant could request the `high-performance` StorageClass (expensive) or worse, a `local-ssd` StorageClass intended for platform components. Use per-class quota restrictions to enforce tenant-to-class mapping.

### ❌ Mistake 6: Not setting `volumeBindingMode: WaitForFirstConsumer`

Using `Immediate` binding means the PV is bound to a specific Availability Zone before the pod is scheduled. If the pod can't run in that AZ (due to node taints or resource constraints), it gets stuck. `WaitForFirstConsumer` binds the PV in the same AZ where the pod lands — essential for node-isolated tenants.

---

## Quick Reference Summary

```
┌─────────────────────────────────────────────────────────────────┐
│          Data Plane Isolation: Storage — Quick Reference         │
├─────────────────┬───────────────────────────────────────────────┤
│ Primary tool    │ StorageClass per tenant type                   │
│                 │ Isolates IOPS pool, provisioner parameters,    │
│                 │ encryption keys                                │
├─────────────────┼───────────────────────────────────────────────┤
│ Most critical   │ reclaimPolicy: Delete (not Retain)            │
│ security config │ Prevents data residue between tenants         │
├─────────────────┼───────────────────────────────────────────────┤
│ Access modes    │ RWO/RWOP for single-tenant data               │
│                 │ RWX only for intentionally shared data        │
├─────────────────┼───────────────────────────────────────────────┤
│ Quota control   │ storageclass.storage.k8s.io/requests.storage  │
│                 │ = "0" blocks class; positive value caps usage  │
├─────────────────┼───────────────────────────────────────────────┤
│ hostPath block  │ PSA restricted profile (recommended)          │
│                 │ OPA Gatekeeper (for custom rules)             │
│                 │ ← Blocking hostPath is mandatory in multi-MT  │
├─────────────────┼───────────────────────────────────────────────┤
│ PVC isolation   │ PVCs are namespace-scoped — built-in boundary │
│                 │ PVs are cluster-scoped — use claimRef or      │
│                 │ dynamic provisioning only                     │
├─────────────────┼───────────────────────────────────────────────┤
│ Encryption      │ StorageClass parameters: encrypted: "true"    │
│                 │ Per-tenant KMS keys for cryptographic isolation│
├─────────────────┼───────────────────────────────────────────────┤
│ Volume binding  │ WaitForFirstConsumer — AZ-aware, works with   │
│ mode            │ node-isolated tenant pools                    │
├─────────────────┼───────────────────────────────────────────────┤
│ Key commands    │ kubectl get pv / pvc -n <ns>                  │
│                 │ kubectl get storageclass                      │
│                 │ kubectl describe resourcequota -n <ns>        │
│                 │ kubectl get pods -A -o json | jq hostPath...  │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## CKS Exam Tips

**Reclaim policy is a security property, not just a cost control.** If an exam question asks about preventing one tenant from reading another tenant's deleted data, the answer is `reclaimPolicy: Delete` on the StorageClass.

**Know the StorageClass quota syntax.** The format `<storageclass-name>.storageclass.storage.k8s.io/requests.storage` is unusual and easy to forget. Practice writing it: `high-performance.storageclass.storage.k8s.io/requests.storage: "0"`.

**hostPath = automatic exam red flag.** Any scenario describing a pod with `hostPath` volume in a multi-tenant context is describing a security vulnerability. The fix is PSA `restricted` profile on the namespace, or removing the `hostPath` and replacing with a PVC.

**PVC namespace scoping is your friend — know its limits.** PVCs are namespace-scoped (safe). PVs are cluster-scoped (require care). Dynamic provisioning creates a new PV per PVC, avoiding the static-PV rebinding risk.

**The StorageClass access mode and reclaim policy are set at the class level** — individual PVCs inherit from the class. If you need to check what reclaim policy a PVC's PV uses, look at the StorageClass, not the PVC itself.

---

## Summary

Storage isolation prevents cross-tenant data leakage through persistent volumes. The core mechanism is defining separate StorageClasses for each tenant tier — not just for performance differentiation, but for security: each class gets its own provisioner configuration, encryption key, and reclaim policy.

The most critical security setting is `reclaimPolicy: Delete`: when a tenant deletes their PVC, the underlying storage is wiped and returned to the pool, leaving no data for the next tenant. `Retain` policy is dangerous in multi-tenant environments because deleted-PVC data persists and can be accidentally exposed to the next tenant who claims that PV.

Access mode selection matters too: `ReadWriteOnce` and `ReadWriteOncePod` provide strong single-tenant access guarantees, while `ReadWriteMany` must be used carefully since it allows simultaneous multi-pod mounting that can span namespaces if not controlled. StorageClass access can be restricted per-namespace using ResourceQuota's per-class storage limits.

The most dangerous storage vector — `hostPath` volumes — bypasses all Kubernetes storage abstractions and gives containers direct access to the node filesystem, including other pods' secrets and cluster certificates. Blocking `hostPath` via PSA `restricted` profile is mandatory for any multi-tenant namespace.

---

## What's Next

**[Chapter 22 — Using Node Pools and Taints/Tolerations for Isolation →](./22%20---%20Using%20Node%20Pools%20and%20Taints%20Tolerations%20for%20Isolation.md)**

With network and storage isolation in place, the final data plane pillar is node-level isolation. Chapter 22 covers dedicated node pools, node taints, pod tolerations, nodeSelector, and node affinity — the mechanisms that prevent tenant pods from co-locating on the same physical nodes, eliminating shared-kernel risk and enabling truly hard isolation for regulated multi-tenant workloads.
