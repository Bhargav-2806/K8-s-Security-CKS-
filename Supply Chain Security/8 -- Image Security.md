# Chapter 8: Image Security — Registries, Naming, Private Repos, and Secrets

---

## Table of Contents

1. [Why Image Security Matters](#1-why-image-security-matters)
2. [Understanding Image Names and Naming Conventions](#2-understanding-image-names-and-naming-conventions)
   - [The Full Image Name Anatomy](#the-full-image-name-anatomy)
   - [How Kubernetes Resolves Image Names](#how-kubernetes-resolves-image-names)
   - [Image Tags vs Digests](#image-tags-vs-digests)
3. [Image Registries — Public and Private](#3-image-registries--public-and-private)
   - [Public Registries](#public-registries)
   - [Private Registries — Why You Need One](#private-registries--why-you-need-one)
   - [Major Private Registry Options](#major-private-registry-options)
4. [Accessing Private Registries](#4-accessing-private-registries)
   - [Docker Login from the CLI](#docker-login-from-the-cli)
   - [Authenticating from Kubernetes Worker Nodes](#authenticating-from-kubernetes-worker-nodes)
5. [Kubernetes Image Pull Secrets — Deep Dive](#5-kubernetes-image-pull-secrets--deep-dive)
   - [Creating the docker-registry Secret](#creating-the-docker-registry-secret)
   - [Using imagePullSecrets in Pod Specs](#using-imagepullsecrets-in-pod-specs)
   - [Attaching imagePullSecrets to a ServiceAccount](#attaching-imagepullsecrets-to-a-serviceaccount)
   - [What the Secret Contains](#what-the-secret-contains)
6. [Image Pull Policies — IfNotPresent, Always, Never](#6-image-pull-policies--ifnotpresent-always-never)
7. [Image Signing and Verification](#7-image-signing-and-verification)
   - [Cosign — Keyless Signing](#cosign--keyless-signing)
   - [Verifying Signatures at Admission](#verifying-signatures-at-admission)
8. [As a DevSecOps / Kubernetes Security Engineer](#8-as-a-devsecops--kubernetes-security-engineer)
9. [Real Present-Day Scenarios](#9-real-present-day-scenarios)
10. [What Happens If You Don't Follow This](#10-what-happens-if-you-dont-follow-this)
11. [Most Common Commands and Syntax](#11-most-common-commands-and-syntax)
12. [Other Tools and Services Available](#12-other-tools-and-services-available)
13. [How AI Is Impacting Image Security](#13-how-ai-is-impacting-image-security)
14. [CKS Exam Tips](#14-cks-exam-tips)
15. [Extra Information and References](#15-extra-information-and-references)

---

## 1. Why Image Security Matters

Every Kubernetes workload starts with a container image. That image is the source of truth for what code runs in your cluster — the operating system base, the runtime, the application libraries, and the application itself. If the image is compromised, everything running inside that container is compromised. If the image is pulled from an untrusted source, you have no assurance that it hasn't been tampered with between the developer's build and the node's runtime.

Image security is therefore foundational — not one of many supply chain controls, but the one that underlies all others. An image signing ceremony, a vulnerability scan, an SBOM — all of these are mechanisms to establish or verify the trustworthiness of the image before it runs.

Image security problems manifest in three primary ways:

**Typosquatting and name confusion attacks.** An attacker publishes `ngnix` (note the transposition) or `nginx-alpine` (a non-official variant) to Docker Hub. A developer accidentally uses the wrong name and pulls malware into production. This happened repeatedly with npm packages and has occurred in container registries too.

**Supply chain compromise via registry.** An attacker gains write access to a registry namespace and pushes a backdoored version of a legitimate image. Anyone pulling without digest pinning picks up the malicious version. This is precisely what happened in the Codecov attack (2021) and several Docker Hub incidents.

**Credential leakage.** Registry credentials stored improperly (in environment variables, in unencrypted ConfigMaps, in CI logs) expose your private registry to unauthorised access — either image theft or malicious pushes.

Understanding Kubernetes image naming, registry mechanics, and secret management is the first line of defence against all three.

---

## 2. Understanding Image Names and Naming Conventions

### The Full Image Name Anatomy

Every container image has a fully qualified name. Most of the time developers use shorthand, and the container runtime (Docker, containerd, CRI-O) expands it silently. Understanding the expansion rules is critical for knowing exactly where your images come from.

Consider this simple pod definition from KodeKloud:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
    - name: nginx
      image: nginx
```

The image field `nginx` is shorthand. The full resolution chain is:

```
nginx
  → library/nginx          (Docker adds "library/" for official images with no account prefix)
  → docker.io/library/nginx (Docker/containerd adds "docker.io" as the default registry)
  → docker.io/library/nginx:latest (":latest" tag added if no tag is specified)
```

The **fully qualified image name** has four components:

```
<registry>/<namespace>/<repository>:<tag>@<digest>

Examples:
  docker.io/library/nginx:1.25.3
  gcr.io/google-containers/pause:3.9
  registry.k8s.io/kube-apiserver:v1.28.0
  ghcr.io/myorg/myapp:v2.1.0
  private-registry.io/apps/internal-app:20240115-abc1234
  myregistry.io/production/payment-service:1.0.0@sha256:abc123...
```

| Component | Meaning | Default if omitted |
|-----------|---------|-------------------|
| `registry` | Hostname (and optionally port) of the registry | `docker.io` |
| `namespace` | Organisation, user, or project within the registry | `library` (for Docker Hub official images) |
| `repository` | Name of the image | (required) |
| `tag` | Mutable label pointing to a specific image version | `latest` |
| `@digest` | Immutable content-addressed SHA256 hash of the image manifest | (none — optional but recommended) |

**If you create your own image repository**, replace `library` with your organisation or username:

```yaml
# Instead of the Docker Hub official image:
image: library/nginx
# or simply:
image: nginx

# Use your organisation's image:
image: your-company/nginx
image: your-company/payment-service:1.2.3
image: myregistry.io/your-company/payment-service:1.2.3
```

### How Kubernetes Resolves Image Names

Kubernetes passes the image string from the Pod spec directly to the container runtime (containerd or CRI-O) running on the worker node. The runtime applies the following resolution rules:

```
1. If image contains a "." or ":" before the first "/", treat as explicit registry hostname.
   myregistry.io/myapp:1.0 → registry=myregistry.io

2. If image contains "/" but no registry hostname (no "." before first "/"), assume docker.io.
   myorg/myapp:1.0 → registry=docker.io, namespace=myorg

3. If image has no "/", assume docker.io/library.
   nginx:1.25 → registry=docker.io, namespace=library

4. If no tag and no digest, append ":latest".
   nginx → nginx:latest → docker.io/library/nginx:latest
```

This resolution is performed by **containerd** (the default CRI in modern Kubernetes) via its `registry.mirrors` and `registry.configs` configuration. You can override the default registry (e.g., to point `docker.io` pulls through an internal mirror) in containerd's config at `/etc/containerd/config.toml`.

### Image Tags vs Digests

**Tags are mutable.** The `:latest` tag, `:1.25`, `:stable` — any tag — is a pointer that can be moved. A registry operator can push a new image and reassign the tag to point to it. This means `nginx:1.25` today may not be the same image as `nginx:1.25` tomorrow if someone pushes a patched version.

**Digests are immutable.** A digest is a SHA256 hash of the image manifest. It uniquely and permanently identifies a specific image. Once an image is pushed with a particular digest, that digest never changes — even if the image is deleted and re-uploaded.

```yaml
# Mutable — can change silently between pulls:
image: nginx:1.25

# Immutable — always exactly this image, forever:
image: nginx:1.25@sha256:593dac25b7733ffb7afe1a72649a43e574778bf025ad60514ef40f6b5d606247

# Get the digest of an image:
docker inspect --format='{{index .RepoDigests 0}}' nginx:1.25
# or
docker pull nginx:1.25
docker images --digests nginx
# or
crane digest docker.io/library/nginx:1.25
```

**Best practice for production:** Pin images by digest, not just by tag. Use the tag for human readability and the digest for immutability:

```yaml
image: nginx:1.25@sha256:593dac25b7733ffb7afe1a72649a43e574778bf025ad60514ef40f6b5d606247
```

This guarantees that what you test in staging is exactly what runs in production — regardless of what happens to the tag.

---

## 3. Image Registries — Public and Private

### Public Registries

Registries are centralised image stores. Every time you build a container image, you push it to a registry. Nodes pull from registries when creating pods.

The major public registries:

| Registry | DNS Name | Primary Use |
|----------|----------|-------------|
| Docker Hub | `docker.io` | Default registry; official images (`nginx`, `postgres`, `python`); community images |
| Google Container Registry | `gcr.io` | Google's images; being deprecated in favour of Artifact Registry |
| Google Artifact Registry | `<region>-docker.pkg.dev` | Google's current standard; multi-format (Docker, Helm, Maven) |
| GitHub Container Registry | `ghcr.io` | GitHub-integrated; tightly coupled to GitHub Actions |
| Amazon ECR Public | `public.ecr.aws` | AWS-hosted public images |
| Quay.io | `quay.io` | Red Hat's registry; strong scanning features |
| Microsoft Container Registry | `mcr.microsoft.com` | Microsoft's official images (.NET, Windows, Azure) |
| registry.k8s.io | `registry.k8s.io` | Official Kubernetes project images (control plane components) |

```yaml
# Examples from KodeKloud — fully qualified image names for well-known images:
image: docker.io/library/nginx
image: gcr.io/kubernetes-e2e-test-images/dnsutils
image: registry.k8s.io/kube-apiserver:v1.28.0
image: mcr.microsoft.com/dotnet/aspnet:8.0
image: quay.io/prometheus/prometheus:v2.48.0
```

### Private Registries — Why You Need One

Public registries are not appropriate for internal application images. Your proprietary business logic, internal service images, and pre-release builds should never be publicly accessible. Private registries solve this by requiring authentication before any pull or push.

Reasons to use a private registry:

- **Intellectual property protection** — Your application code (compiled into the image) is your business. Exposing it publicly exposes your implementation, algorithms, and potentially credentials embedded in the image (a separate problem, but common).
- **Supply chain control** — A private registry lets you enforce which base images are allowed, which images have passed vulnerability scanning, and which images are signed. You cannot enforce these controls on Docker Hub.
- **Pull rate limiting** — Docker Hub throttles anonymous pulls severely and authenticated pulls moderately. Large-scale clusters pulling from Docker Hub will hit rate limits. Private registries (or mirrors) eliminate this.
- **Latency and bandwidth** — Images pulled from a registry co-located with your Kubernetes nodes pull faster. Pulling from Docker Hub across continents adds startup latency.
- **Compliance** — Many compliance frameworks require that software artefacts are stored in controlled, audited repositories.

### Major Private Registry Options

| Registry | Type | Strengths |
|----------|------|-----------|
| **Amazon ECR** | Managed cloud | AWS-native auth (IAM), lifecycle policies, image scanning, cross-region replication |
| **Google Artifact Registry** | Managed cloud | GCP-native auth, multi-format, VPC Service Controls |
| **Azure Container Registry (ACR)** | Managed cloud | Azure AD auth, geo-replication, Tasks for CI/CD |
| **GitHub Container Registry (ghcr.io)** | Managed cloud | GitHub Actions integration, org-level access control |
| **GitLab Container Registry** | Managed/self-hosted | Integrated with GitLab CI, per-project registries |
| **Harbor** | Self-hosted OSS | CNCF project; built-in vulnerability scanning, image replication, RBAC, Helm chart support |
| **JFrog Artifactory** | Self-hosted/managed | Enterprise-grade; multi-format; deep Kubernetes integration |
| **Nexus Repository** | Self-hosted | Popular in Java/Maven shops; supports Docker registries |
| **Quay.io** | Self-hosted/managed | Built-in Clair scanning; robot accounts; strong RBAC |

For most Kubernetes deployments, the recommendation is:

- **AWS clusters** → Amazon ECR (authentication handled transparently by ECR credential helper)
- **GKE** → Google Artifact Registry (Workload Identity Federation, no secret needed)
- **AKS** → Azure Container Registry with Managed Identity
- **On-premises / multi-cloud** → Harbor (CNCF, open-source, full-featured)

---

## 4. Accessing Private Registries

### Docker Login from the CLI

To pull or push images to a private registry, you must authenticate. From the CLI:

```bash
# Login to a private registry
docker login private-registry.io
# Prompts for username and password

# Login with credentials directly (avoid in shell history — use env vars)
docker login private-registry.io \
  --username registry-user \
  --password-stdin <<< "${REGISTRY_PASSWORD}"

# Login to Docker Hub
docker login
# or
docker login docker.io

# Login to Amazon ECR
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin \
    123456789.dkr.ecr.us-east-1.amazonaws.com

# Login to Google Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Login to GitHub Container Registry
echo "${GITHUB_TOKEN}" | docker login ghcr.io --username myorg --password-stdin

# Login to Azure Container Registry
az acr login --name myacr

# After login, run a container from the private registry
docker run private-registry.io/apps/internal-app

# Credentials are stored in ~/.docker/config.json (base64-encoded — not encrypted by default)
cat ~/.docker/config.json
```

> ⚠️ **Important:** `~/.docker/config.json` stores credentials in base64, not encryption. Anyone with read access to this file can decode the credentials. Use a credential helper (docker-credential-ecr-login, docker-credential-gcloud, pass, etc.) to store credentials securely in the system keychain.

### Authenticating from Kubernetes Worker Nodes

Worker nodes run the container runtime (containerd), which pulls images. The node itself needs credentials to pull from private registries. There are three approaches:

**Approach 1: Kubernetes imagePullSecrets (recommended for portability)**
Store credentials as a Kubernetes Secret and reference them in Pod specs. This is the approach covered in depth in Section 5.

**Approach 2: Node-level credential configuration (for cloud-managed clusters)**
Cloud providers can configure nodes to automatically authenticate to their native registry:
- EKS nodes with IAM roles can pull from ECR without Secrets
- GKE nodes with Workload Identity can pull from Artifact Registry without Secrets
- AKS nodes with Managed Identity can pull from ACR without Secrets

**Approach 3: Configure containerd directly on the node**

```toml
# /etc/containerd/config.toml
[plugins."io.containerd.grpc.v1.cri".registry]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
    [plugins."io.containerd.grpc.v1.cri".registry."private-registry.io"]
      endpoint = ["https://private-registry.io"]
  [plugins."io.containerd.grpc.v1.cri".registry.configs]
    [plugins."io.containerd.grpc.v1.cri".registry.configs."private-registry.io".auth]
      username = "registry-user"
      password = "registry-password"
```

This is the least flexible approach (credentials are node-level, not portable, not per-namespace) but is used in air-gapped environments where Kubernetes Secret management is not available.

---

## 5. Kubernetes Image Pull Secrets — Deep Dive

The standard, portable, Kubernetes-native way to authenticate to private registries is via **`imagePullSecrets`** — Kubernetes Secrets of type `kubernetes.io/dockerconfigjson` that contain registry credentials and are referenced in Pod specs.

### Creating the docker-registry Secret

**Method 1: kubectl create secret (recommended for simplicity)**

```bash
kubectl create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=registry-user \
  --docker-password=registry-password \
  --docker-email=registry-user@org.com

# Verify the secret was created
kubectl get secret regcred
kubectl get secret regcred -o yaml

# Create in a specific namespace
kubectl create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=registry-user \
  --docker-password=registry-password \
  --docker-email=registry-user@org.com \
  --namespace=production

# Create a secret for Amazon ECR
ECR_PASSWORD=$(aws ecr get-login-password --region us-east-1)
kubectl create secret docker-registry ecr-secret \
  --docker-server=123456789.dkr.ecr.us-east-1.amazonaws.com \
  --docker-username=AWS \
  --docker-password="${ECR_PASSWORD}" \
  --namespace=production

# Create a secret for GCP Artifact Registry
kubectl create secret docker-registry gcr-secret \
  --docker-server=us-central1-docker.pkg.dev \
  --docker-username=oauth2accesstoken \
  --docker-password="$(gcloud auth print-access-token)" \
  --namespace=production

# Create a secret for GitHub Container Registry
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=myorg \
  --docker-password="${GITHUB_TOKEN}" \
  --namespace=production
```

**Method 2: Create from existing Docker config (if already logged in)**

```bash
# After docker login, use the existing ~/.docker/config.json
kubectl create secret generic regcred \
  --from-file=.dockerconfigjson="${HOME}/.docker/config.json" \
  --type=kubernetes.io/dockerconfigjson

# Useful when you have multiple registries configured in config.json
```

**Method 3: Secret manifest (for GitOps / declarative management)**

```yaml
# The value of .dockerconfigjson is the base64-encoded Docker config JSON
# Generate it: echo -n '{"auths":{"private-registry.io":{"username":"user","password":"pass","auth":"base64(user:pass)"}}}' | base64 -w 0

apiVersion: v1
kind: Secret
metadata:
  name: regcred
  namespace: production
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: eyJhdXRocyI6eyJwcml2YXRlLXJlZ2lzdHJ5LmlvIjp7InVzZXJuYW1lIjoicmVnaXN0cnktdXNlciIsInBhc3N3b3JkIjoicmVnaXN0cnktcGFzc3dvcmQiLCJlbWFpbCI6InJlZ2lzdHJ5LXVzZXJAb3JnLmNvbSIsImF1dGgiOiJjbVZuYVhOMGNua3RkWE5sY2pwc1lXNWtZWGt0Y0dGemMzZHZjbVE9In19fQ==
```

> ⚠️ **GitOps caution:** Never commit real credentials to Git — not even base64-encoded. Use Sealed Secrets, External Secrets Operator, or HashiCorp Vault to inject credentials at deploy time.

### Using imagePullSecrets in Pod Specs

Once the Secret exists, reference it in every Pod (or Deployment) that needs to pull from that registry:

```yaml
# Basic Pod with imagePullSecrets (from KodeKloud example):
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
    - name: nginx
      image: private-registry.io/apps/internal-app
  imagePullSecrets:
    - name: regcred
```

```yaml
# Deployment with imagePullSecrets:
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      imagePullSecrets:
        - name: regcred          # Must exist in the same namespace as the pod
      containers:
        - name: app-container
          image: private-registry.io/apps/internal-app:1.2.3
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
```

```yaml
# Multiple registries — reference multiple secrets:
spec:
  imagePullSecrets:
    - name: ecr-secret       # For images from ECR
    - name: ghcr-secret      # For images from GitHub Container Registry
  containers:
    - name: app
      image: 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:1.0.0
    - name: sidecar
      image: ghcr.io/myorg/sidecar:v2.0.0
```

### Attaching imagePullSecrets to a ServiceAccount

Instead of adding `imagePullSecrets` to every Pod spec individually, you can attach them to the default (or a specific) ServiceAccount. Every pod that uses that ServiceAccount will automatically inherit the pull secrets.

```bash
# Patch the default ServiceAccount in the production namespace
kubectl patch serviceaccount default \
  --namespace=production \
  --patch='{"imagePullSecrets":[{"name":"regcred"}]}'

# Or create a ServiceAccount with imagePullSecrets already attached
kubectl create serviceaccount my-service-account --namespace=production
kubectl patch serviceaccount my-service-account \
  --namespace=production \
  --patch='{"imagePullSecrets":[{"name":"regcred"}]}'
```

```yaml
# ServiceAccount manifest with imagePullSecrets:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production
imagePullSecrets:
  - name: regcred
---
# Pod using the ServiceAccount (inherits imagePullSecrets automatically):
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  namespace: production
spec:
  serviceAccountName: app-service-account  # imagePullSecrets inherited
  containers:
    - name: app
      image: private-registry.io/apps/internal-app:1.0.0
```

**When to use which approach:**

| Approach | Best For |
|----------|----------|
| Per-Pod `imagePullSecrets` | Fine-grained control; different secrets per workload type |
| ServiceAccount-level | Namespace-wide default; all pods in the namespace need the same registry |
| Node-level containerd config | Air-gapped environments; no Kubernetes Secret management |
| Cloud IAM (ECR/GAR/ACR) | Cloud-native clusters; no Secret rotation needed |

### What the Secret Contains

Understanding what is actually inside a `docker-registry` Secret helps you debug pull failures:

```bash
# Decode the secret contents
kubectl get secret regcred -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq .

# Output looks like:
{
  "auths": {
    "private-registry.io": {
      "username": "registry-user",
      "password": "registry-password",
      "email": "registry-user@org.com",
      "auth": "cmVnaXN0cnktdXNlcjpyZWdpc3RyeS1wYXNzd29yZA=="
      # auth = base64(username:password)
    }
  }
}
```

The `auth` field is just `base64(username:password)` — not encrypted. This is why Kubernetes Secrets must be encrypted at rest (via EncryptionConfiguration) and RBAC must restrict who can `get` or `describe` Secrets in the namespace.

---

## 6. Image Pull Policies — IfNotPresent, Always, Never

The `imagePullPolicy` field in the container spec controls when the kubelet attempts to pull the image:

```yaml
spec:
  containers:
    - name: app
      image: myapp:1.0.0
      imagePullPolicy: IfNotPresent  # Pull only if not cached on the node
```

| Policy | Behaviour | When to Use |
|--------|-----------|-------------|
| `IfNotPresent` | Pull only if the image is not already cached on the node | Production with pinned versions (digest or specific tag); fastest startup |
| `Always` | Always pull from registry on every pod start | When using mutable tags like `latest`; ensures freshness |
| `Never` | Never pull; fail if not cached | Air-gapped environments; pre-loaded node images |

**Default behaviour:**
- If tag is `latest` or no tag is specified → `Always`
- If tag is any other specific version → `IfNotPresent`
- If digest is specified → `IfNotPresent`

**Security implications:**

`IfNotPresent` with a mutable tag means the node caches an old image and may not pick up security patches even after the registry image is updated. Always combine `IfNotPresent` with digest pinning to ensure the cached image IS the expected image.

`Always` with a private registry requires the imagePullSecret to be valid at every pod restart — including during node recovery when the registry might be unreachable. This can cause availability issues.

```yaml
# Best practice for production:
spec:
  containers:
    - name: app
      image: myregistry.io/myapp:1.0.0@sha256:abc123...  # Digest-pinned
      imagePullPolicy: IfNotPresent                        # Only pull if not cached; digest ensures correctness
```

---

## 7. Image Signing and Verification

Knowing the image name and registry is not enough — you need to know the image hasn't been tampered with between build and deployment. Image signing provides cryptographic proof that a specific image was produced by a specific entity at a specific time, and has not been modified since.

### Cosign — Keyless Signing

Cosign (from the Sigstore project) is the modern standard for container image signing:

```bash
# Install Cosign
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# Keyless signing (uses OIDC identity from GitHub Actions, GCP, etc.)
cosign sign --yes myregistry.io/myapp:1.0.0

# Key-based signing
cosign generate-key-pair           # Creates cosign.key (private) and cosign.pub (public)
cosign sign --key cosign.key myregistry.io/myapp:1.0.0

# Verify a signature
cosign verify \
  --certificate-identity-regexp "https://github.com/myorg/myrepo" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  myregistry.io/myapp:1.0.0

# Verify with a public key
cosign verify --key cosign.pub myregistry.io/myapp:1.0.0
```

### Verifying Signatures at Admission

Signature verification is only valuable if it is enforced at the point of image use — Kubernetes admission. Two primary approaches:

**Connaisseur** — A Kubernetes admission webhook that verifies Cosign/Notary signatures before allowing pods to be created:

```yaml
# Connaisseur policy — only allow signed images from our registry
apiVersion: connaisseur.kubernetes.io/v1beta1
kind: Policy
metadata:
  name: require-signed-images
spec:
  rules:
    - pattern: "myregistry.io/*"
      validators:
        - name: cosign
          with:
            key: cosign.pub
    - pattern: "*"
      validators: []   # Reject all other images
```

**Kyverno** — Policy engine that can verify Cosign signatures:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "myregistry.io/*"
          attestors:
            - count: 1
              entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      ...
                      -----END PUBLIC KEY-----
```

**OPA Gatekeeper** with external data — can verify signatures against an external Sigstore transparency log (Rekor):

```rego
# OPA policy — verify image is signed
package kubernetes.admission

deny[msg] {
  container := input.review.object.spec.containers[_]
  not image_is_signed(container.image)
  msg := sprintf("Image %v is not signed", [container.image])
}
```

---

## 8. As a DevSecOps / Kubernetes Security Engineer

Image security sits at the intersection of developer workflow (building and tagging images), platform engineering (registry management, access control), and security (signing, scanning, admission enforcement). As a DevSecOps engineer, you own the full chain.

**Registry architecture decisions:** You decide which registry to use, how to structure namespaces (per-team? per-environment? per-criticality?), and what the RBAC model looks like. A well-structured registry has separate namespaces for `dev`, `staging`, and `production` — with prod requiring signed, scanned images before promotion.

**Credential lifecycle management:** Registry credentials expire. ECR tokens expire every 12 hours. Service account tokens have configurable TTLs. You build automation that refreshes `imagePullSecrets` before expiry — otherwise pods can't restart during credential gaps.

```bash
# Refresh ECR credentials automatically (run as a CronJob)
# CronJob that refreshes the ECR imagePullSecret every 6 hours:
apiVersion: batch/v1
kind: CronJob
metadata:
  name: refresh-ecr-credentials
  namespace: production
spec:
  schedule: "0 */6 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: ecr-credential-refresher
          containers:
            - name: refresher
              image: amazon/aws-cli:latest
              command:
                - /bin/sh
                - -c
                - |
                  TOKEN=$(aws ecr get-login-password --region us-east-1)
                  kubectl create secret docker-registry ecr-secret \
                    --docker-server=123456789.dkr.ecr.us-east-1.amazonaws.com \
                    --docker-username=AWS \
                    --docker-password="${TOKEN}" \
                    --namespace=production \
                    --dry-run=client -o yaml | kubectl apply -f -
```

**Enforcing image source policies:** You configure OPA Gatekeeper or Kyverno to enforce that only images from your approved registries can run in production. No `docker.io`, no `gcr.io`, no unknown registries — only `myregistry.io`.

```yaml
# Kyverno policy — only allow images from our private registry
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
spec:
  validationFailureAction: Enforce
  rules:
    - name: validate-registries
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Images must come from myregistry.io or public.ecr.aws"
        pattern:
          spec:
            containers:
              - image: "myregistry.io/* | public.ecr.aws/*"
            =(initContainers):
              - image: "myregistry.io/* | public.ecr.aws/*"
```

**Detecting credential leakage:** You run periodic scans of running pod specs, ConfigMaps, and environment variables looking for patterns that suggest credentials were embedded in the wrong place — a URL with credentials in it, a base64-encoded string in an env var, registry credentials committed to Git. Tools like `truffleHog` and `gitleaks` can be integrated into your CI pipeline.

**Responding to a compromised image:** When you learn that an image in your registry has been compromised (supply chain attack, credential leak, malicious insider), your response playbook:

1. Tag the compromised image with a `quarantine` label in the registry; revoke push credentials
2. Query your SBOM store to identify all running workloads using that image digest
3. Trigger rolling updates in affected Deployments to the clean image version
4. Audit pull logs to determine who and what pulled the compromised image
5. Revoke the compromised image's signature from the transparency log (Rekor)
6. Post-mortem to determine how the compromise occurred and update controls

---

## 9. Real Present-Day Scenarios

### Scenario 1: Docker Hub Typosquatting — nginxofficial, etc.

In 2020, researchers at JFrog discovered hundreds of typosquatted images on Docker Hub — `logstash:8`, `ubuntu-python`, `kali-linux`, and similar names designed to catch developers who mistype or use approximate names. These images contained cryptocurrency miners, reverse shells, and data exfiltration scripts. They had collectively been pulled millions of times.

**The defence:** Always use the fully qualified name (`docker.io/library/nginx`, not `nginx`) and verify the publisher. Official Docker Hub images show the "Docker Official Image" badge and come from the `library` namespace. Anything else is community-published and unverified. For production, pull everything through your private registry after scanning — never pull directly from Docker Hub to production nodes.

### Scenario 2: The `latest` Tag Incident

A mid-size e-commerce company used `image: myapp:latest` in all their Deployments, with `imagePullPolicy: Always`. Their CI pipeline built and pushed to `latest` on every merge to main. A developer accidentally merged a broken branch that crashed on startup. Within minutes, a rolling update killed all their running pods (which started with the new broken image) and the application was down. No rollback was possible via Kubernetes because there was only ever one image — `latest`.

**The fix:** Pin images by semantic version tag tied to the Git commit SHA: `image: myapp:1.0.0-abc1234`. Every build produces a unique, immutable tag. Rolling back is `kubectl set image deployment/myapp app=myapp:1.0.0-xyz9876`. The `latest` tag still exists for convenience but is never referenced in Kubernetes manifests.

### Scenario 3: imagePullSecret Expiry During Incident

A company using Amazon ECR had their `imagePullSecret` created manually six months ago. ECR tokens are valid for 12 hours, but they had used a long-lived IAM access key, so the password was technically valid for months. One night, the IAM key was rotated as part of a security remediation. The `imagePullSecret` in Kubernetes was not updated. At 3am, a node failure triggered pod rescheduling. The rescheduled pods couldn't pull their images (the cached version was gone after a node replacement). A 4-hour incident ensued.

**The fix:** Automate `imagePullSecret` rotation using a CronJob (or use IAM Roles for Service Accounts on EKS, which eliminates the need for pull secrets entirely). Never rely on manually created secrets for production workloads.

### Scenario 4: Dependency Confusion via Private Registry Namespace

A company's private registry was at `mycompany-registry.io`. Their images were named `mycompany-registry.io/internal/payment-service:1.0.0`. A developer on a new team accidentally wrote `image: internal/payment-service:1.0.0` (without the registry prefix) in a pod spec. Kubernetes resolved this as `docker.io/internal/payment-service:1.0.0`. An attacker had registered the `internal` namespace on Docker Hub and published images with matching names. The company briefly ran the attacker's image in a dev cluster before the incident was caught.

**The fix:** Enforce registry allowlisting via Kyverno/OPA that rejects any image not starting with `mycompany-registry.io`. Make it impossible to accidentally pull from Docker Hub in cluster contexts.

### Scenario 5: Private Registry Credential Exposure in Pod Spec

A developer debugging a pull failure ran `kubectl get pod my-pod -o yaml` and saw the `imagePullSecrets` reference. They then ran `kubectl get secret regcred -o yaml` and got the base64-encoded credentials. They pasted this in a Slack message while asking for help. The Slack message was public in a shared channel that included contractors. The registry credentials were now compromised.

**The fix:** RBAC must restrict `get` on `secrets` to only the service accounts and humans who absolutely need it. Use `kubectl describe secret` (which shows metadata but not data) for debugging. Implement audit logging on secret access (`audit.k8s.io/policy`) to detect and alert on anomalous secret reads. Consider using Sealed Secrets or External Secrets Operator so the actual credentials never live as plain Kubernetes Secrets.

---

## 10. What Happens If You Don't Follow This

**Without private registry authentication:**
- Internal images are publicly accessible. Competitors, attackers, and anyone with the image name can pull your application code, analyse it for vulnerabilities, and extract any credentials accidentally embedded in layers.
- Kubernetes nodes fail to pull images and pods remain in `ImagePullBackOff` state. The node will retry with exponential backoff but will never succeed without credentials.

**Without imagePullSecrets configuration:**
- Every pod that references a private image will fail with `ImagePullBackOff`. The error from `kubectl describe pod` will say: `Failed to pull image "private-registry.io/apps/myapp:1.0.0": rpc error: code = Unknown desc = failed to pull and unpack image: failed to resolve reference "private-registry.io/apps/myapp:1.0.0": unexpected status code 401 Unauthorized`.

**Without digest pinning:**
- Images silently change between deploys. What you tested in staging may not be what runs in production. After a supply chain attack that replaces a tagged image, your running workloads may be compromised without any obvious indicator.
- Rollbacks become unreliable — `kubectl rollout undo` restores the old tag, but if the tag now points to a different image, you're not actually rolling back.

**Without secret rotation:**
- Expired credentials cause pods to fail to restart after eviction or node failure. This turns a routine infrastructure event (node replacement, node drain) into a production incident.
- Compromised credentials (leaked registry password) remain valid indefinitely, giving the attacker permanent access to your private registry.

**Without registry allowlisting:**
- Developers (or attackers who compromise a CI/CD pipeline) can introduce images from arbitrary sources into your cluster. This is a primary attack vector: push a malicious image to Docker Hub, compromise a CI/CD job to change the image reference, and the cluster runs the attacker's code.

**Without image signing:**
- A man-in-the-middle attack between the registry and the node (possible in a compromised network or via BGP hijacking) can substitute a different image for the expected one. The kubelet has no way to detect this without cryptographic verification.

---

## 11. Most Common Commands and Syntax

### Registry Authentication

```bash
# Login to Docker Hub
docker login

# Login to a private registry
docker login private-registry.io

# Login to ECR
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin \
    123456789.dkr.ecr.us-east-1.amazonaws.com

# Login to Artifact Registry (GCP)
gcloud auth configure-docker us-central1-docker.pkg.dev

# Login to ACR (Azure)
az acr login --name myacr

# Login to GHCR
echo "${GITHUB_TOKEN}" | docker login ghcr.io --username myorg --password-stdin

# Pull a private image
docker pull private-registry.io/apps/internal-app:1.0.0

# Inspect image for digest
docker inspect --format='{{index .RepoDigests 0}}' nginx:1.25
docker images --digests nginx:1.25
```

### Creating imagePullSecrets

```bash
# Create a docker-registry secret
kubectl create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=registry-user \
  --docker-password=registry-password \
  --docker-email=registry-user@org.com

# Create in a specific namespace
kubectl create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=registry-user \
  --docker-password=registry-password \
  --namespace=production

# Create from existing docker config
kubectl create secret generic regcred \
  --from-file=.dockerconfigjson="${HOME}/.docker/config.json" \
  --type=kubernetes.io/dockerconfigjson

# View the secret contents (decode)
kubectl get secret regcred -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq .

# List all docker-registry secrets
kubectl get secrets --field-selector type=kubernetes.io/dockerconfigjson

# Delete a secret
kubectl delete secret regcred

# Update a secret (delete and recreate)
kubectl delete secret regcred
kubectl create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=new-user \
  --docker-password=new-password
```

### Attaching to ServiceAccount

```bash
# Attach imagePullSecret to default ServiceAccount
kubectl patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"regcred"}]}'

# Attach to a specific namespace's default SA
kubectl patch serviceaccount default \
  --namespace=production \
  -p '{"imagePullSecrets":[{"name":"regcred"}]}'

# Verify ServiceAccount has the pull secret
kubectl get serviceaccount default -o yaml | grep -A 5 imagePullSecrets
```

### Pod Spec with imagePullSecrets

```yaml
# Pod using private registry with imagePullSecrets:
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
    - name: nginx
      image: private-registry.io/apps/internal-app:1.0.0
  imagePullSecrets:
    - name: regcred
```

### Image Pull Policy

```bash
# Check imagePullPolicy of running pods
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].imagePullPolicy}{"\n"}{end}'

# Set imagePullPolicy in a Deployment
kubectl set image deployment/myapp app=myapp:1.0.0 --record
kubectl patch deployment myapp \
  --patch='{"spec":{"template":{"spec":{"containers":[{"name":"app","imagePullPolicy":"IfNotPresent"}]}}}}'
```

### Debugging Pull Failures

```bash
# Check why a pod is in ImagePullBackOff
kubectl describe pod my-pod | grep -A 10 "Events:"

# Common errors:
# - "unauthorized: authentication required" → imagePullSecret missing or wrong
# - "manifest unknown" → image tag doesn't exist in registry
# - "network timeout" → registry unreachable from node
# - "not found" → image name typo or wrong registry

# Test registry reachability from a node
kubectl debug node/worker-1 -it --image=ubuntu -- curl -v https://private-registry.io/v2/

# Check what image is actually running (useful for verifying digest)
kubectl get pod my-pod -o jsonpath='{.status.containerStatuses[*].imageID}'
```

---

## 12. Other Tools and Services Available

### Managed Private Registry Services

| Service | Cloud | Key Features |
|---------|-------|-------------|
| **Amazon ECR** | AWS | IAM integration, lifecycle policies, image scanning (via Inspector), cross-region replication |
| **Google Artifact Registry** | GCP | Workload Identity, multi-format, VPC Service Controls, CMEK |
| **Azure Container Registry** | Azure | Geo-replication, Tasks (CI/CD), Managed Identity, content trust |
| **GitHub Container Registry** | GitHub | Actions-integrated, org-level access, packages API |
| **GitLab Container Registry** | GitLab | Per-project, integrated with GitLab CI, dependency proxy |
| **JFrog Container Registry** | Self-hosted/SaaS | Multi-registry proxy, Xray scanning, smart repo routing |

### Self-Hosted Registry Options

| Tool | Strengths |
|------|-----------|
| **Harbor** (CNCF) | Built-in Trivy scanning, image replication, robot accounts, Helm chart support, RBAC, webhook |
| **Quay.io** (Red Hat) | Clair scanning, robot accounts, time machine (image history), strong RBAC |
| **Nexus Repository** | Multi-format (Docker, npm, Maven, etc.), popular in Java environments |
| **Zot** | OCI-native, lightweight, reference implementation of OCI Distribution Spec |
| **Distribution** (Docker) | Bare-bones OCI registry; no UI; used as backend for other tools |

### Credential Management

| Tool | Purpose |
|------|---------|
| **Sealed Secrets** (Bitnami) | Encrypt Kubernetes Secrets so they can be safely committed to Git |
| **External Secrets Operator** | Sync secrets from AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager into K8s Secrets |
| **HashiCorp Vault** | Enterprise secret management; dynamic credentials; Vault Agent Injector |
| **AWS Secrets Manager** | Managed secrets; automatic rotation; ESO integration |
| **Reloader** (Stakater) | Automatically restarts pods when referenced Secrets change (useful for secret rotation) |
| **k8s-ecr-login-renew** | CronJob that automatically renews ECR imagePullSecrets |

### Image Signing and Trust

| Tool | Purpose |
|------|---------|
| **Cosign** (Sigstore) | Sign and verify OCI images; keyless via OIDC; SBOM attestation |
| **Notation** (Notary v2) | CNCF standard signing; OCI Distribution Spec native |
| **Connaisseur** | Kubernetes admission webhook for signature verification |
| **Kyverno** | Policy engine with built-in Cosign image verification |
| **Ratify** (Azure) | Signature and attestation verification for AKS |

### Registry Scanning and Auditing

| Tool | Purpose |
|------|---------|
| **Trivy** | Combined image scanning + SBOM generation; integrates with Harbor |
| **Clair** | Red Hat's registry-integrated scanner; powers Quay.io |
| **Grype** | SBOM-based vulnerability scanning; fast and accurate |
| **Amazon Inspector** | ECR-integrated scanning; Lambda and EC2 scanning too |
| **Google Artifact Analysis** | Automatic scanning on push to Artifact Registry |
| **Anchore Enterprise** | Enterprise policy engine for image compliance |

---

## 13. How AI Is Impacting Image Security

### AI-Powered Typosquatting Detection

Attackers publish malicious images with names that look like legitimate ones. AI models trained on naming patterns can now detect likely typosquatting with high accuracy:

- Models analyse Levenshtein distance between package names and known legitimate images, combined with pull count, publisher age, and content analysis.
- Docker Hub Scout and JFrog Xray use ML to flag suspicious newly-published images that match the naming patterns of popular images.
- **Real-world application:** When you configure your Kubernetes cluster to only pull from your private registry (which is the correct approach), AI at the registry level scans every image you push *into* that registry to verify its provenance before it becomes available for cluster use.

### AI-Assisted Credential Security

Finding credentials accidentally embedded in container image layers is a hard problem — credentials can appear in any layer, in any file format, encoded in various ways. AI is making this tractable:

- **Layer scanning with NLP** — ML models scan every file in every image layer for patterns resembling API keys, passwords, connection strings, and private keys. Tools like Orca Security and Wiz use these models to find secrets that regex-based scanners miss (obfuscated, split across lines, base64-encoded).
- **Drift detection** — AI compares image layer contents between versions and flags unexpected new files that might contain credentials or backdoors — even when the image tag doesn't change.

### AI in Secret Lifecycle Management

The tedious work of rotating `imagePullSecrets` across dozens of namespaces is being automated with AI-assisted tooling:

- **Predictive rotation** — Systems that observe credential age, usage patterns, and threat intelligence to proactively rotate credentials before they are at risk, rather than on a fixed schedule.
- **Anomaly detection** — ML models learn the normal pull patterns for each registry credential (which images, which nodes, what times) and alert when credentials are used in unexpected ways — a potential sign of credential compromise.

### AI and Registry Content Analysis

Beyond vulnerability scanning, AI is being used to analyse what an image *does* — behavioural analysis before runtime:

- **Static behavioural analysis** — Tools decompile or emulate image entrypoints and scripts to predict runtime behaviour. Malicious images that establish reverse shells, exfiltrate data, or mine cryptocurrency have distinct behavioural signatures that ML can detect before the image ever runs.
- **Supply chain graph analysis** — GUAC and similar tools use graph ML to reason about the full provenance chain of an image: which base image, which build system, which source repository, which developer committed the final layer. Anomalies in any part of the chain surface as risk signals.

---

## 14. CKS Exam Tips

Image Security is a core CKS topic tested across multiple question types. You need to know commands cold.

**High-probability exam tasks:**

1. **Create an imagePullSecret for a private registry:**
   ```bash
   kubectl create secret docker-registry regcred \
     --docker-server=private-registry.io \
     --docker-username=registry-user \
     --docker-password=registry-password \
     --docker-email=registry-user@org.com
   ```

2. **Add imagePullSecrets to a Pod or Deployment spec:**
   ```yaml
   spec:
     imagePullSecrets:
       - name: regcred
     containers:
       - name: app
         image: private-registry.io/apps/myapp:1.0.0
   ```

3. **Attach imagePullSecrets to a ServiceAccount:**
   ```bash
   kubectl patch serviceaccount default \
     -p '{"imagePullSecrets":[{"name":"regcred"}]}'
   ```

4. **Know the full image name resolution:**
   - `nginx` → `docker.io/library/nginx:latest`
   - `myorg/myapp` → `docker.io/myorg/myapp:latest`
   - `myregistry.io/myapp:1.0` → `myregistry.io/myapp:1.0` (no expansion needed)

5. **Debug an ImagePullBackOff:**
   ```bash
   kubectl describe pod my-pod
   # Look in Events section for pull error details
   ```

**Key facts to memorise:**

- Secret type for registry credentials: `kubernetes.io/dockerconfigjson`
- The key inside the secret: `.dockerconfigjson`
- `kubectl create secret docker-registry` is the shorthand command (type is set automatically)
- `imagePullSecrets` is a **pod-level** field (under `spec:`), not container-level
- The secret must be in the **same namespace** as the pod
- Attaching to a ServiceAccount applies the secret to ALL pods using that SA

**Common exam traps:**

- The `imagePullSecrets` field is at `spec.imagePullSecrets`, NOT at `spec.containers[].imagePullSecrets`
- If asked to create a secret for a specific namespace, add `--namespace=<ns>` to the create command
- If a pod is already running and you add an `imagePullSecret`, you may need to delete and recreate the pod — `kubectl apply` on a running pod doesn't restart it
- `kubectl create secret docker-registry` (not `generic` or `tls`) is the correct type for image pull credentials

---

## 15. Extra Information and References

### The .dockerconfigjson Format — Manual Construction

When creating the secret declaratively (e.g., in a Helm chart or GitOps manifest), you need to construct the `.dockerconfigjson` value:

```bash
# Step 1: Create the auth value (base64 of username:password)
AUTH=$(echo -n "registry-user:registry-password" | base64 -w 0)
# Output: cmVnaXN0cnktdXNlcjpyZWdpc3RyeS1wYXNzd29yZA==

# Step 2: Create the config JSON
CONFIG=$(cat <<EOF
{
  "auths": {
    "private-registry.io": {
      "username": "registry-user",
      "password": "registry-password",
      "email": "registry-user@org.com",
      "auth": "${AUTH}"
    }
  }
}
EOF
)

# Step 3: Base64-encode the entire config JSON
DOCKERCONFIGJSON=$(echo -n "${CONFIG}" | base64 -w 0)

# Step 4: Use in a Secret manifest
cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: regcred
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: ${DOCKERCONFIGJSON}
EOF
```

### Mirror Registries — Solving Docker Hub Rate Limits

Docker Hub rate-limits unauthenticated pulls (100/6h per IP) and authenticated pulls (200/6h per account). At scale, Kubernetes clusters hit these limits. The solution is a pull-through mirror:

```toml
# /etc/containerd/config.toml — configure Docker Hub mirror
[plugins."io.containerd.grpc.v1.cri".registry]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
      endpoint = ["https://my-dockerhub-mirror.internal"]
```

With Harbor, you can configure a proxy cache project that transparently mirrors Docker Hub:
- Harbor pulls from Docker Hub on first request and caches
- Subsequent pulls come from Harbor (no rate limit, no Docker Hub dependency)
- All pulls are logged and can be scanned before serving to nodes

### OCI Distribution Specification

All modern registries implement the **OCI Distribution Specification** (formerly the Docker Registry HTTP API v2). Understanding the basic API helps debug pull issues:

```bash
# List tags for an image
curl -u "username:password" \
  https://private-registry.io/v2/apps/internal-app/tags/list

# Get image manifest (to find the digest)
curl -u "username:password" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  https://private-registry.io/v2/apps/internal-app/manifests/1.0.0

# Check if registry supports the OCI spec
curl https://private-registry.io/v2/
# Returns 200 OK if registry is available; 401 if auth required
```

### Image Security Checklist

```
Container Image Security Checklist:

Source:
  ☐ Images built from approved, minimal base images (distroless, alpine, chainguard)
  ☐ No secrets in image layers or environment variables
  ☐ Multi-stage builds to minimise final image size
  ☐ Dockerfile has specific base image digest pinned

Registry:
  ☐ Private registry used for all internal images
  ☐ Registry access protected by authentication
  ☐ RBAC on registry (developers can push to dev, only CI/CD can push to prod)
  ☐ Images scanned for vulnerabilities before promotion to prod
  ☐ Images signed with Cosign before being promoted

Kubernetes Configuration:
  ☐ All private image pods have imagePullSecrets configured
  ☐ imagePullSecrets attached to ServiceAccounts where appropriate
  ☐ Image registry allowlist enforced via Kyverno/OPA
  ☐ Image signature verification enforced at admission
  ☐ Images pinned by digest in production manifests
  ☐ imagePullPolicy: IfNotPresent for pinned images
  ☐ imagePullSecret rotation automated

Monitoring:
  ☐ Registry pull logs reviewed for anomalous access
  ☐ SBOM generated and stored for all production images
  ☐ Continuous vulnerability monitoring via Dependency-Track or similar
```

### References

- [Docker Hub Official Images](https://hub.docker.com/search?image_filter=official)
- [Kubernetes — Pull an Image from a Private Registry](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)
- [Kubernetes — Configure Service Accounts for Pods (imagePullSecrets)](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#add-imagepullsecrets-to-a-service-account)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Harbor — Cloud Native Registry](https://goharbor.io/)
- [Amazon ECR Documentation](https://docs.aws.amazon.com/ecr/latest/userguide/what-is-ecr.html)
- [Google Artifact Registry Documentation](https://cloud.google.com/artifact-registry/docs)
- [NSA/CISA Kubernetes Hardening Guide — Section 4: Supply Chain Risks](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [KodeKloud CKS Course — Image Security](https://learn.kodekloud.com/user/courses/certified-kubernetes-security-specialist-cks/module/e4511664-185f-4204-9aa2-b4250cbadf84/lesson/1dc8b9e2-2f8c-4c62-b718-cbaadf05a542)
