# Chapter 7: Introduction to KubeLinter — Static Analysis for Kubernetes Manifests

---

## Table of Contents

1. [Why KubeLinter Matters](#1-why-kubelinter-matters)
2. [What Is KubeLinter?](#2-what-is-kubelinter)
   - [How KubeLinter Works](#how-kubelinter-works)
   - [What KubeLinter Checks](#what-kubelinter-checks)
3. [The Problem: Misconfigured Kubernetes Manifests](#3-the-problem-misconfigured-kubernetes-manifests)
   - [Anatomy of a Dangerous Manifest](#anatomy-of-a-dangerous-manifest)
   - [Why These Issues Are So Common](#why-these-issues-are-so-common)
4. [Installation and Setup](#4-installation-and-setup)
5. [Basic Usage — Linting Manifests](#5-basic-usage--linting-manifests)
   - [Understanding KubeLinter Output](#understanding-kubelinter-output)
   - [Linting Specific Resource Types](#linting-specific-resource-types)
6. [KubeLinter Rules — Deep Dive](#6-kubelinter-rules--deep-dive)
   - [Built-In Rule Categories](#built-in-rule-categories)
   - [Configuring Custom Rules](#configuring-custom-rules)
   - [Ignoring Rules Per-Resource](#ignoring-rules-per-resource)
7. [Integration with CI/CD Pipelines](#7-integration-with-cicd-pipelines)
   - [Jenkins Integration](#jenkins-integration)
   - [GitHub Actions Integration](#github-actions-integration)
   - [GitLab CI Integration](#gitlab-ci-integration)
   - [ArgoCD and GitOps Integration](#argocd-and-gitops-integration)
8. [As a DevSecOps / Kubernetes Security Engineer](#8-as-a-devsecops--kubernetes-security-engineer)
9. [Real Present-Day Scenarios](#9-real-present-day-scenarios)
10. [What Happens If You Don't Follow This](#10-what-happens-if-you-dont-follow-this)
11. [Most Common Commands and Syntax](#11-most-common-commands-and-syntax)
12. [Other Tools and Services Available](#12-other-tools-and-services-available)
13. [How AI Is Impacting Kubernetes Manifest Linting](#13-how-ai-is-impacting-kubernetes-manifest-linting)
14. [CKS Exam Tips](#14-cks-exam-tips)
15. [Extra Information and References](#15-extra-information-and-references)

---

## 1. Why KubeLinter Matters

Kubernetes is extraordinarily flexible — it will happily run a container as root, with no resource limits, pulling a floating `latest` tag, with no health checks, listening on privileged ports, with full host network access. None of these are blocked by default. The API server validates schema correctness but not security posture. It is entirely possible to run a textbook deployment YAML that passes `kubectl apply` with zero errors and yet represents a severe security and reliability risk.

This is the gap KubeLinter fills. It performs **static analysis** of your Kubernetes manifests — YAML files, Helm charts, and Kustomize bases — *before* they ever reach the cluster. It catches the class of problems that the Kubernetes API will silently accept: dangerous security contexts, missing resource constraints, anti-patterns that will cause failures at scale.

KubeLinter matters because:

- **Misconfigurations are the leading cause of Kubernetes security incidents.** The NSA/CISA Kubernetes Hardening Guide explicitly calls out misconfigured workloads as the primary attack surface. Not zero-days — plain misconfiguration.
- **Manual YAML review does not scale.** A large platform team managing hundreds of microservices cannot review every manifest on every pull request for security posture. Automated lint gates make this systematic.
- **Shift-left security.** Catching a missing `securityContext` at pull request time costs nothing to fix. Catching it after a container escape costs remediation time, incident response, potential breach investigation, and reputational damage.
- **Enforcement without bureaucracy.** KubeLinter enforces your organisation's Kubernetes security baseline without requiring a dedicated policy committee. Define the rules once; the tool enforces them on every commit.
- **Complementary to runtime controls.** KubeLinter at the manifest level works alongside Pod Security Admission, OPA Gatekeeper, and Kyverno at the admission level, and Falco at the runtime level. Together they create defence in depth.

---

## 2. What Is KubeLinter?

KubeLinter is an **open-source static analysis tool** developed by StackRox (now part of Red Hat/IBM) that analyses Kubernetes manifest files — Deployments, DaemonSets, StatefulSets, Services, ConfigMaps, and more — against a set of configurable best-practice rules. It was open-sourced in 2020 and has become a standard part of Kubernetes security pipelines.

KubeLinter is not a runtime tool — it never talks to a live Kubernetes cluster (unless you explicitly feed it live manifests). It works entirely on YAML/JSON files, making it safe, fast, and suitable for pre-deployment gates.

### How KubeLinter Works

![The image explains KubeLinter's workflow: configurable checks, analysis and linting, and report and suggestions, with document icons and a checkmark symbol.](https://kodekloud.com/kk-media/image/upload/v1752871694/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Introduction-to-KubeLinter/frame_100.jpg)

The workflow is three stages:

1. **Configurable Checks** — You define (or accept defaults for) a set of rules. Rules can be enabled, disabled, or customised per-project via a `.kube-linter.yaml` configuration file. Rules cover security, reliability, and operational best practices.

2. **Analysis and Linting** — KubeLinter parses your manifest files, builds an internal model of every Kubernetes object, and runs each enabled rule against each object. Rules are evaluated deterministically and in parallel.

3. **Report and Suggestions** — KubeLinter produces a structured report: which check failed, on which object, at which line, and what remediation is recommended. Exit code 1 on any failure makes it trivially usable as a CI gate.

### What KubeLinter Checks

KubeLinter's built-in checks cover five broad categories:

- **Security** — `runAsNonRoot`, `readOnlyRootFilesystem`, `privileged: false`, `allowPrivilegeEscalation: false`, `capabilities.drop: ALL`, no `hostPID`/`hostNetwork`/`hostIPC`.
- **Images** — No `latest` tag, no unspecified tag, use of image digests encouraged.
- **Reliability** — Liveness and readiness probes required, minimum replica count enforced.
- **Resources** — CPU and memory requests and limits required on all containers.
- **Networking** — No privileged port exposure (< 1024), service type restrictions.

The benefits of running these checks systematically:

![The image lists benefits of using KubeLinter: preventing misconfigurations, improving security, enhancing reliability, and enabling automated reviews.](https://kodekloud.com/kk-media/image/upload/v1752871695/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Introduction-to-KubeLinter/frame_120.jpg)

- **Prevents misconfigurations** — Catches YAML mistakes and dangerous defaults before they reach the cluster.
- **Enhances security** through customizable rules — Enforce your organisation's security baseline consistently across every team.
- **Improves reliability** — Probes, replica counts, and resource limits that ensure workloads behave predictably.
- **Automates reviews** — Replaces ad-hoc manual YAML review with systematic, repeatable, machine-enforced checks. Helps achieve cost efficiency (right-sized resources) and compliance (auditable policy enforcement).

---

## 3. The Problem: Misconfigured Kubernetes Manifests

### Anatomy of a Dangerous Manifest

The following is a typical "beginner" Kubernetes deployment — the kind found in tutorials, blog posts, and unfortunately production clusters at companies that never invested in a security review process:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: app-container
        image: my-app-image:latest
        ports:
        - containerPort: 8080
```

This manifest will be accepted by `kubectl apply` without complaint. Yet it contains at least **seven distinct security and reliability problems:**

| Problem | Risk | KubeLinter Check |
|---------|------|-----------------|
| `replicas: 1` | Single point of failure; one node eviction kills the service | `minimum-three-replicas` (configurable) |
| `image: my-app-image:latest` | `latest` is a floating tag — rebuilt images silently change running code | `no-latest-image` |
| No `resources.requests` | Kubernetes cannot schedule optimally; node can be overloaded | `unset-cpu-requirements`, `unset-memory-requirements` |
| No `resources.limits` | A single pod can consume all node resources (CPU/memory), causing noisy neighbour issues or OOM kills | `unset-cpu-requirements`, `unset-memory-requirements` |
| No `livenessProbe` | Kubernetes cannot detect if the application is deadlocked; pod remains "Running" while actually broken | `liveness-probe` |
| No `readinessProbe` | Traffic is sent to pods that are not yet ready (during startup) or are temporarily degraded | `readiness-probe` |
| No `securityContext` | Container runs as root by default; can write to filesystem; has full Linux capabilities | `run-as-non-root`, `read-only-root-fs`, `no-privilege-escalation`, `drop-net-raw-capability` |

**A hardened version of the same manifest looks like this:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
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
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app-container
        image: my-app-image:1.2.3          # Pinned version, not latest
        ports:
        - containerPort: 8080
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
          limits:
            cpu: "500m"
            memory: "256Mi"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          failureThreshold: 3
```

KubeLinter will pass the hardened version and fail the original. That is its entire job — and it does it before anything reaches the cluster.

### Why These Issues Are So Common

The root cause is that Kubernetes was designed for flexibility, not security by default. Defaults were chosen for developer convenience in 2014-2015, when Kubernetes was new and production security was not yet a primary concern. Those defaults have never been changed for backwards compatibility reasons. This means:

- `runAsRoot` is the default unless you explicitly set `runAsNonRoot: true`
- `readOnlyRootFilesystem` is `false` by default — containers can write anywhere
- `privileged: false` is the default, but `allowPrivilegeEscalation: true` is the default on many distros
- No resource limits by default — unlimited CPU and memory consumption
- No probes by default — pods appear healthy even when frozen

Without a tool like KubeLinter enforcing these fields, developers who are focused on functionality will ship manifests without them. Not out of negligence — they simply don't know what they don't know.

---

## 4. Installation and Setup

KubeLinter is distributed as a single statically-linked binary with no runtime dependencies.

```bash
# Method 1: Direct binary download (Linux amd64)
curl -Lo kube-linter.tar.gz \
  https://github.com/stackrox/kube-linter/releases/download/0.2.3/kube-linter-linux-amd64.tar.gz
tar -xzf kube-linter.tar.gz
sudo mv kube-linter /usr/local/bin/
chmod +x /usr/local/bin/kube-linter

# Verify installation
kube-linter version

# Method 2: Install latest release via GitHub CLI
gh release download --repo stackrox/kube-linter --pattern "kube-linter-linux-amd64.tar.gz"

# Method 3: Install via Go (requires Go 1.19+)
go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest

# Method 4: macOS with Homebrew
brew install kube-linter

# Method 5: Windows with Chocolatey
choco install kube-linter

# Method 6: Docker image (no local installation required)
docker run --rm -v $(pwd):/workdir \
  stackrox/kube-linter:latest lint /workdir/k8s-configs/

# Method 7: Install via krew (kubectl plugin manager)
kubectl krew install lint-k8s
```

**Verify the installation:**

```bash
kube-linter version
# Output: kube-linter version 0.6.x (Go1.21.x)

kube-linter checks list
# Lists all built-in checks with descriptions
```

---

## 5. Basic Usage — Linting Manifests

```bash
# Navigate to your Kubernetes configs directory
cd path/to/k8s-configs

# Lint all YAML files in the current directory (recursively)
kube-linter lint .

# Lint a specific file
kube-linter lint deployment.yaml

# Lint a specific directory
kube-linter lint ./manifests/

# Lint a Helm chart directory
kube-linter lint ./charts/myapp/

# Lint with a custom config file
kube-linter lint . --config .kube-linter.yaml

# Lint and output results as JSON (for downstream processing)
kube-linter lint . --format json

# Lint and output results as SARIF (for GitHub Security tab)
kube-linter lint . --format sarif > results.sarif

# List all available checks (without linting)
kube-linter checks list

# Show details for a specific check
kube-linter checks list | grep -A 5 "no-latest-image"
```

### Understanding KubeLinter Output

When KubeLinter finds issues, its output is detailed and actionable:

```
KubeLinter 0.6.8

/path/to/deployment.yaml: (object: default/my-app apps/v1, Kind=Deployment)
  container "app-container" does not have a read-only root file system
  (check: no-read-only-root-fs, remediation: Set readOnlyRootFilesystem to true in your container's
  securityContext.)

/path/to/deployment.yaml: (object: default/my-app apps/v1, Kind=Deployment)
  container "app-container" has cpu request 0
  (check: unset-cpu-requirements, remediation: Set your container's CPU requests and limits in
  spec.containers[].resources.requests.cpu and spec.containers[].resources.limits.cpu.)

/path/to/deployment.yaml: (object: default/my-app apps/v1, Kind=Deployment)
  container "app-container" has memory limit 0
  (check: unset-memory-requirements, remediation: Set your container's memory requests and limits in
  spec.containers[].resources.requests.memory and spec.containers[].resources.limits.memory.)

/path/to/deployment.yaml: (object: default/my-app apps/v1, Kind=Deployment)
  container "app-container" is not set to runAsNonRoot
  (check: run-as-non-root, remediation: Set runAsUser to a non-zero number and runAsNonRoot to true
  in your pod or container's securityContext.)

/path/to/deployment.yaml: (object: default/my-app apps/v1, Kind=Deployment)
  object has 1 replica but minimum required is 2
  (check: minimum-three-replicas, remediation: Increase the number of replicas in your deployment
  to at least 3.)

Error: found 5 lint errors
```

Each error includes:
- **File path** — which manifest file contains the issue
- **Object** — namespace, name, API version, and Kind
- **Container** — which container within the pod spec
- **Check name** — the rule that was violated (e.g., `no-read-only-root-fs`)
- **Remediation** — precise guidance on what YAML field to set

### Linting Specific Resource Types

```bash
# Only lint Deployment resources
kube-linter lint . --include deployments

# Lint but ignore DaemonSets (e.g., system DaemonSets that need privileged access)
kube-linter lint . --exclude daemonsets

# Lint a Kustomize overlay
kustomize build overlays/production | kube-linter lint -

# Lint Helm-rendered output
helm template myapp ./charts/myapp | kube-linter lint -
```

---

## 6. KubeLinter Rules — Deep Dive

### Built-In Rule Categories

KubeLinter ships with 30+ built-in checks. The most important ones for CKS and real-world security:

**Security checks:**

| Check Name | What It Catches | Remediation |
|---|---|---|
| `run-as-non-root` | Container missing `runAsNonRoot: true` | Add `securityContext.runAsNonRoot: true` |
| `no-read-only-root-fs` | Container missing `readOnlyRootFilesystem: true` | Add `securityContext.readOnlyRootFilesystem: true` |
| `no-privilege-escalation` | Missing `allowPrivilegeEscalation: false` | Add `securityContext.allowPrivilegeEscalation: false` |
| `privileged-container` | Container running as `privileged: true` | Remove `privileged: true` from securityContext |
| `drop-net-raw-capability` | Container has `NET_RAW` capability | Add `capabilities.drop: [NET_RAW]` or `[ALL]` |
| `no-extensions-v1beta1` | Using deprecated `extensions/v1beta1` API | Migrate to `apps/v1` |
| `host-ipc` | Pod using `hostIPC: true` | Remove `hostIPC` or explicitly set to `false` |
| `host-network` | Pod using `hostNetwork: true` | Remove `hostNetwork` or explicitly set to `false` |
| `host-pid` | Pod using `hostPID: true` | Remove `hostPID` or explicitly set to `false` |
| `writable-host-mount` | Volume mounting host paths as writable | Use `readOnly: true` on hostPath mounts |

**Image checks:**

| Check Name | What It Catches | Remediation |
|---|---|---|
| `no-latest-image` | Container image uses `latest` tag | Pin to a specific version or digest |
| `docker-sock` | Volume mounting the Docker socket (`/var/run/docker.sock`) | Remove the Docker socket mount — it grants root on the host |

**Reliability checks:**

| Check Name | What It Catches | Remediation |
|---|---|---|
| `liveness-probe` | Container missing `livenessProbe` | Add `livenessProbe` with appropriate thresholds |
| `readiness-probe` | Container missing `readinessProbe` | Add `readinessProbe` with appropriate thresholds |
| `minimum-three-replicas` | Deployment with fewer than 3 replicas (configurable) | Increase `spec.replicas` |
| `no-anti-affinity` | Deployment missing `podAntiAffinity` rules | Add anti-affinity to spread pods across nodes |

**Resource checks:**

| Check Name | What It Catches | Remediation |
|---|---|---|
| `unset-cpu-requirements` | Container missing `resources.requests.cpu` or `resources.limits.cpu` | Set both requests and limits |
| `unset-memory-requirements` | Container missing `resources.requests.memory` or `resources.limits.memory` | Set both requests and limits |

### Configuring Custom Rules

KubeLinter is configured via a `.kube-linter.yaml` file at the root of your repository:

```yaml
# .kube-linter.yaml

customChecks:
  # Custom check: require specific labels on all Deployments
  - name: required-labels
    description: "All Deployments must have 'team' and 'env' labels"
    template: required-label
    scope:
      objectKinds:
        - DeploymentLike
    params:
      key: team
      message: "Missing required label: team"
  - name: required-env-label
    description: "All Deployments must have env label"
    template: required-label
    scope:
      objectKinds:
        - DeploymentLike
    params:
      key: env
      message: "Missing required label: env"

checks:
  # Start with all default checks enabled
  addAllBuiltIn: true

  # Exclude specific checks that don't apply to your environment
  exclude:
    # If you use Horizontal Pod Autoscaler, replica count is managed externally
    - minimum-three-replicas
    # Some system components legitimately need host network
    - host-network

  # Include specific checks explicitly (if addAllBuiltIn: false)
  include:
    - run-as-non-root
    - no-read-only-root-fs
    - no-privilege-escalation
    - no-latest-image
    - liveness-probe
    - readiness-probe
    - unset-cpu-requirements
    - unset-memory-requirements
```

**Minimum secure configuration (addAllBuiltIn: false, only critical checks):**

```yaml
# .kube-linter.yaml — minimal security baseline
checks:
  addAllBuiltIn: false
  include:
    - run-as-non-root
    - no-read-only-root-fs
    - no-privilege-escalation
    - privileged-container
    - drop-net-raw-capability
    - no-latest-image
    - docker-sock
    - host-ipc
    - host-network
    - host-pid
    - unset-memory-requirements
```

### Ignoring Rules Per-Resource

Sometimes a specific resource legitimately needs to violate a rule — for example, a system DaemonSet that requires host networking, or a legacy application that cannot yet set resource limits. You can suppress KubeLinter warnings on a per-object basis using annotations:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-monitoring-agent
  annotations:
    # Suppress specific checks with justification
    ignore-check.kube-linter.io/host-network: "Node monitoring agent requires host network access to collect metrics"
    ignore-check.kube-linter.io/run-as-non-root: "This agent must run as root to access /proc and /sys"
    ignore-check.kube-linter.io/no-read-only-root-fs: "Agent writes logs to /var/log on the host"
spec:
  # ...
```

> ⚠️ Every suppression annotation should be treated as a finding to revisit. Track them in your security backlog with a plan to eliminate them.

---

## 7. Integration with CI/CD Pipelines

KubeLinter's true power is as a mandatory CI/CD gate — a check that runs on every pull request and blocks merge if any lint errors are found. This shifts security left to the moment of authoring rather than discovery in production.

![The image illustrates a CI/CD integration workflow: checkout code, lint Kubernetes manifests, build Docker image, push Docker image, and deploy to Kubernetes.](https://kodekloud.com/kk-media/image/upload/v1752871696/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Introduction-to-KubeLinter/frame_200.jpg)

The standard CI/CD integration flow:
1. **Check out code** from the repository
2. **Lint Kubernetes manifests** — KubeLinter exits with code 1 if any issues are found, blocking the pipeline
3. **Build Docker image** — only proceeds if linting passes
4. **Push Docker image** to registry
5. **Deploy to Kubernetes** — only after all prior gates pass

### Jenkins Integration

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Install KubeLinter') {
            steps {
                sh '''
                    curl -sSfL https://raw.githubusercontent.com/stackrox/kube-linter/main/scripts/install.sh | sh -
                    kube-linter version
                '''
            }
        }
        
        stage('Lint Kubernetes Manifests') {
            steps {
                sh 'kube-linter lint . --config .kube-linter.yaml'
            }
            post {
                failure {
                    // Send notification on lint failure
                    emailext(
                        subject: "KubeLinter: Manifest Issues Found in ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                        body: "Kubernetes manifest linting failed. Check ${env.BUILD_URL} for details.",
                        to: "${env.CHANGE_AUTHOR_EMAIL}"
                    )
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                sh 'docker build -t myapp:${GIT_COMMIT} .'
            }
        }
        
        stage('Push Docker Image') {
            steps {
                sh 'docker push myregistry.io/myapp:${GIT_COMMIT}'
            }
        }
        
        stage('Deploy to Kubernetes') {
            steps {
                sh 'kubectl apply -f ./k8s/'
            }
        }
    }
}
```

### GitHub Actions Integration

```yaml
# .github/workflows/lint-manifests.yml
name: Lint Kubernetes Manifests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
    paths:
      - '**/*.yaml'
      - '**/*.yml'

jobs:
  lint:
    name: KubeLinter
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      # Option A: Use the official KubeLinter GitHub Action
      - name: Lint Kubernetes manifests (Action)
        uses: stackrox/kube-linter-action@v1
        with:
          directory: k8s/
          config: .kube-linter.yaml
          format: sarif
          output-file: kube-linter-results.sarif

      # Option B: Manual installation and run
      - name: Install KubeLinter
        run: |
          curl -Lo kube-linter.tar.gz \
            https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux-amd64.tar.gz
          tar -xzf kube-linter.tar.gz
          sudo mv kube-linter /usr/local/bin/
      
      - name: Run KubeLinter
        run: kube-linter lint . --config .kube-linter.yaml
      
      # Upload SARIF results to GitHub Security tab
      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kube-linter-results.sarif
          category: kube-linter
```

### GitLab CI Integration

```yaml
# .gitlab-ci.yml
stages:
  - lint
  - build
  - deploy

kube-lint:
  stage: lint
  image: stackrox/kube-linter:latest
  script:
    - kube-linter lint ./k8s/ --config .kube-linter.yaml
  artifacts:
    when: always
    reports:
      # GitLab can display JSON lint reports
      junit: kube-linter-results.json
  rules:
    - changes:
        - "k8s/**/*.yaml"
        - "k8s/**/*.yml"
        - ".kube-linter.yaml"

build:
  stage: build
  needs: [kube-lint]
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

deploy:
  stage: deploy
  needs: [build]
  script:
    - kubectl apply -f ./k8s/
```

### ArgoCD and GitOps Integration

In a GitOps workflow where ArgoCD or Flux syncs manifests from Git to the cluster, KubeLinter acts as a pre-sync gate — blocking changes from being merged into the main branch that ArgoCD would then sync:

```yaml
# Pre-merge check via GitHub Actions on the GitOps repo
name: Validate Manifests Before ArgoCD Sync

on:
  pull_request:
    branches: [main]   # ArgoCD watches main branch

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: KubeLinter security check
        uses: stackrox/kube-linter-action@v1
        with:
          directory: .
          config: .kube-linter.yaml
      
      - name: kubeval schema validation
        run: |
          kubeval --strict --kubernetes-version 1.28.0 **/*.yaml
      
      - name: Kyverno policy check (dry-run)
        run: |
          kyverno apply ./policies/ --resource ./manifests/ --detailed-results
```

This creates a "policy as code" pipeline: KubeLinter catches security misconfigurations, `kubeval` catches schema errors, and Kyverno enforces admission policies — all before a single change reaches the cluster.

---

## 8. As a DevSecOps / Kubernetes Security Engineer

KubeLinter is not just a tool you run — it is a policy enforcement mechanism that reflects your organisation's Kubernetes security standards. Your responsibilities as a DevSecOps engineer go well beyond just running `kube-linter lint`:

**Defining the policy baseline:** You maintain the `.kube-linter.yaml` configuration that represents your organisation's agreed security standard. This involves working with platform teams, application teams, and security leadership to agree on which checks are mandatory, which are advisory, and which are environment-specific (prod vs dev).

**Integrating into the golden path:** You build KubeLinter into your organisation's standard CI/CD templates, Helm chart validation pipelines, and GitOps workflows so that developers don't have to manually invoke it — it runs automatically on every commit.

**Managing exceptions:** You handle requests for `ignore-check` annotations, ensure they are documented with justifications, tracked in your security backlog, and reviewed periodically. An exception is not a permanent pass — it is a time-boxed technical debt item.

**Correlating with runtime findings:** KubeLinter findings at the YAML level should be correlated with runtime security findings (from Falco, Prisma Cloud, etc.). If KubeLinter is consistently flagging `run-as-non-root` for a team's workloads and those workloads are also generating runtime alerts about root processes, that is a signal to invest in remediation support for that team.

**Building custom checks for your context:** KubeLinter's check templating system lets you write custom rules specific to your organisation — for example:
- Requiring all Deployments to carry a `team` label (for cost allocation)
- Requiring a `business-criticality` annotation (for SLA assignment)
- Blocking use of specific deprecated base images (e.g., `ubuntu:20.04` when you've standardised on `ubuntu:22.04`)
- Requiring specific network policies to exist alongside every Deployment

**Running KubeLinter against a live cluster (for remediation campaigns):**

```bash
# Extract all Deployments from the cluster and lint them
kubectl get deployments -A -o yaml | kube-linter lint -

# Find all Deployments running as root in the cluster
kubectl get deployments -A -o json \
  | jq '.items[] | select(.spec.template.spec.containers[].securityContext.runAsNonRoot != true) | .metadata.name'

# Generate a full compliance report of the cluster's current state
kubectl get all -A -o yaml | kube-linter lint - --format json \
  | jq '.Issues[] | {check: .Check, object: .Object.Name, namespace: .Object.Namespace}' \
  | sort | uniq -c | sort -rn
```

---

## 9. Real Present-Day Scenarios

### Scenario 1: The `latest` Tag Time Bomb — Production Incident

A fintech startup was running a Node.js payment service with `image: payment-service:latest`. Their Dockerfile pushed to `latest` on every commit to main. On a Tuesday afternoon, a developer pushed a breaking change that accidentally altered the encryption logic. The change was pushed to `latest`. Kubernetes' image pull policy of `Always` caused pods to restart with the new broken image within minutes. Payments started failing.

**The KubeLinter angle:** `kube-linter lint .` with the `no-latest-image` check enabled would have caught `image: payment-service:latest` in the Deployment YAML before it ever reached the cluster. The fix — pin to `payment-service:${GIT_SHA}` — is trivial. The incident cost the company 4 hours of downtime and significant customer impact.

### Scenario 2: Root Container Compromise via Misconfigured Workload

A media company's content transcoding service was running as root (no `runAsNonRoot` or `securityContext` set) with a writable root filesystem and no capability restrictions. A vulnerability in an FFmpeg library was exploited by an attacker who sent a malicious video file. Because the container ran as root with a writable filesystem, the attacker:

1. Wrote a reverse shell binary to `/tmp/`
2. Escaped to the host via a kernel vulnerability (possible because `CAP_SYS_ADMIN` was available)
3. Pivoted to other pods on the same node via the host network

**The KubeLinter angle:** Five separate KubeLinter checks would have caught this:
- `run-as-non-root` — required `runAsNonRoot: true`
- `no-read-only-root-fs` — required `readOnlyRootFilesystem: true`
- `no-privilege-escalation` — required `allowPrivilegeEscalation: false`
- `drop-net-raw-capability` — required dropping `CAP_NET_RAW` and ideally all capabilities
- `host-network` — verified that `hostNetwork: false`

If even three of these had been enforced, the attack chain would have been broken.

### Scenario 3: Resource Limits Missing — The Noisy Neighbour Cascade

A SaaS platform had no resource limits on any of their microservices (KubeLinter's `unset-memory-requirements` and `unset-cpu-requirements` checks would have caught this). A memory leak in their recommendation engine caused it to consume all available memory on the node — 64GB. Kubernetes began OOM-killing other pods on the same node, including their authentication service and payment processor. A cascading failure took down the entire platform for 90 minutes.

**The remediation:** After the incident, the engineering team ran `kube-linter lint . --format json` against all their manifests, generating 847 distinct resource-related findings. They used the output to prioritise and systematically add requests and limits to every service over a two-week sprint. The second noisy-neighbour incident never came.

### Scenario 4: Compliance Audit — SOC 2 Type II Evidence

A healthcare data company undergoing SOC 2 Type II certification needed to demonstrate that their Kubernetes workloads enforce the principle of least privilege. Their auditor asked for evidence that containers are not running as root and do not have unnecessary Linux capabilities.

Rather than manually reviewing hundreds of manifests, the security team ran:

```bash
kube-linter lint ./k8s/ --format json \
  | jq '.Issues[] | select(.Check | IN("run-as-non-root", "drop-net-raw-capability", "no-privilege-escalation")) | {file: .Object.FilePath, object: .Object.Name, check: .Check}' \
  > compliance-findings.json
```

This produced a precise list of non-compliant workloads. They fixed all findings (or added `ignore-check` annotations with documented justifications for the two DaemonSets that legitimately needed elevated privileges). The auditor accepted the KubeLinter CI gate as evidence of ongoing controls.

### Scenario 5: Supply Chain Attack via Malicious Helm Chart

An attacker published a malicious Helm chart to a public chart repository. The chart included a DaemonSet with `hostPID: true`, `hostNetwork: true`, and `volumes` mounting `/` from the host — effectively granting the attacker root access to every node in any cluster that installed it. The chart was disguised as a popular monitoring agent.

**KubeLinter as defence:** When a platform engineer ran `helm template malicious-agent ./charts/ | kube-linter lint -`, the lint output immediately showed:

```
DaemonSet "monitoring-agent": host PID sharing is not allowed (check: host-pid)
DaemonSet "monitoring-agent": host network sharing is not allowed (check: host-network)
DaemonSet "monitoring-agent": volume "host-root" mounts a sensitive host path "/" (check: writable-host-mount)
```

The red flags were unmistakeable. The chart was rejected. KubeLinter had effectively detected a supply chain attack embedded in Kubernetes YAML.

---

## 10. What Happens If You Don't Follow This

**Without any manifest linting:**
- Misconfigured workloads reach production invisibly. You only discover the problem when something breaks or is exploited. At that point, the cost of remediation is orders of magnitude higher than during development.
- Security audits fail. SOC 2, ISO 27001, PCI-DSS, and healthcare compliance frameworks all require evidence of least-privilege enforcement. "We do manual reviews sometimes" is not accepted as evidence.
- Container escapes become more likely. Root containers with writable filesystems and unrestricted capabilities are significantly easier to exploit in post-exploitation scenarios.

**Without CI/CD integration:**
- KubeLinter becomes a developer toy rather than an enforcement mechanism. Without a mandatory gate, developers will skip running it locally under time pressure. "I'll fix it later" becomes "this runs in production forever."
- Policy drift occurs silently. Even if you start with a clean baseline, new services added by teams who weren't trained on your standards will introduce misconfigurations that accumulate over time.

**Without custom configuration:**
- Default KubeLinter rules may not match your environment. A blanket `minimum-three-replicas` check will fail your single-replica dev environment components. Without proper configuration, teams start ignoring KubeLinter output entirely ("it always fails, it's not useful"). Configuration makes KubeLinter signal-to-noise ratio high enough to take seriously.

**Specific consequences of each check being absent:**

| Check Not Enforced | Real-World Consequence |
|---|---|
| `run-as-non-root` | Container compromise → immediate root access → easier privilege escalation |
| `no-read-only-root-fs` | Attacker can write malicious binaries, backdoors, or data exfiltration tools |
| `no-latest-image` | Silent breaking changes deployed via CI; inability to reproduce past deployments |
| `liveness-probe` | Deadlocked pods stay in service indefinitely; users see errors but pods appear "Running" |
| `readiness-probe` | Traffic sent to pods not yet ready; 5xx errors during deployments |
| `unset-memory-requirements` | OOM kills cascade across the node; noisy neighbour failures |
| `host-network` | Container traffic bypasses NetworkPolicies; host DNS resolution; potential ARP spoofing |
| `host-pid` | Container can see and send signals to all processes on the host |
| `docker-sock` | Docker socket mount = root on the host, period. This is the most dangerous misconfiguration in Kubernetes. |

---

## 11. Most Common Commands and Syntax

### Installation

```bash
# Linux (latest release)
curl -Lo kube-linter.tar.gz \
  https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux-amd64.tar.gz
tar -xzf kube-linter.tar.gz && sudo mv kube-linter /usr/local/bin/

# macOS
brew install kube-linter

# Via Docker (no installation)
docker run --rm -v $(pwd):/workdir stackrox/kube-linter:latest lint /workdir/
```

### Linting

```bash
# Lint current directory (all YAML files recursively)
kube-linter lint .

# Lint specific file
kube-linter lint deployment.yaml

# Lint with custom config
kube-linter lint . --config .kube-linter.yaml

# Lint Helm chart output
helm template myapp ./charts/myapp | kube-linter lint -

# Lint Kustomize output
kustomize build overlays/prod | kube-linter lint -

# Lint all manifests from a live cluster namespace
kubectl get all -n production -o yaml | kube-linter lint -

# Lint all cluster manifests
kubectl get all -A -o yaml | kube-linter lint -
```

### Output Formats

```bash
# Default (human-readable)
kube-linter lint .

# JSON output (for scripting/downstream processing)
kube-linter lint . --format json

# SARIF (for GitHub/GitLab Security tabs)
kube-linter lint . --format sarif > results.sarif

# Count issues by check
kube-linter lint . --format json \
  | jq '[.Issues[].Check] | group_by(.) | map({check: .[0], count: length}) | sort_by(.count) | reverse'
```

### Check Management

```bash
# List all available checks
kube-linter checks list

# List checks in JSON format
kube-linter checks list --format json

# Show checks matching a keyword
kube-linter checks list | grep -i "security"

# Show which checks are enabled with current config
kube-linter checks list --config .kube-linter.yaml
```

### Scripting and Automation

```bash
# Count total lint errors (for reporting)
ERRORS=$(kube-linter lint . --format json | jq '.Issues | length')
echo "Total lint issues: $ERRORS"

# Extract just the check names that failed
kube-linter lint . --format json | jq -r '.Issues[].Check' | sort | uniq -c | sort -rn

# Find all objects failing a specific check
kube-linter lint . --format json \
  | jq '.Issues[] | select(.Check == "run-as-non-root") | {object: .Object.Name, namespace: .Object.Namespace, file: .Object.FilePath}'

# Exit with non-zero only if critical checks fail (custom threshold)
kube-linter lint . --format json \
  | jq -e '.Issues[] | select(.Check | IN("run-as-non-root", "privileged-container", "docker-sock"))' \
  && { echo "Critical security checks failed"; exit 1; }
```

### Per-Resource Suppression

```yaml
# In manifest YAML — suppress specific checks with annotation
metadata:
  annotations:
    ignore-check.kube-linter.io/run-as-non-root: "Justified reason here"
    ignore-check.kube-linter.io/host-network: "System DaemonSet requires host network"
    ignore-check.kube-linter.io/minimum-three-replicas: "Managed by HPA"
```

---

## 12. Other Tools and Services Available

### Static Manifest Analysis (Similar to KubeLinter)

| Tool | Type | Strengths | Best For |
|------|------|-----------|----------|
| **KubeLinter** | Open-source | Kubernetes-specific, fast, configurable, CI-friendly | Security + best practice linting |
| **kube-score** | Open-source | Weighted scoring model; outputs severity-graded report | Gradual adoption via score thresholds |
| **Polaris** (Fairwinds) | Open-source + commercial | Web dashboard, Admission webhook, wide check library | Teams wanting UI + policy enforcement |
| **Conftest** | Open-source | OPA/Rego-based; write arbitrary policies as code | Custom policy-as-code |
| **Checkov** (Bridgecrew) | Open-source + commercial | Multi-IaC (Kubernetes, Terraform, CloudFormation); SARIF output | Multi-cloud IaC security |
| **Terrascan** (Tenable) | Open-source | Kubernetes + Terraform + Helm; SARIF output; OPA-based | IaC + K8s combined |
| **Snyk IaC** | Commercial | IDE integration, drift detection, fix PRs | Developer-centric IaC security |
| **Datree** | Commercial | Cloud-based policy as a service; central policy management | Centralised multi-team enforcement |
| **Kubesec** | Open-source | Security risk score (numeric), minimal dependencies | Quick security scoring |

### Schema Validation (Complementary to Linting)

| Tool | Purpose |
|------|---------|
| **kubeval** | Validates YAML against Kubernetes JSON schemas; catches API version mistakes |
| **kubeconform** | Faster kubeval alternative; supports CRD schemas |
| **kubectl --dry-run=server** | Live API validation against a cluster's installed CRDs |

### Admission Control (Runtime Enforcement — after manifest linting)

| Tool | Purpose |
|------|---------|
| **OPA Gatekeeper** | Rego-based admission policies; enforces at cluster level |
| **Kyverno** | Kubernetes-native admission policies; simpler DSL |
| **Pod Security Admission (PSA)** | Built into Kubernetes; enforces `restricted`, `baseline`, `privileged` profiles |
| **Connaisseur** | Image signature verification at admission |

### Combined Security Platforms

| Platform | Key Features |
|------|---------|
| **Prisma Cloud** (Palo Alto) | Manifest scanning + runtime + compliance + cloud security |
| **Wiz** | Agentless; cloud + container + Kubernetes + IaC scanning |
| **Lacework** | Behavioural anomaly detection + compliance + IaC scanning |
| **Snyk Container** | Combined image scanning + IaC + manifest analysis |

---

## 13. How AI Is Impacting Kubernetes Manifest Linting

### AI-Powered Rule Generation

Traditional manifest linting requires security engineers to write rules based on known best practices. AI is enabling a new paradigm where rules are generated from:

- **Incident data** — Analysing historical Kubernetes security incidents and container escapes to automatically derive rules that would have prevented them. Security researchers are training models on CVE descriptions and Kubernetes audit logs to suggest new KubeLinter checks.
- **Cluster observation** — Tools like Fairwinds Insights use ML to observe what your cluster actually does in production and recommend resource requests/limits based on real usage patterns rather than guesses.
- **Policy synthesis** — LLMs can translate natural-language security requirements ("no container should be able to write to the host filesystem") into formal KubeLinter/OPA/Kyverno rules.

### AI-Assisted Remediation

When KubeLinter flags 200 issues across 50 manifests, fixing them manually is tedious. AI tools are automating this:

- **GitHub Copilot Autofix** — When integrated with SARIF output from KubeLinter, Copilot can suggest inline code changes to fix flagged issues in YAML directly in the PR review interface.
- **AI manifest generators** — Tools like `kubectl-ai` and Helm chart AI generators are being trained to produce KubeLinter-compliant YAML by default — security best practices baked in from generation, not bolted on afterward.
- **LLM-powered explanation** — Security teams use AI assistants to explain KubeLinter findings to developers who are unfamiliar with Kubernetes security concepts. "Why does `readOnlyRootFilesystem: true` matter?" is a question that AI can explain at the right level of detail for each audience.

### AI and Contextual Risk Scoring

Not all KubeLinter findings are equally risky. `minimum-three-replicas` failing on a low-traffic internal tooling Deployment is very different from it failing on a payments service. AI is being used to:

- **Contextualise findings** — Score findings based on the workload's labels (`business-criticality`, `env=production`), the service's network exposure, and the sensitivity of the data it handles.
- **Predict exploit likelihood** — EPSS-like models are being trained specifically for Kubernetes misconfigurations. A `privileged: true` container exposed via a LoadBalancer Service has dramatically higher exploit likelihood than the same misconfiguration on a pod with no external network access.
- **Prioritise remediation** — AI-ranked KubeLinter findings tell security teams "fix these 10 first" rather than presenting an undifferentiated list of 200 issues.

### The Future: Autonomous Manifest Security

The direction of travel is toward AI agents that:
1. Observe a PR modifying Kubernetes manifests
2. Run KubeLinter (and other checks) automatically
3. Analyse the findings with context from the PR description and workload labels
4. Generate a remediation PR that fixes the flagged issues
5. Explain the changes in plain language to the developer
6. Learn from which remediations were accepted vs rejected to improve future suggestions

This closes the human loop almost entirely — security becomes ambient in the development process rather than a gate or a review step.

---

## 14. CKS Exam Tips

KubeLinter is specifically tested in the CKS exam — you need to know how to install it, run it, and interpret its output on a live Kubernetes manifest.

**High-probability exam tasks:**

1. **Install KubeLinter from the official source:**
   ```bash
   curl -Lo kube-linter.tar.gz \
     https://github.com/stackrox/kube-linter/releases/download/0.2.3/kube-linter-linux-amd64.tar.gz
   tar -xzf kube-linter.tar.gz
   sudo mv kube-linter /usr/local/bin/
   ```

2. **Lint a given manifest and identify what is wrong:**
   ```bash
   kube-linter lint deployment.yaml
   # Read the output — it tells you exactly what check failed and what to fix
   ```

3. **Lint all files in a directory:**
   ```bash
   kube-linter lint .
   kube-linter lint ./k8s/
   ```

4. **Fix the manifest based on KubeLinter output** — you need to know what YAML to add:
   - `no-latest-image` → change `image: nginx:latest` to `image: nginx:1.25`
   - `run-as-non-root` → add `securityContext.runAsNonRoot: true` and `runAsUser: 10001`
   - `no-read-only-root-fs` → add `securityContext.readOnlyRootFilesystem: true`
   - `liveness-probe` → add a `livenessProbe` block
   - `readiness-probe` → add a `readinessProbe` block
   - `unset-cpu-requirements` → add `resources.requests.cpu` and `resources.limits.cpu`

5. **Know what the KubeLinter workflow produces** — configurable checks → analysis and linting → report and suggestions (the three-stage diagram).

**Key facts to remember:**
- KubeLinter was created by **StackRox** (now Red Hat)
- It performs **static analysis** — it does NOT connect to a running cluster
- Exit code is **1** if any issues are found, **0** if clean
- The `--format json` flag produces machine-readable output
- Configuration file is `.kube-linter.yaml`
- Per-resource suppression uses the annotation prefix `ignore-check.kube-linter.io/`

**Common exam traps:**
- If the exam says "lint the manifests in `/etc/kubernetes/manifests`" — that directory contains control plane pod manifests (apiserver, etcd, etc.) which will have many KubeLinter warnings by design. Focus on the application manifest you're asked to fix.
- KubeLinter checks are **case-sensitive** in the config file — `run-as-non-root` not `runAsNonRoot`
- You cannot suppress all checks globally in the manifest — suppression is per-check via `ignore-check.kube-linter.io/<check-name>` annotations

---

## 15. Extra Information and References

### KubeLinter Check Template System

KubeLinter's custom check system is built on **templates** — pre-built rule patterns that you parameterise. Understanding the available templates lets you write powerful custom checks:

```yaml
# Available templates:
# required-annotation   — Require specific annotation on all objects
# required-label        — Require specific label on all objects
# env-var               — Check for specific environment variable
# port-exposed          — Check for specific port exposure
# disallow-decl         — Disallow a specific YAML field value
# verify-selector       — Validate label selector consistency
# read-secret           — Detect secrets mounted as env vars vs volumes

# Example: Custom check requiring a 'cost-center' label
customChecks:
  - name: require-cost-center-label
    description: "All Deployments must have a cost-center label for billing"
    template: required-label
    scope:
      objectKinds:
        - DeploymentLike
    params:
      key: cost-center
      message: "Deployment missing required cost-center label"
```

### Integrating KubeLinter with Pre-Commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/stackrox/kube-linter
    rev: v0.6.8
    hooks:
      - id: kube-linter
        args: [--config, .kube-linter.yaml]
```

This ensures developers get KubeLinter feedback before they even push — the fastest possible feedback loop.

### KubeLinter vs Kubernetes Admission Control — The Right Layer for Each

A common misconception is that KubeLinter and admission controllers (OPA Gatekeeper, Kyverno, Pod Security Admission) do the same thing. They are complementary:

```
Layer 1: Developer Workstation
  → Pre-commit hooks: kube-linter lint (fastest feedback, free)
  
Layer 2: CI/CD Pipeline (Pull Request)
  → kube-linter lint as a required status check (blocks merge)
  → Optional: conftest, checkov, terrascan for additional checks
  
Layer 3: Kubernetes Admission (kubectl apply)
  → OPA Gatekeeper / Kyverno: enforces policies in-cluster
  → Pod Security Admission: enforces baseline/restricted profiles
  → ImagePolicyWebhook: verifies image signatures
  
Layer 4: Runtime (Container running)
  → Falco: detects anomalous behaviour
  → Seccomp/AppArmor: kernel-level enforcement
  → NetworkPolicy: runtime network enforcement
```

KubeLinter is cheapest (no cluster needed, runs in seconds) and provides the fastest feedback. Admission control is the safety net — it catches what slips past KubeLinter (e.g., manifests applied by a rogue operator bypassing CI/CD). Both layers are necessary.

### Full Hardened Manifest Template

```yaml
# Full production-ready, KubeLinter-compliant Deployment template
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
  labels:
    app: my-app
    team: platform         # Required by custom check
    env: production        # Required by custom check
    cost-center: eng-001   # Required by custom check
  annotations:
    app.kubernetes.io/version: "1.2.3"
spec:
  replicas: 3              # minimum-three-replicas satisfied
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      securityContext:
        runAsNonRoot: true          # run-as-non-root satisfied (pod level)
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault      # seccomp profile applied
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app
                    operator: In
                    values: [my-app]
              topologyKey: kubernetes.io/hostname  # no-anti-affinity satisfied
      containers:
      - name: app-container
        image: my-app-image:1.2.3   # no-latest-image satisfied
        ports:
        - containerPort: 8080
        resources:
          requests:
            cpu: "100m"             # unset-cpu-requirements satisfied
            memory: "128Mi"         # unset-memory-requirements satisfied
          limits:
            cpu: "500m"
            memory: "256Mi"
        securityContext:
          allowPrivilegeEscalation: false   # no-privilege-escalation satisfied
          readOnlyRootFilesystem: true       # no-read-only-root-fs satisfied
          runAsNonRoot: true                 # run-as-non-root satisfied (container level)
          capabilities:
            drop:
              - ALL                          # drop-net-raw-capability satisfied
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
          failureThreshold: 3               # liveness-probe satisfied
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          failureThreshold: 3               # readiness-probe satisfied
        volumeMounts:
        - name: tmp
          mountPath: /tmp                   # writable temp dir (readOnlyRootFilesystem needs this)
      volumes:
      - name: tmp
        emptyDir: {}
```

### References

- [KubeLinter GitHub Repository](https://github.com/stackrox/kube-linter)
- [KubeLinter Documentation](https://docs.kubelinter.io)
- [KubeLinter Built-In Checks Reference](https://docs.kubelinter.io/#/generated/checks)
- [StackRox KubeLinter Blog Post](https://www.stackrox.io/blog/introducing-kubelinter-an-open-source-linter-for-kubernetes-yamls/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [KodeKloud CKS Course — Introduction to KubeLinter](https://learn.kodekloud.com/user/courses/certified-kubernetes-security-specialist-cks/module/e4511664-185f-4204-9aa2-b4250cbadf84/lesson/c6882453-00b7-4859-afcc-2cadf7b124ee)
