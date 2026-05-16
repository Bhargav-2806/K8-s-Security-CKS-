# Chapter 10: Scan Images for Known Vulnerabilities — Trivy

---

## Table of Contents

1. [Why Vulnerability Scanning Matters](#1-why-vulnerability-scanning-matters)
2. [Understanding CVEs — Common Vulnerabilities and Exposures](#2-understanding-cves--common-vulnerabilities-and-exposures)
   - [What Is a CVE?](#what-is-a-cve)
   - [CVE Severity Scoring — CVSS](#cve-severity-scoring--cvss)
   - [Real CVE Example — CVE-2020-5911 (NGINX Controller)](#real-cve-example--cve-2020-5911-nginx-controller)
   - [How Vulnerability Scanners Work](#how-vulnerability-scanners-work)
3. [What Is Trivy?](#3-what-is-trivy)
   - [What Trivy Can Scan](#what-trivy-can-scan)
   - [How Trivy Works Internally](#how-trivy-works-internally)
4. [Installing Trivy](#4-installing-trivy)
5. [Scanning Container Images](#5-scanning-container-images)
   - [Basic Image Scan](#basic-image-scan)
   - [Understanding Trivy Output](#understanding-trivy-output)
   - [Filtering by Severity](#filtering-by-severity)
   - [Scanning for Fixable Vulnerabilities Only](#scanning-for-fixable-vulnerabilities-only)
   - [Scanning Tar Archives](#scanning-tar-archives)
   - [Scanning by Digest](#scanning-by-digest)
6. [Scanning Beyond Images — Filesystems, Repos, K8s Clusters](#6-scanning-beyond-images--filesystems-repos-k8s-clusters)
7. [Output Formats — JSON, SARIF, CycloneDX, Table](#7-output-formats--json-sarif-cyclonedx-table)
8. [Best Practices for Image Scanning](#8-best-practices-for-image-scanning)
9. [Integrating Trivy into CI/CD Pipelines](#9-integrating-trivy-into-cicd-pipelines)
10. [As a DevSecOps / Kubernetes Security Engineer](#10-as-a-devsecops--kubernetes-security-engineer)
11. [Real Present-Day Scenarios](#11-real-present-day-scenarios)
12. [What Happens If You Don't Follow This](#12-what-happens-if-you-dont-follow-this)
13. [Most Common Commands and Syntax](#13-most-common-commands-and-syntax)
14. [Other Tools and Services Available](#14-other-tools-and-services-available)
15. [How AI Is Impacting Vulnerability Scanning](#15-how-ai-is-impacting-vulnerability-scanning)
16. [CKS Exam Tips](#16-cks-exam-tips)
17. [Extra Information and References](#17-extra-information-and-references)

---

## 1. Why Vulnerability Scanning Matters

Every container image is a snapshot of software — the OS base, system libraries, language runtimes, and application dependencies — at a moment in time. The problem is that software vulnerabilities are discovered continuously. A container image that was vulnerability-free when built in January may have ten critical CVEs by March, not because the image changed, but because security researchers found flaws in packages that were already in the image.

Without scanning, you have no visibility into this risk. You are running software in production with unknown exposure to publicly disclosed vulnerabilities — vulnerabilities that attackers can look up in the same NVD database that your scanner uses.

Vulnerability scanning matters because:

- **Attackers scan first.** Before exploiting a system, attackers identify its components and look up known CVEs. If you don't know what CVEs are in your images, the attacker knows more about your attack surface than you do.
- **Most exploits target known vulnerabilities.** The Verizon Data Breach Investigations Report consistently shows that the majority of exploits use vulnerabilities that had patches available for months or years before exploitation. Scanning + patching breaks this chain.
- **Minimal images reduce attack surface.** The fewer packages an image contains, the fewer potential vulnerabilities. Scanning motivates the discipline of keeping images lean — every unnecessary package is a potential CVE.
- **Compliance requires it.** PCI-DSS Requirement 6.3.3, FedRAMP, HIPAA, and ISO 27001 all require vulnerability management programmes. Trivy scanning with documented results is direct evidence of compliance.
- **Supply chain attacks target dependencies.** Log4Shell (CVE-2021-44228) was a vulnerability in a logging library used transitively by thousands of applications. Without scanning, organisations didn't know they used Log4j at all. Scanning finds these hidden exposures.

---

## 2. Understanding CVEs — Common Vulnerabilities and Exposures

### What Is a CVE?

CVE stands for **Common Vulnerabilities and Exposures**. It is a standardised system for identifying and cataloguing publicly known software security vulnerabilities. The CVE programme is maintained by MITRE Corporation and sponsored by the US Cybersecurity and Infrastructure Security Agency (CISA).

![The image shows a webpage listing Common Vulnerabilities and Exposures (CVE) search results, detailing specific security issues with descriptions and identifiers.](https://kodekloud.com/kk-media/image/upload/v1752871717/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Scan-images-for-known-vulnerabilities-Trivy/frame_50.jpg)

The CVE system serves several important functions:

- **Simplifies bug reporting** — A single authoritative identifier (`CVE-YYYY-NNNNN`) prevents duplicate entries and confusion when multiple researchers find the same vulnerability
- **Assigns unique identifiers** — Every distinct vulnerability gets its own CVE ID, enabling precise cross-referencing across scanners, advisories, and patches
- **Provides standardised information** — Description, affected versions, references, severity score — all in one place for developers and administrators to prioritise remediation

CVEs are published in the **National Vulnerability Database (NVD)** at nvd.nist.gov, and are mirrored by Aqua Security's `trivy-db`, the GitHub Advisory Database, OSV (open source vulnerabilities at osv.dev), and many commercial databases.

**Two primary categories of vulnerabilities:**

1. **Vulnerabilities that allow bypassing security controls** — Gaining unauthorised access to data, escalating privileges, executing arbitrary code, or reading information intended only for authorised users. Examples: SQL injection, buffer overflows, path traversal, authentication bypass.

2. **Vulnerabilities that degrade system performance or stability** — Causing service interruptions, exhausting resources, crashing processes, or making the system unstable. Examples: denial-of-service vulnerabilities, memory leaks exploitable as DoS, null pointer dereferences.

### CVE Severity Scoring — CVSS

Each CVE is rated using the **CVSS** (Common Vulnerability Scoring System). CVSS provides a numerical score from 0.0 to 10.0, which maps to a qualitative severity label:

![The image shows a color-coded CVE severity score scale from 0 to 10, with CVSS v2.0 and v3.0 rating comparisons.](https://kodekloud.com/kk-media/image/upload/v1752871718/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Scan-images-for-known-vulnerabilities-Trivy/frame_130.jpg)

**CVSS v3.x Severity Mapping:**

| Score | Severity | Recommended SLA |
|-------|----------|-----------------|
| 0.0 | None | No action required |
| 0.1 – 3.9 | Low | Patch within 90 days |
| 4.0 – 6.9 | Medium | Patch within 30 days |
| 7.0 – 8.9 | High | Patch within 7 days |
| 9.0 – 10.0 | Critical | Patch immediately (24–72 hours) |

**CVSS v3 vector components** (used to calculate the score):

```
Attack Vector (AV):      N=Network, A=Adjacent, L=Local, P=Physical
Attack Complexity (AC):  L=Low, H=High
Privileges Required (PR): N=None, L=Low, H=High
User Interaction (UI):   N=None, R=Required
Scope (S):               U=Unchanged, C=Changed
Confidentiality (C):     H=High, L=Low, N=None
Integrity (I):           H=High, L=Low, N=None
Availability (A):        H=High, L=Low, N=None

Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
  → Network-exploitable, low complexity, no auth, no user interaction, full CIA impact
  → This is a remote code execution vulnerability anyone can trigger from the internet

Example: CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = 1.8 Low
  → Requires local access, high complexity, high privileges, user interaction, low confidentiality impact
  → Difficult to exploit; limited impact
```

**CVSS v2 vs v3 differences:** CVSS v2 ratings are systematically lower than CVSS v3 for the same vulnerability. This is why you'll see some CVEs listed with both a v2 score (e.g., 5.0 Medium) and a v3 score (e.g., 7.5 High) for the same issue. Always use the v3 score as the authoritative severity. Trivy displays whichever is available, defaulting to v3.

### Real CVE Example — CVE-2020-5911 (NGINX Controller)

![The image shows details of CVE-2020-5911, highlighting a high severity score of 7.3 for a vulnerability in NGINX Controller on Debian/Ubuntu systems.](https://kodekloud.com/kk-media/image/upload/v1752871720/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Scan-images-for-known-vulnerabilities-Trivy/frame_190.jpg)

**CVE-2020-5911** is a real high-severity vulnerability (CVSS score: 7.3) in the NGINX Controller installer. The vulnerability: the installer downloaded Kubernetes packages using an **insecure HTTP URL** instead of HTTPS on Debian and Ubuntu systems. This creates a man-in-the-middle attack vector — an attacker positioned on the network between the installer and the download server could substitute malicious packages, leading to arbitrary code execution during installation.

This example illustrates several key points:
- **Installation-time vulnerabilities** are just as serious as runtime ones
- **Insecure transport** (HTTP instead of HTTPS) is a distinct vulnerability class
- A score of 7.3 (High) means this requires patching within your SLA (typically 7 days)
- This would be caught by Trivy scanning the NGINX controller image

### How Vulnerability Scanners Work

![The image shows a "CVE Scanner" with a smartphone icon and a list of CVE identifiers and descriptions related to software vulnerabilities.](https://kodekloud.com/kk-media/image/upload/v1752871722/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Scan-images-for-known-vulnerabilities-Trivy/frame_240.jpg)

A vulnerability scanner like Trivy operates by:

1. **Extracting components** — The scanner opens the container image layers and identifies all installed packages using package manager databases (dpkg for Debian/Ubuntu, rpm for RHEL/CentOS, apk for Alpine) and language package manifests (package.json, requirements.txt, pom.xml, go.sum, Gemfile.lock).

2. **Building a component inventory** — For each identified package: name, version, type (OS package or language library), and location within the image.

3. **Cross-referencing against vulnerability databases** — Each component's name and version is looked up in CVE databases (NVD, GitHub Advisory Database, OSV, RedHat Security Database, Debian Security Tracker, Alpine SecDB, etc.). Trivy uses its own pre-downloaded `trivy-db` database for offline/fast scanning.

4. **Reporting matches** — Any component version that appears in the vulnerability database as vulnerable is reported with the CVE ID, severity, and fix version if available.

```
Container Image (nginx:1.18.0)
    ↓ extract layers
Package List:
  nginx 1.18.0 (from dpkg)
  openssl 1.1.1d (from dpkg)
  curl 7.64.0 (from dpkg)
  bash 5.0-4 (from dpkg)
  ...
    ↓ cross-reference with trivy-db
Vulnerability Database:
  nginx 1.18.0 → CVE-2021-23017 (Critical) fixed in 1.20.1
  openssl 1.1.1d → CVE-2020-1971 (High) fixed in 1.1.1i
  curl 7.64.0 → CVE-2020-8169 (High) fixed in 7.74.0
    ↓ output
Report:
  CRITICAL: 3 | HIGH: 33 | MEDIUM: 9 | LOW: 110
  [detailed table per vulnerability]
```

Once vulnerabilities are identified, your remediation options are:
- **Upgrade to a fixed version** — Update the base image or the specific package to a version where the CVE is patched
- **Apply additional security measures** — Runtime mitigation (seccomp, AppArmor, network isolation) while waiting for an upstream fix
- **Remove unnecessary packages** — If you don't need `curl` or `bash` in your production image, remove them entirely — no package, no vulnerability

The foundational principle: **the fewer packages in your container image, the smaller your attack surface.**

---

## 3. What Is Trivy?

Trivy is a **comprehensive, open-source vulnerability and misconfiguration scanner** developed by Aqua Security. It was released in 2019 and has rapidly become the most widely used container security scanner, with over 20,000 GitHub stars and integrations in virtually every major CI/CD platform.

Trivy is single-binary, fast, accurate, and requires no setup beyond installation — it downloads its own vulnerability database (`trivy-db`) on first run and keeps it updated. This makes it dramatically simpler to deploy than older scanners that required separate database services.

### What Trivy Can Scan

Trivy is not just an image scanner — it is a multi-target, multi-scanner security tool:

| Target | What It Scans |
|--------|---------------|
| **Container images** | OS packages, language libraries, embedded files |
| **Filesystems** | Local directories, looking for package manifests |
| **Git repositories** | Source code repos (local or remote) |
| **Kubernetes clusters** | All resources in the cluster: pods, deployments, config |
| **SBOMs** | CycloneDX or SPDX files |
| **Helm charts** | Rendered manifests for misconfigurations |
| **Terraform / CloudFormation** | IaC files for misconfiguration |
| **Virtual machine images** | `.vmdk`, `.vhd` files |

Trivy's scanners:

| Scanner | What It Finds |
|---------|---------------|
| **vuln** | CVEs in OS packages and language libraries |
| **secret** | Hardcoded secrets (API keys, passwords, tokens) in image layers |
| **misconfig** | Kubernetes, Docker, Terraform misconfigurations |
| **license** | Software license violations (GPL in proprietary apps, etc.) |
| **rbac** | Kubernetes RBAC misconfigurations (overly permissive roles) |

### How Trivy Works Internally

```
trivy image nginx:1.18.0
  1. Pull image (if not cached)
  2. Extract all layer tarballs
  3. Run catalogers (dpkg, rpm, apk, npm, pip, go, java, ruby, rust, php...)
  4. Build component list with name, version, type, PURL
  5. Download/update trivy-db (vulnerability database, ~200MB, updated daily)
  6. Cross-reference each component against trivy-db
  7. Filter results by severity/fixability/ignore rules
  8. Output in requested format (table, JSON, SARIF, CycloneDX, SPDX)
```

Trivy's vulnerability database aggregates from:
- NVD (National Vulnerability Database)
- GitHub Security Advisories
- Red Hat Security Data API
- Debian Security Bug Tracker
- Ubuntu Security Notices
- Alpine SecDB
- OSV (Open Source Vulnerabilities)
- PHP Security Advisories
- Ruby Advisory DB
- npm/PyPI advisories

---

## 4. Installing Trivy

```bash
# Method 1: Debian/Ubuntu — via APT repository (from KodeKloud)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Method 2: RPM-based (RHEL, CentOS, Amazon Linux)
cat << 'EOF' | sudo tee /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=0
enabled=1
EOF
sudo yum -y update
sudo yum -y install trivy

# Method 3: macOS with Homebrew
brew install trivy

# Method 4: Direct binary download (any Linux)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Method 5: Docker (no installation needed)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image nginx:1.18.0

# Method 6: Via GitHub releases (specific version)
VERSION="0.48.3"
curl -Lo trivy.tar.gz \
  "https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz"
tar -xzf trivy.tar.gz
sudo mv trivy /usr/local/bin/

# Verify installation
trivy --version

# Update the vulnerability database manually (otherwise auto-updated on first scan)
trivy image --download-db-only
```

---

## 5. Scanning Container Images

### Basic Image Scan

```bash
# Scan an image by name and tag — pulls from registry if not cached locally
trivy image nginx:1.18.0

# Scan a specific version
trivy image nginx:1.25.3

# Scan the latest tag (not recommended for production)
trivy image nginx:latest

# Scan a private registry image (must be logged in first)
docker login private-registry.io
trivy image private-registry.io/apps/myapp:1.0.0

# Scan an image from Amazon ECR
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com
trivy image 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:1.0.0
```

### Understanding Trivy Output

When you run `trivy image nginx:1.18.0`, the output includes a summary and a detailed table:

```
2021-03-21T02:54:18.240Z  INFO  Detecting Debian vulnerabilities...
2021-03-21T02:54:18.295Z  INFO  Trivy skips scanning programming language libraries
                                 because no supported file was detected

nginx:1.18.0 (debian 10.8)
Total: 155 (UNKNOWN: 0, LOW: 110, MEDIUM: 9, HIGH: 33, CRITICAL: 3)

+------------------+---------------------+----------+-----------------+------------------------------------------+
|      LIBRARY     |   VULNERABILITY ID  | SEVERITY | INSTALLED VER   |                   TITLE                  |
+------------------+---------------------+----------+-----------------+------------------------------------------+
| apt              | CVE-2011-3374       | LOW      | 1.8.2.2         | apt-key does not validate signatures...   |
| bash             | CVE-2019-18276      | LOW      | 5.0-4           | bash: privilege escalation...             |
|                  | TEMP-0841856-B188AF |          |                 | security-tracker.debian.org/tracker/...   |
| coreutils        | CVE-2016-2781       | LOW      | 8.30-3          | chroot: improper parent session escape... |
|                  | CVE-2017-18018      | LOW      |                 | chown/chgrp race condition...             |
| curl             | CVE-2020-8169       | HIGH     | 7.64.0-4+deb10u1| libcurl: partial password disclosure...   |
+------------------+---------------------+----------+-----------------+------------------------------------------+
```

**Reading the output columns:**

| Column | Meaning |
|--------|---------|
| `LIBRARY` | Package or library name (as registered in the OS package manager or language ecosystem) |
| `VULNERABILITY ID` | CVE identifier (CVE-YYYY-NNNNN) or temporary advisory ID (TEMP-...) |
| `SEVERITY` | CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN |
| `INSTALLED VERSION` | The version currently in the image (vulnerable version) |
| `FIXED VERSION` | (when present) The version that contains the fix — upgrade target |
| `TITLE` | Brief description of the vulnerability |

**The summary line explained:**
```
Total: 155 (UNKNOWN: 0, LOW: 110, MEDIUM: 9, HIGH: 33, CRITICAL: 3)
  → 155 total vulnerabilities found across all packages
  → 3 Critical: require immediate action
  → 33 High: require patching within your SLA (typically 7 days)
  → 9 Medium: patch within 30 days
  → 110 Low: patch within 90 days (or accept risk)
  → 0 Unknown: severity data unavailable
```

**What to do first:** Focus on Critical, then High. The Low severity findings in `nginx:1.18.0` are largely in system utilities (`bash`, `coreutils`, `apt`) that have known theoretical vulnerabilities but may not be exploitable in your container context. High and Critical findings in runtime libraries (`curl`, `openssl`, `libssl`) are more urgent because they are likely in active code paths.

**Comparing distributions — the Alpine advantage:**

```bash
# nginx:1.18.0 on Debian — 155 vulnerabilities (as shown above)
trivy image nginx:1.18.0
# Total: 155

# nginx:1.18.0-alpine — Alpine Linux is extremely minimal
trivy image nginx:1.18.0-alpine
# Total: 0

# This is why Alpine, distroless, and chainguard images are preferred:
# Fewer packages = fewer vulnerabilities = smaller attack surface
```

### Filtering by Severity

```bash
# Show only CRITICAL vulnerabilities
trivy image --severity CRITICAL nginx:1.18.0

# Show only CRITICAL and HIGH
trivy image --severity CRITICAL,HIGH nginx:1.18.0

# Show only HIGH and MEDIUM
trivy image --severity HIGH,MEDIUM nginx:1.18.0

# Show all severities (explicit — same as default)
trivy image --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL nginx:1.18.0
```

### Scanning for Fixable Vulnerabilities Only

```bash
# Show only vulnerabilities that have a fix available
trivy image --ignore-unfixed nginx:1.18.0

# Combine: only Critical/High that have fixes
trivy image --severity CRITICAL,HIGH --ignore-unfixed nginx:1.18.0
```

`--ignore-unfixed` is extremely useful for prioritisation. Many CVEs — especially in well-maintained OS packages — have no fix available because the vulnerability was discovered but the upstream project hasn't patched it yet. These are important to know about but cannot be remediated immediately, so filtering them out for day-to-day triage reduces noise.

### Scanning Tar Archives

```bash
# Save a Docker image as a tar file
docker save nginx:1.18.0 > nginx.tar

# Scan the tar file (useful for:
#   - scanning images in air-gapped environments
#   - scanning images before they are pushed to a registry
#   - scanning images in CI/CD before docker push)
trivy image --input nginx.tar

# Scan with severity filter
trivy image --input nginx.tar --severity CRITICAL,HIGH

# Scan and output JSON
trivy image --input nginx.tar --format json --output results.json
```

### Scanning by Digest

```bash
# Pin to a specific image digest for reproducible scanning
trivy image nginx@sha256:593dac25b7733ffb7afe1a72649a43e574778bf025ad60514ef40f6b5d606247

# Get the digest of an image you pulled
docker inspect nginx:1.25 --format '{{index .RepoDigests 0}}'
```

---

## 6. Scanning Beyond Images — Filesystems, Repos, K8s Clusters

Trivy is not limited to container images. It can scan the entire supply chain:

```bash
# Scan a local filesystem (source code, looking for vulnerable dependencies)
trivy fs /path/to/source/code
trivy fs .   # Current directory

# Scan a filesystem for secrets too
trivy fs --scanners secret,vuln .

# Scan a Git repository (remote URL)
trivy repo https://github.com/myorg/myapp

# Scan a specific branch/commit
trivy repo --branch main https://github.com/myorg/myapp

# Scan an entire Kubernetes cluster
trivy k8s --report summary cluster
trivy k8s --report all cluster   # Verbose output for every resource
trivy k8s --severity CRITICAL,HIGH --report summary cluster

# Scan all pods in a specific namespace
trivy k8s --include-namespaces production --report summary cluster

# Scan a specific Kubernetes resource
trivy k8s deployment/myapp

# Scan Kubernetes YAML manifests (for misconfigurations before applying)
trivy config ./k8s/

# Scan a Helm chart
trivy config ./charts/myapp/
helm template myapp ./charts/myapp | trivy config -

# Scan a pre-existing SBOM (CycloneDX or SPDX)
trivy sbom nginx-sbom.cyclonedx.json
trivy sbom nginx-sbom.spdx.json

# Scan an OCI image without pulling (using OCI layout format)
trivy image --input /path/to/oci-layout

# Scan AWS ECR images across accounts (via AWS CLI)
trivy aws --account 123456789 --region us-east-1 ecr
```

---

## 7. Output Formats — JSON, SARIF, CycloneDX, Table

```bash
# Default: human-readable table
trivy image nginx:1.18.0

# JSON output (for downstream processing, scripting, dashboards)
trivy image --format json --output results.json nginx:1.18.0

# Parse JSON with jq — get only Critical findings
trivy image --format json nginx:1.18.0 \
  | jq '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL") | {id: .VulnerabilityID, pkg: .PkgName, installed: .InstalledVersion, fixed: .FixedVersion}'

# SARIF (for GitHub Security tab, GitLab, SonarQube)
trivy image --format sarif --output results.sarif nginx:1.18.0

# CycloneDX (SBOM with vulnerability data — combines generation + scanning)
trivy image --format cyclonedx --output results.cdx.json nginx:1.18.0

# SPDX SBOM output
trivy image --format spdx-json --output results.spdx.json nginx:1.18.0

# GitHub Actions summary format
trivy image --format github --output results.github.json nginx:1.18.0

# Template-based custom output
trivy image --format template --template "@contrib/html.tpl" --output results.html nginx:1.18.0

# Count vulnerabilities by severity (for threshold enforcement)
trivy image --format json nginx:1.18.0 \
  | jq '[.Results[].Vulnerabilities[] | .Severity] | group_by(.) | map({severity: .[0], count: length})'
```

---

## 8. Best Practices for Image Scanning

![The image lists best practices for image scanning, including continuous rescanning, using Kubernetes Admission Controllers, maintaining a pre-scanned repository, and integrating scanning into CI/CD pipelines.](https://kodekloud.com/kk-media/image/upload/v1752871723/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Scan-images-for-known-vulnerabilities-Trivy/frame_450.jpg)

The KodeKloud-recommended best practices, expanded with operational detail:

**1. Periodically rescan images to maintain security over time**

A scan that returns zero findings today may return Critical findings tomorrow — new CVEs are published daily. Re-scan your running images on a schedule:

```bash
# Scheduled rescan via CronJob (simplified)
# Get all unique images from running pods
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' \
  | sort -u | while read img; do
    echo "=== Scanning: $img ==="
    trivy image --severity HIGH,CRITICAL --exit-code 0 "$img"
  done
```

**2. Integrate scanning into Kubernetes Admission Controllers to inspect images before pod deployment**

Use Trivy-Operator (the Kubernetes-native Trivy deployment) or combine Trivy with OPA/Kyverno to block pods with Critical vulnerabilities at admission. Be aware of potential delays — scanning adds latency to pod creation.

```bash
# Install Trivy Operator (scans all images in the cluster continuously)
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --set="trivy.ignoreUnfixed=true"

# View scan results for all workloads
kubectl get vulnerabilityreports -A
kubectl get vulnerabilityreports -n production -o wide
```

**3. Maintain an internal registry with pre-scanned, trusted images**

Instead of scanning every pull (which adds latency), scan images when they are pushed to your private registry. Only images that pass scanning are promoted to the `production` registry namespace. Nodes only pull from `production` — they never pull unscanned images.

```
CI/CD builds image → push to staging-registry/myapp:1.0
  → Trivy scans; if CRITICAL > 0, promotion blocked
  → If clean: cosign sign + promote to prod-registry/myapp:1.0
  → Kubernetes only pulls from prod-registry → all images pre-scanned
```

**4. Incorporate vulnerability scanning into your CI/CD pipeline**

Every new build is scanned before deployment. Findings above a threshold block promotion:

```bash
# CI/CD gate — fail build on Critical findings
trivy image --exit-code 1 --severity CRITICAL myapp:${BUILD_TAG}
# Exit code 0: no Critical CVEs → build passes
# Exit code 1: Critical CVEs found → build fails, deployment blocked
```

**Additional best practices beyond KodeKloud:**

**5. Use the most minimal base image possible**

```bash
# Vulnerable — Debian-based nginx with 155 CVEs
FROM nginx:1.18.0    # 155 vulnerabilities

# Better — Alpine-based nginx with 0 CVEs
FROM nginx:1.18.0-alpine

# Best — Distroless (no shell, no package manager, minimal OS)
FROM gcr.io/distroless/static-debian12

# Best for nginx — Chainguard (rebuilt daily, actively patched)
FROM cgr.dev/chainguard/nginx:latest
```

**6. Pin exact image versions with digests**

```bash
# Don't scan a moving target
trivy image nginx:1.25  # Tag can change — different image tomorrow

# Scan the exact image by digest
trivy image nginx:1.25@sha256:593dac25b7733ffb7afe1a72649a43e574778bf025ad60514ef40f6b5d606247
```

**7. Use `.trivyignore` for accepted risks**

```bash
# .trivyignore — suppress specific CVEs that you've accepted (with justification)
# Format: one CVE per line, optional comments
CVE-2011-3374       # bash: ancient low-severity; no exploitable code path in our image
CVE-2016-2781       # coreutils: local-only; containers don't use chroot
CVE-2019-18276      # bash: not present in shell-less distroless images

# Use the ignore file
trivy image --ignorefile .trivyignore nginx:1.18.0
```

---

## 9. Integrating Trivy into CI/CD Pipelines

### GitHub Actions

```yaml
# .github/workflows/trivy-scan.yml
name: Container Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # Required for uploading SARIF to GitHub Security tab
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      
      # Option A: Official Trivy GitHub Action
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: 1          # Fail the build if findings exist
      
      # Upload results to GitHub Security tab
      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

      # Option B: Manual Trivy invocation (more control)
      - name: Install Trivy
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      - name: Scan for Critical vulnerabilities (blocks on failure)
        run: |
          trivy image \
            --severity CRITICAL \
            --ignore-unfixed \
            --exit-code 1 \
            --format table \
            myapp:${{ github.sha }}

      - name: Scan for all vulnerabilities (informational, doesn't block)
        if: always()
        run: |
          trivy image \
            --format json \
            --output trivy-full-report.json \
            myapp:${{ github.sha }}
      
      - name: Upload full report as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: trivy-report
          path: trivy-full-report.json
```

### GitLab CI

```yaml
# .gitlab-ci.yml
trivy-scan:
  stage: test
  image: aquasec/trivy:latest
  variables:
    DOCKER_HOST: tcp://docker:2375
  services:
    - docker:dind
  script:
    - trivy image --exit-code 0 --severity MEDIUM,HIGH --format json --output report.json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - trivy image --exit-code 1 --severity CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    when: always
    reports:
      container_scanning: report.json
  allow_failure: false
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps { sh 'docker build -t myapp:${GIT_COMMIT} .' }
        }
        stage('Trivy Scan') {
            steps {
                sh '''
                    trivy image \
                      --severity CRITICAL,HIGH \
                      --ignore-unfixed \
                      --exit-code 1 \
                      --format json \
                      --output trivy-report.json \
                      myapp:${GIT_COMMIT}
                '''
                archiveArtifacts 'trivy-report.json'
            }
        }
        stage('Push') {
            steps { sh 'docker push myregistry.io/myapp:${GIT_COMMIT}' }
        }
    }
    post {
        failure {
            emailext body: "Trivy found Critical/High vulnerabilities in build ${BUILD_NUMBER}",
                     subject: "Security Gate Failed - ${JOB_NAME}",
                     to: "security@yourorg.com"
        }
    }
}
```

### Kubernetes CronJob for Continuous Monitoring

```yaml
# CronJob that rescans all running images nightly
apiVersion: batch/v1
kind: CronJob
metadata:
  name: trivy-nightly-scan
  namespace: security
spec:
  schedule: "0 2 * * *"   # 2am nightly
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: trivy-scanner
          containers:
            - name: scanner
              image: aquasec/trivy:latest
              command:
                - /bin/sh
                - -c
                - |
                  # Get all unique images from running pods
                  for image in $(kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u); do
                    echo "=== Scanning: $image ==="
                    trivy image --severity CRITICAL,HIGH --format json "$image" >> /reports/scan-$(date +%Y%m%d).json
                  done
              volumeMounts:
                - name: reports
                  mountPath: /reports
          volumes:
            - name: reports
              persistentVolumeClaim:
                claimName: trivy-reports
          restartPolicy: OnFailure
```

---

## 10. As a DevSecOps / Kubernetes Security Engineer

As a DevSecOps engineer, you are responsible for more than just running `trivy image`. You own the scanning strategy, the thresholds, the exception process, and the integration into your software delivery pipeline.

**Defining vulnerability SLAs and thresholds:**

```
Severity    SLA         CI/CD Gate Action
---------   -------     ------------------
CRITICAL    24-72h      Block build immediately; alert on-call
HIGH        7 days      Block build; create JIRA ticket assigned to team
MEDIUM      30 days     Warn only; create JIRA ticket; no build block
LOW         90 days     Report only; quarterly review
UNKNOWN     Best effort Report only; investigate severity manually
```

**Managing the `--ignore-unfixed` decision:** There are two philosophies:

- **Include unfixed:** You see your total exposure. Some vulnerabilities have no patch yet — you might apply runtime mitigations (seccomp, capability dropping) while waiting. This approach requires a mature process to handle the noise.
- **Ignore unfixed:** You only action vulnerabilities that can actually be fixed. Reduces noise dramatically. Risk: you lose visibility into unfixable exposures that require alternative mitigations.

Most organisations start with `--ignore-unfixed` and graduate to full visibility as their vulnerability management programme matures.

**Building a remediation workflow:**

```bash
# Step 1: Identify what's vulnerable
trivy image --format json myapp:1.0.0 > current-findings.json

# Step 2: Get the fixed versions
jq '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL") | {pkg: .PkgName, installed: .InstalledVersion, fixed: .FixedVersion}' current-findings.json

# Step 3: Update Dockerfile base image or package pinning
# FROM nginx:1.18.0 → FROM nginx:1.25.3
# RUN apt-get install -y libssl1.1=1.1.1n-0+deb10u3

# Step 4: Rebuild and rescan
docker build -t myapp:1.0.1 .
trivy image --format json myapp:1.0.1 > post-fix-findings.json

# Step 5: Verify the Critical CVE is gone
diff \
  <(jq -r '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL") | .VulnerabilityID' current-findings.json | sort) \
  <(jq -r '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL") | .VulnerabilityID' post-fix-findings.json | sort)
```

**Handling the "false positive" problem:** Trivy sometimes flags vulnerabilities in packages that are installed but whose vulnerable code path is not reachable. For example, a library might have a CVE in its HTTPS client implementation, but your image never makes outbound HTTPS calls. In these cases:

1. Assess using EPSS score (probability of exploitation in the wild)
2. Verify code path reachability (manual or via AI-powered reachability tools)
3. If confirmed not reachable: add to `.trivyignore` with documented justification and VEX statement
4. Review the suppression quarterly

**Running Trivy Operator for cluster-wide continuous scanning:**

```bash
# Trivy Operator watches all pods and continuously scans their images
# Reports results as Kubernetes CRDs (VulnerabilityReport, ConfigAuditReport, etc.)

# Install
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system --create-namespace

# Check vulnerability reports for the production namespace
kubectl get vulnerabilityreports -n production
kubectl describe vulnerabilityreport -n production replicaset-myapp-abc123-app

# Get all Critical findings across the cluster
kubectl get vulnerabilityreports -A -o json \
  | jq '.items[].report.vulnerabilities[] | select(.severity == "CRITICAL") | {id: .vulnerabilityID, pkg: .resource, namespace: .namespace}'

# Set up Prometheus metrics from Trivy Operator
# trivy-operator exposes metrics at :8080/metrics for Prometheus scraping
# trivy_image_vulnerabilities{severity="CRITICAL", namespace="production"} 3
```

---

## 11. Real Present-Day Scenarios

### Scenario 1: Log4Shell — The CVE That Defined Container Scanning

In December 2021, CVE-2021-44228 (Log4Shell) was disclosed — a remote code execution vulnerability in Apache Log4j 2, with a CVSS score of 10.0 (the maximum). Any application that used Log4j 2 for logging and accepted user-controlled input was vulnerable to arbitrary code execution.

The organisations that had Trivy scanning integrated into their CI/CD pipelines fared significantly better:

```bash
# Immediate response after Log4Shell disclosure:
# Scan all images in your registry for log4j-core
trivy image --severity CRITICAL --format json myapp:1.0.0 \
  | jq '.Results[].Vulnerabilities[] | select(.VulnerabilityID == "CVE-2021-44228")'

# Scan entire cluster
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u \
  | xargs -I {} trivy image --severity CRITICAL {} 2>&1 | grep "CVE-2021-44228"
```

Organisations with automated scanning had a complete blast radius report within hours. Those without scanning spent days doing manual Java dependency archaeology across hundreds of services.

### Scenario 2: The Never-Rebuilt Docker Image — 847 CVEs

A startup deployed their application in 2019 and never rebuilt the Docker image. By 2023, their `ubuntu:18.04`-based image had accumulated 847 known vulnerabilities including 23 Critical and 156 High. They only discovered this when a customer's security team ran Trivy as part of due diligence before signing a contract. The contract was delayed by 6 months while they rebuilt their entire image pipeline.

**The prevention:** A nightly Trivy scan of all running images would have surfaced the growing vulnerability count years earlier, triggering incremental remediation rather than a crisis rebuild.

### Scenario 3: Trivy in CI Catches Critical Before Production

A DevOps team at a fintech company added a Trivy gate to their GitHub Actions pipeline with `--exit-code 1 --severity CRITICAL`. Three weeks later, their regular dependency update bumped `requests` (a Python HTTP library) from 2.27.1 to 2.28.0. The new version had a CVE (hypothetical — for illustration) with a CVSS of 9.1 (Critical). The CI gate caught it:

```
Error: CRITICAL: 1
CVE-2023-XXXXX (CRITICAL) - requests 2.28.0
Fixed in: 2.28.2
```

The developer pinned `requests==2.28.2` in `requirements.txt`, rebuilt, and the scan passed. Total time: 15 minutes. In a pre-Trivy world, this CVE would have silently reached production.

### Scenario 4: Alpine vs Debian — The Distribution Choice

A platform team was standardising their base image policy. They ran Trivy comparisons:

```bash
trivy image python:3.11            # debian-based → 267 vulnerabilities
trivy image python:3.11-slim       # debian-slim  → 67 vulnerabilities
trivy image python:3.11-alpine     # alpine-based → 1 vulnerability (often 0)
trivy image cgr.dev/chainguard/python:3.11  # chainguard → 0 vulnerabilities
```

The Trivy output made a compelling case for switching to Alpine or Chainguard-based images. The team adopted a policy: new services must use `python:*-alpine` or `cgr.dev/chainguard/python`; existing services have 90 days to migrate.

### Scenario 5: The Trivy Operator Alerts Before the Attacker Strikes

A Kubernetes platform team deployed Trivy Operator, which continuously rescanned all running images as new CVEs were published. On a Wednesday, a new Critical CVE was published for `openssl 3.0.x`. By Thursday morning, Trivy Operator had flagged 12 running pods in the production namespace as newly vulnerable. The security team received an alert (via Prometheus alerting rules on `trivy_image_vulnerabilities{severity="CRITICAL"} > 0`), triaged it, and the platform team initiated a rolling update of affected deployments — all before any exploitation attempt.

---

## 12. What Happens If You Don't Follow This

**Without any vulnerability scanning:**
- Known, exploitable CVEs accumulate in production images. You become the low-hanging fruit — attackers scan for specific vulnerable versions using tools like Shodan, censys, and masscan. If your service is internet-facing and has a public CVE in a reachable library, exploitation may be only a matter of time.
- The average time between CVE publication and active exploitation has dropped from months to days. The window to patch before attacks begin is narrowing every year.

**Without scanning in CI/CD:**
- Vulnerabilities are only discovered at production scanning time (if you have it), or during security audits, or after a breach. The cost of remediation at each stage increases by an order of magnitude.
- Developers have no feedback loop. They don't know they introduced a CVE. They can't learn the scanning-fix cycle that leads to better dependency hygiene over time.

**Without continuous re-scanning:**
- An image that was clean at build time may be running in production 6 months later with dozens of High and Critical vulnerabilities. Without re-scanning, you have no visibility into this decay.
- This is not theoretical. The Equifax breach (2017, $1.4B cost) involved Apache Struts CVE-2017-5638, which had a patch available for two months before the breach. Automated scanning with re-scan would have surfaced this.

**Without `--ignore-unfixed` discipline:**
- If you always include unfixed CVEs in your gate criteria, you can end up blocking builds for vulnerabilities that have no patch yet and no exploits in the wild. This causes gate fatigue — developers learn to ignore the scan results. Once gates are ignored, the real Critical/High findings are missed.

**Without using minimal base images:**
- Debian-based images routinely show 100-300 vulnerabilities at baseline. Alpine and distroless images start near 0. If you don't control your base image choice, you are fighting a perpetual uphill battle against OS-level CVE accumulation that has nothing to do with your application.

---

## 13. Most Common Commands and Syntax

### Installation

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install trivy

# Script install
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Check version
trivy --version
```

### Image Scanning

```bash
# Basic scan (all severities, table output)
trivy image nginx:1.18.0

# Severity filtering
trivy image --severity CRITICAL nginx:1.18.0
trivy image --severity CRITICAL,HIGH nginx:1.18.0
trivy image --severity HIGH,MEDIUM,LOW nginx:1.18.0

# Only fixable vulnerabilities
trivy image --ignore-unfixed nginx:1.18.0

# Combined: Critical+High, fixable only
trivy image --severity CRITICAL,HIGH --ignore-unfixed nginx:1.18.0

# Scan from tar archive
docker save nginx:1.18.0 > nginx.tar
trivy image --input nginx.tar

# Exit code for CI gates
trivy image --exit-code 1 --severity CRITICAL nginx:1.18.0
# Exit 0 if no Critical; Exit 1 if any Critical found
```

### Output Formats

```bash
# JSON
trivy image --format json --output results.json nginx:1.18.0

# SARIF (for GitHub/GitLab Security tabs)
trivy image --format sarif --output results.sarif nginx:1.18.0

# CycloneDX SBOM with vulnerabilities
trivy image --format cyclonedx --output results.cdx.json nginx:1.18.0

# SPDX SBOM
trivy image --format spdx-json --output results.spdx.json nginx:1.18.0

# HTML report
trivy image --format template --template "@contrib/html.tpl" --output results.html nginx:1.18.0
```

### Scanning Other Targets

```bash
# Filesystem / source code
trivy fs .
trivy fs /path/to/source

# Kubernetes cluster
trivy k8s --report summary cluster
trivy k8s --severity CRITICAL,HIGH --report summary cluster

# SBOM
trivy sbom nginx-sbom.cyclonedx.json

# Git repository
trivy repo https://github.com/myorg/myapp

# Kubernetes config files
trivy config ./k8s/
```

### Database Management

```bash
# Update vulnerability database manually
trivy image --download-db-only

# Skip database update (useful in air-gapped environments)
trivy image --skip-db-update nginx:1.18.0

# Use a custom database (air-gapped)
trivy image --db-repository my-registry.io/trivy-db:2 nginx:1.18.0

# Clear Trivy cache
trivy image --clear-cache
```

### Trivy Operator (Kubernetes-native)

```bash
# Install
helm install trivy-operator aqua/trivy-operator --namespace trivy-system --create-namespace

# View all vulnerability reports
kubectl get vulnerabilityreports -A

# View reports for a specific namespace
kubectl get vulnerabilityreports -n production

# Get the full report for a specific workload
kubectl describe vulnerabilityreport -n production <report-name>

# Get all Critical findings cluster-wide using jq
kubectl get vulnerabilityreports -A -o json \
  | jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, criticals: [.report.vulnerabilities[] | select(.severity == "CRITICAL")] | length}'
```

---

## 14. Other Tools and Services Available

### Open-Source Vulnerability Scanners

| Tool | Strengths | Best For |
|------|-----------|----------|
| **Trivy** (Aqua) | All-in-one; fast; SBOM generation; K8s cluster scanning; misconfig detection | General-purpose; most complete |
| **Grype** (Anchore) | SBOM-first scanning; fast; VEX support; lightweight | SBOM-centric workflows |
| **Clair** (Red Hat) | Mature; integrates with Quay.io; API-driven | Registry-integrated scanning |
| **Syft + Grype** | Separate SBOM generation + scanning | Maximum SBOM control |
| **Docker Scout** | Built into Docker CLI; Docker Hub integration | Docker-native workflows |
| **Snyk Container** | Developer experience; fix PRs; IDE integration | Developer-facing security |

### Commercial Vulnerability Scanning Platforms

| Platform | Key Feature |
|----------|------------|
| **Prisma Cloud** (Palo Alto) | Full platform: scan + runtime + compliance + CSPM |
| **Wiz** | Agentless; cloud-native; graph-based; risk context |
| **Lacework** | Behavioural analytics + vulnerability scanning |
| **Snyk** | Developer-centric; fix suggestions; IDE plugins |
| **Anchore Enterprise** | Enterprise Grype + policy engine + CI integration |
| **JFrog Xray** | Embedded in JFrog Artifactory; binary and dependency scanning |
| **Qualys Container Security** | Integration with Qualys VM programme |
| **Twistlock** (now Prisma Cloud) | Runtime + vulnerability; Kubernetes-native |

### Cloud-Native Scanning

| Service | Best For |
|---------|---------|
| **Amazon Inspector** | Automatic ECR scanning; Lambda scanning; EC2 |
| **Google Artifact Analysis** | Automatic scan on push to Artifact Registry; Container Analysis API |
| **Azure Defender for Containers** | ACR scanning; runtime protection for AKS |
| **GitHub Advanced Security** | Dependency scanning in GitHub Actions; Dependabot |

### Continuous Monitoring

| Tool | Purpose |
|------|---------|
| **Trivy Operator** | Kubernetes-native; watches all pods; VulnerabilityReport CRDs |
| **Dependency-Track** | SBOM-based continuous monitoring; policy engine |
| **GUAC** (Google) | Graph-based; org-wide SBOM and vulnerability relationship mapping |

---

## 15. How AI Is Impacting Vulnerability Scanning

### AI-Powered Exploitability Prioritisation — EPSS

The biggest challenge in vulnerability management is not finding CVEs — Trivy finds them all. The challenge is knowing which ones to fix first. A typical image might have 100-200 vulnerabilities; fixing all of them is not possible; fixing the wrong ones wastes time.

EPSS (Exploit Prediction Scoring System) uses ML trained on exploit data (Exploit-DB, threat intelligence feeds, PoC repositories) to predict the probability that a given CVE will be exploited in the wild in the next 30 days. This is fundamentally different from CVSS, which measures theoretical severity, not actual exploitation likelihood.

```bash
# Trivy can show EPSS scores alongside CVSS
trivy image --format json nginx:1.18.0 \
  | jq '.Results[].Vulnerabilities[] | {id: .VulnerabilityID, cvss: .CVSS.nvd.V3Score, epss: .EPSS}'

# Prioritise by EPSS — fix high-EPSS CVEs first, even if CVSS is Medium
# A CVSS 5.0 CVE with EPSS 0.94 (94% probability of exploitation) is more urgent
# than a CVSS 9.0 CVE with EPSS 0.001 (0.1% probability)
```

### AI-Powered Reachability Analysis

The most significant source of noise in vulnerability scanning is "the vulnerable code path isn't used." An image might contain `openssl` with a CVE in a specific cipher suite that your application never uses. Traditional scanners can't distinguish; AI can.

- **Snyk's Reachability Analysis** and **Endor Labs** use call graph analysis combined with ML to determine whether the vulnerable function is actually in a reachable code path.
- **Rezilion** does runtime analysis — it observes which functions actually execute in production and uses this to suppress unreachable vulnerabilities, often reducing the actionable CVE count by 80-95%.
- **Aqua's DTA** (Dynamic Threat Analysis) runs images in an isolated sandbox and observes runtime behaviour, then correlates with CVEs to identify exploitable paths.

### AI-Assisted Remediation

When Trivy finds a vulnerability, it tells you "upgrade to version X." AI goes further:

- **GitHub Dependabot with AI enhancement** — Analyses whether the proposed version upgrade will break existing tests, based on the change log and semantic version delta.
- **Snyk's Fix PRs** — Automatically generates pull requests that update vulnerable dependencies, with an AI-assessed confidence score on whether the update is safe.
- **Renovate Bot with Trivy integration** — Creates automatic PRs for Dockerfile base image updates, prioritised by Trivy severity scores.

### AI in Vulnerability Database Enhancement

The NVD and CVE database have a well-known backlog problem — new CVEs are often published weeks or months after disclosure, and CVSS scores are sometimes incomplete or inaccurate. AI is being used to:

- **Predict CVSS scores** for new CVEs before NVD analysts complete their review, enabling faster scanner updates
- **Enrich CVE descriptions** with affected component lists, detecting which packages are affected from vendor advisories and patch notes
- **Cross-reference databases** — Reconcile CVE entries across NVD, GitHub Advisories, OSV, and vendor-specific advisories to produce more complete and accurate vulnerability data

---

## 16. CKS Exam Tips

Trivy is directly tested in the CKS exam. You need to know the exact commands — the exam does not give partial credit for close answers.

**High-probability exam tasks:**

1. **Scan a specific image for vulnerabilities:**
   ```bash
   trivy image nginx:1.18.0
   ```

2. **Scan and filter by severity:**
   ```bash
   trivy image --severity CRITICAL nginx:1.18.0
   trivy image --severity CRITICAL,HIGH nginx:1.18.0
   ```

3. **Scan and ignore unfixed vulnerabilities:**
   ```bash
   trivy image --ignore-unfixed nginx:1.18.0
   ```

4. **Scan a tar archive:**
   ```bash
   docker save nginx:1.18.0 > nginx.tar
   trivy image --input nginx.tar
   ```

5. **Scan with JSON output:**
   ```bash
   trivy image --format json --output results.json nginx:1.18.0
   ```

6. **Scan and exit with code 1 on Critical findings (CI gate):**
   ```bash
   trivy image --exit-code 1 --severity CRITICAL nginx:1.18.0
   ```

7. **Know what CVE stands for** — Common Vulnerabilities and Exposures

8. **Know the severity levels** — CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN (in order)

9. **Understand the Trivy output columns** — LIBRARY, VULNERABILITY ID, SEVERITY, INSTALLED VERSION, FIXED VERSION, TITLE

**Key facts to memorise:**

- Trivy is made by **Aqua Security**
- Default output format is `table` (human-readable)
- `--severity` takes comma-separated values: `CRITICAL,HIGH`
- `--ignore-unfixed` suppresses CVEs with no available fix
- `--input` is used for tar archives
- `--exit-code 1` makes Trivy return exit code 1 when vulnerabilities matching severity are found (for CI gates)
- `--format json/sarif/cyclonedx/spdx-json` for machine-readable output

**Common exam traps:**

- `--severity CRITICAL HIGH` (space-separated) is **wrong** — use `--severity CRITICAL,HIGH` (comma-separated, no space)
- `--input` is used for tar files, not for filesystem directories (use `trivy fs` for directories)
- The command is `trivy image` not `trivy scan` or `trivy container`
- If the exam asks you to save an image first: `docker save <image> > file.tar` then `trivy image --input file.tar`
- Alpine-based images typically show zero or very few vulnerabilities — if asked to compare, `nginx:1.18.0` (Debian, ~155 CVEs) vs `nginx:1.18.0-alpine` (Alpine, ~0 CVEs) is the canonical example

---

## 17. Extra Information and References

### Trivy Configuration File

```yaml
# trivy.yaml (or ~/.trivy/trivy.yaml) — default configuration
image:
  removed-pkgs: true

vulnerability:
  type:
    - os
    - library
  ignore-unfixed: true

severity:
  - CRITICAL
  - HIGH

format: table

exit-code: 1

ignore:
  # .trivyignore format — list of CVE IDs to suppress
  - CVE-2011-3374
  - CVE-2016-2781

db:
  skip-update: false
  light: false
```

### CVSS Calculator

Understanding CVSS scores helps you understand why a vulnerability has the severity it does:

```
CVE-2021-44228 (Log4Shell):
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0 CRITICAL
  → AV:N  = Network-exploitable (anyone on internet)
  → AC:L  = Low complexity (easy to exploit)
  → PR:N  = No privileges required
  → UI:N  = No user interaction
  → S:C   = Scope Changed (can affect other systems)
  → C:H/I:H/A:H = Full CIA impact
  → Result: Maximum possible score (10.0)

CVE-2020-5911 (NGINX Controller, KodeKloud example):
  CVSS: 7.3 HIGH
  → Insecure HTTP download → MITM attack vector
  → High severity but not Critical because it requires MITM positioning
```

### NVD CVE Search

```bash
# Look up a CVE in the NVD directly (for manual verification)
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" \
  | jq '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData'

# Look up via OSV (open source vulnerabilities)
curl "https://api.osv.dev/v1/vuln/CVE-2021-44228" | jq '.affected[].package'
```

### Trivy Vulnerability Database Sources

```bash
# Trivy aggregates from multiple databases:
# - NVD: https://nvd.nist.gov
# - GitHub Advisory DB: https://github.com/advisories
# - OSV: https://osv.dev
# - Red Hat: https://access.redhat.com/security/cve/
# - Debian: https://security-tracker.debian.org
# - Ubuntu: https://ubuntu.com/security/cves
# - Alpine: https://secdb.alpinelinux.org
# - PHP: https://github.com/FriendsOfPHP/security-advisories
# - Ruby: https://github.com/rubysec/ruby-advisory-db
# - npm/PyPI: via OSV

# trivy-db is updated daily and downloadable from:
# https://github.com/aquasecurity/trivy-db/releases
```

### Trivy in Air-Gapped Environments

```bash
# In environments without internet access:

# 1. Download trivy-db on an internet-connected machine
trivy image --download-db-only
# Database saved to ~/.cache/trivy/db/

# 2. Transfer to air-gapped environment (via USB/internal transfer)
tar -czf trivy-db.tar.gz ~/.cache/trivy/db/

# 3. Extract on air-gapped machine
mkdir -p ~/.cache/trivy/db/
tar -xzf trivy-db.tar.gz -C ~/.cache/trivy/

# 4. Scan without internet
trivy image --skip-db-update --skip-java-db-update nginx:1.18.0

# Alternative: host trivy-db internally as an OCI image
trivy image --db-repository my-internal-registry.io/trivy-db:2 nginx:1.18.0
```

### References

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
- [Trivy Operator — Kubernetes-native Trivy](https://aquasecurity.github.io/trivy-operator/latest/)
- [NVD — National Vulnerability Database](https://nvd.nist.gov)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [EPSS — Exploit Prediction Scoring System](https://www.first.org/epss)
- [OSV — Open Source Vulnerabilities](https://osv.dev)
- [GitHub Security Advisories](https://github.com/advisories)
- [CISA Known Exploited Vulnerabilities (KEV) Catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [KodeKloud CKS Course — Scan Images for Known Vulnerabilities](https://learn.kodekloud.com/user/courses/certified-kubernetes-security-specialist-cks/module/e4511664-185f-4204-9aa2-b4250cbadf84/lesson/23e7cda2-6540-4704-9e6b-5754cefc2a55)
