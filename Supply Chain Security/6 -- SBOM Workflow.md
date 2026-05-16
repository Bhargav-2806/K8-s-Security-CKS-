# Chapter 6: SBOM Workflow — Generate, Store, Scan, Analyze, Remediate, Monitor

---

## Table of Contents

1. [Why the SBOM Workflow Matters](#1-why-the-sbom-workflow-matters)
2. [What Is the SBOM Workflow?](#2-what-is-the-sbom-workflow)
3. [Step 1 — Generate the SBOM](#3-step-1--generate-the-sbom)
   - [Choosing Your Format](#choosing-your-format)
   - [Syft — Primary Generation Tool](#syft--primary-generation-tool)
   - [Other Generation Tools](#other-generation-tools)
4. [Step 2 — Securely Store the SBOM](#4-step-2--securely-store-the-sbom)
5. [Step 3 — Scan the SBOM for Vulnerabilities](#5-step-3--scan-the-sbom-for-vulnerabilities)
6. [Step 4 — Analyze the Scan Results](#6-step-4--analyze-the-scan-results)
   - [CVE Analysis Deep Dive](#cve-analysis-deep-dive)
   - [Understanding CVSS Scores](#understanding-cvss-scores)
   - [VEX — Cutting Through Alert Fatigue](#vex--cutting-through-alert-fatigue)
7. [Step 5 — Remediate Identified Issues](#7-step-5--remediate-identified-issues)
8. [Step 6 — Continuous Monitoring and Alerts](#8-step-6--continuous-monitoring-and-alerts)
9. [As a DevSecOps / Kubernetes Security Engineer](#9-as-a-devsecops--kubernetes-security-engineer)
10. [Real Present-Day Scenarios](#10-real-present-day-scenarios)
11. [What Happens If You Don't Follow This](#11-what-happens-if-you-dont-follow-this)
12. [Most Common Commands and Syntax](#12-most-common-commands-and-syntax)
13. [Other Tools and Services Available](#13-other-tools-and-services-available)
14. [How AI Is Impacting SBOM Workflows](#14-how-ai-is-impacting-sbom-workflows)
15. [CKS Exam Tips](#15-cks-exam-tips)
16. [Extra Information and References](#16-extra-information-and-references)

---

## 1. Why the SBOM Workflow Matters

Generating an SBOM is not a one-time checkbox — it is a living, operational process that runs through every stage of your software development lifecycle. An SBOM sitting in a file with no scanning, no analysis, and no monitoring provides exactly zero security benefit. The entire value of an SBOM is realised only through a complete, repeatable workflow.

Consider what happens during the lifecycle of a typical Kubernetes workload. You build a container image today — your nginx:1.25 base has no known critical CVEs. Three months later, a new vulnerability is disclosed in one of its libraries. Without a workflow that continuously monitors your SBOMs, you have no automated way to know your running pods are now vulnerable. The SBOM workflow closes this gap.

The workflow matters because:

- **Software never stops changing.** New CVEs are published daily. An SBOM that was clean at build time may have open vulnerabilities by deployment time.
- **Dependencies have dependencies.** Without an SBOM workflow, transitive dependencies stay invisible. Most real-world attacks exploit indirect dependencies — packages you didn't know you were using.
- **Compliance demands evidence.** US Executive Order 14028, the EU Cyber Resilience Act, NIST SP 800-218, and FedRAMP all require not just SBOM generation but SBOM-based vulnerability management — meaning you need the full workflow, not just the file.
- **Supply chain attacks are runtime threats.** SolarWinds, Log4Shell, XZ Utils — each was a supply chain compromise that a proper SBOM workflow with continuous monitoring would have detected and surfaced faster.
- **Mean Time to Remediate (MTTR) is a security metric.** Organisations with automated SBOM workflows patch critical vulnerabilities in hours. Those without take days to weeks.

---

## 2. What Is the SBOM Workflow?

The SBOM workflow is a six-stage continuous process that transforms raw software components into an actionable security posture. It is not linear — it is cyclical. After monitoring, new SBOM generations are triggered, scans are re-run, and the loop repeats on every build and on every new CVE disclosure.

![The image illustrates an "SBOM Workflow" with steps: Generate SBOM, Store SBOM, Scan SBOM, Analyze Results, Remediate Issues, and Monitor.](https://kodekloud.com/kk-media/image/upload/v1752871712/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-SBOM-Workflow/frame_30.jpg)

The six steps are:

1. **Generate** — Produce a machine-readable inventory of all components in your software artefact (container image, source repository, binary).
2. **Store** — Persist the SBOM in a secure, versioned, tamper-evident repository alongside the artefact it describes.
3. **Scan** — Feed the SBOM into a vulnerability scanner that cross-references every component against CVE databases (NVD, OSV, GitHub Advisories).
4. **Analyze** — Interpret scan results, triage findings by severity and exploitability, produce VEX statements where applicable.
5. **Remediate** — Update affected packages, rebuild images, adjust base images, or apply mitigating controls.
6. **Monitor** — Continuously rerun scans as new CVEs are disclosed, alert on threshold violations, integrate into CI/CD gates.

Two formats dominate the SBOM space — SPDX and CycloneDX. Each has distinct strengths:

![The image presents a choice between two SBOM standards: SPDX and CycloneDX.](https://kodekloud.com/kk-media/image/upload/v1752871713/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-SBOM-Workflow/frame_50.jpg)

- **Use SPDX** for open-source projects and enterprises that require licensing compliance, need to trace software origins, perform security audits, and manage vulnerabilities across their portfolio. SPDX is the NTIA-recommended format and has strong government adoption.
- **Use CycloneDX** to enhance vulnerability management across the software lifecycle, ensure software integrity with built-in VEX support, and integrate with tooling like Dependency-Track. CycloneDX is the OWASP standard and has the richest vulnerability context features.

```
Format Selection Guide:
  ┌─────────────────────────────┬──────────────────────┬──────────────────────┐
  │ Use Case                    │ SPDX                 │ CycloneDX            │
  ├─────────────────────────────┼──────────────────────┼──────────────────────┤
  │ License compliance          │ ✅ Primary use case   │ ⚠️ Supported          │
  │ Vulnerability management    │ ⚠️ Supported          │ ✅ Primary use case   │
  │ VEX statements              │ ⚠️ Separate document  │ ✅ Embedded           │
  │ Government/federal projects │ ✅ Strong adoption    │ ✅ Also accepted      │
  │ CI/CD toolchain integration │ ⚠️ Growing            │ ✅ Wide support       │
  │ Open-source auditing        │ ✅ Native             │ ⚠️ Supported          │
  │ SBOM merging/nesting        │ ✅ Strong             │ ✅ Strong             │
  └─────────────────────────────┴──────────────────────┴──────────────────────┘
```

In practice, many mature security teams generate **both formats** from the same scan and publish them together.

---

## 3. Step 1 — Generate the SBOM

SBOM generation is the process of inspecting a software artefact and producing a structured inventory of all components — packages, libraries, binaries, files, and their relationships. Quality of generation matters enormously: an SBOM that misses 30% of your dependencies is worse than useless because it creates a false sense of security.

### Choosing Your Format

Decide early whether you need SPDX, CycloneDX, or both. Most modern tools support both formats. Key considerations:

- **Regulatory environment** — FedRAMP and US government buyers often specify SPDX. EU CRA accepts both.
- **Toolchain** — If you use Dependency-Track for continuous monitoring, CycloneDX is natively supported. FOSSA and Black Duck work well with SPDX.
- **Vulnerability workflow** — CycloneDX's embedded VEX makes it superior for vulnerability management pipelines.

### Syft — Primary Generation Tool

Syft, developed by Anchore, is the industry standard for SBOM generation from container images and filesystems. It detects packages across virtually all ecosystems: deb, rpm, apk, npm, pip, gem, go modules, Java JARs, and more.

```bash
# Install Syft on Linux/macOS
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
syft version

# Generate an SPDX-JSON SBOM for a Docker image
syft nginx:1.25 -o spdx-json > nginx-sbom.spdx.json

# Generate a CycloneDX-JSON SBOM for a Docker image
syft nginx:1.25 -o cyclonedx-json > nginx-sbom.cyclonedx.json

# Generate SBOM from local source code directory
syft /path/to/source/code -o spdx-json > source-sbom.spdx.json

# Generate both formats simultaneously
syft nginx:1.25 -o spdx-json=nginx.spdx.json -o cyclonedx-json=nginx.cyclonedx.json

# Generate SBOM from a running container
syft $(docker inspect --format='{{.Image}}' my-container) -o cyclonedx-json

# Generate SBOM from a tarball (useful for offline builds)
syft packages docker-archive:/path/to/image.tar -o cyclonedx-json

# Generate SBOM from an OCI image directory
syft packages oci-dir:/path/to/oci-layout -o spdx-json

# Scope to specific package catalogers (faster for targeted analysis)
syft nginx:1.25 -o cyclonedx-json --catalogers=dpkg,rpm,apk

# Exclude specific paths from SBOM generation
syft nginx:1.25 -o cyclonedx-json --exclude "/tmp/**"

# Output in human-readable table format for quick review
syft nginx:1.25
```

**What Syft captures per package:**

```
Name:     libssl3
Version:  3.0.11-1~deb12u2
Type:     deb
PURL:     pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64
CPE:      cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*
Location: /var/lib/dpkg/status
Layer:    sha256:abc123...
```

### Other Generation Tools

Beyond Syft, other tools generate SBOMs in specific contexts:

```bash
# Trivy (Aqua Security) — combines SBOM generation + scanning in one tool
trivy image --format cyclonedx --output nginx-sbom.json nginx:1.25
trivy image --format spdx-json --output nginx-sbom.spdx.json nginx:1.25
trivy fs --format cyclonedx --output sbom.json /path/to/src

# cdxgen — excellent for application-level SBOMs from source
npm install -g @cyclonedx/cdxgen
cdxgen -t java /path/to/java/app -o bom.json
cdxgen -t python /path/to/python/app -o bom.json
cdxgen -t nodejs /path/to/node/app -o bom.json

# Microsoft sbom-tool
sbom-tool generate -b /path/to/build -bc /path/to/source -pn MyPackage -pv 1.0.0 -ps MyOrg

# Kubernetes cluster SBOM (using BoKS)
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | sort -u > images.txt
# Then syft each image
```

**SBOM generation in GitHub Actions CI/CD:**

```yaml
# .github/workflows/sbom.yml
name: Generate and Store SBOM

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker Image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Install Syft
        uses: anchore/sbom-action/download-syft@v0

      - name: Generate SBOM (CycloneDX)
        uses: anchore/sbom-action@v0
        with:
          image: myapp:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json

      - name: Generate SBOM (SPDX)
        uses: anchore/sbom-action@v0
        with:
          image: myapp:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Upload SBOMs as artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sboms
          path: |
            sbom.cyclonedx.json
            sbom.spdx.json
```

---

## 4. Step 2 — Securely Store the SBOM

An SBOM that cannot be verified for integrity is an SBOM that cannot be trusted. Secure storage means three things: the SBOM is **versioned** (one per build, tied to the exact artefact digest), **tamper-evident** (signed or checksummed), and **accessible** (retrievable by scanners, auditors, and downstream consumers).

**Storage options and their tradeoffs:**

```
┌────────────────────────┬───────────────────────────────┬────────────────────────────────┐
│ Storage Backend        │ Pros                          │ Cons                           │
├────────────────────────┼───────────────────────────────┼────────────────────────────────┤
│ OCI Registry (cosign)  │ Co-located with image,        │ Requires cosign; registry      │
│                        │ cryptographically verified,   │ must support OCI 1.1           │
│                        │ pulled on demand              │                                │
├────────────────────────┼───────────────────────────────┼────────────────────────────────┤
│ JFrog Artifactory      │ Enterprise-grade, policy      │ Licensed; cost                 │
│                        │ enforcement, REST API         │                                │
├────────────────────────┼───────────────────────────────┼────────────────────────────────┤
│ Sonatype Nexus         │ Popular in Java shops,        │ Setup overhead                 │
│                        │ strong OSS support            │                                │
├────────────────────────┼───────────────────────────────┼────────────────────────────────┤
│ GitHub Packages /      │ Free for public repos,        │ Less access control than       │
│ GitHub Releases        │ CI/CD integrated              │ enterprise repos               │
├────────────────────────┼───────────────────────────────┼────────────────────────────────┤
│ Dependency-Track       │ SBOM-native, continuous       │ Self-hosted; requires ops      │
│                        │ monitoring built in           │                                │
├────────────────────────┼───────────────────────────────┼────────────────────────────────┤
│ S3 / GCS / Azure Blob  │ Cheap, durable, scalable      │ No SBOM-native features;       │
│                        │                               │ need integrity layer           │
└────────────────────────┴───────────────────────────────┴────────────────────────────────┘
```

**Best practice: attach SBOMs to container images as OCI attestations using Cosign:**

```bash
# Sign the image (keyless, using OIDC/Sigstore)
cosign sign --yes myregistry.io/myapp:1.0.0

# Attach the CycloneDX SBOM as an attestation
cosign attest --yes \
  --predicate sbom.cyclonedx.json \
  --type cyclonedx \
  myregistry.io/myapp:1.0.0

# Attach the SPDX SBOM as an attestation
cosign attest --yes \
  --predicate sbom.spdx.json \
  --type spdxjson \
  myregistry.io/myapp:1.0.0

# Verify the attestation exists and is valid
cosign verify-attestation \
  --type cyclonedx \
  myregistry.io/myapp:1.0.0

# Download the attached SBOM from the registry
cosign download attestation myregistry.io/myapp:1.0.0 \
  | jq '.payload | @base64d | fromjson | .predicate'
```

**Upload SBOM to Dependency-Track via API:**

```bash
# Base64-encode the SBOM
SBOM_BASE64=$(base64 -w 0 sbom.cyclonedx.json)

# Upload to Dependency-Track
curl -s -X PUT \
  -H "X-Api-Key: ${DTRACK_API_KEY}" \
  -H "Content-Type: application/json" \
  "https://dtrack.yourcompany.com/api/v1/bom" \
  -d "{
    \"projectName\": \"myapp\",
    \"projectVersion\": \"1.0.0\",
    \"autoCreate\": true,
    \"bom\": \"${SBOM_BASE64}\"
  }"
```

**Naming convention for versioned SBOMs:**

```bash
# Tie SBOM filename to image digest — not just tag
IMAGE_DIGEST=$(docker inspect --format='{{.Id}}' nginx:1.25)
SBOM_NAME="nginx-1.25-${IMAGE_DIGEST:7:12}.cyclonedx.json"
```

---

## 5. Step 3 — Scan the SBOM for Vulnerabilities

Vulnerability scanning against an SBOM is fundamentally different from scanning an image directly. An SBOM scan is faster (no image pull), reproducible (static file), shareable (can be sent to customers), and works offline. The scanner cross-references every PURL and CPE in the SBOM against vulnerability databases: NVD (National Vulnerability Database), GitHub Advisories, OSV (Open Source Vulnerabilities), and commercial databases.

**Grype — the primary SBOM vulnerability scanner:**

```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan a CycloneDX SBOM (produced by Syft)
grype sbom:nginx-sbom.cyclonedx.json

# Scan an SPDX SBOM
grype sbom:nginx-sbom.spdx.json

# Scan with output in JSON (for downstream processing)
grype sbom:nginx-sbom.cyclonedx.json -o json > grype-results.json

# Scan and fail CI if any Critical or High CVEs found
grype sbom:nginx-sbom.cyclonedx.json --fail-on critical

# Scan a Docker image directly (Grype generates SBOM internally)
grype nginx:1.25

# Scan and output only the CVE summary table
grype sbom:nginx-sbom.cyclonedx.json -o table

# Show only fixable vulnerabilities
grype sbom:nginx-sbom.cyclonedx.json --only-fixed

# Use a specific vulnerability database (offline/air-gapped environments)
grype sbom:nginx-sbom.cyclonedx.json --db-update-url file:///path/to/grype-db
```

**Example Grype output:**

```bash
# Example: grype sbom:nginx-sbom.cyclonedx.json
NAME                              INSTALLED    FIXED-IN      TYPE   VULNERABILITY   SEVERITY
libssl3                           3.0.11       3.0.14        deb    CVE-2024-5535   Medium
libnginx-mod-http-xslt-filter     1.10.3       1.10.3-1+deb9u5 deb CVE-2020-11724 Medium
zlib1g                            1:1.2.13     (none)        deb    CVE-2023-45853  Critical
libgnutls30                       3.7.9        3.8.1         deb    CVE-2024-0553   High
curl                              7.88.1       8.5.0         deb    CVE-2023-38545  High
```

**Trivy for combined generation + scanning:**

```bash
# Trivy scans image and produces vulnerability report in one step
trivy image nginx:1.25

# Trivy using a pre-generated SBOM
trivy sbom nginx-sbom.cyclonedx.json

# Trivy with SARIF output (for GitHub Security tab)
trivy sbom nginx-sbom.cyclonedx.json --format sarif --output results.sarif

# Trivy in CI — fail build on HIGH or CRITICAL
trivy image --exit-code 1 --severity HIGH,CRITICAL nginx:1.25
```

---

## 6. Step 4 — Analyze the Scan Results

Raw scanner output is a list of CVEs — it is not yet a security decision. Analysis transforms that list into prioritised, actionable findings by adding context: What is the real exploitability? Is the vulnerable code path actually reachable? Has a vendor already assessed this? What is the blast radius if exploited?

### CVE Analysis Deep Dive

Grype's JSON output provides rich detail per vulnerability. The KodeKloud example illustrates the structure of a finding — CVE-2020-11724 in `libnginx-mod-http-xslt-filter`:

```json
{
  "vulnerability": {
    "id": "CVE-2020-11724",
    "severity": "Medium",
    "links": [
      "http://security-tracker.debian.org/tracker/CVE-2020-11724"
    ]
  },
  "cvss-v2": {
    "base-score": 5,
    "vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N"
  },
  "matched-by": {
    "matcher": "dpkg-matcher",
    "search-key": "distro[debian 9] constraint[< 1.10.3-1+deb9u5 (deb)]"
  },
  "artifact": {
    "name": "libnginx-mod-http-xslt-filter",
    "version": "1.10.3-1+deb9u3",
    "type": "deb",
    "found-by": "dpkg-catalog"
  },
  "locations": [
    {
      "path": "/var/lib/dpkg/status",
      "layer-index": 1
    }
  ],
  "metadata": {
    "package": "libnginx-mod-http-xslt-filter",
    "source": "nginx",
    "version": "1.10.3-1+deb9u3"
  }
}
```

**Reading this finding:** CVE-2020-11724 is a Medium severity vulnerability in the Nginx XSLT filter module, version 1.10.3-1+deb9u3 on Debian 9. The fixed version is 1.10.3-1+deb9u5. The CVSS v2 base score is 5.0, with network attack vector (AV:N), low complexity (AC:L), no authentication required (Au:N), no confidentiality impact (C:N), partial integrity impact (I:P), and no availability impact (A:N). The `matched-by` field tells you exactly how Grype matched it — via the dpkg package database (dpkg-matcher).

**Analysis checklist for each finding:**

```
For every vulnerability found, ask:
  1. Is the vulnerable package actually USED in this image? (Not just installed)
  2. Is the vulnerable code PATH reachable at runtime?
  3. Does a fix exist? (check "FIXED-IN" column in Grype output)
  4. What is the actual exploitability in our context? (e.g., is it a local-only exploit on a network container?)
  5. Is there a vendor assessment (VEX) already published?
  6. What is our SLA for this severity? (Critical: 24h, High: 7d, Medium: 30d, Low: 90d)
```

### Understanding CVSS Scores

```
CVSS v3 Score → Severity Mapping:
  0.0         → None
  0.1 – 3.9   → Low
  4.0 – 6.9   → Medium
  7.0 – 8.9   → High
  9.0 – 10.0  → Critical

Key CVSS v3 Vectors:
  AV: Attack Vector       (N=Network, A=Adjacent, L=Local, P=Physical)
  AC: Attack Complexity   (L=Low, H=High)
  PR: Privileges Required (N=None, L=Low, H=High)
  UI: User Interaction    (N=None, R=Required)
  S:  Scope               (U=Unchanged, C=Changed)
  C:  Confidentiality     (H=High, L=Low, N=None)
  I:  Integrity           (H=High, L=Low, N=None)
  A:  Availability        (H=High, L=Low, N=None)

Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
  → Network exploitable, low complexity, no auth, no user interaction = very dangerous
```

### VEX — Cutting Through Alert Fatigue

Large container images can have hundreds of CVEs, most of which are not actually exploitable in your specific context. VEX (Vulnerability Exploitability eXchange) lets you publish machine-readable statements that say "this CVE exists in our SBOM but is not exploitable because X."

```bash
# Create a VEX document using OpenVEX CLI
vexctl create \
  --author "Security Team <security@yourorg.com>" \
  --product "pkg:oci/myapp@sha256:abc123" \
  --vuln CVE-2020-11724 \
  --status not_affected \
  --justification "vulnerable_code_not_in_execute_path" \
  > cve-2020-11724-vex.json

# VEX Status values:
#   not_affected       — code path not reachable
#   affected           — vulnerable and exploitable
#   fixed              — fix applied
#   under_investigation — still being assessed

# Apply VEX to a Grype scan to suppress known-not-affected findings
grype sbom:nginx-sbom.cyclonedx.json --vex cve-2020-11724-vex.json
```

---

## 7. Step 5 — Remediate Identified Issues

Remediation is the action phase — converting vulnerability findings into concrete fixes that reduce risk. The approach depends on where the vulnerability lives: base image OS packages, application dependencies, or the application code itself.

![The image outlines the SBOM process: generate, store, scan, analyze, remediate issues, and monitor, highlighting a problematic component in an app.](https://kodekloud.com/kk-media/image/upload/v1752871714/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-SBOM-Workflow/frame_190.jpg)

**Remediation strategies by vulnerability location:**

```
Vulnerability in OS base image packages (e.g., libssl, curl, zlib):
  → Strategy 1: Rebuild with updated base image (docker pull nginx:1.25-bookworm; rebuild)
  → Strategy 2: Pin to a newer base digest in Dockerfile
  → Strategy 3: Switch to distroless/chainguard base (eliminates most OS packages entirely)
  → Strategy 4: Add package update in Dockerfile (last resort — avoid installing package manager in prod images)

Vulnerability in application dependencies (e.g., npm, pip, maven):
  → Strategy 1: Update package version in package.json / requirements.txt / pom.xml
  → Strategy 2: Use a patched fork (if upstream is slow)
  → Strategy 3: Apply a runtime mitigation (env variable, config flag)

Vulnerability in first-party code:
  → Strategy 1: Fix the code (only option here)
  → Strategy 2: Apply WAF rule while fix is developed

Vulnerability is present but not exploitable:
  → Strategy: Publish VEX statement (not_affected) and suppress in scans
```

**Dockerfile remediation example — applying OS package updates:**

```dockerfile
# Before remediation — pinned to old base with known CVEs
FROM nginx:1.10.3-alpine

# After remediation — Option 1: Use newer base
FROM nginx:1.25-alpine

# After remediation — Option 2: Patch packages in existing base (less ideal)
FROM nginx:1.10.3-alpine
RUN apk update && apk upgrade --no-cache \
    libssl3 \
    libcrypto3 \
    curl

# After remediation — Option 3: Use distroless (eliminates most OS CVEs)
FROM cgr.dev/chainguard/nginx:latest
```

**Updating application dependencies:**

```bash
# Python — update vulnerable package
pip install --upgrade vulnerable-package==X.Y.Z
pip freeze > requirements.txt

# Node.js — fix audit vulnerabilities
npm audit fix
npm audit fix --force  # for breaking changes

# Java (Maven) — update in pom.xml and verify
mvn versions:display-dependency-updates
mvn versions:use-latest-releases

# Go — update vulnerable module
go get vulnerable-module@latest
go mod tidy
```

**Verify remediation with a post-fix SBOM scan:**

```bash
# Rebuild image with fix applied
docker build -t myapp:1.0.1-patched .

# Generate new SBOM
syft myapp:1.0.1-patched -o cyclonedx-json > myapp-1.0.1-patched.cyclonedx.json

# Rescan
grype sbom:myapp-1.0.1-patched.cyclonedx.json

# Compare with previous scan to confirm CVE is gone
grype sbom:myapp-1.0.1-patched.cyclonedx.json -o json \
  | jq '.matches[].vulnerability.id' | sort > after.txt

diff before.txt after.txt
# CVE-2020-11724 should no longer appear
```

> ⚠️ **Critical rule:** Always test remediation actions in a controlled (staging) environment before deploying to production. Updating a shared library can introduce regressions. For example, upgrading OpenSSL in a base image has historically broken TLS handshakes with certain cipher configurations.

---

## 8. Step 6 — Continuous Monitoring and Alerts

The final step transforms the SBOM workflow from a point-in-time scan into a persistent security posture. Continuous monitoring means your SBOMs are automatically rescanned whenever new CVEs are published — not just when you build a new image.

![The image outlines a continuous monitoring process for SBOM, including generating, storing, scanning, analyzing, remediating, and monitoring, with automated scanning and regular updates.](https://kodekloud.com/kk-media/image/upload/v1752871716/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-SBOM-Workflow/frame_210.jpg)

**Why continuous monitoring is necessary:** A container image that was vulnerability-free at build time (Monday) can have a Critical CVE disclosed against it on Friday. Without continuous monitoring, you will not know your Tuesday deployment is now vulnerable until you rebuild — which could be weeks away.

**Dependency-Track — the gold standard for continuous SBOM monitoring:**

```bash
# Deploy Dependency-Track via Docker Compose
curl -LO https://dependencytrack.org/docker-compose.yml
docker compose up -d

# Access at http://localhost:8080 (API server) and http://localhost:8080 (frontend)

# Upload SBOM to Dependency-Track (creates project automatically)
curl -X PUT \
  -H "X-Api-Key: ${DTRACK_API_KEY}" \
  -H "Content-Type: application/json" \
  "https://dtrack.yourcompany.com/api/v1/bom" \
  -d @- << EOF
{
  "projectName": "myapp",
  "projectVersion": "1.0.0",
  "autoCreate": true,
  "bom": "$(base64 -w 0 sbom.cyclonedx.json)"
}
EOF

# Dependency-Track will:
# 1. Parse all components from the SBOM
# 2. Query NVD, OSV, GitHub Advisories, VulnDB continuously
# 3. Alert when new CVEs are published against your components
# 4. Show policy violations (e.g., GPL components in proprietary app)
# 5. Track SBOM history across versions
```

**Setting up CI/CD gates:**

```yaml
# GitHub Actions — block merges when Critical CVEs found
- name: Scan SBOM for Critical Vulnerabilities
  run: |
    grype sbom:sbom.cyclonedx.json --fail-on critical
    if [ $? -ne 0 ]; then
      echo "::error::Critical vulnerabilities found. Merge blocked."
      exit 1
    fi

# Alternatively, use thresholds
- name: Vulnerability Gate
  run: |
    CRIT_COUNT=$(grype sbom:sbom.cyclonedx.json -o json | jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length')
    HIGH_COUNT=$(grype sbom:sbom.cyclonedx.json -o json | jq '[.matches[] | select(.vulnerability.severity=="High")] | length')
    
    echo "Critical: ${CRIT_COUNT}, High: ${HIGH_COUNT}"
    
    if [ "${CRIT_COUNT}" -gt "0" ]; then
      echo "Build failed: ${CRIT_COUNT} Critical CVEs found"
      exit 1
    fi
    
    if [ "${HIGH_COUNT}" -gt "5" ]; then
      echo "Build failed: ${HIGH_COUNT} High CVEs exceeds threshold of 5"
      exit 1
    fi
```

**Automated alerting with Grype daemon:**

```bash
# Grype can be run as a daemon that watches an SBOM directory
# and alerts on new vulnerabilities
grype sbom:sbom.cyclonedx.json -o json \
  | jq '.matches[] | select(.vulnerability.severity | IN("Critical", "High")) | {id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name}' \
  | curl -X POST -H "Content-Type: application/json" \
    -d @- https://hooks.slack.com/services/YOUR_WEBHOOK
```

**Monitoring SBOMs across an entire Kubernetes cluster:**

```bash
# Get all unique images running in the cluster
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' \
  | sort -u > cluster-images.txt

# Generate SBOMs for all images
while IFS= read -r image; do
  name=$(echo "$image" | tr '/:' '_')
  syft "$image" -o cyclonedx-json > "sboms/${name}.cyclonedx.json"
  echo "Generated SBOM for: $image"
done < cluster-images.txt

# Scan all SBOMs and produce a cluster-wide vulnerability report
for sbom in sboms/*.cyclonedx.json; do
  echo "=== $sbom ==="
  grype "sbom:$sbom" --fail-on critical
done
```

---

## 9. As a DevSecOps / Kubernetes Security Engineer

In real-world environments, you own the SBOM workflow end-to-end. This means more than knowing the commands — it means building pipelines, enforcing policies, handling exceptions, and training your team.

**Day-to-day responsibilities involving SBOM workflows:**

**In CI/CD pipelines:** You integrate SBOM generation into every build. The pipeline does not complete without a signed SBOM attached to the image. Vulnerability scanning gates block promotion from `dev` to `staging` if Critical CVEs are found. You manage the `grype.yaml` configuration to tune thresholds and allowlists.

**In Kubernetes admission:** You configure `ImagePolicyWebhook` or OPA Gatekeeper to reject images that do not have a valid Cosign-signed SBOM attestation. This means no image can run in production unless it passed through your SBOM workflow.

```yaml
# OPA Gatekeeper policy — require SBOM attestation on all images
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireSBOMAttestation
metadata:
  name: require-sbom-attestation
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "DaemonSet", "StatefulSet"]
    namespaces: ["production"]
  parameters:
    cosignPublicKey: "-----BEGIN PUBLIC KEY-----..."
    attestationType: "cyclonedx"
```

**In incident response:** When a new zero-day is announced (e.g., another Log4Shell-type event), you immediately query your SBOM store to identify which running workloads contain the affected component. Without SBOMs, this process takes days of manual image inspection. With SBOMs, it takes minutes.

```bash
# "Do any of our running images contain log4j-core?"
for sbom in sboms/*.cyclonedx.json; do
  if jq -e '.components[] | select(.name == "log4j-core")' "$sbom" > /dev/null 2>&1; then
    echo "ALERT: log4j-core found in $(basename $sbom)"
  fi
done
```

**In compliance reporting:** You generate SBOM reports for auditors, customers, and regulators. You maintain SBOM archives tied to specific image digests for historical traceability. When a customer asks "what libraries were in the version of your product we were running 6 months ago?", you can answer precisely.

**In team enablement:** You write runbooks for how developers should interact with the SBOM workflow. You define what to do when a build is blocked by a CVE: Who approves exceptions? What is the VEX process? What is the SLA for fixing Critical findings?

**Common pitfalls you avoid:**

- Scanning images by tag (not digest) — tags are mutable; always scan by digest
- Not scanning transitive dependencies — Syft catches these; make sure your configuration enables deep scanning
- Ignoring "Medium" severity at scale — 50 unpatched Medium CVEs create more cumulative risk than 1 High
- Storing unsigned SBOMs — without integrity verification, an attacker can substitute a clean SBOM for a vulnerable one
- Only scanning at build time — continuous monitoring is mandatory; build-time scans miss CVEs disclosed post-build

---

## 10. Real Present-Day Scenarios

### Scenario 1: Log4Shell Response — 2021 (The SBOM Case Study)

In December 2021, CVE-2021-44228 (Log4Shell) was disclosed in Apache Log4j 2. It affected virtually every Java application that used logging. The critical differentiator between organisations was whether they had SBOMs.

- **Without SBOMs:** Teams spent 72–96 hours manually inspecting every Java application, grepping for `log4j` in JAR manifests, checking Maven dependencies one by one. Many missed transitive inclusions (log4j as a dependency of a dependency).
- **With SBOMs:** Teams queried their SBOM repository in minutes: `SELECT * FROM sbom_components WHERE name='log4j-core' AND version < '2.15.0'`. Complete affected inventory in under 30 minutes. Remediation started immediately.

**The lesson:** Build your SBOM workflow *before* the next zero-day, not after.

### Scenario 2: XZ Utils Backdoor — 2024

In March 2024, CVE-2024-3094 revealed that XZ Utils versions 5.6.0 and 5.6.1 contained a deliberate backdoor inserted by a malicious contributor. The backdoor affected systems using glibc and systemd (primarily Fedora and Debian testing/unstable).

- Organisations with SBOMs for their container images could immediately determine whether any image contained `xz-utils >= 5.6.0`.
- `grype sbom:*.cyclonedx.json | grep CVE-2024-3094` across all SBOMs gave an instant blast-radius report.
- Those without SBOMs had to pull and inspect every image manually — a process that took days across large fleets.

### Scenario 3: Dependency Confusion via SBOM Poisoning

A less-publicised attack vector: an attacker gains access to your SBOM storage (e.g., an S3 bucket with weak access controls) and replaces your SBOM with a crafted one that omits certain vulnerable components. Your Grype scanner sees a clean SBOM and gives the image a green light — but the actual image is still vulnerable.

**Defence:** Always sign SBOMs with Cosign before storing. Verify the signature before scanning. Never trust an unsigned SBOM pulled from storage.

```bash
# Before scanning, verify SBOM signature
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "https://github.com/myorg/myrepo" \
  myregistry.io/myapp:1.0.0 \
  | jq '.payload | @base64d | fromjson | .predicate' > verified-sbom.json

# Now scan the verified SBOM — not an unsigned one from storage
grype sbom:verified-sbom.json
```

### Scenario 4: Regulatory Audit — EU Cyber Resilience Act

A European enterprise receives an audit request under the EU Cyber Resilience Act (effective 2027). The auditor requests: "Provide machine-readable SBOMs for all versions of your product shipped in the last 12 months, with evidence that they were scanned for vulnerabilities."

- Their SBOM workflow automatically archives CycloneDX SBOMs for every release (stored alongside the image in the OCI registry as Cosign attestations).
- Grype scan reports are stored as CI/CD artefacts with timestamps, tied to specific image digests.
- The auditor receives a complete, verifiable history in hours.
- A competitor without an SBOM workflow scrambles to reconstruct 12 months of dependency history from source code — an incomplete and unverifiable process.

### Scenario 5: Supply Chain Attack via Compromised Base Image

A popular `node:18-alpine` base image is found to contain a malicious package injected between versions. Organisations pulling `node:18-alpine` without pinning to a digest are exposed.

- Teams with continuous SBOM monitoring receive alerts immediately when Grype's CVE database is updated with the new advisory.
- Policy-as-code in their Kubernetes admission controller blocks any new deployments using the compromised image digest.
- SBOMs for currently-running pods reveal exactly which workloads need immediate rollback.

---

## 11. What Happens If You Don't Follow This

**Without SBOM generation:**
- You have no inventory of what is in your software. You cannot answer "are we affected by CVE-X?" without manually inspecting every image.
- Compliance audits fail immediately — US EO 14028, EU CRA, and FedRAMP all require SBOMs.
- When a supply chain attack occurs, you have no basis for impact assessment.

**Without secure SBOM storage:**
- SBOMs can be modified after the fact (tampering), creating false compliance evidence.
- SBOM history is lost when images are pushed over. Historical traceability — critical for incident response — is impossible.
- An attacker who gains write access to your SBOM store can replace your SBOMs with clean fakes, bypassing your vulnerability gates.

**Without scanning:**
- Known, fixable vulnerabilities accumulate in production images. The longer they remain, the higher the probability of exploitation.
- The Equifax breach (2017) was caused by an unpatched Apache Struts vulnerability that had been public for months. Automated SBOM scanning with CI gates would have caught it before deployment.

**Without analysis and prioritisation:**
- Raw scanner output creates alert fatigue. Security teams drown in Medium CVEs that are not exploitable. Critical ones get lost in the noise.
- Without VEX, every "not affected" finding consumes engineering time investigating false positives.

**Without remediation:**
- Scanning without fixing is pure theatre — it gives the appearance of security without the substance.
- Organisations that generate SBOMs but have no remediation SLAs are often worse off than those with no SBOMs — they know about vulnerabilities but cannot demonstrate action.

**Without continuous monitoring:**
- An image that is clean on build day may be exploited on day 90 when a new CVE is published.
- Real-world examples: Kubernetes CVE-2018-1002105 (privilege escalation) and CVE-2019-11246 (kubectl path traversal) both affected images that were "clean" at build time. Without continuous monitoring, running workloads remained vulnerable for months after public disclosure.

---

## 12. Most Common Commands and Syntax

### Syft — SBOM Generation

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Basic generation
syft nginx:1.25                                        # Table output (human-readable)
syft nginx:1.25 -o spdx-json                          # SPDX JSON
syft nginx:1.25 -o cyclonedx-json                     # CycloneDX JSON
syft nginx:1.25 -o cyclonedx-xml                      # CycloneDX XML

# Multiple outputs
syft nginx:1.25 -o spdx-json=nginx.spdx.json -o cyclonedx-json=nginx.cdx.json

# Scan from various sources
syft /path/to/source/code -o spdx-json               # Local filesystem
syft docker-archive:image.tar -o cyclonedx-json       # Docker archive
syft oci-dir:/path/to/oci -o spdx-json               # OCI layout

# Filter
syft nginx:1.25 -o cyclonedx-json --exclude "/usr/share/**"
syft nginx:1.25 -o cyclonedx-json --catalogers=dpkg,apk  # Only specific catalogers
```

### Grype — SBOM Vulnerability Scanning

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan an SBOM
grype sbom:nginx-sbom.cyclonedx.json                  # Table output
grype sbom:nginx-sbom.spdx.json -o json               # JSON output
grype sbom:nginx-sbom.cyclonedx.json --fail-on critical  # Exit code 1 on Critical
grype sbom:nginx-sbom.cyclonedx.json --only-fixed     # Show only fixable CVEs

# Scan directly (Grype generates SBOM internally)
grype nginx:1.25
grype /path/to/source/code

# Apply VEX suppressions
grype sbom:nginx.cdx.json --vex vex-statements.json

# Update vulnerability database
grype db update

# List vulnerability database status
grype db status
```

### Trivy — Combined Scanning

```bash
# Install
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan image (generates SBOM internally)
trivy image nginx:1.25
trivy image --severity HIGH,CRITICAL nginx:1.25
trivy image --exit-code 1 --severity CRITICAL nginx:1.25  # Block on Critical

# Generate SBOM with Trivy
trivy image --format cyclonedx --output nginx.cdx.json nginx:1.25
trivy image --format spdx-json --output nginx.spdx.json nginx:1.25

# Scan a pre-existing SBOM
trivy sbom nginx-sbom.cyclonedx.json
trivy sbom --severity CRITICAL,HIGH nginx-sbom.cdx.json

# Scan Kubernetes cluster
trivy k8s --report summary cluster
trivy k8s --severity CRITICAL --report summary all

# Scan filesystem
trivy fs /path/to/code

# Output SARIF (for GitHub/GitLab security reports)
trivy image --format sarif --output results.sarif nginx:1.25
```

### Cosign — Image Signing and SBOM Attestation

```bash
# Install
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
mv cosign-linux-amd64 /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign

# Keyless signing (OIDC)
cosign sign --yes myregistry.io/myapp:1.0.0

# Key-based signing
cosign generate-key-pair                               # Creates cosign.key and cosign.pub
cosign sign --key cosign.key myregistry.io/myapp:1.0.0

# Attach CycloneDX SBOM as attestation
cosign attest --yes \
  --predicate sbom.cyclonedx.json \
  --type cyclonedx \
  myregistry.io/myapp:1.0.0

# Attach SPDX SBOM as attestation
cosign attest --yes \
  --predicate sbom.spdx.json \
  --type spdxjson \
  myregistry.io/myapp:1.0.0

# Verify image signature
cosign verify \
  --certificate-identity-regexp "https://github.com/myorg" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  myregistry.io/myapp:1.0.0

# Verify SBOM attestation and download
cosign verify-attestation \
  --type cyclonedx \
  myregistry.io/myapp:1.0.0 | jq '.payload | @base64d | fromjson | .predicate'

# Download SBOM from OCI registry
cosign download attestation myregistry.io/myapp:1.0.0
```

### Dependency-Track — Continuous Monitoring

```bash
# Upload SBOM via API
SBOM=$(base64 -w 0 sbom.cyclonedx.json)
curl -X PUT \
  -H "X-Api-Key: ${DTRACK_API_KEY}" \
  -H "Content-Type: application/json" \
  "https://dtrack.yourcompany.com/api/v1/bom" \
  -d "{\"projectName\":\"myapp\",\"projectVersion\":\"1.0\",\"autoCreate\":true,\"bom\":\"${SBOM}\"}"

# Get project vulnerability summary
curl -H "X-Api-Key: ${DTRACK_API_KEY}" \
  "https://dtrack.yourcompany.com/api/v1/metrics/project/PROJECT_UUID/current"

# Export findings as JSON
curl -H "X-Api-Key: ${DTRACK_API_KEY}" \
  "https://dtrack.yourcompany.com/api/v1/finding/project/PROJECT_UUID/export"
```

### OpenVEX — Vulnerability Exploitability Exchange

```bash
# Install OpenVEX CLI
go install github.com/openvex/vexctl@latest

# Create a VEX document
vexctl create \
  --author "security@yourorg.com" \
  --product "pkg:oci/myapp@sha256:abc123" \
  --vuln CVE-2020-11724 \
  --status not_affected \
  --justification "vulnerable_code_not_in_execute_path" > vex.json

# Merge multiple VEX documents
vexctl merge vex1.json vex2.json > merged-vex.json

# Attach VEX to OCI image
cosign attest --yes \
  --predicate vex.json \
  --type openvex \
  myregistry.io/myapp:1.0.0
```

---

## 13. Other Tools and Services Available

### SBOM Generation

| Tool | Strengths | Best For |
|------|-----------|----------|
| **Syft** (Anchore) | Widest ecosystem support (30+ package types), active development, Grype integration | General-purpose; container images + filesystems |
| **Trivy** (Aqua Security) | Combined SBOM generation + scanning, K8s cluster scanning, SARIF output | All-in-one scanning; K8s native environments |
| **cdxgen** (CycloneDX) | Excellent application-level SBOM from source code (Java, Node, Python, Go, Ruby) | Source code; CI/CD pipelines |
| **Microsoft SBOM Tool** | Integrates with Azure Pipelines, SPDX focused | Azure/Microsoft ecosystems |
| **Tern** | Container layer-by-layer analysis, licence detection | Deep image layer analysis |
| **OSS Review Toolkit (ORT)** | Full dependency resolution, licence scanning, SBOM generation | Enterprise compliance audits |
| **FOSSA** | Commercial; licence compliance + SBOM, legal review workflows | Enterprise licence management |
| **Black Duck** (Synopsys) | Commercial; deep binary scanning, code snippet detection | Enterprise; binary composition analysis |
| **Snyk** | Developer-friendly, integrates with IDEs, issue tracking | Developer-centric security |

### Vulnerability Scanning

| Tool | Strengths | Best For |
|------|-----------|----------|
| **Grype** (Anchore) | Purpose-built for SBOM scanning, fast, VEX support | SBOM-first vulnerability scanning |
| **Trivy** (Aqua) | All-in-one; K8s cluster scanning, secrets detection, IaC scanning | Kubernetes environments |
| **Clair** (Red Hat/Quay) | Mature, OCI registry integration, API-first | Registry-integrated scanning |
| **Snyk Container** | IDE integration, developer experience, fix PRs | Developer-centric workflows |
| **Wiz** | Cloud-native, agentless, runtime context | Cloud-native; AWS/GCP/Azure environments |
| **Lacework** | Behavioural analytics, anomaly detection, runtime | Runtime security + compliance |
| **Prisma Cloud** (Palo Alto) | Full cloud security platform | Enterprise cloud security |
| **Amazon Inspector** | Native AWS integration, Lambda scanning, ECR scanning | AWS environments |
| **Google Artifact Analysis** | Native GCP; automatic scanning on push to Artifact Registry | GCP environments |

### Continuous SBOM Monitoring

| Tool | Type | Key Feature |
|------|------|------------|
| **Dependency-Track** (OWASP) | Open-source | CycloneDX native; policy engine; BOM diff; REST API |
| **Grype** (daemon mode) | Open-source | Lightweight; good for small deployments |
| **GUAC** (Google) | Open-source | Graph-based; aggregate SBOMs across entire org; query "blast radius" |
| **Kusari** | Commercial | SBOM as a service; SLSA verification |
| **Anchore Enterprise** | Commercial | Enterprise Grype + Syft + policy engine |
| **JFrog Xray** | Commercial | Embedded in JFrog Artifactory; transitive dep scanning |
| **Rezilion** | Commercial | Runtime exploitability analysis; reduces noise by 95%+ |
| **Finite State** | Commercial | IoT/embedded device SBOM management |

### Image Signing and Verification

| Tool | Use Case |
|------|----------|
| **Cosign** (Sigstore) | Image signing + SBOM attestation (keyless via OIDC) |
| **Notation** (Notary v2) | CNCF standard; OCI registry native |
| **GPG + skopeo** | Traditional signing; air-gapped environments |
| **SPIFFE/SPIRE** | Workload identity; complements image signing |

### Policy Enforcement

| Tool | Use Case |
|------|----------|
| **OPA Gatekeeper** | Kubernetes admission — enforce SBOM presence, signature verification |
| **Kyverno** | Kubernetes-native policy; simpler DSL than OPA |
| **ImagePolicyWebhook** | Kubernetes built-in; allow/deny images based on policy |
| **Connaisseur** | Kubernetes admission; validates Cosign/Notary signatures |

---

## 14. How AI Is Impacting SBOM Workflows

### AI-Powered SBOM Generation Accuracy

Traditional SBOM generators rely on package managers and manifest files. AI models trained on code can now detect components that manifest-based tools miss — particularly in cases where developers have vendored dependencies (copy-paste of library code without a package manager entry), used obfuscated or minified code, or embedded binaries.

- **Google's OSV-SCALIBR** uses ML to improve accuracy of package identification in language-agnostic binary scanning.
- **AI-powered Syft plugins** are being developed to identify components from compiled binaries using function signature matching.
- **LLM-assisted SBOM auditing** — tools like Chainguard's AI layer analysis can describe what a container image's layers are doing in natural language, helping humans review auto-generated SBOMs for accuracy.

### AI in Vulnerability Triage and Prioritisation

The hardest part of SBOM workflows is not generating the SBOM or running Grype — it is deciding which of the 200 CVEs in a large image actually need to be fixed today. AI is transforming this:

- **Exploitability scoring** — Models trained on exploit databases predict the probability that a given CVE will be actively exploited in the next 30 days. EPSS (Exploit Prediction Scoring System) is the leading open model; tools like Rezilion and Wiz integrate EPSS scores alongside CVSS.
- **Reachability analysis** — AI models analyse call graphs to determine whether the vulnerable function in a dependency is actually invoked by your application code. Only reachable vulnerabilities need immediate patching. Snyk and Endor Labs are leaders here.
- **VEX automation** — Instead of security engineers manually writing VEX statements, AI can analyse code and determine whether a vulnerable code path is reachable, then auto-generate VEX statements. This is still early-stage but commercially available from Chainguard and Anchore.

### AI-Generated Remediation Guidance

When Grype identifies CVE-2020-11724 in `libnginx-mod-http-xslt-filter 1.10.3-1+deb9u3`, it tells you what is vulnerable. AI tools take the next step:

- **GitHub Copilot Autofix** — Integrated into GitHub's dependency scanning, it generates pull requests that update vulnerable dependencies in `package.json`, `requirements.txt`, or `pom.xml` automatically.
- **Dependabot + AI** — Microsoft Research is developing AI enhancement to Dependabot that assesses whether an automated dependency update will break tests, reducing developer resistance to automated patches.
- **Dockerfile remediation bots** — Tools like Renovate Bot with AI scoring prioritise which Dockerfile `FROM` base image updates to apply based on vulnerability impact vs update risk.

### AI in SBOM Monitoring and Anomaly Detection

- **SBOM drift detection** — ML models learn the expected component composition of an image over time and flag unexpected additions (e.g., a new package appears between builds that was not added intentionally — potential supply chain compromise).
- **Temporal anomaly detection** — AI tracks the velocity of new CVEs against your SBOM components. A sudden spike in advisories against a component you heavily depend on triggers an alert before any specific CVE is publicly confirmed.
- **GUAC with graph ML** — Google's GUAC (Graph for Understanding Artifact Composition) is building ML-powered queries that can answer questions like "given this newly disclosed CVE, which of our 10,000 microservices are transitively affected?" across an org-wide graph of SBOMs.

### AI and SBOM in the Era of AI Models Themselves

A meta-challenge: AI models (LLMs, image classifiers, etc.) are themselves software artefacts with dependencies. The concept of ML-BOM (Machine Learning Bill of Materials) is emerging:

- **CycloneDX 1.6** introduced the MLBOM subspec — covering datasets, model weights, training parameters, and their provenance.
- **AI supply chain attacks** are real: poisoned training datasets, malicious model weights uploaded to HuggingFace, malicious Jupyter notebooks with hidden payloads.
- SBOM workflows are being extended to cover ML pipelines — tracking which dataset version was used, which training framework, which model checkpoint — exactly as traditional SBOMs track library versions.

---

## 15. CKS Exam Tips

The CKS exam tests whether you can perform SBOM-related operations in a live Kubernetes cluster. Focus on practical execution, not theory.

**High-probability exam tasks:**

1. **Generate an SBOM from a container image using Syft:**
   ```bash
   syft nginx:1.25 -o cyclonedx-json > nginx-sbom.json
   syft nginx:1.25 -o spdx-json > nginx-sbom.spdx.json
   ```

2. **Scan an SBOM for vulnerabilities using Grype:**
   ```bash
   grype sbom:nginx-sbom.json
   grype sbom:nginx-sbom.json -o json | jq '.matches[].vulnerability.id'
   grype sbom:nginx-sbom.json --fail-on critical
   ```

3. **Use Trivy to scan an image or SBOM:**
   ```bash
   trivy image nginx:1.25
   trivy sbom nginx-sbom.json
   trivy image --format cyclonedx --output sbom.json nginx:1.25
   ```

4. **Know the 6-step SBOM workflow** — if asked to describe or diagram it: Generate → Store → Scan → Analyze → Remediate → Monitor.

5. **Know which format to use when:**
   - SPDX → open-source, licensing, government projects
   - CycloneDX → vulnerability management, VEX, Dependency-Track integration

6. **Understand CVE JSON output from Grype** — be able to read the `vulnerability.id`, `severity`, `artifact.name`, `artifact.version`, and `matched-by` fields.

7. **Know the remediation flow** — after Grype finds a CVE: update the Dockerfile base image or package version, rebuild, regenerate SBOM, rescan to confirm the CVE is gone.

**Key command mnemonics for the exam:**

```
syft <image> -o cyclonedx-json     → Generate CycloneDX SBOM
syft <image> -o spdx-json         → Generate SPDX SBOM
grype sbom:<file>                  → Scan SBOM for CVEs
grype sbom:<file> --fail-on critical → Gate on Critical severity
trivy image <image>                → Scan image directly
trivy sbom <file>                  → Scan SBOM with Trivy
```

**Common traps:**

- The exam may say "scan the SBOM" — use `grype sbom:filename.json` (note the `sbom:` prefix — without it, Grype treats the argument as an image name, not an SBOM file)
- If asked to generate for a registry image, make sure the image is pullable in the exam environment — authenticate first if needed: `docker login <registry>`
- Know the difference between `syft nginx:1.25` (scans the image) and `syft /path/to/dir` (scans a directory)

---

## 16. Extra Information and References

### NTIA Minimum Elements in SBOM Context

The SBOM workflow must produce SBOMs that meet NTIA minimum elements. The Syft + Grype workflow satisfies all of these:

| NTIA Element | Syft Output Field |
|---|---|
| Supplier Name | `component.supplier` / `packageSupplier` |
| Component Name | `component.name` / `packageName` |
| Component Version | `component.version` / `packageVersion` |
| Other Unique Identifiers | PURL (`component.purl`) / CPE |
| Dependency Relationships | `dependencies[]` / DESCRIBES / CONTAINS |
| Author of SBOM | `metadata.authors` / `documentNamespace` |
| Timestamp | `metadata.timestamp` / `created` |

### SBOM Storage in OCI Registries — The Referrers API

OCI 1.1 introduced the Referrers API — a standard way to attach artefacts (SBOMs, signatures, attestations) to an existing image without modifying it. Cosign uses this API for attestations.

```bash
# List all referrers (SBOMs, signatures, attestations) attached to an image
cosign triangulate myregistry.io/myapp:1.0.0

# In registries supporting OCI 1.1 natively
oras discover myregistry.io/myapp@sha256:<digest>
```

### The SLSA Connection

SBOM workflows are a core part of SLSA (Supply chain Levels for Software Artefacts) compliance:

- **SLSA Level 1:** Provenance exists (basic SBOM generation satisfies this)
- **SLSA Level 2:** Provenance is hosted and signed (SBOM + Cosign signature satisfies this)
- **SLSA Level 3:** Provenance is produced by isolated build systems (CI/CD-generated signed SBOMs in ephemeral builders satisfies this)
- **SLSA Level 4 (roadmap):** Two-party review + hermetic builds

```bash
# Verify SLSA provenance (using slsa-verifier)
slsa-verifier verify-image myregistry.io/myapp:1.0.0 \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.0.0
```

### Relevant Standards and Frameworks

- **NTIA Minimum Elements for SBOM** — https://www.ntia.gov/sbom
- **US Executive Order 14028** — Mandates SBOM for federal software procurement (May 2021)
- **EU Cyber Resilience Act (CRA)** — Requires SBOM for CE-marked digital products (effective 2027)
- **NIST SP 800-218 (SSDF)** — Secure Software Development Framework; SBOM as evidence of practice
- **CISA SBOM Resources** — https://www.cisa.gov/sbom
- **OpenSSF SBOM Everywhere SIG** — Working group on SBOM tooling standards
- **OWASP CycloneDX** — https://cyclonedx.org
- **SPDX Specification** — https://spdx.github.io/spdx-spec
- **OSV (Open Source Vulnerabilities)** — https://osv.dev — open vulnerability database used by Grype/Trivy
- **EPSS** — Exploit Prediction Scoring System — https://www.first.org/epss

### Syft Configuration File

```yaml
# ~/.syft.yaml or .syft.yaml in project root
output:
  - "cyclonedx-json"
  - "spdx-json"

file:
  metadata:
    digests:
      - "sha256"
      - "sha1"

package:
  search-unindexed-archives: true
  search-indexed-archives: true

catalogers:
  default-catalogers:
    - dpkg
    - rpm
    - apk
    - go-module
    - python
    - javascript-package
    - java
    - ruby-gemfile
    - cargo

exclude:
  - "/tmp/**"
  - "/var/cache/**"
```

### Grype Configuration File

```yaml
# ~/.grype.yaml or .grype.yaml in project root
output: "table"
file: ""
distro: ""
add-cpes-if-none: false
output-template-file: ""
check-for-app-update: true
only-fixed: false
platform: ""
fail-on-severity: ""
match:
  java:
    using-cpes: true
  dotnet:
    using-cpes: true

ignore:
  # Ignore known false positives
  - vulnerability: CVE-2020-11724
    fix-state: not-fixed
    package:
      name: libnginx-mod-http-xslt-filter

db:
  cache-dir: "$XDG_CACHE_HOME/grype/db"
  update-url: "https://toolbox-data.anchore.io/grype/databases/listing.json"
  auto-update: true
```

### References

- [Syft GitHub Repository](https://github.com/anchore/syft)
- [Grype GitHub Repository](https://github.com/anchore/grype)
- [Trivy Documentation](https://aquasecurity.github.io/trivy)
- [Cosign / Sigstore Documentation](https://docs.sigstore.dev)
- [OWASP Dependency-Track](https://dependencytrack.org)
- [GUAC — Graph for Understanding Artifact Composition](https://guac.sh)
- [OpenVEX](https://github.com/openvex/vexctl)
- [SLSA Framework](https://slsa.dev)
- [NVD — National Vulnerability Database](https://nvd.nist.gov)
- [OSV — Open Source Vulnerabilities](https://osv.dev)
- [EPSS — Exploit Prediction Scoring System](https://www.first.org/epss)
- [KodeKloud CKS Course — SBOM Workflow](https://learn.kodekloud.com/user/courses/certified-kubernetes-security-specialist-cks/module/e4511664-185f-4204-9aa2-b4250cbadf84/lesson/3a467f49-70a7-4b61-bd44-f3cb004c32b8)
