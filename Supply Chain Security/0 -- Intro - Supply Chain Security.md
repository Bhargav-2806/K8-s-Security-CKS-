# Supply Chain Security — Module Introduction

> **Module:** Supply Chain Security | **CKS Domain Weight:** 20% | **Chapters:** 10

---

## Table of Contents

1. [What Is Supply Chain Security?](#1-what-is-supply-chain-security)
2. [Why This Module Matters](#2-why-this-module-matters)
3. [The Threat Landscape — Attacks That Shaped This Field](#3-the-threat-landscape--attacks-that-shaped-this-field)
4. [The Four-Stage Supply Chain Model](#4-the-four-stage-supply-chain-model)
5. [Chapter-by-Chapter Breakdown](#5-chapter-by-chapter-breakdown)
6. [How the Chapters Connect — The Learning Path](#6-how-the-chapters-connect--the-learning-path)
7. [Key Tools Covered in This Module](#7-key-tools-covered-in-this-module)
8. [As a DevSecOps / Kubernetes Security Engineer](#8-as-a-devsecops--kubernetes-security-engineer)
9. [Real Present-Day Scenarios — Cross-Cutting Themes](#9-real-present-day-scenarios--cross-cutting-themes)
10. [What Happens If You Ignore Supply Chain Security](#10-what-happens-if-you-ignore-supply-chain-security)
11. [How AI Is Impacting the Entire Supply Chain](#11-how-ai-is-impacting-the-entire-supply-chain)
12. [CKS Exam Coverage for This Module](#12-cks-exam-coverage-for-this-module)
13. [Key Concepts Quick Reference](#13-key-concepts-quick-reference)

---

## 1. What Is Supply Chain Security?

Software supply chain security is the practice of securing every link in the chain that connects source code to running containers in your Kubernetes cluster. It is not a single tool or a single check — it is a discipline that spans the entirety of how software is built, packaged, distributed, and deployed.

The "supply chain" metaphor is deliberate. In traditional manufacturing, a supply chain compromise happens when an attacker tampers with a component before it reaches the final assembly line — bad bolts delivered to an aircraft factory, for example. In software, the equivalent is an attacker compromising a dependency, a build tool, a container registry, or a CI/CD pipeline, and inserting malicious code before the software reaches production. The software looks legitimate — it came from a trusted source — but it has been tampered with.

In the context of Kubernetes, the supply chain encompasses:

```
Developer's IDE
    ↓  writes code using open-source dependencies
Source Repository (Git)
    ↓  code is committed, reviewed, merged
CI/CD Pipeline
    ↓  code is built into a container image
Container Registry
    ↓  image is stored and distributed
Kubernetes Admission
    ↓  image is pulled and validated before running
Running Pod
    ↓  container executes with runtime protections
```

Each arrow in this chain is a potential attack vector. Supply chain security applies controls at every stage to ensure that what comes out the end — a running Kubernetes workload — is exactly what the developer intended, with no tampering, no known vulnerabilities, and no unauthorised components.

---

## 2. Why This Module Matters

Supply chain security carries **20% of the CKS exam weight** — the largest single domain. That weighting reflects its real-world significance: supply chain attacks have consistently been among the most damaging and difficult to detect breaches of the past decade.

But beyond the exam, supply chain security matters because:

**The attack surface is enormous and largely invisible.** The average Node.js application has 683 transitive dependencies. A Python Django application may have 200+. A Java Spring Boot application may pull in 500+ JAR files. Most developers can name their direct dependencies; almost none can name their transitive ones. Each of those packages is a potential attack vector — and attackers know this.

**Default Kubernetes provides no supply chain controls.** A fresh Kubernetes cluster will happily run any container image from any registry, built by anyone, with any content, with no verification, no scanning, and no record of what is inside. Supply chain controls are entirely opt-in — this module teaches you what to opt into.

**Regulatory and compliance requirements are now explicit.** US Executive Order 14028 (May 2021) mandated that federal agencies require SBOMs from software vendors. The EU Cyber Resilience Act (effective 2027) requires machine-readable SBOMs for all CE-marked digital products. FedRAMP, PCI-DSS, SOC 2, and ISO 27001 all reference software supply chain controls. This is no longer optional for organisations in regulated industries.

**The SLSA framework formalises what "good" looks like.** The Supply chain Levels for Software Artefacts (SLSA) framework, developed by Google and now a CNCF specification, provides a maturity model from Level 0 (no controls) to Level 3 (hermetic, verified builds with signed provenance). This module covers the practices that achieve SLSA Level 1-3.

---

## 3. The Threat Landscape — Attacks That Shaped This Field

Supply chain security is not theoretical. The controls in this module were motivated by a series of real, high-impact attacks:

### SolarWinds (2020)
Attackers (Russian state-sponsored group Cozy Bear) compromised the build system of SolarWinds — a network monitoring software company. They inserted a backdoor called SUNBURST into SolarWinds Orion software during the build process, before the legitimate SolarWinds signing ceremony. The signed, legitimate-looking update was distributed to 18,000 customers, including US government agencies and Fortune 500 companies. The compromise went undetected for 9 months.

**What it teaches:** Build system integrity is not optional. Even signing the final artefact is insufficient if the build system is compromised. SLSA Level 3 (isolated, hermetic builds with verified provenance) directly addresses this.

### Log4Shell — CVE-2021-44228 (2021)
A remote code execution vulnerability with a CVSS score of 10.0 was discovered in Apache Log4j 2 — a Java logging library used transitively by thousands of applications. Most affected organisations didn't know they used Log4j at all, because it was a dependency of a dependency of a dependency. The exploitation was trivial (a single log statement could trigger it) and weaponised within hours of disclosure.

**What it teaches:** Transitive dependency visibility is critical. Without SBOMs and continuous scanning (Trivy, Grype), organisations had no way to quickly identify exposure. With SBOMs, the blast radius was clear in minutes.

### Codecov (2021)
Attackers compromised Codecov's CI/CD pipeline and modified the Bash uploader script that thousands of companies used in their own CI/CD pipelines. The modified script exfiltrated environment variables (including API keys, secrets, and credentials) from any CI/CD system that ran it. The compromise lasted 2 months before detection, affecting thousands of organisations including Twilio, Hashicorp, and Atlassian.

**What it teaches:** CI/CD pipeline integrity and the danger of pulling scripts from external URLs without verification. Any `curl <url> | bash` pattern in a CI/CD pipeline is a potential supply chain attack vector.

### XZ Utils Backdoor — CVE-2024-3094 (2024)
A patient, sophisticated attacker spent two years building trust in the XZ Utils open-source project under a fictitious identity. Once they gained commit access, they inserted a backdoor into XZ Utils versions 5.6.0 and 5.6.1 that would have allowed SSH authentication bypass on any system using glibc and systemd. It was accidentally discovered before widespread deployment by a Microsoft engineer who noticed that SSH logins were 500ms slower than expected.

**What it teaches:** Insider threats and social engineering target open-source maintainers, not just corporate employees. SBOM generation and continuous scanning would have flagged affected versions immediately after CVE disclosure.

### Dependency Confusion (2021)
Security researcher Alex Birsan published a paper describing how he was able to execute code inside Apple, Microsoft, PayPal, and 35 other companies by uploading packages with the same name as internal packages to public registries (npm, PyPI, Ruby Gems). Build systems that were configured to check public registries before private ones would pull the malicious public package instead of the internal one.

**What it teaches:** Registry allowlisting (Chapter 9) and private registry precedence configuration are essential. If your build system can pull from public registries, an attacker can weaponise the naming system against you.

---

## 4. The Four-Stage Supply Chain Model

Supply chain security controls map to four stages of the software lifecycle. This module covers each stage:

```
┌─────────────────────────────────────────────────────────────────┐
│  Stage 1: SOURCE                                                 │
│  Where code and dependencies originate                          │
│  Controls: Dependency management, SBOM generation from source,  │
│            code signing, branch protection, peer review         │
│  Covered in: Ch. 3 (SBOM), Ch. 5 (SBOM Format)                │
├─────────────────────────────────────────────────────────────────┤
│  Stage 2: BUILD                                                  │
│  Where source becomes a container image                         │
│  Controls: Minimal base images, multi-stage builds,             │
│            SLSA provenance, signed builds, no secrets in layers │
│  Covered in: Ch. 4 (Minimize Base Image)                       │
├─────────────────────────────────────────────────────────────────┤
│  Stage 3: TEST / DISTRIBUTE                                      │
│  Where images are scanned, signed, and stored                   │
│  Controls: Vulnerability scanning, SBOM attachment, signing,    │
│            private registry, image policy, SBOM workflow        │
│  Covered in: Ch. 6 (SBOM Workflow), Ch. 8 (Image Security),    │
│              Ch. 10 (Trivy Scanning)                            │
├─────────────────────────────────────────────────────────────────┤
│  Stage 4: DEPLOY / RUN                                           │
│  Where images run as pods in Kubernetes                         │
│  Controls: ImagePolicyWebhook, registry allowlisting,           │
│            admission control, KubeLinter, runtime enforcement   │
│  Covered in: Ch. 7 (KubeLinter), Ch. 9 (Registry Allowlist)   │
└─────────────────────────────────────────────────────────────────┘
```

**Cross-cutting controls** (apply across all stages):
- **SBOM** (Chapters 3, 5, 6) — Component inventory that enables all other controls
- **Signing** (Cosign/Sigstore) — Cryptographic proof of authenticity at each stage
- **Policy as code** (OPA, Kyverno) — Machine-enforceable rules that prevent human error

---

## 5. Chapter-by-Chapter Breakdown

### Chapter 1 — Overview of Supply Chain Security
**Core topic:** What supply chain security is, why it matters, and the SLSA framework (Levels 0-3).

Introduces the concept of a software supply chain, the four-stage model (Source, Build, Test, Deploy), and the SLSA framework for measuring supply chain maturity. Covers real-world attacks (SolarWinds, Log4Shell, XZ Utils, Codecov) and the ecosystem of tools and standards.

**Key concepts:** SLSA levels, supply chain threat model, 4-stage model, provenance.

---

### Chapter 2 — Risks of Inadequate Supply Chain Management
**Core topic:** What goes wrong when supply chain controls are absent or weak.

Eight distinct risk categories: unverified open-source components, compromised build pipelines, insecure artefact storage, insufficient vulnerability management, lack of provenance verification, unsigned container images, dependency confusion, and compromised CI/CD. For each: attack mechanics, real-world examples, and specific mitigations.

**Key concepts:** Dependency confusion, typosquatting, CI/CD compromise, unsigned images, lack of provenance.

---

### Chapter 3 — What Is SBOM and Why It's Important
**Core topic:** Software Bill of Materials — the foundational inventory that makes all other supply chain controls possible.

Explains what an SBOM is (a structured, machine-readable inventory of every component in a software artefact), why it matters (Log4Shell as the case study), the regulatory push (EO 14028, EU CRA), NTIA minimum elements, VEX (Vulnerability Exploitability eXchange), and how SBOMs integrate with Cosign attestations.

**Key concepts:** SBOM definition, NTIA 7 minimum elements, EO 14028, VEX, Cosign attestation, SBOMs in CI/CD.

---

### Chapter 4 — Minimize Base Image Footprint
**Core topic:** Container image hygiene — reducing attack surface by keeping images as small as possible.

Multi-stage Docker builds (for Go, Python, Java, Node.js), distroless images, Chainguard images, `FROM scratch`, layer anatomy, image size vs vulnerability count tradeoffs, and `.dockerignore`. The principle: every package not in the image is a CVE that cannot be in the image.

**Key concepts:** Multi-stage builds, distroless, Chainguard, `FROM scratch`, layer minimisation, `.dockerignore`.

---

### Chapter 5 — SBOM Format
**Core topic:** SPDX and CycloneDX — the two dominant SBOM standards, their structure, differences, and when to use each.

Deep dive into both formats with real JSON/tag-value examples. SPDX 3.0 changes (AI Profile, Security Profile, JSON-LD). CycloneDX 1.6 features (CBOM, ML BOM, Attestations, embedded VEX). PURL (Package URL) standard. NTIA minimum elements mapped to both formats. Side-by-side comparison table.

**Key concepts:** SPDX, CycloneDX, PURL, NTIA elements, VEX in CycloneDX, format selection criteria.

---

### Chapter 6 — SBOM Workflow
**Core topic:** The six-stage operational SBOM lifecycle — from generation through continuous monitoring.

The complete SBOM workflow: Generate (Syft) → Store (Cosign attestation, Dependency-Track) → Scan (Grype) → Analyze (CVSS, VEX, alert fatigue) → Remediate (Dockerfile updates, dependency upgrades) → Monitor (Dependency-Track continuous scanning, CI gates). Includes CVE-2020-11724 analysis example from KodeKloud.

**Key concepts:** Syft, Grype, 6-step workflow, Cosign attestation storage, VEX, Dependency-Track, CI gates.

---

### Chapter 7 — Introduction to KubeLinter
**Core topic:** Static analysis for Kubernetes manifest files — catching misconfigurations before they reach the cluster.

KubeLinter's three-stage workflow (Configurable Checks → Analysis → Report). The anatomy of a misconfigured Kubernetes manifest (7 problems in one YAML). All 30+ built-in checks categorised by security/image/reliability/resource. Custom rules via `.kube-linter.yaml`. CI/CD integration (Jenkins, GitHub Actions, GitLab, ArgoCD). Per-resource suppression with annotations.

**Key concepts:** `kube-linter lint .`, check categories, misconfigured manifest anatomy, CI/CD gates, `ignore-check` annotations.

---

### Chapter 8 — Image Security
**Core topic:** Container image naming conventions, registries, private registry authentication, and imagePullSecrets.

Full image name anatomy (registry/namespace/repository:tag@digest). How Kubernetes resolves short image names. Tag vs digest immutability. Public vs private registries. Creating docker-registry Secrets. `imagePullSecrets` in pod specs and ServiceAccounts. `imagePullPolicy` tradeoffs. Image signing with Cosign. Admission verification with Kyverno and Connaisseur.

**Key concepts:** `kubectl create secret docker-registry`, `imagePullSecrets`, image name resolution, digest pinning, `imagePullPolicy`, Cosign signing.

---

### Chapter 9 — Whitelist Allowed Registries / Image Policy Webhook
**Core topic:** Enforcing that only images from approved registries can run in the cluster — four implementation approaches.

Four approaches: Custom Validating Webhook (Python example), OPA Gatekeeper with Rego, Kyverno ClusterPolicy, and the built-in `ImagePolicyWebhook` admission controller. For `ImagePolicyWebhook`: `AdmissionConfiguration` file, webhook kubeconfig, enabling in kube-apiserver static pod, volume mounts, and the critical `defaultAllow` security decision.

**Key concepts:** `ImagePolicyWebhook`, `AdmissionConfiguration`, `--enable-admission-plugins`, `defaultAllow`, OPA Rego deny rule, Kyverno registry allowlist.

---

### Chapter 10 — Scan Images for Known Vulnerabilities (Trivy)
**Core topic:** Vulnerability scanning with Trivy — from CVE fundamentals to CI/CD integration and continuous monitoring.

CVE system and CVSS scoring (severity scale, CVSS v2 vs v3, CVE-2020-5911 example). Trivy installation and basic image scanning (`trivy image nginx:1.18.0`). Output interpretation (5-column table, summary line). Severity filtering (`--severity CRITICAL,HIGH`), `--ignore-unfixed`, tar archive scanning (`--input`). Output formats (JSON, SARIF, CycloneDX). CI/CD integration. Trivy Operator for continuous cluster monitoring. Alpine vs Debian comparison.

**Key concepts:** `trivy image`, `--severity`, `--ignore-unfixed`, `--input`, `--exit-code 1`, CVE, CVSS, Alpine vs Debian, Trivy Operator.

---

## 6. How the Chapters Connect — The Learning Path

The chapters in this module build on each other. Understanding the progression makes each chapter richer:

```
Ch. 1 (Overview) + Ch. 2 (Risks)
  → Establish the "why" — what the threat landscape looks like and what
    happens without controls. Foundation for everything that follows.
        ↓
Ch. 3 (SBOM) + Ch. 5 (SBOM Format) + Ch. 6 (SBOM Workflow)
  → The SBOM trilogy. Ch. 3 is the concept, Ch. 5 is the formats (SPDX/CycloneDX),
    Ch. 6 is the operational workflow (Generate→Store→Scan→Analyze→Remediate→Monitor).
    SBOMs are the inventory layer that enables vulnerability management.
        ↓
Ch. 4 (Minimize Base Image)
  → Reduce attack surface at the source. Fewer packages = fewer CVEs.
    Directly reduces the findings that Ch. 10 (Trivy) would surface.
        ↓
Ch. 10 (Trivy Scanning)
  → Scan images to find CVEs. Works on both the base image (which Ch. 4 minimises)
    and application dependencies (which Ch. 3 inventories in the SBOM).
        ↓
Ch. 8 (Image Security)
  → Control which images are used and from where. Registry management,
    imagePullSecrets, image signing — the distribution layer.
        ↓
Ch. 9 (Registry Allowlisting / ImagePolicyWebhook)
  → Enforce at the cluster level that only approved-registry images can run.
    The admission gate that enforces Ch. 8's registry strategy.
        ↓
Ch. 7 (KubeLinter)
  → Static analysis on the Kubernetes manifests themselves (not the images).
    Catches misconfigurations in how images are referenced and pods are configured.
    Complements Ch. 9 (which checks registry) with checks on the pod spec itself.
```

**The defence-in-depth model this module builds:**

```
Layer 1: Source/Build
  Ch. 4 — Minimal base image → fewer CVEs from the start

Layer 2: Artefact Inventory
  Ch. 3, 5, 6 — SBOM → know everything in the image

Layer 3: Vulnerability Detection
  Ch. 6, 10 — Trivy + Grype → find CVEs in the inventory

Layer 4: Distribution Control
  Ch. 8 — Registry management → control where images come from

Layer 5: Admission Enforcement
  Ch. 9 — Registry allowlisting → enforce approved sources
  Ch. 7 — KubeLinter → enforce secure manifest configuration

Layer 6: Continuous Monitoring
  Ch. 6 — SBOM workflow monitoring → re-scan as new CVEs emerge
  Ch. 10 — Trivy Operator → cluster-wide continuous scanning
```

Each layer assumes the previous one can be bypassed — that is the nature of defence in depth. Together they make a comprehensive supply chain security posture.

---

## 7. Key Tools Covered in This Module

| Tool | Purpose | Chapter(s) |
|------|---------|-----------|
| **Syft** | SBOM generation from container images and filesystems | 6 |
| **Grype** | SBOM-based vulnerability scanning | 6 |
| **Trivy** | Combined image scanning + SBOM generation + K8s cluster scanning | 6, 10 |
| **Cosign** | Container image signing and SBOM attestation (Sigstore) | 3, 6, 8 |
| **KubeLinter** | Static analysis of Kubernetes manifest files | 7 |
| **OPA Gatekeeper** | Policy-as-code admission control (Rego language) | 9 |
| **Kyverno** | YAML-native Kubernetes policy enforcement | 9 |
| **ImagePolicyWebhook** | Built-in K8s admission controller for image policy | 9 |
| **Dependency-Track** | Continuous SBOM monitoring and vulnerability management | 6 |
| **Harbor** | Self-hosted private registry with built-in scanning | 8 |
| **Docker** | Container image build, tag, push, save, login | 4, 8 |
| **OpenVEX / vexctl** | Vulnerability Exploitability eXchange statements | 6 |
| **GUAC** | Graph for Understanding Artifact Composition | 6 |

**Tool relationships:**

```
BUILD PHASE:
  Docker (build) → Syft (generate SBOM) → Cosign (sign image + attest SBOM)
                                         → Trivy (scan image)

STORE PHASE:
  Registry (Harbor, ECR, GAR) ← Docker push (signed image)
  Dependency-Track ← SBOM upload via API

GATE PHASE (CI/CD):
  Grype sbom:<file> → CVE findings → fail if Critical
  KubeLinter lint . → manifest issues → fail if security checks fail
  trivy image --exit-code 1 → CVE findings → fail if Critical

DEPLOY PHASE (Kubernetes Admission):
  ImagePolicyWebhook → check image registry
  OPA Gatekeeper / Kyverno → enforce registry allowlist + manifest policy
  Cosign verify-attestation → check image is signed

MONITOR PHASE:
  Trivy Operator → continuous cluster scanning
  Dependency-Track → continuous SBOM monitoring, new CVE alerts
```

---

## 8. As a DevSecOps / Kubernetes Security Engineer

Supply chain security is arguably the highest-leverage area for a DevSecOps engineer. A single well-configured Trivy gate in CI/CD prevents all vulnerable images from reaching production. A single registry allowlist policy prevents all images from unapproved sources. These are multiplicative controls — they apply to every workload, every team, every deployment.

Your supply chain security responsibilities span the entire SDLC:

**At the development stage:** You define the approved base image catalogue. You provide Dockerfile templates that embed multi-stage build patterns and use the approved minimal base images. You integrate KubeLinter into pre-commit hooks and IDE plugins so developers get feedback before they even push.

**At the CI/CD stage:** You build the scanning pipeline. Every build triggers `syft` (SBOM generation) + `trivy image` (vulnerability scan) + `kube-linter lint` (manifest analysis). You define the severity thresholds that gate promotion. You manage `.trivyignore` and `ignore-check` annotations — ensuring every suppression has a documented justification and a review date.

**At the registry stage:** You configure the private registry (Harbor, ECR, GAR). You enforce that only Cosign-signed, Trivy-scanned images can be promoted to the production namespace. You manage RBAC on the registry — developers can push to `dev`, only the CI/CD service account can push to `prod`.

**At the deployment stage:** You configure `ImagePolicyWebhook` or OPA Gatekeeper/Kyverno to enforce registry allowlisting. You ensure kube-apiserver static pod manifests include the correct flags and file mounts. You manage the `defaultAllow` decision (fail-open vs fail-closed) and ensure the webhook is HA.

**At the monitoring stage:** You deploy Trivy Operator and configure Prometheus alerts on Critical vulnerability counts. You connect Dependency-Track to receive SBOM uploads from CI/CD and alert when new CVEs are published against known components. You define the incident response runbook for "new Critical CVE in production image."

**Your supply chain maturity targets by SLSA level:**

```
SLSA Level 1 (Baseline — achievable immediately):
  ✓ Generate SBOMs for all builds (Ch. 3, 5, 6)
  ✓ Scan images with Trivy in CI/CD (Ch. 10)
  ✓ Use private registry (Ch. 8)

SLSA Level 2 (Standard — achievable in 1-3 months):
  ✓ Sign images with Cosign (Ch. 8)
  ✓ Attach SBOM as Cosign attestation (Ch. 6)
  ✓ Enforce registry allowlisting (Ch. 9)
  ✓ Use minimal base images (Ch. 4)
  ✓ KubeLinter in CI/CD (Ch. 7)

SLSA Level 3 (Advanced — achievable in 3-12 months):
  ✓ Hermetic, isolated CI/CD builds (ephemeral runners, no network access during build)
  ✓ Verified SBOM provenance via Cosign at admission (Ch. 9)
  ✓ Continuous SBOM monitoring (Ch. 6)
  ✓ Trivy Operator cluster-wide scanning (Ch. 10)
  ✓ Full VEX programme (Ch. 6)
```

---

## 9. Real Present-Day Scenarios — Cross-Cutting Themes

### The Complete Supply Chain Attack — Step by Step

Here is how a full supply chain attack looks against an organisation with no supply chain controls, and how each chapter's control would have broken the chain:

```
Attack: Compromised npm package

Step 1: Attacker publishes "lodash-utils" to npm (typosquatting "lodash")
→ Prevention: Ch. 3 SBOM generation detects the exact package name and version;
  Ch. 10 Trivy scans for CVEs associated with "lodash-utils"

Step 2: Developer accidentally uses "lodash-utils" instead of "lodash" in package.json
→ Prevention: Ch. 6 SBOM workflow — Grype scan catches if lodash-utils has
  known CVE associations or is flagged as suspicious

Step 3: CI/CD builds image with lodash-utils baked in
→ Prevention: Ch. 10 Trivy scanning in CI/CD — if lodash-utils has CVEs,
  build is blocked by the --exit-code 1 gate

Step 4: Image is pushed to the container registry
→ Prevention: Ch. 8 — Only Cosign-signed, Trivy-clean images are promoted
  to the production registry namespace

Step 5: Kubernetes pod attempts to run the image
→ Prevention: Ch. 9 — ImagePolicyWebhook/OPA checks that image came from
  approved registry; image was signed and SBOM-attested

Step 6: Pod runs but lodash-utils does something malicious at runtime
→ Prevention: Ch. 4 — distroless image; no shell; limited capabilities;
  runtime behaviour anomaly detected by Falco (covered in Runtime Security module)
```

In an organisation with all 10 chapters' controls implemented, this attack is blocked at step 3 (CI/CD gate) at the very latest. More likely it is caught at step 1-2 when SBOM generation flags the unexpected package.

### The Regulatory Audit — EU Cyber Resilience Act

A European SaaS company in 2026 receives an audit request under the EU Cyber Resilience Act. The auditor requires machine-readable SBOMs for all product versions shipped in the last 12 months, evidence of vulnerability scanning, and proof of a documented remediation process.

The company that implemented this module's controls responds within hours:
- **SBOMs**: 12 months of Syft-generated CycloneDX SBOMs, stored as Cosign attestations alongside each image in their OCI registry — immutable, timestamped, signed.
- **Scanning evidence**: CI/CD logs showing Trivy scans for every build, with JSON reports stored as artefacts, tied to specific image digests.
- **Remediation process**: Documented JIRA tickets created automatically when Dependency-Track flags new CVEs, with SLA tracking (Critical: 72h, High: 7d).

The company that did not implement these controls scrambles for weeks trying to reconstruct dependency history from source code — an incomplete, unverifiable process.

---

## 10. What Happens If You Ignore Supply Chain Security

Ignoring supply chain security doesn't mean nothing happens. It means you don't know what's happening until something breaks catastrophically.

**The accumulation model:** Without scanning, every image in your cluster accumulates CVEs silently over time. The image built in January may have 5 CVEs at build time. By July it has 47. By December it has 312 — including 15 Critical. You don't know any of this unless you scan.

**The exploitation model:** Attackers actively scan for Kubernetes clusters running containers with known CVEs. Tools like `kube-hunter`, Shodan, and customised exploit scanners identify clusters running specific vulnerable versions. The attack is not "someone decides to attack you" — it is "automated scanners find your exposed service with a known CVE and launch the exploit automatically."

**The compliance model:** A SOC 2 Type II audit, a PCI-DSS assessment, or a FedRAMP review will ask: "Show me your software composition analysis programme." Without SBOMs, without scanning, without registry controls, there is no programme to show. The audit fails. The certification is withheld. In regulated industries, this has direct business consequences — lost contracts, mandatory remediation periods, public disclosure.

**The incident model:** When a zero-day is disclosed (the next Log4Shell), the organisations that respond in hours are those with SBOMs and automated scanning. They query their SBOM store: "Which of our running images contains the affected component?" Answer in minutes. Remediation starts immediately. The organisations without supply chain controls spend days doing manual archaeology — pulling every image, grepping JAR manifests, checking Maven dependency trees — an error-prone process that misses transitive inclusions.

---

## 11. How AI Is Impacting the Entire Supply Chain

AI is transforming every chapter of this module simultaneously:

**SBOM generation (Chapters 3, 5, 6):** ML models can now detect components in compiled binaries that package-manager-based tools miss — vendored code, embedded JARs, obfuscated dependencies. LLMs synthesise SBOM metadata from build logs and source analysis. AI auto-generates VEX statements based on code reachability analysis.

**Vulnerability prioritisation (Chapters 6, 10):** EPSS (Exploit Prediction Scoring System) uses ML to predict which CVEs will be actively exploited in the next 30 days — far more actionable than CVSS severity alone. AI-powered reachability analysis (Snyk, Endor Labs, Rezilion) reduces actionable CVE counts by 80-95% by identifying which vulnerable functions are actually called.

**Image analysis (Chapters 4, 8, 10):** ML models perform static behavioural analysis of images before they run — detecting patterns associated with cryptominers, reverse shells, and data exfiltration tools even for zero-day malware. AI detects SBOM drift between image versions, flagging supply chain tampering.

**Policy generation (Chapters 7, 9):** LLMs translate natural-language security requirements into Rego policies (OPA) and Kyverno rules. AI lints policies for common mistakes (too-broad allowlists, missing initContainer checks, silent bypasses). AI generates custom KubeLinter checks from incident post-mortems.

**Automated remediation (Chapters 4, 6, 10):** AI-powered bots (Dependabot, Renovate with AI scoring, GitHub Copilot Autofix) automatically generate pull requests that update vulnerable dependencies, assess whether updates are breaking, and prioritise which ones to apply first.

**The AI supply chain itself:** AI models are now artefacts in the software supply chain. CycloneDX 1.6's ML-BOM subspec enables SBOMs for AI models — tracking training datasets, model weights, training parameters, and their provenance. AI supply chain attacks (poisoned training data, malicious model weights on HuggingFace) are a new category that the principles of this module apply directly to.

---

## 12. CKS Exam Coverage for This Module

Supply chain security is 20% of the CKS exam — approximately 6-8 questions in a 15-17 question exam. The exam is hands-on; you will be asked to perform tasks in a live cluster, not just answer multiple-choice questions.

**High-probability exam tasks by chapter:**

| Chapter | Likely Exam Task |
|---------|-----------------|
| Ch. 4 | Write a multi-stage Dockerfile; identify which base image has fewer CVEs |
| Ch. 6 | Generate SBOM with Syft; scan SBOM with Grype; interpret Grype output |
| Ch. 7 | Run `kube-linter lint` on a given manifest; fix the identified issues |
| Ch. 8 | Create `docker-registry` Secret; add `imagePullSecrets` to a Pod/Deployment |
| Ch. 9 | Enable `ImagePolicyWebhook` in kube-apiserver static pod; create `AdmissionConfiguration` |
| Ch. 10 | Run `trivy image` with specific flags; interpret output; filter by severity |

**The five most important commands for the exam:**

```bash
# 1. Generate SBOM with Syft
syft nginx:1.25 -o cyclonedx-json > nginx-sbom.json

# 2. Scan SBOM with Grype
grype sbom:nginx-sbom.json
grype sbom:nginx-sbom.json --severity CRITICAL

# 3. Scan image with Trivy
trivy image nginx:1.18.0
trivy image --severity CRITICAL,HIGH --ignore-unfixed nginx:1.18.0

# 4. Lint Kubernetes manifests with KubeLinter
kube-linter lint .
kube-linter lint deployment.yaml

# 5. Create imagePullSecret
kubectl create secret docker-registry regcred \
  --docker-server=private-registry.io \
  --docker-username=registry-user \
  --docker-password=registry-password
```

**The most exam-dangerous topic — ImagePolicyWebhook:**
The `ImagePolicyWebhook` configuration is the most technically complex and error-prone topic in this module. The two most common failure modes are (1) forgetting to mount the AdmissionConfiguration file into the kube-apiserver static pod, and (2) the kube-apiserver failing to restart after modification, taking away `kubectl` access. Always verify the API server comes back: `watch crictl ps | grep apiserver`.

**Exam mindset for this module:**
Supply chain security questions often combine two topics — e.g., "scan this image with Trivy AND ensure the Deployment uses an imagePullSecret." Read the question carefully to identify all required steps. Know the exact flag names (`--severity`, `--ignore-unfixed`, `--input`, `--exit-code`). Know the exact `kubectl create secret` syntax. Know that `--enable-admission-plugins` takes a comma-separated list and that existing plugins must be preserved.

---

## 13. Key Concepts Quick Reference

### Acronyms and Definitions

| Term | Full Name | What It Is |
|------|-----------|-----------|
| **SBOM** | Software Bill of Materials | Machine-readable inventory of all components in a software artefact |
| **CVE** | Common Vulnerabilities and Exposures | Standardised identifier for a publicly known software vulnerability |
| **CVSS** | Common Vulnerability Scoring System | Numerical severity rating system for CVEs (0.0–10.0) |
| **SLSA** | Supply chain Levels for Software Artefacts | CNCF maturity framework for supply chain security (Levels 0-3) |
| **SPDX** | Software Package Data Exchange | Linux Foundation SBOM standard; strong for licensing |
| **CycloneDX** | CycloneDX | OWASP SBOM standard; strong for vulnerability management |
| **PURL** | Package URL | Standard URI scheme for identifying software packages (`pkg:deb/debian/curl@7.88.1`) |
| **VEX** | Vulnerability Exploitability eXchange | Machine-readable statement about CVE exploitability in a specific context |
| **NTIA** | National Telecommunications and Information Administration | US body that defined 7 minimum elements for SBOMs |
| **EO 14028** | Executive Order 14028 | US executive order mandating SBOMs for federal software procurement (2021) |
| **EU CRA** | EU Cyber Resilience Act | EU regulation requiring SBOMs for CE-marked digital products (effective 2027) |
| **EPSS** | Exploit Prediction Scoring System | ML model predicting probability of CVE exploitation in the wild |

### Severity Levels at a Glance

```
CRITICAL (9.0–10.0) → Patch immediately (24-72 hours)
HIGH     (7.0–8.9)  → Patch within 7 days
MEDIUM   (4.0–6.9)  → Patch within 30 days
LOW      (0.1–3.9)  → Patch within 90 days
NONE     (0.0)      → No action required
```

### Tool Quick Reference

```
Generate SBOM:  syft <image> -o cyclonedx-json
Scan SBOM:      grype sbom:<file>
Scan image:     trivy image <image>
Lint manifests: kube-linter lint .
Sign image:     cosign sign <image>
Verify sig:     cosign verify-attestation --type cyclonedx <image>
Pull secret:    kubectl create secret docker-registry <name> --docker-server=... --docker-username=... --docker-password=...
Trivy flags:    --severity CRITICAL,HIGH | --ignore-unfixed | --input <tar> | --exit-code 1
Grype flags:    --fail-on critical | --only-fixed | -o json
```

### Chapter → Control → Tool Mapping

```
Minimize Attack Surface    → Ch. 4  → Docker multi-stage, distroless, Chainguard
Know Your Components       → Ch. 3  → SBOM concept
SBOM Formats               → Ch. 5  → SPDX, CycloneDX, PURL
Operational SBOM Workflow  → Ch. 6  → Syft, Grype, Cosign, Dependency-Track
Lint Manifests             → Ch. 7  → KubeLinter
Image Registry Security    → Ch. 8  → docker-registry Secret, imagePullSecrets, Cosign
Enforce Approved Registries→ Ch. 9  → ImagePolicyWebhook, OPA, Kyverno
Scan for CVEs              → Ch. 10 → Trivy
```

---

*This module builds a complete, layered supply chain security posture. Each chapter is a control; each control addresses a specific attack vector; together they implement defence-in-depth from source code to running pod.*

*Proceed to Chapter 1 → Overview of Supply Chain Security*
