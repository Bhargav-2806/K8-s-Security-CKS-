# Chapter 9: Whitelist Allowed Registries — Image Policy Webhook

---

## Table of Contents

1. [Why Registry Whitelisting Matters](#1-why-registry-whitelisting-matters)
2. [Understanding the Risk — Unrestricted Image Sources](#2-understanding-the-risk--unrestricted-image-sources)
3. [The Kubernetes Admission Control Pipeline](#3-the-kubernetes-admission-control-pipeline)
4. [Approach 1 — Custom Validating Admission Webhook](#4-approach-1--custom-validating-admission-webhook)
   - [How the Webhook Works](#how-the-webhook-works)
   - [Python Webhook Example](#python-webhook-example)
   - [Deploying the Webhook in Kubernetes](#deploying-the-webhook-in-kubernetes)
5. [Approach 2 — OPA Gatekeeper with Rego Policies](#5-approach-2--opa-gatekeeper-with-rego-policies)
   - [Installing OPA Gatekeeper](#installing-opa-gatekeeper)
   - [Rego Policy for Registry Allowlisting](#rego-policy-for-registry-allowlisting)
   - [OPA Gatekeeper ConstraintTemplate and Constraint](#opa-gatekeeper-constrainttemplate-and-constraint)
6. [Approach 3 — Kyverno Policy for Registry Enforcement](#6-approach-3--kyverno-policy-for-registry-enforcement)
7. [Approach 4 — Built-In ImagePolicyWebhook Admission Controller](#7-approach-4--built-in-imagepolicywebhook-admission-controller)
   - [The AdmissionConfiguration File](#the-admissionconfiguration-file)
   - [The KubeConfig for the Webhook Server](#the-kubeconfig-for-the-webhook-server)
   - [Enabling ImagePolicyWebhook in kube-apiserver](#enabling-imagepolicywebhook-in-kube-apiserver)
   - [Static Pod Configuration (kubeadm clusters)](#static-pod-configuration-kubeadm-clusters)
   - [defaultAllow — Fail Open vs Fail Closed](#defaultallow--fail-open-vs-fail-closed)
8. [As a DevSecOps / Kubernetes Security Engineer](#8-as-a-devsecops--kubernetes-security-engineer)
9. [Real Present-Day Scenarios](#9-real-present-day-scenarios)
10. [What Happens If You Don't Follow This](#10-what-happens-if-you-dont-follow-this)
11. [Most Common Commands and Syntax](#11-most-common-commands-and-syntax)
12. [Other Tools and Services Available](#12-other-tools-and-services-available)
13. [How AI Is Impacting Registry Enforcement](#13-how-ai-is-impacting-registry-enforcement)
14. [CKS Exam Tips](#14-cks-exam-tips)
15. [Extra Information and References](#15-extra-information-and-references)

---

## 1. Why Registry Whitelisting Matters

By default, any user with permission to create pods in a Kubernetes cluster can specify any container image from any registry anywhere on the internet. There is no built-in check on where images come from. A developer can write `image: some-random-dockerhub-user/crypto-miner:latest` and Kubernetes will dutifully pull and run it — as long as the node can reach the registry.

This is a foundational supply chain control problem. The entire point of maintaining a private registry with vulnerability scanning, image signing, and SBOM generation is to ensure that only trusted, inspected images run in your cluster. But none of those controls matter if a user can bypass them by simply specifying a different registry in the Pod spec.

Registry whitelisting — enforcing that only images from approved registries are permitted — closes this gap at the cluster level. It works at admission time: before any image is ever pulled, the admission controller checks whether the specified registry is on the approved list and rejects the request if it is not.

Registry whitelisting matters because:

- **It enforces your image pipeline** — If images must come from `myregistry.io`, then images must have gone through your build, scan, sign, and SBOM pipeline to get there.
- **It prevents typosquatting and supply chain attacks** — A user cannot accidentally or maliciously reference `nginxofficial` from Docker Hub if Docker Hub is not an allowed registry.
- **It satisfies compliance requirements** — PCI-DSS, FedRAMP, SOC 2, and ISO 27001 all have requirements around software integrity and controlled software supply chains. Registry allowlisting is a concrete, auditable control.
- **It enables zero-trust for workloads** — In a zero-trust model, every component must be verified. "This image came from our registry" is a necessary (though not sufficient) step in that verification chain.
- **It limits blast radius** — Even if a developer's credentials are compromised, the attacker cannot deploy arbitrary images from arbitrary sources into the cluster.

---

## 2. Understanding the Risk — Unrestricted Image Sources

Consider this pod definition — perfectly valid YAML, perfectly accepted by Kubernetes with no admission controls:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sample-pod
spec:
  containers:
    - name: sample-app
      image: some-registry.io/a-very-vulnerable-image
```

The `image` field accepts any string. The container runtime will attempt to pull from wherever the string points. This means:

- A developer can pull from `docker.io`, `ghcr.io`, `quay.io`, `some-random-registry.io`, or any other reachable URL
- An attacker who has compromised a CI/CD pipeline can substitute a malicious image from an attacker-controlled registry
- A negligent or malicious insider can run cryptocurrency miners, data exfiltration tools, or backdoored applications
- Images that have never been scanned, signed, or SBOMed can run alongside your carefully controlled production workloads

The attack scenarios enabled by unrestricted image sources:

```
Scenario A: Typosquatting
  Developer types: image: curlimages/curl:7.88
  Attacker published: curlimage/curl:7.88 (note missing 's')
  Without registry allowlisting: Kubernetes pulls the malicious image
  With allowlisting to "myregistry.io": Rejected at admission

Scenario B: Compromised CI/CD
  Attacker gains write access to CI/CD system
  Changes image reference from: myregistry.io/app:1.0 
  To: attacker-registry.io/backdoored-app:1.0
  Without registry allowlisting: Production runs the backdoored image
  With allowlisting: Rejected — attacker-registry.io not on approved list

Scenario C: Dependency Confusion
  Internal package: mycompany-registry.io/internal/helper:1.0
  Developer uses: helper:1.0 (missing registry prefix)
  Resolves to: docker.io/library/helper:1.0 or docker.io/helper:1.0
  Without allowlisting: If an attacker published 'helper' to Docker Hub, it runs
  With allowlisting: docker.io is not approved; request rejected
```

---

## 3. The Kubernetes Admission Control Pipeline

Before diving into the implementation approaches, it is essential to understand where registry enforcement fits in the Kubernetes request lifecycle.

![The image illustrates the Kubernetes admission control process, showing steps from kubectl through authentication, authorization, admission controllers, to creating a pod.](https://kodekloud.com/kk-media/image/upload/v1752871727/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Whitelist-Allowed-Registries-Image-Policy-Webhook/frame_150.jpg)

Every request to the Kubernetes API server passes through four sequential stages:

1. **Authentication** — Who are you? The API server verifies the identity of the requestor via certificates, bearer tokens, OIDC, or other mechanisms. Unauthenticated requests are rejected (401).

2. **Authorization** — Are you allowed to do this? RBAC (or ABAC, Node, Webhook) checks whether the authenticated identity has permission to perform the requested action on the requested resource. Unauthorised requests are rejected (403).

3. **Admission Control** — Should this request be permitted based on policy? This is where registry enforcement happens. Admission controllers can mutate requests (MutatingAdmissionWebhook) or validate them (ValidatingAdmissionWebhook). A validation rejection returns a 403 with a policy message. This happens **before** any image is pulled.

4. **Persistence** — The validated, admitted request is written to etcd and the object is created.

Registry whitelisting operates at stage 3 — Admission Control. There are four primary approaches, each with different tradeoffs:

| Approach | Built-in? | Flexibility | Operational Overhead | Best For |
|----------|-----------|-------------|---------------------|----------|
| Custom Validating Webhook | No | Full | High (maintain a service) | Custom logic beyond simple registry check |
| OPA Gatekeeper | No | Full (Rego) | Medium (deploy Gatekeeper) | Organisations already using OPA |
| Kyverno | No | High (YAML) | Low (simpler than OPA) | Teams wanting simpler policy DSL |
| ImagePolicyWebhook | Yes (built-in) | Requires external webhook server | Medium | CKS exam; built-in; no 3rd-party operators |

---

## 4. Approach 1 — Custom Validating Admission Webhook

### How the Webhook Works

A Validating Admission Webhook is an HTTPS endpoint that the Kubernetes API server calls for every (configured) resource creation/modification request. The webhook receives a JSON `AdmissionReview` object containing the full request, evaluates it against its policy, and returns an `AdmissionReview` response with `allowed: true` or `allowed: false`.

```
kubectl apply -f pod.yaml
  → API Server receives Pod creation request
  → Authentication ✓
  → Authorization ✓
  → API Server sends AdmissionReview to webhook HTTPS endpoint
  → Webhook inspects pod.spec.containers[*].image
  → Webhook returns {allowed: true} or {allowed: false, status: {message: "..."}}
  → If allowed: false → kubectl gets error message; pod not created
  → If allowed: true → pod created
```

### Python Webhook Example

The KodeKloud example demonstrates a Flask-based admission webhook that allows only images from `internal-registry.io`:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_REGISTRY = "internal-registry.io"

@app.route("/validate", methods=["POST"])
def validate():
    # Parse the incoming AdmissionReview request
    admission_review = request.json
    request_object = admission_review["request"]
    
    # Extract all container images from the pod spec
    containers = request_object["object"]["spec"].get("containers", [])
    init_containers = request_object["object"]["spec"].get("initContainers", [])
    ephemeral_containers = request_object["object"]["spec"].get("ephemeralContainers", [])
    
    all_containers = containers + init_containers + ephemeral_containers
    
    status = True
    message = ""
    
    for container in all_containers:
        image_name = container["image"]
        if ALLOWED_REGISTRY not in image_name:
            message = f"Image '{image_name}' is not from an allowed registry. Only '{ALLOWED_REGISTRY}' images are permitted."
            status = False
            break
    
    # Build the AdmissionReview response
    return jsonify({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": request_object["uid"],
            "allowed": status,
            "status": {
                "code": 200 if status else 403,
                "message": message
            }
        }
    })

if __name__ == "__main__":
    # The webhook MUST run on HTTPS — Kubernetes requires TLS
    app.run(host="0.0.0.0", port=443, ssl_context=("/certs/tls.crt", "/certs/tls.key"))
```

**More complete webhook with multi-registry support:**

```python
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Allow multiple registries
ALLOWED_REGISTRIES = [
    "mycompany-registry.io",
    "gcr.io/myproject",          # GCP Artifact Registry
    "123456789.dkr.ecr.us-east-1.amazonaws.com",  # ECR
]

def image_is_allowed(image: str) -> bool:
    """Return True if the image comes from an allowed registry."""
    for allowed in ALLOWED_REGISTRIES:
        if image.startswith(allowed):
            return True
    return False

@app.route("/validate", methods=["POST"])
def validate():
    review = request.json
    uid = review["request"]["uid"]
    spec = review["request"]["object"]["spec"]
    
    all_containers = (
        spec.get("containers", []) +
        spec.get("initContainers", []) +
        spec.get("ephemeralContainers", [])
    )
    
    denied_images = [
        c["image"] for c in all_containers
        if not image_is_allowed(c["image"])
    ]
    
    if denied_images:
        message = f"Images from unapproved registries: {', '.join(denied_images)}. Allowed: {ALLOWED_REGISTRIES}"
        logging.warning(f"DENIED uid={uid}: {message}")
        return jsonify({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {"code": 403, "message": message}
            }
        })
    
    logging.info(f"ALLOWED uid={uid}")
    return jsonify({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {"uid": uid, "allowed": True}
    })

@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200
```

### Deploying the Webhook in Kubernetes

```yaml
# 1. TLS Certificate (the webhook MUST use HTTPS)
# Generate cert: openssl or cert-manager
apiVersion: v1
kind: Secret
metadata:
  name: registry-webhook-tls
  namespace: kube-system
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
---
# 2. Deployment for the webhook server
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry-admission-webhook
  namespace: kube-system
spec:
  replicas: 2   # HA — see note below
  selector:
    matchLabels:
      app: registry-admission-webhook
  template:
    metadata:
      labels:
        app: registry-admission-webhook
    spec:
      containers:
        - name: webhook
          image: myregistry.io/registry-admission-webhook:1.0.0
          ports:
            - containerPort: 443
          volumeMounts:
            - name: tls
              mountPath: /certs
              readOnly: true
      volumes:
        - name: tls
          secret:
            secretName: registry-webhook-tls
---
# 3. Service exposing the webhook
apiVersion: v1
kind: Service
metadata:
  name: registry-admission-webhook
  namespace: kube-system
spec:
  selector:
    app: registry-admission-webhook
  ports:
    - port: 443
      targetPort: 443
---
# 4. ValidatingWebhookConfiguration — tells the API server to call our webhook
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: registry-policy
webhooks:
  - name: registry-policy.kube-system.svc
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
      - operations: ["CREATE", "UPDATE"]
        apiGroups: ["apps"]
        apiVersions: ["v1"]
        resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
    clientConfig:
      service:
        name: registry-admission-webhook
        namespace: kube-system
        path: /validate
      caBundle: <base64-encoded-CA-cert>   # CA that signed the webhook's TLS cert
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail    # Fail closed — reject if webhook is unreachable
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system]   # Don't enforce on system namespace
```

> ⚠️ **High Availability is mandatory.** If your admission webhook server becomes unreachable and `failurePolicy: Fail` is set, NO pods can be created in the cluster — including the webhook's own pods during recovery. Always run at least 2 replicas with appropriate PodDisruptionBudget, and consider exempting `kube-system` from the webhook scope.

---

## 5. Approach 2 — OPA Gatekeeper with Rego Policies

OPA (Open Policy Agent) Gatekeeper is the CNCF-endorsed approach for policy-as-code in Kubernetes. It runs as an admission webhook but abstracts the webhook infrastructure — you write policy in Rego, not in application code.

### Installing OPA Gatekeeper

```bash
# Install via Helm
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper gatekeeper/gatekeeper --namespace gatekeeper-system --create-namespace

# Install via manifest
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Verify installation
kubectl get pods -n gatekeeper-system
kubectl get crd | grep gatekeeper
```

### Rego Policy for Registry Allowlisting

The KodeKloud example shows a raw OPA Rego policy (for OPA without Gatekeeper — used when OPA is deployed as a sidecar or standalone webhook):

```rego
package kubernetes.admission

# Deny any pod that uses an image not starting with "internal-registry.io/"
deny[msg] {
    input.request.kind.kind == "Pod"
    image := input.request.object.spec.containers[_].image
    not startswith(image, "internal-registry.io/")
    msg := sprintf("Image '%s' is not from a trusted registry. Only images from 'internal-registry.io/' are allowed.", [image])
}

# Also check initContainers
deny[msg] {
    input.request.kind.kind == "Pod"
    image := input.request.object.spec.initContainers[_].image
    not startswith(image, "internal-registry.io/")
    msg := sprintf("initContainer image '%s' is not from a trusted registry.", [image])
}
```

**Extended Rego for multiple allowed registries:**

```rego
package kubernetes.admission

allowed_registries := {
    "internal-registry.io",
    "mycompany-registry.io",
    "gcr.io/myproject",
    "123456789.dkr.ecr.us-east-1.amazonaws.com"
}

image_is_allowed(image) {
    allowed := allowed_registries[_]
    startswith(image, allowed)
}

deny[msg] {
    input.request.kind.kind == "Pod"
    containers := input.request.object.spec.containers
    image := containers[_].image
    not image_is_allowed(image)
    msg := sprintf("Image '%s' is from an unapproved registry. Allowed registries: %v", [image, allowed_registries])
}
```

### OPA Gatekeeper ConstraintTemplate and Constraint

With OPA Gatekeeper, policy is split into two Kubernetes CRDs:

```yaml
# 1. ConstraintTemplate — defines the policy logic (Rego)
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: allowedimageregistries
spec:
  crd:
    spec:
      names:
        kind: AllowedImageRegistries
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedRegistries:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package allowedimageregistries

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not image_allowed(container.image)
          msg := sprintf("Container image '%v' is from a disallowed registry. Allowed: %v", [container.image, input.parameters.allowedRegistries])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not image_allowed(container.image)
          msg := sprintf("initContainer image '%v' is from a disallowed registry.", [container.image])
        }

        image_allowed(image) {
          registry := input.parameters.allowedRegistries[_]
          startswith(image, registry)
        }
---
# 2. Constraint — instantiates the template with specific parameters
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: AllowedImageRegistries
metadata:
  name: prod-registry-allowlist
spec:
  enforcementAction: deny      # "deny" blocks; "warn" warns only; "dryrun" just audits
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production", "staging"]   # Apply only to these namespaces
  parameters:
    allowedRegistries:
      - "mycompany-registry.io/"
      - "gcr.io/myproject/"
      - "123456789.dkr.ecr.us-east-1.amazonaws.com/"
```

```bash
# Apply both resources
kubectl apply -f constraint-template.yaml
kubectl apply -f constraint.yaml

# Test — try creating a pod with an unapproved image
kubectl run test --image=nginx --namespace=production
# Error: admission webhook "validation.gatekeeper.sh" denied the request:
# Container image 'nginx' is from a disallowed registry.

# Audit existing violations (doesn't block, just reports)
kubectl get allowedimageregistries prod-registry-allowlist -o yaml
# Look for .status.violations — lists currently running pods that violate the policy
```

---

## 6. Approach 3 — Kyverno Policy for Registry Enforcement

Kyverno offers a simpler YAML-native policy DSL that does not require Rego:

```bash
# Install Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace

# Verify
kubectl get pods -n kyverno
```

```yaml
# ClusterPolicy — enforce approved registries cluster-wide
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
  annotations:
    policies.kyverno.io/title: Restrict Image Registries
    policies.kyverno.io/category: Supply Chain Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: "Images must come from approved registries only."
spec:
  validationFailureAction: Enforce    # Enforce=block; Audit=report only
  background: true                    # Audit existing resources
  rules:
    - name: validate-registries
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["production", "staging"]
      exclude:
        any:
          - resources:
              namespaces: [kube-system]   # Exempt system namespace
      validate:
        message: "Images must come from mycompany-registry.io or gcr.io/myproject. Got: {{request.object.spec.containers[0].image}}"
        foreach:
          - list: "request.object.spec.containers"
            deny:
              conditions:
                all:
                  - key: "{{element.image}}"
                    operator: NotIn
                    value:
                      - "mycompany-registry.io/*"
                      - "gcr.io/myproject/*"
                      - "123456789.dkr.ecr.us-east-1.amazonaws.com/*"
          - list: "request.object.spec.initContainers"
            deny:
              conditions:
                all:
                  - key: "{{element.image}}"
                    operator: NotIn
                    value:
                      - "mycompany-registry.io/*"
                      - "gcr.io/myproject/*"

---
# Check Kyverno policy reports (audit results for existing resources)
# kubectl get policyreport -A
# kubectl get clusterpolicyreport
```

**Kyverno vs OPA Gatekeeper for this use case:**

| Aspect | Kyverno | OPA Gatekeeper |
|--------|---------|----------------|
| Policy language | YAML (Kyverno DSL) | Rego (functional logic language) |
| Learning curve | Low | High |
| Flexibility | Good for most use cases | Unlimited — Rego is Turing complete |
| Audit mode | Built-in (`Audit` action) | Built-in (`dryrun` enforcement) |
| Mutation support | Yes (MutatingWebhook) | Limited |
| CKS exam focus | No | Yes (OPA in Kubernetes is covered) |

---

## 7. Approach 4 — Built-In ImagePolicyWebhook Admission Controller

`ImagePolicyWebhook` is a **built-in Kubernetes admission controller** (no third-party software needed) that delegates image policy decisions to an external webhook server. Unlike the custom validating webhook approach (which you build and deploy yourself), ImagePolicyWebhook provides a standardised interface specifically designed for image policy.

The key distinction from a generic `ValidatingAdmissionWebhook`:
- Only applies to images (not general pod configuration)
- Has built-in `defaultAllow` behaviour for when the webhook is unreachable
- Has configurable `allowTTL` and `denyTTL` for caching decisions
- Is enabled as a named plugin (`ImagePolicyWebhook`) in the admission plugins list

### The AdmissionConfiguration File

The API server reads an `AdmissionConfiguration` file that specifies how to connect to the webhook server:

```yaml
# /etc/kubernetes/admission-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/kubernetes/admission-kubeconfig.yaml  # Auth config for webhook
      allowTTL: 50         # How long (seconds) to cache "allow" decisions
      denyTTL: 50          # How long (seconds) to cache "deny" decisions
      retryBackoff: 500    # Milliseconds to wait between retries
      defaultAllow: true   # What to do if webhook is unreachable:
                           #   true  = fail open (allow all images) — availability over security
                           #   false = fail closed (deny all images) — security over availability
```

**defaultAllow — a critical security decision:**

```
defaultAllow: true  → "Fail open"
  Pro: If the webhook goes down, pods can still be created. High availability.
  Con: If the webhook goes down deliberately (DoS), ANY image can be deployed.
  Use when: Your availability SLA is critical and you accept temporary policy bypass risk.

defaultAllow: false → "Fail closed"
  Pro: If the webhook goes down, NO pods can be created. No policy bypass possible.
  Con: Webhook downtime means cluster cannot schedule new workloads. This includes
       system components that need to reschedule — potentially cascading failure.
  Use when: Security is paramount; you have a highly available webhook with PDB.
```

### The KubeConfig for the Webhook Server

The `kubeConfigFile` referenced in the `AdmissionConfiguration` is a standard Kubernetes kubeconfig format, but instead of pointing to the API server, it points to the image policy webhook server:

```yaml
# /etc/kubernetes/admission-kubeconfig.yaml
apiVersion: v1
kind: Config
clusters:
- name: name-of-remote-imagepolicy-service
  cluster:
    certificate-authority: /path/to/ca.pem           # CA that signed the webhook server's TLS cert
    server: https://images.example.com/policy         # Webhook HTTPS endpoint
users:
- name: name-of-api-server
  user:
    client-certificate: /path/to/cert.pem             # API server's client cert (for mTLS)
    client-key: /path/to/key.pem                      # API server's client key
contexts:
- context:
    cluster: name-of-remote-imagepolicy-service
    user: name-of-api-server
  name: imagepolicy-context
current-context: imagepolicy-context
```

**What the webhook server receives and must return:**

The ImagePolicyWebhook sends an `ImageReview` object (note: different from the generic `AdmissionReview`):

```json
// Request sent TO the webhook:
{
  "apiVersion": "imagepolicy.k8s.io/v1alpha1",
  "kind": "ImageReview",
  "spec": {
    "containers": [
      {"image": "myregistry.io/myapp:1.0.0"},
      {"image": "myregistry.io/sidecar:2.0.0"}
    ],
    "initContainers": [
      {"image": "myregistry.io/init:1.0.0"}
    ],
    "namespace": "production"
  }
}

// Response FROM the webhook:
{
  "apiVersion": "imagepolicy.k8s.io/v1alpha1",
  "kind": "ImageReview",
  "status": {
    "allowed": true,
    "reason": "All images from approved registry"
  }
}

// Or rejection:
{
  "apiVersion": "imagepolicy.k8s.io/v1alpha1",
  "kind": "ImageReview",
  "status": {
    "allowed": false,
    "reason": "Image 'unknown-registry.io/malware:1.0' is not from an approved registry"
  }
}
```

### Enabling ImagePolicyWebhook in kube-apiserver

**For clusters where kube-apiserver runs as a systemd service:**

```bash
ExecStart=/usr/local/bin/kube-apiserver \
  --advertise-address=${INTERNAL_IP} \
  --allow-privileged=true \
  --apiserver-count=3 \
  --authorization-mode=Node,RBAC \
  --bind-address=0.0.0.0 \
  --enable-swagger-ui=true \
  --etcd-servers=https://127.0.0.1:2379 \
  --event-ttl=1h \
  --runtime-config=api/all \
  --service-cluster-ip-range=10.32.0.0/24 \
  --service-node-port-range=30000-32767 \
  --v=2 \
  # These two flags enable ImagePolicyWebhook:
  --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook \
  --admission-control-config-file=/etc/kubernetes/admission-config.yaml
```

Note: The `--enable-admission-plugins` flag takes a **comma-separated list**. Include all the admission plugins you need, not just `ImagePolicyWebhook`. Check what is currently enabled before modifying:

```bash
# Check currently enabled admission plugins
kube-apiserver --help | grep "enable-admission-plugins"
# or inspect the running process
ps aux | grep kube-apiserver | grep "admission-plugins"
```

### Static Pod Configuration (kubeadm clusters)

In kubeadm-based clusters, the kube-apiserver runs as a static pod managed by kubelet. Its manifest is at `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    - --authorization-mode=Node,RBAC
    - --advertise-address=172.17.0.107
    - --allow-privileged=true
    - --enable-bootstrap-token-auth=true
    # Add these two lines to enable ImagePolicyWebhook:
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/admission-config.yaml
    image: registry.k8s.io/kube-apiserver:v1.28.0
    name: kube-apiserver
    volumeMounts:
    - mountPath: /etc/kubernetes/admission-config.yaml
      name: admission-config
      readOnly: true
    - mountPath: /etc/kubernetes/admission-kubeconfig.yaml
      name: admission-kubeconfig
      readOnly: true
    - mountPath: /path/to/ca.pem
      name: webhook-ca
      readOnly: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/admission-config.yaml
      type: File
    name: admission-config
  - hostPath:
      path: /etc/kubernetes/admission-kubeconfig.yaml
      type: File
    name: admission-kubeconfig
  - hostPath:
      path: /path/to/ca.pem
      type: File
    name: webhook-ca
```

> ⚠️ **Critical:** After modifying `/etc/kubernetes/manifests/kube-apiserver.yaml`, kubelet automatically restarts the apiserver static pod. The API server will be briefly unavailable. Always have kubectl access to verify it comes back up: `kubectl get pods -n kube-system | grep apiserver`. If the API server doesn't restart cleanly, check its logs: `kubectl logs kube-apiserver-<node> -n kube-system`.

> ⚠️ **Volume mounts are required:** The admission config file, the kubeconfig, and all certificates referenced within them must be mounted into the static pod. If the files are on the host at `/etc/kubernetes/`, use `hostPath` volume mounts to make them available inside the container.

---

## 8. As a DevSecOps / Kubernetes Security Engineer

Registry whitelisting is one of the most impactful single controls you can implement in a Kubernetes cluster. As a DevSecOps engineer, your job is to choose the right approach, implement it correctly, maintain it, and handle the exceptions without breaking developer velocity.

**Choosing the right approach for your organisation:**

- **Small team, simple requirements** → Kyverno with `Audit` mode first, then `Enforce`. Simple YAML, easy to understand.
- **OPA already in your stack** → OPA Gatekeeper with ConstraintTemplate. Consistent with your existing policy framework.
- **CKS exam or vanilla Kubernetes** → ImagePolicyWebhook. Built-in, no third-party operators.
- **Custom business logic** → Custom ValidatingAdmissionWebhook. Maximum flexibility.
- **All of the above (enterprise)** → Kyverno for developer-facing policy + ImagePolicyWebhook as a belt-and-suspenders control for the built-in layer.

**Rollout strategy — how to enforce without breaking things:**

1. **Audit mode first** — Deploy Kyverno or OPA in audit/dryrun mode. Let it run for 2 weeks and generate policy reports. Understand what would be denied.
2. **Fix violations** — Work with teams to move non-compliant images to the approved registry.
3. **Enforce in non-production** — Switch to `Enforce` in dev/staging namespaces. Let teams experience and adapt.
4. **Enforce in production** — After 2+ weeks of stability in staging, enforce in production.

**Handling exceptions:**

```bash
# Kyverno — namespace-level exception
kubectl label namespace legacy-app "policies.kyverno.io/exclude=true"

# Or use Kyverno PolicyException CRD (Kyverno 1.9+)
apiVersion: kyverno.io/v2alpha1
kind: PolicyException
metadata:
  name: legacy-app-exception
  namespace: legacy-app
spec:
  exceptions:
    - policyName: restrict-image-registries
      ruleNames: ["validate-registries"]
  match:
    any:
      - resources:
          kinds: [Pod]
          namespaces: [legacy-app]

# OPA Gatekeeper — namespace exemption
kubectl annotate namespace legacy-app admission.gatekeeper.sh/ignore=yes
```

**Monitoring policy effectiveness:**

```bash
# Kyverno — check policy violations across all namespaces
kubectl get policyreport -A -o json \
  | jq '.items[].results[] | select(.result == "fail") | {policy: .policy, resource: .resources[0].name, message: .message}'

# OPA Gatekeeper — audit results
kubectl get allowedimageregistries prod-registry-allowlist -o jsonpath='{.status.violations}' | jq .

# Get all pods running images from unapproved registries (cluster-wide audit)
kubectl get pods -A -o json \
  | jq -r '.items[] | {ns: .metadata.namespace, name: .metadata.name, images: [.spec.containers[].image]} | select(.images[] | startswith("mycompany-registry.io") | not) | "\(.ns)/\(.name): \(.images)"'
```

**Testing your policy before enforcement:**

```bash
# Test with a dry-run pod (won't actually create if policy blocks)
kubectl run test-denied --image=nginx --dry-run=server 2>&1
# If policy is working: Error from server: admission webhook "..." denied the request

# Test with an approved image
kubectl run test-allowed --image=mycompany-registry.io/nginx:1.25 --dry-run=server 2>&1
# If policy is working: pod/test-allowed created (server dry run)
```

---

## 9. Real Present-Day Scenarios

### Scenario 1: The Cryptominer Deployment

A company with no registry controls experienced a junior developer accidentally running a Helm chart from an untrusted source. The chart included a DaemonSet with `image: xmrig/xmrig:latest` — a well-known open-source cryptocurrency miner published to Docker Hub. The DaemonSet deployed to every node, consuming 80% of CPU across the cluster.

**The fix:** A Kyverno policy restricting images to `companyregistry.io/*` would have blocked the DaemonSet creation at admission. The developer would have received: `"Image 'xmrig/xmrig:latest' is from a disallowed registry."` Zero cryptomining.

### Scenario 2: ImagePolicyWebhook — The `defaultAllow: false` Cascade

A financial services company configured `defaultAllow: false` in their ImagePolicyWebhook configuration. This is the correct security choice. However, their webhook server was deployed as a single replica in `kube-system` without a PodDisruptionBudget. During a cluster upgrade, the webhook pod was evicted and rescheduled. For 90 seconds, no new pods could be created anywhere in the cluster — including the webhook pod itself (which needed to be created to re-enable pod creation, a classic deadlock).

**The lesson:** With `defaultAllow: false`, the webhook must be:
- Running with **minimum 2 replicas** at all times
- Protected by a **PodDisruptionBudget** (maxUnavailable: 0)
- In a namespace **excluded from its own enforcement** (to allow self-recovery)
- Monitored with alerts on availability

### Scenario 3: OPA Audit Mode Reveals Scope of the Problem

A team at a retail company suspected their developers were using arbitrary Docker Hub images but had no data. They deployed OPA Gatekeeper in `dryrun` mode with a constraint requiring all images to come from `mycompany-registry.io`. After one week, they queried the audit results and found:

```bash
kubectl get allowedimageregistries prod-registry-allowlist -o yaml | grep -A 200 "violations:"
```

They found 847 violations across 23 namespaces — 847 running pods using Docker Hub, `ghcr.io`, `quay.io`, and dozens of random registries. This data gave them a precise remediation roadmap. Without OPA audit mode, they would have had to manually inspect every pod.

### Scenario 4: The CKS Exam — ImagePolicyWebhook Misconfiguration

A candidate was asked to enable `ImagePolicyWebhook` and configure it to use a webhook server already running in the cluster. The common failure mode is forgetting to mount the admission config file into the kube-apiserver static pod. The file exists on the host at `/etc/kubernetes/admission-config.yaml`, but the kube-apiserver container cannot see it unless a `hostPath` volume mount is added to `/etc/kubernetes/manifests/kube-apiserver.yaml`. Without the mount, the API server fails to start and the candidate loses access to `kubectl` — a difficult situation to recover from.

**The recovery procedure if kube-apiserver fails to start:**
1. SSH to the control plane node directly
2. Check why it didn't start: `crictl logs $(crictl ps -a | grep kube-apiserver | awk '{print $1}')`
3. Fix the manifest: `vi /etc/kubernetes/manifests/kube-apiserver.yaml`
4. Wait for kubelet to restart the static pod: `watch crictl ps | grep apiserver`

### Scenario 5: Multi-Registry Exception Management at Scale

A large enterprise with 50+ development teams found that enforcing a single registry was impractical — different teams had legitimate needs for images from `public.ecr.aws` (AWS official images), `gcr.io/google.com/cloudsdktool` (Google Cloud SDK), and their internal registry. They implemented a tiered approach:

- **Tier 1 (production namespace):** Only `mycompany-registry.io` — all images must be built and scanned internally
- **Tier 2 (staging namespace):** `mycompany-registry.io` + `public.ecr.aws` — AWS managed images also allowed
- **Tier 3 (dev namespace):** `mycompany-registry.io` + `public.ecr.aws` + `gcr.io/google.com` — developer-friendly
- **Tier 4 (sandbox namespace):** No restriction — for experimentation

This was implemented with namespace-level Kyverno `Policy` objects (not `ClusterPolicy`) that applied different rules per namespace tier.

---

## 10. What Happens If You Don't Follow This

**Without any registry restriction:**
- Any authenticated cluster user can run any image from any registry. This is a direct supply chain attack surface. The blast radius of a compromised developer account or CI/CD system is unlimited — they can introduce any malware, backdoor, or miner into the cluster.
- Cryptominer deployments are the most common consequence — they are detectable but embarrassing and costly (cloud compute bills, performance impact).
- Regulatory auditors ask "how do you ensure only approved software runs in your cluster?" Without registry controls, there is no satisfactory answer.

**Without `ImagePolicyWebhook` volume mounts correctly configured:**
- The kube-apiserver fails to start. The entire Kubernetes control plane is unavailable. `kubectl` stops working. This is a high-severity outage, especially catastrophic during the CKS exam.

**With `defaultAllow: true` when security is required:**
- If the webhook becomes unavailable (network issue, pod crash, OOM kill), all images become allowed again. An attacker who can cause the webhook to crash (via a DoS against the webhook endpoint, or by exploiting a vulnerability in the webhook server) effectively disables your registry policy.

**With `defaultAllow: false` without HA webhook:**
- Webhook pod failure → no pods can be created → services cannot scale or recover → cascading availability failure. The policy designed to improve security becomes an availability single point of failure.

**Without namespacing your enforcement:**
- Enforcing registry policy on `kube-system` with strict rules can break cluster components. Control plane components use images from `registry.k8s.io`, `gcr.io`, etc. Always exempt `kube-system` and your policy engine's own namespace from registry enforcement.

---

## 11. Most Common Commands and Syntax

### Checking Existing Admission Plugins

```bash
# See what admission plugins are currently enabled
ps aux | grep kube-apiserver | tr ' ' '\n' | grep "admission-plugins"

# Or check the static pod manifest
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep "admission"

# List all default enabled plugins
kube-apiserver --help 2>&1 | grep -A 5 "enable-admission"
```

### Enabling ImagePolicyWebhook

```bash
# Edit the static pod manifest (kubeadm cluster)
vim /etc/kubernetes/manifests/kube-apiserver.yaml

# Add these two lines to the command section:
# - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
# - --admission-control-config-file=/etc/kubernetes/admission-config.yaml

# Verify the API server restarts (watch for the container to come back)
watch -n 1 "crictl ps | grep kube-apiserver"
# or
kubectl get pods -n kube-system -w | grep apiserver
```

### Creating the Admission Config File

```bash
# Create the AdmissionConfiguration file
cat > /etc/kubernetes/admission-config.yaml << 'EOF'
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/kubernetes/admission-kubeconfig.yaml
      allowTTL: 50
      denyTTL: 50
      retryBackoff: 500
      defaultAllow: true
EOF

# Create the KubeConfig for the webhook
cat > /etc/kubernetes/admission-kubeconfig.yaml << 'EOF'
apiVersion: v1
kind: Config
clusters:
- name: image-policy-webhook
  cluster:
    certificate-authority: /etc/kubernetes/pki/ca.crt
    server: https://image-policy-webhook.kube-system.svc:443/policy
users:
- name: kube-apiserver
  user:
    client-certificate: /etc/kubernetes/pki/apiserver.crt
    client-key: /etc/kubernetes/pki/apiserver.key
contexts:
- context:
    cluster: image-policy-webhook
    user: kube-apiserver
  name: image-policy
current-context: image-policy
EOF
```

### OPA Gatekeeper Commands

```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Check Gatekeeper pods
kubectl get pods -n gatekeeper-system

# Apply a ConstraintTemplate
kubectl apply -f constraint-template.yaml

# Apply a Constraint
kubectl apply -f constraint.yaml

# Check violations (audit mode results)
kubectl get constraint -A
kubectl describe allowedimageregistries prod-registry-allowlist

# Test a pod that should be denied
kubectl run test --image=nginx --namespace=production --dry-run=server
```

### Kyverno Commands

```bash
# Install Kyverno
kubectl apply -f https://github.com/kyverno/kyverno/releases/latest/download/install.yaml

# Check Kyverno pods
kubectl get pods -n kyverno

# Apply a policy
kubectl apply -f registry-policy.yaml

# Get policy reports (violations in Audit mode)
kubectl get policyreport -A
kubectl get policyreport -n production -o yaml

# Check cluster-wide policy reports
kubectl get clusterpolicyreport

# Test a policy without applying
kyverno apply registry-policy.yaml --resource pod.yaml
```

### Testing Registry Enforcement

```bash
# Test that a denied registry is blocked
kubectl run nginx-from-hub --image=nginx --namespace=production
# Expected: error from admission webhook

# Test that an allowed registry is permitted
kubectl run myapp --image=mycompany-registry.io/myapp:1.0.0 --namespace=production
# Expected: pod created

# Audit all running pods for registry compliance
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' \
  | awk '!($3 ~ /^mycompany-registry\.io\//) {print "VIOLATION:", $0}'
```

---

## 12. Other Tools and Services Available

### Policy Enforcement Engines

| Tool | Approach | Language | Strengths |
|------|----------|----------|-----------|
| **OPA Gatekeeper** | CRD-based | Rego | CNCF; most flexible; large community; audit mode |
| **Kyverno** | CRD-based | YAML DSL | Easy to learn; mutation support; generate policies; cosign verification |
| **jsPolicy** | CRD-based | JavaScript | Familiar language for JS teams |
| **Kubewarden** | CRD-based | WASM | Write policies in Rust, Go, Python; compile to WASM |
| **Polaris** (Fairwinds) | Webhook | YAML | Pre-built best practice rules; dashboard |

### Registry Security Platforms

| Tool | Type | Key Feature |
|------|------|------------|
| **Harbor** | Self-hosted | Per-project webhook policies; push/pull access control |
| **JFrog Xray** | Commercial | Repository-level policies; block promotion on violations |
| **Anchore Enterprise** | Commercial | Kubernetes admission plugin; policy bundles |
| **Prisma Cloud** | Commercial | Registry scanning + runtime admission control in one platform |
| **Snyk Container** | Commercial | Registry scanning with IDE and CI integration |
| **Amazon ECR** | Managed | Repository policies; lifecycle rules; basic image scanning |

### Admission Webhook Frameworks

| Tool | Purpose |
|------|---------|
| **controller-runtime** | Go framework for building admission webhooks (used by most operators) |
| **kube-webhook-certgen** | Automatically generate and inject TLS certs for admission webhooks |
| **cert-manager** | Manages TLS certificates for webhooks; integrates with Kyverno |
| **Metacontroller** | Simplifies building admission webhooks for non-Go developers |

---

## 13. How AI Is Impacting Registry Enforcement

### AI-Powered Registry Analysis

Static allowlisting — "only images from X registry are allowed" — is necessary but not sufficient. An attacker who can push to your approved registry (compromised CI/CD, insider threat) bypasses the allowlist entirely. AI is adding a second layer:

- **Behavioural image analysis** — ML models analyse the contents of each image pushed to your registry. Images that contain unusual binaries, network scanning tools, cryptocurrency miners, or encoded shell scripts are flagged before they are deployable. JFrog Xray and Aqua Security's DTA (Dynamic Threat Analysis) use this approach.
- **Provenance graph ML** — Systems like GUAC build dependency graphs of your entire image fleet and use graph neural networks to detect anomalies: an image that suddenly has 50% more packages than its predecessor, or a package that appears in your images but has never been through your build system.
- **Push anomaly detection** — ML models learn normal push patterns for each registry namespace and alert on deviations: a new image pushed at 3am, a push that bypassed normal CI/CD (no associated build pipeline event), an image size that is dramatically different from historical versions.

### AI in Policy Generation

Writing effective Rego policies or Kyverno rules for complex registry scenarios (multi-tier, namespace-specific, exception-aware) requires deep expertise. AI is lowering the barrier:

- **LLM policy synthesis** — Tools like OpenAI Codex and GitHub Copilot can generate Kyverno and OPA policies from natural-language descriptions: "Write a Kyverno policy that allows images from mycompany-registry.io in all namespaces except kube-system, and requires images to have a specific label indicating they passed security scanning."
- **Policy lint and verification** — AI tools analyse policies for common mistakes: overly broad allowlists, missing `initContainers` checks, namespace exemptions that are too wide, and `failurePolicy: Ignore` settings that create silent bypasses.

### AI in Admission Control

- **Risk-based admission** — Rather than binary allow/deny, AI-enhanced admission controllers score each image based on multiple signals (CVE count, age of base image, SBOM completeness, signature validity, registry reputation) and apply policies based on the composite risk score. Low-risk images are allowed immediately; high-risk images trigger additional review or are denied.
- **Adaptive allowlisting** — ML models analyse deployment patterns over time and automatically suggest additions to or removals from registry allowlists. New legitimate registries used by a majority of teams are flagged for review; approved registries that haven't been used in 90 days are flagged for removal.

---

## 14. CKS Exam Tips

The CKS exam has specific tasks around ImagePolicyWebhook and registry enforcement. This is one of the most exam-specific topics in the CKS — it requires knowledge of exact file locations, flag names, and file formats.

**High-probability exam tasks:**

1. **Enable ImagePolicyWebhook in kube-apiserver static pod:**
   - Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`
   - Add `--enable-admission-plugins=NodeRestriction,ImagePolicyWebhook`
   - Add `--admission-control-config-file=/path/to/admission-config.yaml`

2. **Create the AdmissionConfiguration file:**
   ```yaml
   apiVersion: apiserver.config.k8s.io/v1
   kind: AdmissionConfiguration
   plugins:
   - name: ImagePolicyWebhook
     configuration:
       imagePolicy:
         kubeConfigFile: /path/to/kubeconfig
         allowTTL: 50
         denyTTL: 50
         retryBackoff: 500
         defaultAllow: true
   ```

3. **Create the webhook kubeconfig:**
   - Know the format: `clusters[].cluster.server` points to the webhook URL
   - `clusters[].cluster.certificate-authority` is the CA for the webhook server's TLS cert
   - `users[].user.client-certificate` and `client-key` are the API server's mTLS client credentials

4. **Mount the config files into the kube-apiserver static pod:**
   - Files on the host need `hostPath` volumes and `volumeMounts`
   - If the file is already accessible at the same path inside the container (e.g., `/etc/kubernetes/`), the mount may already exist

5. **Know what OPA Rego policy denying unapproved registries looks like:**
   ```rego
   deny[msg] {
     input.request.kind.kind == "Pod"
     image := input.request.object.spec.containers[_].image
     not startswith(image, "internal-registry.io/")
     msg := sprintf("Image '%s' is not from a trusted registry", [image])
   }
   ```

**Critical facts to memorise:**

- The flag is `--enable-admission-plugins` (plural) not `--enable-admission-plugin`
- The admission config is specified with `--admission-control-config-file` (exact flag name)
- `ImagePolicyWebhook` only checks **image names** — not other pod configuration
- The API object type in the webhook request is `ImageReview` (not `AdmissionReview`)
- `defaultAllow: true` = fail open; `defaultAllow: false` = fail closed
- The `kubeConfigFile` in `AdmissionConfiguration` must be accessible at that path **inside the kube-apiserver container** — not just on the host

**Common exam traps:**

- **Forgetting the volume mount** — The most common failure. The config file path in `--admission-control-config-file` must be accessible inside the kube-apiserver container. If you put the file at `/etc/kubernetes/admission-config.yaml` on the host, you need to verify that `/etc/kubernetes/` is already mounted (it usually is in kubeadm clusters). Check the existing `volumeMounts` section.
- **API server not restarting** — After editing the static pod manifest, watch for the API server to come back: `watch crictl ps | grep apiserver`. If it doesn't come back in 30 seconds, check logs: `crictl logs $(crictl ps -a | grep apiserver | head -1 | awk '{print $1}')`.
- **Using `--admission-plugins` instead of `--enable-admission-plugins`** — The wrong flag name is silently ignored; the API server starts but the plugin is not enabled.
- **Missing `NodeRestriction` from the plugins list** — Always include your existing plugins when modifying `--enable-admission-plugins`, otherwise you might accidentally disable them.

---

## 15. Extra Information and References

### The ImageReview API — What the Webhook Receives

Unlike `ValidatingAdmissionWebhook` which receives `AdmissionReview` objects, `ImagePolicyWebhook` uses the `imagepolicy.k8s.io/v1alpha1` API:

```bash
# The webhook receives an ImageReview and must return an ImageReview

# Request from API server → webhook:
{
  "apiVersion": "imagepolicy.k8s.io/v1alpha1",
  "kind": "ImageReview",
  "spec": {
    "containers": [
      {"image": "myregistry.io/myapp:1.0"},
      {"image": "myregistry.io/sidecar:2.0"}
    ],
    "initContainers": [],
    "annotations": {
      "mycluster.io/imagegroup": "myapp"  # Custom annotations can be passed
    },
    "namespace": "production"
  }
}

# Response from webhook → API server (allow):
{
  "apiVersion": "imagepolicy.k8s.io/v1alpha1",
  "kind": "ImageReview",
  "status": {
    "allowed": true
  }
}

# Response from webhook → API server (deny):
{
  "apiVersion": "imagepolicy.k8s.io/v1alpha1",
  "kind": "ImageReview",
  "status": {
    "allowed": false,
    "reason": "Image 'badregistry.io/malware:1.0' is not from an approved registry"
  }
}
```

### Combining Approaches — Belt and Suspenders

For maximum security, combine multiple approaches at different layers:

```
Layer 1: Developer IDE
  → kube-linter or conftest checks image registry in local YAML files
  → Catches mistakes at authoring time

Layer 2: CI/CD Pipeline
  → Policy-as-code check in pull request pipeline
  → `conftest test pod.yaml` against OPA policy

Layer 3: Kubernetes Admission (ImagePolicyWebhook or OPA/Kyverno)
  → Hard enforcement at cluster level
  → No image from unapproved registry can run, even if CI/CD is bypassed

Layer 4: Runtime (Falco)
  → Alert on unexpected outbound connections from containers
  → Even if a malicious image somehow runs, Falco detects C2 callback attempts
```

### Exempting Namespaces from Policy

All registry enforcement approaches need careful namespace exemption:

```yaml
# Kyverno — exempt a namespace using matchExpressions
spec:
  rules:
    - name: validate-registries
      match:
        any:
          - resources:
              kinds: [Pod]
      exclude:
        any:
          - resources:
              namespaces:
                - kube-system
                - kyverno
                - gatekeeper-system
                - monitoring    # If Prometheus uses non-approved images

# OPA Gatekeeper — namespace annotation to exclude
kubectl annotate namespace kube-system admission.gatekeeper.sh/ignore=yes

# ValidatingWebhookConfiguration — namespace selector to exclude kube-system
spec:
  namespaceSelector:
    matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: NotIn
        values:
          - kube-system
          - kyverno
          - gatekeeper-system
```

### References

- [Kubernetes — Using Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Kubernetes — Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubernetes — ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)
- [OPA Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/website/docs/)
- [OPA Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Kyverno Documentation](https://kyverno.io/docs/)
- [Kyverno — Restrict Image Registries](https://kyverno.io/policies/best-practices/restrict-image-registries/restrict-image-registries/)
- [AdmissionConfiguration API Reference](https://kubernetes.io/docs/reference/config-api/apiserver-config.v1/)
- [KodeKloud CKS Course — Whitelist Allowed Registries Image Policy Webhook](https://learn.kodekloud.com/user/courses/certified-kubernetes-security-specialist-cks/module/e4511664-185f-4204-9aa2-b4250cbadf84/lesson/6125bec1-413f-46be-8c24-2d0fca37dd57)
