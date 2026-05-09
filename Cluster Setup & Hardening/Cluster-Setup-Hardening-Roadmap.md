# 🛠️ Roadmap: Cluster Setup & Hardening

Welcome to the **Cluster Setup & Hardening** module. This is the most critical phase of the Kubernetes security journey. While the 4Cs give us the big picture, this module focuses specifically on the **Cluster** layer—turning a default, "open" Kubernetes installation into a production-hardened fortress.

## 📖 Introduction

Setting up a Kubernetes cluster is easy; securing it is the hard part. By default, Kubernetes is designed for usability and flexibility, which often means many security features are either disabled or set to permissive defaults. 

**Cluster Hardening** is the process of reducing the attack surface by removing unnecessary privileges, encrypting communications, and implementing strict access controls. The goal is to ensure that even if one component is compromised, the attacker cannot move laterally through the cluster or escalate their privileges to gain full control.

In this series, we will move step-by-step through the following domains:
1. **Compliance & Auditing:** Checking our work against industry standards.
2. **Identity & Access:** Ensuring only the right people/services can do the right things.
3. **Encryption:** Protecting data in transit and at rest.
4. **Infrastructure Protection:** Hardening the actual nodes and binaries.
5. **Traffic Control:** Managing how data flows into and within the cluster.

---

## 🗺️ Learning Path & Checklist

Below is the step-by-step progression we will follow. Each item represents a critical security milestone.

### Phase 1: The Security Baseline 🔍
- [ ] **CIS Benchmarks**
    - *What:* Using the Center for Internet Security (CIS) guidelines to find misconfigurations.
    - *Goal:* Establish a "Security Score" and identify immediate gaps.
- [ ] **Verifying Platform Binaries**
    - *What:* Ensuring that `kubelet`, `kube-apiserver`, and other binaries haven't been tampered with.
    - *Goal:* Prevent "Supply Chain" attacks on the cluster components themselves.
- [ ] **Upgrade Kubernetes Frequently**
    - *What:* Maintaining the latest stable version of K8s.
    - *Goal:* Patch known CVEs and remove deprecated, insecure APIs.

### Phase 2: Identity & Access Management (IAM) 🔑
- [ ] **Authentication**
    - *What:* "Who are you?" Implementing OIDC, Certificates, and Token-based auth.
    - *Goal:* Ensure no anonymous or unauthorized users can reach the API.
- [ ] **Authorization**
    - *What:* "What are you allowed to do?" Deep dive into RBAC (Roles, ClusterRoles).
    - *Goal:* Implement the Principle of Least Privilege (PoLP).
- [ ] **Service Accounts**
    - *What:* Managing identities for pods and automated processes.
    - *Goal:* Prevent pods from using overly permissive default service accounts.

### Phase 3: Hardening the Communication 🔒
- [ ] **TLS in Kubernetes**
    - *What:* Implementing Mutual TLS (mTLS) for all component-to-component talk.
    - *Goal:* Prevent Man-in-the-Middle (MITM) attacks.
- [ ] **Securing the Kubernetes Dashboard**
    - *What:* Restricting access to the web UI.
    - *Goal:* Prevent the dashboard from becoming an easy entry point for attackers.
- [ ] **Protect Node Metadata and Endpoints**
    - *What:* Blocking access to cloud provider metadata APIs (e.g., `169.254.169.254`).
    - *Goal:* Stop attackers from stealing cloud IAM roles from within a pod.

### Phase 4: Network Fortressing 🌐
- [ ] **Network Policies**
    - *What:* Creating L3/L4 firewalls between pods.
    - *Goal:* Implement a "Default Deny" policy to stop lateral movement.
- [ ] **Securing Ingress**
    - *What:* Hardening the entry point of the cluster.
    - *Goal:* Protect against external attacks using TLS termination and WAFs.

---

## 🚀 How to use this Guide

1. **The Theory:** Each topic will start with the "Why" and "How" it works.
2. **The Practical:** We will implement each step in a live cluster.
3. **The Verification:** We will use tools like `kube-bench` or `kubectl` to prove the security fix is working.

> [!TIP]
> **Don't rush.** Security is about the details. One small mistake in an RBAC role can leave your entire cluster open.
