# 7 — Minimize IAM Roles

> **What you'll learn:** What IAM is and why it mirrors Linux user management in the cloud, how to structure users, groups, and roles with least privilege, how AWS resources use IAM roles (not static credentials), how IAM connects to Kubernetes node security, and how to audit and continuously review cloud permissions.

---

## Table of Contents

1. [What is IAM?](#1-what-is-iam)
2. [IAM vs Linux User Management — The Parallel](#2-iam-vs-linux-user-management--the-parallel)
3. [The Root Account — Same Rule, Cloud Edition](#3-the-root-account--same-rule-cloud-edition)
4. [IAM Users and Groups](#4-iam-users-and-groups)
5. [IAM Policies — How Permissions Are Defined](#5-iam-policies--how-permissions-are-defined)
6. [IAM Groups — Managing Permissions at Scale](#6-iam-groups--managing-permissions-at-scale)
7. [IAM Roles for AWS Resources](#7-iam-roles-for-aws-resources)
8. [IAM and Kubernetes — The Connection](#8-iam-and-kubernetes--the-connection)
9. [Multi-Cloud IAM — AWS, GCP, and Azure](#9-multi-cloud-iam--aws-gcp-and-azure)
10. [Continual Review and Auditing](#10-continual-review-and-auditing)
11. [Real-World Scenarios](#11-real-world-scenarios)
12. [Common Mistakes & Gotchas](#12-common-mistakes--gotchas)
13. [CKS Exam Tips](#13-cks-exam-tips)

---

## 1. What is IAM?

**IAM (Identity and Access Management)** is the system cloud providers use to control *who* can do *what* to *which* resources. It is the cloud equivalent of Linux user accounts, groups, sudo rules, and file permissions — but for cloud infrastructure.

```mermaid
flowchart LR
    subgraph LINUX["Linux IAM (On-Prem)"]
        LU["Users\nmark, alice, kubelet"]
        LG["Groups\nsudo, docker, k8s-admin"]
        LP["Permissions\n/etc/sudoers\nfile permissions\nRBAC"]
        LU --> LG --> LP
    end

    subgraph CLOUD["Cloud IAM (AWS)"]
        CU["IAM Users\nmark@example.com\nlcy@example.com"]
        CG["IAM Groups\nDeveloper Group\nOps Group\nAudit Group"]
        CP["IAM Policies\nEC2FullAccess\nS3ReadOnly\nCustomPolicies"]
        CR["IAM Roles\nFor services\nEC2, Lambda, EKS"]
        CU --> CG --> CP
        CR --> CP
    end

    LINUX <-->|"Same principle:\nLeast Privilege"| CLOUD
```

### What IAM Controls

| Cloud Resource | IAM Controls Access To |
|---|---|
| **Compute** | EC2 instances, Lambda functions, EKS nodes |
| **Storage** | S3 buckets, EBS volumes, EFS filesystems |
| **Databases** | RDS, DynamoDB, ElastiCache |
| **Networking** | VPCs, Security Groups, Route Tables |
| **Identity** | Other IAM users, roles, and policies |
| **Kubernetes** | EKS clusters, node groups, API access |
| **Secrets** | AWS Secrets Manager, Parameter Store |

---

## 2. IAM vs Linux User Management — The Parallel

Everything we've covered about Linux user security in this module maps directly to IAM:

| Linux Concept | IAM Equivalent | Principle |
|---|---|---|
| `root` account | AWS root account | Avoid for daily ops — emergency use only |
| Regular user (UID 1000+) | IAM user | Human identity for specific tasks |
| System account (UID 1-999) | IAM role (for services) | Machine identity — not for humans |
| `/etc/sudoers` | IAM policy | Defines what actions are allowed |
| sudo group | IAM group | Bundle users with similar permissions |
| `sudo systemctl restart nginx` | IAM policy action `ec2:StopInstances` | Specific action grant |
| `PermitRootLogin no` | Securing root account | Prevent direct root/admin access |
| `chmod 600 ~/.ssh/id_rsa` | IAM access key rotation | Protect credentials |
| `visudo` | IAM policy JSON editor | Safe policy editing with validation |

```mermaid
mindmap
  root((PoLP in\nthe Cloud))
    AWS Root Account
      Only used to create first IAM admin
      MFA enabled always
      Access keys never created
      Credentials locked in vault
    IAM Users
      One user per human
      No shared accounts
      MFA required
      Access keys rotated regularly
    IAM Groups
      Permissions attached to groups not users
      Developer Group
      Ops Group
      ReadOnly Group
    IAM Roles
      For AWS services and resources
      No static credentials stored
      Temporary credentials via STS
      Used by EC2 Lambda EKS
```

---

## 3. The Root Account — Same Rule, Cloud Edition

Just as in Linux where the `root` account should never be used for daily operations, the **AWS root account** holds full administrative power over everything — billing, account closure, IAM, every service — and should be treated accordingly.

```mermaid
flowchart TD
    ROOT["☠️ AWS Root Account\nFull control of everything\nCan delete all resources\nCan close the account\nCan bypass all IAM policies\nCAN NEVER BE RESTRICTED BY IAM"]

    FIRST["First-Time Only Use:\n1. Sign in with root\n2. Create first IAM admin user\n3. Enable MFA on root\n4. Never use root again\n5. Lock credentials in a vault"]

    BREAK_GLASS["Break-Glass Scenarios Only:\n- Locked out of all IAM admin accounts\n- Billing/account-level changes\n- Closing the account\n- Removing MFA device"]

    ROOT --> FIRST
    ROOT --> BREAK_GLASS

    style ROOT fill:#ff6b6b,color:#fff
    style FIRST fill:#6bcb77,color:#fff
    style BREAK_GLASS fill:#ffd93d,color:#333
```

### Root Account Hardening Checklist

```
✅ Enable MFA (hardware key or authenticator app — NOT SMS)
✅ Never create access keys for root
✅ Use a strong, unique password stored in a password manager
✅ Store root credentials in a physical safe (or sealed envelope)
✅ Set up billing alerts so root account abuse is detected
✅ Enable CloudTrail to log all root account usage
✅ Review: AWS Security Hub will alert on any root account activity
```

---

## 4. IAM Users and Groups

![AWS root account hierarchy with four users: Lucy, Shiva, Abdul, and Anita](https://kodekloud.com/kk-media/image/upload/v1752871741/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Minimize-IAM-roles/frame_120.jpg)

When Mark creates a new AWS account, the first step is creating individual IAM users for each team member — **one user per human, never shared accounts**.

### Why Individual IAM Users?

```mermaid
flowchart LR
    subgraph SHARED["❌ Shared Account (Bad)"]
        S1["Single user: devteam\nPassword shared among 5 people"]
        S2["Any of the 5 people can\nact as 'devteam'"]
        S3["Audit log shows 'devteam deleted\nproduction database'\nWho was it? Unknown."]
        S1 --> S2 --> S3
    end

    subgraph INDIVIDUAL["✅ Individual Accounts (Good)"]
        I1["lucy: owns her credentials"]
        I2["shiva: owns his credentials"]
        I3["Audit log shows:\n'shiva deleted production database\nat 2024-07-29 02:15 UTC from 192.168.1.50'"]
        I1 --> I3
        I2 --> I3
    end

    style SHARED fill:#ff6b6b,color:#fff
    style INDIVIDUAL fill:#6bcb77,color:#fff
```

### Creating IAM Users (AWS Console vs CLI)

**Using AWS CLI:**

```bash
# Create a new IAM user
aws iam create-user --user-name lucy

# Create login profile (console password)
aws iam create-login-profile \
  --user-name lucy \
  --password "TempPass123!" \
  --password-reset-required   # Force password change on first login

# Create access keys (for CLI/API access — rotate regularly)
aws iam create-access-key --user-name lucy
# Returns: AccessKeyId + SecretAccessKey
# Store SecretAccessKey immediately — it's shown only once!

# List all IAM users
aws iam list-users

# Get user details
aws iam get-user --user-name lucy
```

---

## 5. IAM Policies — How Permissions Are Defined

![User permissions: AmazonEC2Create and AmazonS3BucketAccess for Shiva, Abdul, and Anita](https://kodekloud.com/kk-media/image/upload/v1752871742/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Minimize-IAM-roles/frame_160.jpg)

An **IAM policy** is a JSON document that defines what actions are allowed or denied, on which resources, and under what conditions.

### Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ec2:StopInstances"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-dev-bucket",
        "arn:aws:s3:::my-dev-bucket/*"
      ]
    }
  ]
}
```

### Policy Fields Explained

| Field | Values | Description |
|---|---|---|
| `Effect` | `Allow` / `Deny` | Whether to grant or block |
| `Action` | e.g., `ec2:RunInstances` | The API call being permitted |
| `Resource` | ARN or `*` | Which specific resource this applies to |
| `Condition` | IP, time, MFA, tags | Optional — add conditions to allow/deny |
| `Principal` | User/role ARN | Who this applies to (in resource-based policies) |

### Types of IAM Policies

```mermaid
flowchart TD
    subgraph TYPES["IAM Policy Types"]
        MP["AWS Managed Policies\nPre-built by AWS\nAmazonEC2FullAccess\nAmazonS3ReadOnlyAccess\nAdministratorAccess"]
        CP["Customer Managed Policies\nYou create them\nFine-grained control\nVersion-controlled"]
        IP["Inline Policies\nEmbedded directly in user/role\nNot reusable\nAvoid in production"]
        RBP["Resource-Based Policies\nAttached to the resource\nS3 bucket policy\nKMS key policy"]
    end

    style MP fill:#4d96ff,color:#fff
    style CP fill:#6bcb77,color:#fff
    style IP fill:#ffd93d,color:#333
    style RBP fill:#a855f7,color:#fff
```

### Least Privilege Policy — Before vs After

```json
// ❌ Over-broad — given "just to be safe"
{
  "Effect": "Allow",
  "Action": "*",           // Every AWS action
  "Resource": "*"          // Every resource
}
```

```json
// ✅ Least privilege — developer who needs EC2 + specific S3 bucket
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2DeveloperAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ec2:DescribeImages",
        "ec2:TerminateInstances"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:Region": "us-east-1"   // Only in this region
        }
      }
    },
    {
      "Sid": "S3DevBucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::dev-team-bucket",       // Only THIS bucket
        "arn:aws:s3:::dev-team-bucket/*"
      ]
    }
  ]
}
```

---

## 6. IAM Groups — Managing Permissions at Scale

![IAM Developer Group with Shiva, Abdul, and Anita — AmazonEC2Create and AmazonS3BucketAccess](https://kodekloud.com/kk-media/image/upload/v1752871744/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Minimize-IAM-roles/frame_180.jpg)

Instead of attaching policies to each individual user, group users with similar roles and attach policies to the group. This is the cloud equivalent of Linux groups + sudoers.

```mermaid
flowchart TD
    subgraph GROUPS["IAM Groups → Policies"]
        DEV["Developer Group\n🧑‍💻 Shiva, Abdul, Anita"]
        OPS["Ops Group\n🔧 Lucy, Charlie"]
        AUDIT["Audit Group\n🔍 Compliance Team"]
        READONLY["ReadOnly Group\n👁 Stakeholders"]
    end

    subgraph POLICIES["Attached Policies"]
        P1["EC2FullAccess\nS3DevBucketAccess\nCloudWatchLogs"]
        P2["EC2FullAccess\nS3FullAccess\nRDSFullAccess\nIAMReadOnly"]
        P3["AWSCloudTrailReadOnlyAccess\nSecurityHubReadOnlyAccess\nIAMReadOnly"]
        P4["ViewOnlyAccess"]
    end

    DEV --> P1
    OPS --> P2
    AUDIT --> P3
    READONLY --> P4
```

### Group Management Commands

```bash
# Create a group
aws iam create-group --group-name developers

# Attach a managed policy to the group
aws iam attach-group-policy \
  --group-name developers \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess

# Add a user to the group
aws iam add-user-to-group \
  --group-name developers \
  --user-name shiva

aws iam add-user-to-group --group-name developers --user-name abdul
aws iam add-user-to-group --group-name developers --user-name anita

# List group members
aws iam get-group --group-name developers

# List policies attached to group
aws iam list-attached-group-policies --group-name developers

# Remove user from group (offboarding)
aws iam remove-user-from-group \
  --group-name developers \
  --user-name shiva
```

### The Group-Based Permission Model

```mermaid
sequenceDiagram
    participant HR as HR System
    participant ADMIN as Cloud Admin
    participant IAM as AWS IAM

    Note over HR,IAM: New developer joins team
    HR->>ADMIN: Shiva joined — Developer role
    ADMIN->>IAM: aws iam create-user --user-name shiva
    ADMIN->>IAM: aws iam add-user-to-group --group developers --user-name shiva
    IAM-->>ADMIN: Shiva now has all developer permissions via group

    Note over HR,IAM: Developer leaves team
    HR->>ADMIN: Shiva is leaving — effective today
    ADMIN->>IAM: aws iam remove-user-from-group --group developers --user-name shiva
    ADMIN->>IAM: aws iam delete-login-profile --user-name shiva
    ADMIN->>IAM: aws iam delete-access-key --user-name shiva --access-key-id AKIA...
    IAM-->>ADMIN: Shiva has zero access immediately
```

---

## 7. IAM Roles for AWS Resources

![S3BucketAccessRole — allowing EC2 to access S3](https://kodekloud.com/kk-media/image/upload/v1752871745/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Minimize-IAM-roles/frame_300.jpg)

AWS services (EC2, Lambda, EKS nodes) cannot use username/password credentials. They use **IAM Roles** — which provide **temporary, automatically-rotated credentials** via the AWS Security Token Service (STS).

### The Problem Without IAM Roles

```mermaid
flowchart LR
    subgraph BAD["❌ Static Credentials (Wrong Way)"]
        EC2["EC2 Instance\nRunning application"]
        CODE["Application code\nexport AWS_ACCESS_KEY_ID=AKIA...\nexport AWS_SECRET_ACCESS_KEY=..."]
        S3["S3 Bucket"]
        EC2 --> CODE --> S3
        ATTK["🔴 Attacker reads\n/proc/environ or env vars\n→ Permanent AWS credentials stolen"]
        CODE --> ATTK
    end

    subgraph GOOD["✅ IAM Role (Right Way)"]
        EC2G["EC2 Instance\nAttached: S3AccessRole"]
        IMDS["Instance Metadata Service\n169.254.169.254\nProvides temporary creds\nAuto-rotated every hour"]
        S3G["S3 Bucket"]
        EC2G --> IMDS --> S3G
        ATKG["🔴 Attacker reads metadata\nGets credentials... but they\nexpire in 1 hour maximum"]
        IMDS --> ATKG
    end

    style BAD fill:#ff6b6b,color:#fff
    style GOOD fill:#6bcb77,color:#fff
```

### Creating an IAM Role for EC2 (S3 Access Example)

```bash
# Step 1 — Create a trust policy (who can assume this role)
cat > trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"   // Only EC2 instances can assume this role
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Step 2 — Create the role
aws iam create-role \
  --role-name S3AccessRole \
  --assume-role-policy-document file://trust-policy.json

# Step 3 — Attach permissions to the role (what it can do)
aws iam attach-role-policy \
  --role-name S3AccessRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Step 4 — Create an instance profile (needed to attach role to EC2)
aws iam create-instance-profile \
  --instance-profile-name S3AccessProfile

# Step 5 — Add the role to the instance profile
aws iam add-role-to-instance-profile \
  --instance-profile-name S3AccessProfile \
  --role-name S3AccessRole

# Step 6 — Launch EC2 with the role attached
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t3.micro \
  --iam-instance-profile Name=S3AccessProfile \
  ...

# On the EC2 instance — application gets credentials automatically
# Via SDK: boto3.client('s3')  ← No keys needed, role provides creds
# Via CLI: aws s3 ls            ← Uses role credentials from IMDS
```

### IAM Role for EKS Worker Nodes

EKS worker nodes (Kubernetes nodes) also use IAM roles:

```bash
# Create the EKS node IAM role
aws iam create-role \
  --role-name EKSNodeRole \
  --assume-role-policy-document file://eks-trust-policy.json

# Attach required policies for K8s worker nodes
aws iam attach-role-policy \
  --role-name EKSNodeRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy

aws iam attach-role-policy \
  --role-name EKSNodeRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy

aws iam attach-role-policy \
  --role-name EKSNodeRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
# ^ Only these 3 — nothing more
```

---

## 8. IAM and Kubernetes — The Connection

IAM is not just a cloud concept — it directly impacts the security of your Kubernetes cluster when running on a cloud provider.

### Three Critical IAM + K8s Intersections

```mermaid
flowchart TD
    subgraph INTERSECTION["IAM ↔ Kubernetes Security"]
        I1["1. EKS Node IAM Role\nWorker nodes assume a role\nToo broad = nodes can delete S3\nLeast privilege = only ECR + VPC + EKS"]

        I2["2. Pod IAM Roles (IRSA)\nPods assume IAM roles via\nIAM Roles for Service Accounts\nEach pod gets only what it needs"]

        I3["3. IMDS Access from Pods\nPods can call 169.254.169.254\nand steal the NODE's IAM credentials\nBlock with IMDSv2 + NetworkPolicy\n(Covered in Ch. 18)"]
    end

    style I1 fill:#4d96ff,color:#fff
    style I2 fill:#6bcb77,color:#fff
    style I3 fill:#ff6b6b,color:#fff
```

### IAM Roles for Service Accounts (IRSA) — PoLP for Pods

```yaml
# Without IRSA: Pod uses node's IAM role (over-privileged)
# All pods on the node can do anything the node's role allows

# With IRSA: Pod gets its own scoped IAM role
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-reader
  namespace: production
  annotations:
    # This SA assumes a specific IAM role with minimal permissions
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/s3-readonly-role
```

```bash
# The s3-readonly-role policy — only list and read one specific bucket
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::my-app-bucket",
      "arn:aws:s3:::my-app-bucket/*"
    ]
  }]
}
# If this pod is compromised: attacker can only read this one bucket
# NOT the node's full IAM role permissions
```

---

## 9. Multi-Cloud IAM — AWS, GCP, and Azure

![AWS Trusted Advisor, Google Cloud Security Command Center, and Azure Advisor logos](https://kodekloud.com/kk-media/image/upload/v1752871748/notes-assets/images/Certified-Kubernetes-Security-Specialist-CKS-Minimize-IAM-roles/frame_340.jpg)

The same least privilege concepts apply across all major cloud providers:

| Concept | AWS | GCP | Azure |
|---|---|---|---|
| **Root account** | Root user | Owner role | Global Administrator |
| **Human identities** | IAM Users | Google Accounts | Azure AD Users |
| **Groups** | IAM Groups | Google Groups | Azure AD Groups |
| **Service identity** | IAM Roles | Service Accounts | Managed Identities |
| **Permission document** | IAM Policy (JSON) | IAM Binding + Roles | Role Assignments |
| **Temporary credentials** | STS AssumeRole | Workload Identity | Managed Identity tokens |
| **Audit logs** | CloudTrail | Cloud Audit Logs | Azure Activity Log |
| **Policy advisor** | AWS Access Analyzer | IAM Recommender | Azure Advisor |
| **Security posture** | AWS Trusted Advisor / Security Hub | Security Command Center | Microsoft Defender for Cloud |

### GCP IAM Quick Reference

```bash
# GCP equivalent of IAM role for a service account
gcloud iam service-accounts create app-sa \
  --description="App service account" \
  --display-name="App Service Account"

# Grant minimal permissions
gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:app-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"   # Read-only, not storage.admin

# List current IAM policy
gcloud projects get-iam-policy my-project

# Audit who has owner/editor roles (too broad)
gcloud projects get-iam-policy my-project \
  --format=json | jq '.bindings[] | select(.role=="roles/owner" or .role=="roles/editor")'
```

### Azure IAM Quick Reference

```bash
# List all role assignments in a subscription
az role assignment list --all --output table

# Create a service principal with minimal role
az ad sp create-for-rbac \
  --name "my-app-sp" \
  --role "Storage Blob Data Reader" \
  --scopes "/subscriptions/<sub-id>/resourceGroups/myRG/providers/Microsoft.Storage/storageAccounts/myaccount"

# Check what a principal can do (like kubectl auth can-i)
az role assignment list --assignee my-app-sp@tenant --output table
```

---

## 10. Continual Review and Auditing

Permissions accumulate over time. Users get roles "temporarily" that never get removed. Services gain permissions "just in case" that were never needed. Regular auditing is mandatory.

```mermaid
flowchart LR
    ASSIGN["Permission\nAssigned"]
    USE["Permission\nUsed Regularly"]
    UNUSED["Permission\nNot Used\n> 90 days"]
    REVIEW["Periodic Review\nQuarterly audit"]
    REMOVE["Permission\nRemoved"]

    ASSIGN -->|"Active use"| USE
    ASSIGN -->|"Forgotten"| UNUSED
    USE -->|"Role changes\nor offboarding"| REVIEW
    UNUSED --> REVIEW
    REVIEW -->|"Not needed"| REMOVE
    REMOVE -->|"Re-request\nif needed"| ASSIGN

    style UNUSED fill:#ff6b6b,color:#fff
    style REMOVE fill:#6bcb77,color:#fff
```

### AWS IAM Auditing Commands

```bash
# Generate a credential report (all users, last used times)
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | column -t -s ','
# Shows: user, password_last_used, access_key_1_last_used, mfa_active

# Find users with keys not rotated in > 90 days
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F',' 'NR>1 && $10 != "N/A" && $10 < "2024-01-01" {print $1, "key last used:", $10}'

# List all users and their attached policies
aws iam list-users --query 'Users[].UserName' --output text | \
  xargs -I {} sh -c 'echo "=== {} ===" && aws iam list-attached-user-policies --user-name {}'

# Find users without MFA
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F',' 'NR>1 && $8 == "false" {print "No MFA:", $1}'

# List all roles and when they were last used
aws iam get-account-authorization-details \
  --filter Role \
  --query 'RoleDetailList[].{Role:RoleName,LastUsed:RoleLastUsed.LastUsedDate}' \
  --output table

# Use AWS Access Analyzer to find over-privileged resources
aws accessanalyzer list-analyzers
aws accessanalyzer list-findings --analyzer-arn <analyzer-arn>

# Find users with Administrator access (should be minimal)
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### AWS Trusted Advisor — Automated Checks

AWS Trusted Advisor automatically checks for IAM issues:

```bash
# View IAM-related Trusted Advisor checks via CLI
aws trustedadvisor list-checks \
  --query "checks[?category=='security'].{Name:name,Id:id}" \
  --output table

# Checks include:
# - Root account MFA not enabled
# - IAM Access keys not rotated in > 90 days
# - Users without MFA
# - Users with access keys and console password (unnecessary)
# - Policies granting full administrative access
```

### IAM Policy Simulator

Before applying a policy, test what it actually allows:

```bash
# Simulate if a user can perform an action
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789:user/shiva \
  --action-names s3:DeleteBucket \
  --resource-arns arn:aws:s3:::prod-bucket

# Output:
# {
#   "EvaluationResults": [{
#     "EvalActionName": "s3:DeleteBucket",
#     "EvalDecision": "implicitDeny"   ← Good — Shiva cannot delete prod bucket
#   }]
# }
```

---

## 11. Real-World Scenarios

### Scenario 1 — Tesla's Cryptomining Attack (2018)

**What happened:** Tesla's Kubernetes cluster on AWS was compromised. The attacker gained access to a pod, discovered the Kubernetes dashboard was exposed without authentication, used it to get environment variables containing AWS credentials, and then used those credentials to access Tesla's S3 buckets containing sensitive data. The attacker also used the AWS account to mine cryptocurrency.

**The IAM failure:** Pods were running with the worker node's IAM role, which had broad S3 and EC2 permissions. There were no IRSA-scoped roles. The credentials were static access keys stored in environment variables.

```mermaid
sequenceDiagram
    participant ATK as Attacker
    participant POD as Compromised Pod
    participant DASH as K8s Dashboard (unauthenticated)
    participant IMDS as IMDS / Env Vars
    participant AWS as AWS (S3, EC2)

    ATK->>DASH: Access unauthenticated dashboard
    DASH-->>ATK: Full cluster control
    ATK->>POD: Exec into pod
    POD->>IMDS: curl 169.254.169.254/...
    IMDS-->>ATK: AWS credentials (node role)
    ATK->>AWS: aws s3 cp s3://tesla-data/ .
    AWS-->>ATK: Sensitive telemetry data
    ATK->>AWS: Deploy cryptominer EC2 instances
```

**Prevention with proper IAM:**

```json
// Node IAM role — minimal required for K8s
{
  "Statement": [
    {"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "Resource": "*"}
    // No S3 access at node level
  ]
}
// S3 access only via IRSA for specific pods that need it
```

---

### Scenario 2 — Privilege Escalation via Misconfigured IAM Role

**Situation:** A developer was given an IAM role with `iam:PassRole` and `ec2:RunInstances` permissions — ostensibly to deploy EC2 instances. They discovered they could launch an EC2 instance with a more privileged IAM role (the admin role) and then use that instance's credentials to gain admin access.

```bash
# The attack — escalating via iam:PassRole
aws ec2 run-instances \
  --image-id ami-... \
  --iam-instance-profile Name=AdminInstanceProfile   # Pass the admin role!
# Now SSH into the instance and use its admin credentials

# Prevention — restrict which roles can be passed
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::*:role/developer-role-only"
  # ← Can only pass THIS specific role, not the admin role
}
```

---

### Scenario 3 — Orphaned Access Keys

**Situation:** A contractor worked on a project for 6 months and was given AWS IAM access keys. When the contract ended, their IAM user was disabled but the access keys were not deleted. Eighteen months later, those keys (which were never rotated) were leaked in a GitHub commit. The attacker used the still-valid keys — the user was "disabled" but the access keys were not.

```bash
# How to check for access keys on disabled users
aws iam list-users --query 'Users[].UserName' --output text | \
  while read user; do
    status=$(aws iam get-login-profile --user-name $user 2>/dev/null | jq -r '.LoginProfile.PasswordResetRequired' 2>/dev/null)
    keys=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[].Status' --output text)
    if echo "$keys" | grep -q "Active"; then
      echo "User: $user | Keys: $keys"
    fi
  done

# Proper offboarding
aws iam delete-login-profile --user-name contractor  # Disable console
aws iam list-access-keys --user-name contractor       # Find all keys
aws iam delete-access-key --user-name contractor --access-key-id AKIAIOSFODNN7EXAMPLE
aws iam delete-access-key --user-name contractor --access-key-id AKIAI44QH8DHBEXAMPLE
aws iam remove-user-from-group --group-name developers --user-name contractor
# Consider deleting the user entirely
aws iam delete-user --user-name contractor
```

---

## 12. Common Mistakes & Gotchas

| Mistake | Consequence | Fix |
|---|---|---|
| Using root for daily operations | Root compromise = total account loss, all data gone | Create IAM admin user immediately, never use root again |
| Attaching `AdministratorAccess` to users/services | One compromise = unlimited blast radius | Use specific managed or custom policies |
| Static access keys in code/config files | Keys committed to Git = permanent credential leak | Use IAM roles + IRSA; rotate keys if they must exist |
| Not enabling MFA for privileged users | Password theft = account takeover | MFA required for all console access |
| Not rotating access keys regularly | Old keys accumulate — any could be leaked | Rotate every 90 days; delete unused keys |
| Not auditing unused permissions | Permission creep — roles grow over time | Quarterly audit with credential reports |
| Using `iam:PassRole` without restriction | Privilege escalation to admin-level roles | Restrict `iam:PassRole` to specific target roles |
| Granting `s3:*` when only read is needed | Accidental deletion of production data | Use `s3:GetObject`, `s3:ListBucket` only |
| Not using IRSA for pods | All pods share node's IAM role | IRSA gives each pod its own minimal role |
| Shared IAM users between humans | No attribution in audit logs | One user per human, always |

---

## 13. CKS Exam Tips

```mermaid
mindmap
  root((CKS Exam\nIAM Roles))
    Core Concept
      IAM = cloud equivalent of Linux user management
      Same PoLP principles apply
      Root = Linux root, avoid daily use
    AWS Key Concepts
      Users for humans
      Groups for permission bundles
      Roles for services and resources
      Policies define what is allowed
    Kubernetes Connection
      EKS nodes use IAM roles
      IRSA scopes roles to pods
      IMDS exposes node role to pods
      Block IMDS with NetworkPolicy
    Auditing
      AWS Trusted Advisor
      Credential reports
      Access Analyzer
      CloudTrail for audit logs
    Not CKS exam focus
      IAM is conceptual for CKS
      Deep AWS CLI not tested
      Focus on the principles
      IRSA and IMDS are relevant
```

> **CKS Exam Note:** IAM itself is not deeply tested in the CKS exam — the exam focuses on Kubernetes-level security. However, understanding IAM is essential because:
> - The exam may ask about securing cloud metadata (IMDS) — which ties directly to node IAM roles
> - IRSA (IAM roles for service accounts) is the correct answer to "how do pods access AWS resources securely"
> - The concept of least privilege from IAM underpins all Kubernetes RBAC questions

### The IAM-to-Kubernetes Mapping

| IAM Concept | Kubernetes Equivalent |
|---|---|
| IAM User | Kubernetes User (certificate-based) |
| IAM Group | Kubernetes Group (in RBAC) |
| IAM Role (for services) | Kubernetes Service Account |
| IAM Policy | RBAC Role / ClusterRole |
| IAM Role Binding | Kubernetes RoleBinding |
| AWS Trusted Advisor | `kubectl auth can-i --list` |
| CloudTrail audit log | Kubernetes Audit log (Ch. 20) |

---

## Summary

```mermaid
flowchart TD
    ROOT["Root Account\n☠️ Lock away — emergency only\nMFA always enabled"]
    USERS["IAM Users\n👤 One per human\nNever shared\nMFA required"]
    GROUPS["IAM Groups\n👥 Bundle by role\nAttach policies to groups\nnot individuals"]
    ROLES["IAM Roles\n⚙️ For AWS services\nTemporary credentials\nNo static keys"]
    POLICIES["IAM Policies\n📋 Define what's allowed\nLeast privilege\nSpecific resources"]
    AUDIT["Regular Audits\n🔍 Credential reports\nRemove unused permissions\nRotate keys"]

    ROOT --> USERS --> GROUPS --> POLICIES
    ROLES --> POLICIES
    POLICIES --> AUDIT
    AUDIT -->|"Permission drift caught\nremoved"| POLICIES

    style ROOT fill:#ff6b6b,color:#fff
    style ROLES fill:#4d96ff,color:#fff
    style AUDIT fill:#6bcb77,color:#fff
```

| Concept | Key Point |
|---|---|
| **Root account** | Full power — use only to create first IAM admin, enable MFA, then lock away |
| **IAM Users** | One per human, individual accountability, MFA required |
| **IAM Groups** | Attach policies to groups not individuals — easier to manage at scale |
| **IAM Roles** | For AWS services and resources — temporary credentials, no static keys |
| **IAM Policies** | JSON documents — specific actions, specific resources, least privilege |
| **IRSA** | IAM Roles for Service Accounts — gives K8s pods their own minimal IAM role |
| **IMDS risk** | Pods can steal node's IAM role via 169.254.169.254 — block with NetworkPolicy |
| **Audit tools** | AWS Trusted Advisor, Access Analyzer, credential reports, CloudTrail |
| **Quarterly reviews** | Permissions accumulate — regular audit prevents privilege creep |
