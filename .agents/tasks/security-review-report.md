# Pre-Deployment Security Review — Retail Store Sample App

**Scope:** `retail-store-sample-app` (aws-containers) source, Helm charts, docker-compose, and Terraform IaC under `terraform/` (apprunner, ecs, eks, lib), plus `../cloudwatch-alarms.yaml`.
**Review type:** Read-only static review. No code was modified. This is not a full SAST/dependency CVE scan.
**Context:** Upstream README (line 33) explicitly states: *"This project is intended for educational purposes only and not for production use."* The goal here is to surface risks before deploying it for an AWS DevOps Agent demo.

> Note on `.terraform/modules/**`: the EKS working directory has downloaded third-party modules on disk. Those are external dependencies, not this project's code, and are excluded from the findings below except where this project configures them.

---

## Executive Summary

The sample is **reasonably well engineered from a container/secrets standpoint** and much better than a typical "demo" app: Dockerfiles run as a non-root `appuser` with pinned base images, Helm `securityContext` blocks drop all capabilities and set `readOnlyRootFilesystem: true` / `runAsNonRoot: true`, the ECS and App Runner paths inject database credentials through AWS Secrets Manager (not plaintext env), RDS and OpenSearch are encrypted at rest, backend services are private, and Renovate is configured for dependency updates. There are **no real/live hardcoded secrets** committed to the repo.

The concerns that matter are mostly **network-exposure and transport-encryption** issues inherent to a quick-start demo, plus a few IaC hardening gaps:

- The **public entry point (UI) is served over plain HTTP** with no TLS, on both the ECS ALB and the EKS internet-facing NLB.
- On **ECS, every service task security group allows ingress from `0.0.0.0/0` on port 8080** — not just the UI/ALB. This is the single most impactful finding for a deployed environment.
- The **EKS API server endpoint is public** (`cluster_endpoint_public_access = true`) with no CIDR allow-list.
- **Spring Actuator endpoints (`metrics`, `prometheus`) are exposed unauthenticated** on the UI's web port, reachable through the public load balancer.
- **ElastiCache transit encryption is disabled**; a couple of IAM/resource policies are broader than least privilege (`dynamodb:*`, OpenSearch `Principal: "*"`); RDS master passwords use a weak `random_string` (length 10, no symbols).
- On the **EKS path specifically**, DB/OpenSearch/RabbitMQ passwords are passed as **plaintext Terraform template variables** into Helm (and land in Terraform state / rendered k8s Secrets), unlike the ECS/App Runner paths which use Secrets Manager.

**Verdict for a disposable demo:** Deployable with care. Nothing here is an immediate "do not deploy." But the public-HTTP UI, the ECS `0.0.0.0/0` task SGs, the public EKS API endpoint, and the unauthenticated metrics endpoints are worth tightening even for a short-lived demo if it runs in a shared or internet-reachable account. See the final section for the pragmatic triage.

---

## Critical

None. No live credentials, no world-open databases, no public write-access storage, no `AdministratorAccess`/`*:*` IAM roles were found.

---

## High

### H-1. ECS per-service task security group open to the entire internet on port 8080
**Severity:** High
**File:** `terraform/lib/ecs/service/sg.tf` (lines ~1–18)

Every ECS service (ui, catalog, carts, checkout, orders) is created by the shared `./service` module, whose security group has:

```hcl
ingress {
  protocol    = "tcp"
  from_port   = 8080
  to_port     = 8080
  cidr_blocks = ["0.0.0.0/0"]
}
```

The tasks run in subnets with `assign_public_ip = false` (`terraform/lib/ecs/service/ecs.tf`), so direct reachability depends on the subnet routing/VPC layout, but the SG itself places **no network restriction** on who may reach the app port. Only the UI needs to accept traffic (and only from the ALB SG); the backend services should accept 8080 only from the UI/peer services. This exposes backend APIs (cart, orders, checkout, catalog) far more widely than intended.

**Remediation:** Restrict ingress to the ALB security group for the UI, and to the peer-service security group(s) for backends, instead of `0.0.0.0/0`. The EKS path already does this correctly (scopes to `vpc_cidr_block`) — mirror that. At minimum scope to the VPC CIDR.

### H-2. Public UI served over plain HTTP (no TLS) — ECS ALB and EKS NLB
**Severity:** High (Medium for a throwaway demo with no real data)
**Files:**
- `terraform/lib/ecs/alb.tf` — ALB listener is `port = 80, protocol = "HTTP"` only; no HTTPS listener, no ACM cert, no HTTP→HTTPS redirect. ALB SG ingress is `http-80-tcp` from `0.0.0.0/0`.
- `terraform/eks/default/values/ui.yaml` — UI Service is `type: LoadBalancer` with `aws-load-balancer-scheme: internet-facing` (NLB), no TLS annotations.

All user traffic, including anything entered in the UI, traverses the public internet unencrypted. There is no certificate management anywhere in the default stack.

**Remediation:** Add an HTTPS (443) listener with an ACM certificate and redirect 80→443 on the ALB; add TLS/ACM annotations (and a hostname) to the EKS NLB/ingress. For a demo without a domain, at least acknowledge the exposure and avoid entering any sensitive data.

### H-3. EKS cluster API endpoint publicly accessible with no allow-list
**Severity:** High
**File:** `terraform/lib/eks/eks.tf` — `cluster_endpoint_public_access = true` and no `cluster_endpoint_public_access_cidrs` set.

The Kubernetes API server is reachable from anywhere on the internet. Authentication still applies, but it broadens the attack surface for credential-stuffing/known-CVE exploitation of the control plane and removes any network backstop.

**Remediation:** Set `cluster_endpoint_public_access_cidrs` to your admin IP/range, or disable public access and use private access + a bastion/VPN. For a demo, scoping to your own egress IP is a one-line change.

### H-4. Spring Actuator metrics/prometheus endpoints exposed unauthenticated behind the public LB
**Severity:** High (Medium for a demo)
**File:** `src/ui/src/main/resources/application.yml` (management block, ~line 70):

```yaml
management:
  endpoints:
    web:
      exposure:
        include: info,health,metrics,prometheus
```

These run on the same web port the public load balancer forwards to (8080). `health` is needed for LB health checks, but `metrics`, `prometheus`, and `info` are exposed without authentication and reachable from the internet once the UI is public (H-2). This leaks internal metrics, JVM/build info, and operational detail useful to an attacker. The Helm charts additionally annotate pods with `prometheus.io/scrape` on `/actuator/prometheus` and `/metrics` (`src/ui/chart/values.yaml`, `src/catalog/chart/values.yaml`).

**Remediation:** Expose only `health` (and ideally a liveness/readiness subset) on the public path; move `metrics`/`prometheus` to a separate management port not routed by the public LB, or protect them with auth/network policy. Scrape metrics in-cluster rather than via the internet-facing endpoint.

---

## Medium

### M-1. ElastiCache (Redis) transit encryption disabled
**Severity:** Medium
**File:** `terraform/lib/dependencies/elasticache.tf` — `transit_encryption_enabled = false`.

Checkout session data to/from Redis is unencrypted in transit within the VPC. The docker-compose dev Redis is also plain `redis://` with no auth, which is fine locally but mirrors the posture.

**Remediation:** Set `transit_encryption_enabled = true` (and consider an AUTH token / at-rest encryption) for the managed ElastiCache.

### M-2. RDS/Aurora master passwords use weak `random_string`
**Severity:** Medium
**Files:** `terraform/lib/dependencies/orders_rds.tf` and `catalog_rds.tf`:

```hcl
master_password = random_string.orders_db_master.result   # length = 10, special = false
```

Both Aurora clusters derive the master password from a 10-character alphanumeric `random_string` with `special = false`. This is weaker than the `random_password` (length 16, special chars) correctly used for Amazon MQ in `mq.tf`, and `random_string` is not treated as a Terraform sensitive value the way `random_password` is. Databases are not publicly accessible (SGs restrict to app SGs), which limits the blast radius.

**Remediation:** Use `random_password` with length ≥ 16 and symbols for the RDS master credentials, consistent with the MQ pattern; or let the module manage credentials in Secrets Manager with rotation.

### M-3. Overly broad `dynamodb:*` action in carts IAM policy
**Severity:** Medium
**File:** `terraform/lib/dependencies/dynamodb.tf` — the carts policy grants `"Action": "dynamodb:*"`.

The resource is correctly scoped to the single carts table and its indexes, so this is not account-wide, but the action grant is far broader than the app needs (it needs Get/Put/Query/UpdateItem/DeleteItem/BatchGet/Scan at most). Granted to the carts task role on ECS and the IRSA role on EKS.

**Remediation:** Replace `dynamodb:*` with the explicit list of required actions (least privilege).

### M-4. OpenSearch access policy uses `Principal: "*"`
**Severity:** Medium
**File:** `terraform/lib/dependencies/catalog_opensearch.tf` — the `access_policies` document grants `Effect: Allow, Principal: "*", Action: es:*` on the domain.

The domain is VPC-only (`vpc_options` with a dedicated SG allowing 443 only from the catalog SG), fine-grained access control is enabled (`internal_user_database_enabled` with a master user), and `enforce_https` + node-to-node + at-rest encryption are on — so the practical exposure is bounded by the VPC and the SG. Still, a wildcard principal with `es:*` is not least privilege and is a flagged anti-pattern.

**Remediation:** Scope the principal to the specific task/instance role ARNs that need access, and narrow the actions.

### M-5. EKS path passes DB/OpenSearch/RabbitMQ passwords as plaintext Terraform template vars
**Severity:** Medium
**Files:** `terraform/eks/default/kubernetes.tf` (helm_release catalog/orders) and `terraform/eks/default/values/catalog.yaml`, `values/ui.yaml`.

Unlike the ECS and App Runner paths (which inject credentials via `aws_secretsmanager_secret_version` references), the EKS Helm releases interpolate `database_password`, `opensearch_password`, and `rabbitmq_password` directly into values via `templatefile(...)`. These values therefore land in **Terraform state** (state is `.gitignore`d, but state files commonly end up in S3/local disk) and are rendered into standard Kubernetes `Secret` objects (base64, not encrypted unless envelope encryption is enabled on the cluster — which is not configured here).

**Remediation:** Use the AWS Secrets Store CSI driver (the EKS blueprints addon for it exists in the module tree) or External Secrets to mount credentials, and enable EKS secrets envelope encryption (KMS) on the cluster. At minimum, keep Terraform state in an encrypted, access-controlled backend.

### M-6. `orders` Secrets Manager secret not encrypted with the customer-managed KMS key
**Severity:** Medium (Low)
**File:** `terraform/lib/ecs/orders.tf` — `aws_secretsmanager_secret.orders_db` has no `kms_key_id`, whereas `catalog.tf` sets `kms_key_id = aws_kms_key.cmk.key_id` on its secrets.

The orders DB/MQ secret falls back to the AWS-managed default Secrets Manager key, inconsistent with catalog and with the CMK-based `kms:Decrypt*` grant in the orders policy.

**Remediation:** Set `kms_key_id = aws_kms_key.cmk.key_id` on the orders secrets for consistency and tighter key control.

### M-7. ECS tasks run with `readonlyRootFilesystem = false` and ECS Exec enabled
**Severity:** Medium (Low for a demo)
**File:** `terraform/lib/ecs/service/ecs.tf` — `readonlyRootFilesystem = false` in `base_container`, and `enable_execute_command = true` on every service (with a matching `ssmmessages:*` exec IAM policy in `service/iam.tf`).

The container hardening applied in the Helm/k8s path (`readOnlyRootFilesystem: true`, drop ALL caps) is **not** mirrored on ECS: the root FS is writable and interactive `ecs exec` into any task is enabled by default. ECS Exec is convenient for a demo but is a remote-shell capability into production tasks.

**Remediation:** Set `readonlyRootFilesystem = true` (with tmpfs mounts as the compose files already do) and gate `enable_execute_command` behind a variable that defaults to `false` for non-demo use.

---

## Low

### L-1. docker-compose `DB_PASSWORD` has no default — but one weak dev secret exists
**Severity:** Low (local-dev only)
**Files:** `src/catalog/docker-compose.yml`, `src/orders/docker-compose.yml`, `src/app/docker-compose.yml`, `src/checkout/.env`.

The `DB_PASSWORD` pattern (`POSTGRES_PASSWORD=${DB_PASSWORD}`, `MYSQL_ROOT_PASSWORD=${DB_PASSWORD}`, `RABBITMQ_DEFAULT_PASS=${DB_PASSWORD}`, etc.) relies on an environment variable with **no committed default** — good, no secret is baked in. Note `catalog-db` also sets `MYSQL_ALLOW_EMPTY_PASSWORD=true`, so if `DB_PASSWORD` is unset locally the MySQL root account would have an empty password (local compose only). The only committed env value is `src/checkout/.env` → `TEST=testing123`, which is a harmless placeholder, not a credential. The cart compose hardcodes dummy AWS creds (`AWS_ACCESS_KEY_ID=key` / `AWS_SECRET_ACCESS_KEY=dummy`) that are placeholders for the local DynamoDB container.

**Remediation:** None required for the committed repo. For local use, always set a strong `DB_PASSWORD` and avoid relying on `MYSQL_ALLOW_EMPTY_PASSWORD`.

### L-2. `RETAIL_CATALOG_SEARCH_OS_TLS_SKIP_VERIFY=true` in catalog dev compose
**Severity:** Low (local-dev only)
**Files:** `src/catalog/docker-compose.yml` (line 27), `src/catalog/config/config.go:44` (`default=false`), `src/catalog/repository/opensearch.go:72`.

The code default is `false` (verify TLS); only the local compose turns verification off to talk to the demo OpenSearch over plain HTTP. The managed path uses `enforce_https` + verified TLS. No production code path disables verification by default.

**Remediation:** None for the repo default. Do not carry `TLS_SKIP_VERIFY=true` into any deployed config.

### L-3. Node-to-node "all traffic" and broad egress in EKS node SG
**Severity:** Low
**File:** `terraform/lib/eks/eks.tf` — `node_security_group_additional_rules` includes `ingress_self_all` (all ports/protocols node-to-node) and `egress_all` to `0.0.0.0/0` (+ IPv6).

Common for EKS, but worth noting: unrestricted egress and all-port node-to-node traffic reduce lateral-movement containment. Not unusual for a demo cluster.

**Remediation:** For hardened environments, constrain egress to required destinations and limit node-to-node ports; acceptable to leave as-is for a demo.

### L-4. Helm image `tag:` left blank in chart defaults
**Severity:** Low / Informational
**Files:** `src/ui/chart/values.yaml`, `src/catalog/chart/values.yaml` (`image.tag:` empty).

The chart default leaves `tag` empty (falls back to the chart `appVersion`), and the Terraform path explicitly injects a resolved `image_tag`. So it is not a literal `:latest` in the default deploy path. However, the ECS OpenTelemetry sidecar does pin to a moving tag: `public.ecr.aws/cloudwatch-agent/cloudwatch-agent:latest` (`terraform/lib/ecs/service/ecs.tf`), which is only used when `opentelemetry_enabled = true`.

**Remediation:** Pin the cloudwatch-agent sidecar to a specific digest/version. Ensure the deploy always sets an explicit app image tag (it does via Terraform).

---

## Informational / Positive observations

- **No live secrets committed.** The only committed env value is a placeholder (`TEST=testing123`); Helm secret templates (`src/catalog/chart/templates/secret.yaml`, `src/orders/chart/templates/secret-db.yaml`, `rabbitmq-secret.yaml`) reference `.Values`, not literals.
- **`.gitignore` correctly excludes** `*.tfvars`, `*.tfstate*`, `.env`, `.terraform`, kubeconfigs, and `*.lock.hcl`. No `tfstate`/`tfvars` are tracked (verified via `git ls-files`).
- **Dockerfiles are hardened:** multi-stage builds, non-root `USER appuser`, pinned base images (`amazonlinux:2023`, `node:20-alpine`) — no `:latest` in app images, no running as root.
- **Container runtime hardening in compose/Helm:** `cap_drop: all`, `no-new-privileges`, `read_only`/`readOnlyRootFilesystem: true`, `runAsNonRoot: true`, `runAsUser: 1000`, tmpfs mounts, and memory limits are set across services. (ECS task defs are the exception — see M-7.)
- **Secrets Manager used on ECS and App Runner** for DB/MQ/OpenSearch credential injection, with scoped `secretsmanager:GetSecretValue` + `kms:Decrypt*` policies and a customer-managed KMS key (catalog).
- **Encryption at rest enabled** for RDS (`storage_encrypted = true`), OpenSearch (`encrypt_at_rest`, node-to-node, enforce_https), and DynamoDB (AWS-managed default). App Runner backends are **private** (`is_publicly_accessible = false`) with VPC ingress.
- **IAM is largely least-privilege:** scoped CloudWatch Logs, per-service roles, carts DynamoDB restricted to the specific table (action breadth aside, M-3). No `AdministratorAccess` or `Resource: *` with broad admin actions found (the `*` resources present are limited to X-Ray put and SSM-messages exec actions, which are standard).
- **Renovate is configured** (`renovate.json`) across github-actions, terraform, npm, maven, gomod with a 14-day minimum release age — good supply-chain posture.
- **UI contains a playful LLM system prompt** in `src/ui/src/main/resources/application.yml` (spy-themed chatbot persona); the chat feature is disabled by default (`chat.enabled: false`). No security issue, but if the chat/Bedrock/OpenAI feature is enabled for the demo, review for prompt-injection and ensure the OpenAI `api-key`/Bedrock region are supplied via secrets, not committed.

---

## cloudwatch-alarms.yaml review

**File:** `/Users/sampcour/Documents/Projects/DevOpsAgentDemo/cloudwatch-alarms.yaml`

This CloudFormation template defines an SNS topic and 13 CloudWatch alarms for the DevOps-agent fault-injection demo. Findings:

- **No hardcoded account IDs, ARNs, access keys, or credentials.** Values are parameterized (`EKSClusterName`, `SNSTopicName`) and reference logical resources. Clean from a secrets standpoint.
- **I-1 (Low/Informational): SNS topic has no encryption and no explicit access policy.** `AlarmSNSTopic` sets no `KmsMasterKeyId` (notifications unencrypted at rest) and no topic policy. For alarm metadata this is low risk, but if any subscriber or sensitive detail is added, consider SSE-KMS and a least-privilege topic policy restricting publishers to CloudWatch.
- **I-2 (Informational): No SNS subscriptions defined.** The topic is created but nothing subscribes, so alarms will fire silently. Not a security issue; add subscriptions (and confirm them) if notifications are expected.
- Resource names/dimensions (`retail-store-carts`, `retail-store-catalog`, `retail-store-orders`, cluster `retail-store`) assume specific names — operationally they must match the deployed stack, but no security concern.

**Remediation (optional):** Add `KmsMasterKeyId` to the SNS topic and a topic policy scoping `SNS:Publish` to `cloudwatch.amazonaws.com`.

---

## Is it safe to deploy for a demo?

**Pragmatic verdict: Yes, deployable for a short-lived, disposable demo — with a few guardrails.** This is a maintained AWS sample with genuinely good baseline hygiene (non-root containers, encrypted data stores, Secrets Manager on ECS/App Runner, no committed secrets). It is explicitly not production-grade, and the review confirms the gaps are the expected quick-start ones rather than anything alarming.

**Issues that matter even for a short-lived demo** (fix or consciously accept before deploying, especially in a shared or internet-reachable account):

1. **ECS `0.0.0.0/0` on task SGs (H-1)** — if you deploy the ECS variant, tighten this; it exposes backend APIs more than the UI alone. The EKS variant does not have this issue.
2. **Public EKS API endpoint (H-3)** — scope `cluster_endpoint_public_access_cidrs` to your IP; it is a one-line change and meaningfully shrinks attack surface.
3. **Public HTTP UI (H-2) + unauthenticated actuator metrics (H-4)** — fine if you treat the demo as fully public and **enter no real or sensitive data**. If anyone will type anything they care about, add TLS and stop routing `metrics`/`prometheus` through the public LB.
4. Keep the environment **short-lived and in an isolated/sandbox account**, and tear it down after the demo (the RDS modules use `skip_final_snapshot = true`, so destroys are clean but irreversible — expected for a demo).

**Issues that mainly matter for production (acceptable to defer for a throwaway demo):** weak RDS passwords (M-2), ElastiCache transit encryption (M-1), `dynamodb:*` / OpenSearch `Principal:"*"` least-privilege tightening (M-3, M-4), EKS plaintext-password-to-Helm and secrets envelope encryption (M-5), orders CMK consistency (M-6), ECS writable root FS + ECS Exec (M-7), node SG egress (L-3), and the cloudwatch-agent `:latest` sidecar pin (L-4).

**Bottom line:** Safe enough to demo in a disposable, isolated account if you (a) don't put real data through the public HTTP UI, (b) lock down the EKS API endpoint and — if using ECS — the task security groups, and (c) tear it down afterward. None of the findings rise to "must not deploy," and there are no live secrets or world-open datastores.
