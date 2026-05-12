# Floci IAM Abuse Lab

A self-contained AWS IAM misconfiguration lab running entirely in Docker via
[Floci](https://github.com/floci-io/floci) — no real AWS account required.
Demonstrates real attack chains, then proves remediation using GRC tooling.

---

## What This Lab Covers

| # | Attack | Misconfiguration | GRC Finding |
|---|--------|-----------------|-------------|
| 1 | Namespace isolation baseline | Bucket owned by allowed account | S3-003/004 |
| 2 | Lambda pivot — attacker reads vault via exec role | `s3:*` on `Resource: *` | IAM-001 |
| 3 | SSM SecureString dump via Lambda | `ssm:GetParameter*` on `Resource: *` | IAM-002 |
| 4 | `iam:PassRole` privilege escalation | `iam:PassRole` on `Resource: *` no condition | IAM-003/004 |
| 5 | Any account can invoke Lambda | Missing `aws_lambda_permission` | LAMBDA-001 |

---

## Directory Structure

```
iam-lab/
├── docker-compose.yml           Floci container config
├── README.md                    This file
├── lambda_src/
│   ├── index.js                 Lambda source — list/read/ssm_dump actions
│   └── data_processor.zip       Built deployment package (build before apply)
├── scripts/
│   ├── env.sh                   Shared env config sourced by all scripts
│   ├── quicktest.sh             Sanity check — run this first every time
│   ├── 01_access_denied_demo.sh Proves namespace isolation
│   ├── 02_lambda_pivot.sh       Lambda pivot + PassRole privesc
│   ├── 04_compare_roles.sh      Side-by-side matrix + CSV report
│   └── destroy.sh               Safe destroy — pre-empties versioned bucket
├── terraform/
│   └── main.tf                  VULNERABLE infrastructure
├── terraform-fix/
│   └── main.tf                  FIXED infrastructure
└── policies/
    ├── run_grc_checks.sh        Runs all GRC tools with pass/fail per mode
    ├── opa/
    │   ├── iam_no_wildcard_resources.rego
    │   ├── s3_security_baseline.rego
    │   └── iam_test.rego
    └── tfsec/
        └── iam_wildcard_resources.yaml
```

---

## Prerequisites

```bash
# Docker Engine + Compose v2
docker --version && docker compose version

# Terraform >= 1.3
terraform --version

# AWS CLI v2
aws --version

# zip + python3
zip --version && python3 --version

# OPA
curl -L -o /usr/local/bin/opa \
  https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x /usr/local/bin/opa
opa version

# conftest
wget https://github.com/open-policy-agent/conftest/releases/download/v0.50.0/conftest_0.50.0_Linux_x86_64.tar.gz
tar xzf conftest_0.50.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/
conftest --version

# tfsec
sudo apt install tfsec -y
tfsec --version

# GitHub CLI (optional — for pushing to GitHub)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | \
  sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
  https://cli.github.com/packages stable main" | \
  sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh -y
```

---

## How Identity Works in This Lab

Floci uses **12-digit numeric Access Key IDs as account IDs**. Resources are
stored in completely separate namespaces — there is no shared state between
accounts. Account `222222222222` looking up a bucket owned by `111111111111`
gets a 404 because it does not exist in that account's namespace.

```
AWS_ACCESS_KEY_ID=111111111111  →  account 111111111111  (allowed — owns S3/SSM)
AWS_ACCESS_KEY_ID=222222222222  →  account 222222222222  (attacker — denied)
AWS_ACCESS_KEY_ID=test          →  account 000000000000  (root — IAM/Lambda)
```

### Why three identities?

Floci has a known limitation where 12-digit AKIDs break `CreateFunction` and
IAM API calls returning HTTP 500. The Terraform uses a dual-provider setup:

- S3 buckets, objects, SSM parameters → `access_key = "111111111111"` so the
  `allowed` profile owns them
- IAM roles, Lambda functions → `access_key = "test"` (root) to avoid the bug

The Lambda env vars include `AWS_ACCESS_KEY_ID=111111111111` so the runtime
reads S3/SSM from the allowed account namespace when executing.

### Floci health check

After starting Floci, services appear as `running` only after their first
request — this is lazy initialization and is expected behaviour. The version
check is sufficient to confirm Floci is ready:

```bash
curl -s http://localhost:4566/_localstack/health | jq .version
# Expected: "1.5.14"
```

To trigger service initialization before running the lab:

```bash
aws s3api list-buckets
aws ssm describe-parameters
aws lambda list-functions
```

---

## Setup

### 1. Clone and enter the repo

```bash
git clone https://github.com/leeclay95/iam_lab.git
cd iam_lab
```

### 2. Fix data directory permissions

Floci runs as non-root inside the container. Without this, hybrid storage
writes fail and all S3/SSM operations return errors.

```bash
sudo chmod -R 777 ./floci-data
```

### 3. Start Floci

If a container named `floci` already exists from a previous session, remove
it first:

```bash
docker stop floci 2>/dev/null; docker rm floci 2>/dev/null; true
docker network rm iam_lab_net 2>/dev/null; true
```

Start fresh:

```bash
docker compose up -d
sleep 5
curl -s http://localhost:4566/_localstack/health | jq .version
```

Expected output: `"1.5.14"`

### 4. Configure AWS CLI profiles

Three named profiles are required. The scripts use `--profile` flags
internally so these must exist regardless of what is set in the shell.

```bash
aws configure --profile allowed
# Access Key ID:     111111111111
# Secret Access Key: test
# Region:            us-east-1
# Output:            json

aws configure --profile attacker
# Access Key ID:     222222222222
# Secret Access Key: test
# Region:            us-east-1
# Output:            json

aws configure --profile root
# Access Key ID:     test
# Secret Access Key: test
# Region:            us-east-1
# Output:            json
```

Verify all three are configured correctly:

```bash
aws configure list --profile allowed   # should show 111111111111
aws configure list --profile attacker  # should show 222222222222
aws configure list --profile root      # should show test
```

### 5. Set up three terminal shells

Open three separate terminals. Export the following in each one at the start
of every session. Adding these to `~/.zshrc` or `~/.bashrc` makes them
persistent across restarts.

> **Important:** If `~/.aws/config` has an `[default]` section containing
> `sso_start_url`, remove it. SSO profiles intercept all unauthenticated
> calls and cause `session expired` errors that override these exports.

**Shell 1 — Allowed** (owns S3 and SSM, runs all test scripts):
```bash
export AWS_ACCESS_KEY_ID=111111111111
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
unset AWS_PROFILE
unset AWS_SESSION_TOKEN
```

**Shell 2 — Attacker** (denied on everything, used for manual verification):
```bash
export AWS_ACCESS_KEY_ID=222222222222
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
unset AWS_PROFILE
unset AWS_SESSION_TOKEN
```

**Shell 3 — Root / Terraform** (all Terraform operations, IAM, Lambda):
```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
unset AWS_PROFILE
unset AWS_SESSION_TOKEN
```

### 6. Build the Lambda package

```bash
cd lambda_src
zip data_processor.zip index.js
cd ..
```

---

## Running the Lab

### Phase A — Vulnerable environment

**From Shell 3:**
```bash
cd terraform
terraform init
terraform apply -auto-approve
```

Lambda pulls `public.ecr.aws/lambda/nodejs18.x` on first deploy — allow
1-2 minutes. Watch progress with `docker logs floci --tail 20 -f`.

**Verify from Shell 1 — should return data:**
```bash
aws s3api list-buckets --output text
aws s3 cp s3://company-secrets-vault/credentials/db-creds.txt -
# Expected: DB_HOST=prod-db.internal ... DB_PASSWORD=SuperSecret123!
```

**Verify from Shell 2 — should be denied:**
```bash
aws s3 cp s3://company-secrets-vault/credentials/db-creds.txt - 2>&1
# Expected: 404 Not Found
```

**Run all tests and GRC checks from Shell 1:**
```bash
cd ..
./scripts/quicktest.sh --vuln
./scripts/01_access_denied_demo.sh --vuln
./scripts/02_lambda_pivot.sh --vuln
./scripts/04_compare_roles.sh --vuln
./policies/run_grc_checks.sh --vuln
```

### Phase B — Destroy vulnerable environment

**From Shell 3:**
```bash
cd ..
./scripts/destroy.sh --vuln
```

**Verify everything is gone from Shell 3:**
```bash
aws s3api list-buckets --output text
aws lambda list-functions --query 'Functions[].FunctionName' --output text
aws iam list-roles --query 'Roles[].RoleName' --output text
```

All three should return empty output.

### Phase C — Fixed environment

**From Shell 3:**
```bash
cd terraform-fix
terraform init
terraform apply -auto-approve
```

**Verify from Shell 1 — should return data:**
```bash
aws s3api list-buckets --output text
aws s3 cp s3://company-secrets-vault-fixed/credentials/db-creds.txt -
aws ssm get-parameter --name /prod/db/password --with-decryption \
  --output text --query 'Parameter.Value'
```

**Verify from Shell 2 — should be denied:**
```bash
aws s3 cp s3://company-secrets-vault-fixed/credentials/db-creds.txt - 2>&1
# Expected: 404 Not Found
```

**Run all tests and GRC checks from Shell 1:**
```bash
cd ..
./scripts/quicktest.sh --fixed
./scripts/01_access_denied_demo.sh --fixed
./scripts/02_lambda_pivot.sh --fixed
./scripts/04_compare_roles.sh --fixed
./policies/run_grc_checks.sh --fixed
```

---

## Expected Results

### Vulnerable (`--vuln`)

```
quicktest              all PASS
01_access_denied       attacker DENIED on all sensitive paths ✓
                       allowed ALLOWED on all paths ✓
02_lambda_pivot        Phase 1: direct access DENIED ✓
                       Phase 2: vault enumerated, db-creds exfiltrated,
                                SSM SecureStrings dumped via Lambda pivot
                       Phase 3: evil Lambda created via PassRole abuse,
                                PII exfiltrated
04_compare_roles       credentials/* — Allowed=ALLOW Attacker=DENY ✓
run_grc_checks         OPA 8/8 PASS
                       conftest IAM: 8 failures detected ✓
                       tfsec: 9 HIGH findings detected ✓
```

### Fixed (`--fixed`)

```
quicktest              all PASS
01_access_denied       attacker DENIED ✓  allowed ALLOWED ✓
02_lambda_pivot        Phase 2: scoped role cannot read sensitive prefixes ✓
                       Phase 3: overpermissive role does not exist ✓
04_compare_roles       credentials/* — Allowed=ALLOW Attacker=DENY ✓
run_grc_checks         OPA 8/8 PASS
                       conftest IAM: 0 failures ✓
                       tfsec: No problems detected ✓
```

**Expected ALLOW results that are not findings:**

- `s3:PutObject` as attacker — writes into the attacker's own empty namespace,
  not the vault
- `ssm:GetParametersByPath /prod/` as attacker — returns an empty list from
  the attacker's namespace, not the vault contents

---

## Teardown and Full Reset

### Destroy the current lab environment

**From Shell 3:**
```bash
# If running the fixed lab
./scripts/destroy.sh --fixed

# If running the vulnerable lab
./scripts/destroy.sh --vuln
```

Confirm all resources are gone:
```bash
aws s3api list-buckets --output text
aws lambda list-functions --query 'Functions[].FunctionName' --output text
aws iam list-roles --query 'Roles[].RoleName' --output text
```

All three should return empty.

### Stop and remove Floci

```bash
docker compose down
```

Confirm the container and network are gone:
```bash
docker ps -a | grep floci        # should return nothing
docker network ls | grep iam_lab # should return nothing
```

### Full reset — wipe all stored data

If you want a completely clean slate including all Floci state:

```bash
docker compose down
sudo rm -rf floci-data/*
```

To bring the lab back up from scratch after a full reset:

```bash
sudo chmod -R 777 ./floci-data
docker compose up -d
sleep 5
curl -s http://localhost:4566/_localstack/health | jq .version
```

---

## Remediation Reference

### IAM-001/002 — Wildcard resource on S3/SSM actions

```json
// Before
{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}

// After
{"Effect": "Allow", "Action": ["s3:GetObject"],
 "Resource": ["arn:aws:s3:::company-secrets-vault/app-output/*"]}
```

### IAM-003/004 — `iam:PassRole` without condition or scope

```json
// Before
{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}

// After
{
  "Effect": "Allow",
  "Action": ["iam:PassRole"],
  "Resource": ["arn:aws:iam::ACCOUNT:role/lambda-correctly-scoped-role"],
  "Condition": {
    "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
  }
}
```

### LAMBDA-001 — No resource-based invoke policy

```hcl
resource "aws_lambda_permission" "invoke_restriction" {
  statement_id  = "AllowOnlyAuthorizedAccount"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.data_processor_fixed.function_name
  principal     = "arn:aws:iam::111111111111:root"
}
```