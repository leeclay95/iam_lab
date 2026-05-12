#!/bin/bash
# quicktest.sh — sanity check before running full scripts
# Usage: ./scripts/quicktest.sh [--vuln|--fixed]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh" "${1:---vuln}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

echo -e "${BOLD}=== Floci IAM Lab — Quick Sanity Check [${ENV_LABEL}] ===${NC}"
echo ""

info "Checking Floci health..."
curl -sf http://localhost:4566/_localstack/health &>/dev/null \
  && pass "Floci is up" \
  || { fail "Floci not reachable — is docker-compose up?"; exit 1; }

info "Checking AWS profiles..."
ALLOWED_KEY=$(aws configure get aws_access_key_id --profile allowed 2>/dev/null)
ATTACKER_KEY=$(aws configure get aws_access_key_id --profile attacker 2>/dev/null)
[ "$ALLOWED_KEY"  = "111111111111" ] && pass "allowed profile  = $ALLOWED_KEY" || fail "allowed profile wrong (got: $ALLOWED_KEY)"
[ "$ATTACKER_KEY" = "222222222222" ] && pass "attacker profile = $ATTACKER_KEY" || fail "attacker profile wrong (got: $ATTACKER_KEY)"

info "Checking bucket: $BUCKET"
aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null \
  && pass "Bucket $BUCKET exists" \
  || { fail "Bucket not found — run terraform apply in terraform/ or terraform-fix/"; exit 1; }

info "Listing objects as allowed account..."
OBJS=$(aws s3api list-objects-v2 \
  --bucket "$BUCKET" \
  --profile allowed \
  --output text \
  --query 'Contents[].Key' 2>&1)
echo "  Objects:"
echo "$OBJS" | tr '\t' '\n' | sed 's/^/    /'

echo ""
info "Core deny test (attacker)..."
OUT=$(aws s3 cp "s3://${BUCKET}/credentials/db-creds.txt" - --profile attacker 2>&1)
if echo "$OUT" | grep -qiE "AccessDenied|403|404|Not Found|NoSuchBucket"; then
  pass "Attacker DENIED on credentials/ ✓"
else
  fail "Attacker NOT denied: $OUT"
fi

OUT=$(aws s3 cp "s3://${BUCKET}/credentials/db-creds.txt" - --profile allowed 2>&1)
if echo "$OUT" | grep -qiE "AccessDenied|error|Error"; then
  fail "Allowed account unexpectedly denied: $OUT"
else
  pass "Allowed account can read credentials/ ✓"
fi

echo ""
info "Checking Lambda: $LAMBDA_NAME"
FUNC=$(aws lambda get-function --profile root \
  --function-name "$LAMBDA_NAME" \
  --output text \
  --query 'Configuration.FunctionName' 2>&1)
echo "$FUNC" | grep -q "$LAMBDA_NAME" \
  && pass "Lambda $LAMBDA_NAME exists ✓" \
  || fail "Lambda not found: $FUNC"

echo ""
info "SSM check (allowed account)..."
OUT=$(aws ssm get-parameter \
  --name /prod/db/password \
  --with-decryption \
  --profile allowed \
  --output text \
  --query 'Parameter.Value' 2>&1)
echo "$OUT" | grep -q "SuperSecret" \
  && pass "SSM SecureString readable by allowed account ✓" \
  || info "SSM result: $OUT"

echo ""
echo -e "${BOLD}Sanity check complete. Run full tests:${NC}"
echo "  ./scripts/01_access_denied_demo.sh ${1:---vuln}"
echo "  ./scripts/02_lambda_pivot.sh        ${1:---vuln}"
echo "  ./scripts/04_compare_roles.sh       ${1:---vuln}"
