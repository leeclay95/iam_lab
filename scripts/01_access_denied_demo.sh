#!/bin/bash
# 01_access_denied_demo.sh
# Usage: ./scripts/01_access_denied_demo.sh [--vuln|--fixed]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh" "${1:---vuln}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}\n"; }
pass()   { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail()   { echo -e "  ${RED}[FAIL]${NC} $*"; }
info()   { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

check_deny() {
  local desc="$1"; shift
  local out
  out=$("$@" 2>&1)
  if echo "$out" | grep -qiE "AccessDenied|403|Forbidden|404|Not Found|NoSuchBucket"; then
    pass "$desc → DENIED ✓"
  else
    fail "$desc → Expected denial, got: $out"
  fi
}

check_allow() {
  local desc="$1"; shift
  local out
  out=$("$@" 2>&1)
  if echo "$out" | grep -qiE "AccessDenied|403|Forbidden|NoSuchBucket"; then
    fail "$desc → Expected allow, got: $out"
  else
    pass "$desc → ALLOWED ✓"
    echo "$out" | head -3 | sed 's/^/      /'
  fi
}

banner "TEST 01 — AccessDenied via Account Isolation [${ENV_LABEL}]"

info "Bucket:  $BUCKET"
info "allowed  profile = account 111111111111"
info "attacker profile = account 222222222222"

echo ""
echo -e "${BOLD}── Attacker account — all should be DENIED ──${NC}"

check_deny "s3:GetObject credentials/db-creds.txt" \
  aws s3 cp "s3://${BUCKET}/credentials/db-creds.txt" - --profile attacker

check_deny "s3:GetObject credentials/api-keys.txt" \
  aws s3 cp "s3://${BUCKET}/credentials/api-keys.txt" - --profile attacker

check_deny "s3:GetObject pii/employees.csv" \
  aws s3 cp "s3://${BUCKET}/pii/employees.csv" - --profile attacker

check_deny "s3:ListBucket" \
  aws s3api list-objects-v2 --bucket "$BUCKET" --profile attacker

echo ""
echo -e "${BOLD}── Allowed account — all should be ALLOWED ──${NC}"

check_allow "s3:GetObject credentials/db-creds.txt" \
  aws s3 cp "s3://${BUCKET}/credentials/db-creds.txt" - --profile allowed

check_allow "s3:GetObject pii/employees.csv" \
  aws s3 cp "s3://${BUCKET}/pii/employees.csv" - --profile allowed

check_allow "s3:ListBucket" \
  aws s3api list-objects-v2 --bucket "$BUCKET" --profile allowed --output text --query 'Contents[].Key'

echo ""
echo -e "${BOLD}── Public prefix ──${NC}"

check_allow "s3:GetObject public/notice.txt (as attacker)" \
  aws s3 cp "s3://${BUCKET}/public/notice.txt" - --profile attacker

echo ""
info "Test 01 complete [${ENV_LABEL}]."
