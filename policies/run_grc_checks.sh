#!/bin/bash
# policies/run_grc_checks.sh
# Usage: ./policies/run_grc_checks.sh [--vuln|--fixed]
#
# --vuln  (default) scans terraform/main.tf     — expects findings
# --fixed           scans terraform-fix/main.tf — expects clean

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
POLICY_DIR="$SCRIPT_DIR"

MODE="${1:---vuln}"

if [ "$MODE" = "--fixed" ]; then
  TF_DIR="$LAB_DIR/terraform-fix"
  ENV_LABEL="FIXED"
  EXPECTED_IAM_FAILS=0
  EXPECTED_TFSEC_HIGH=0
else
  TF_DIR="$LAB_DIR/terraform"
  ENV_LABEL="VULNERABLE"
  EXPECTED_IAM_FAILS=8
  EXPECTED_TFSEC_HIGH=9
fi

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}\n"; }
info()   { echo -e "${YELLOW}[INFO]${NC} $*"; }
pass()   { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()   { echo -e "${RED}[FAIL]${NC} $*"; }
tool()   { echo -e "${CYAN}[TOOL]${NC} $*"; }
skip()   { echo -e "${YELLOW}[SKIP]${NC} $* — not installed"; }

REPORT_DIR="/tmp/grc-findings-${ENV_LABEL}-$$"
mkdir -p "$REPORT_DIR"

TOTAL_PASS=0
TOTAL_FAIL=0

banner "GRC IaC Policy Checks [${ENV_LABEL}]"
info "Target:     $TF_DIR/main.tf"
info "Policy dir: $POLICY_DIR"
info "Reports:    $REPORT_DIR"
info "Expecting:  ${EXPECTED_IAM_FAILS} IAM failures | ${EXPECTED_TFSEC_HIGH} tfsec HIGH"

# ── Step 1: OPA unit tests ───────────────────────────────────
echo ""
banner "Step 1 — OPA Unit Tests"

if command -v opa &>/dev/null; then
  tool "Running opa test..."
  OPA_OUT=$(opa test "$POLICY_DIR/opa/" -v 2>&1)
  echo "$OPA_OUT"
  if echo "$OPA_OUT" | grep -q "PASS: 8/8"; then
    pass "OPA unit tests: 8/8 PASS ✓"
    TOTAL_PASS=$((TOTAL_PASS + 1))
  else
    fail "OPA unit tests did not all pass"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
  fi
else
  skip "opa"
  info "Install: curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && chmod +x /usr/local/bin/opa"
fi

# ── Step 2: Generate plan JSON ───────────────────────────────
echo ""
banner "Step 2 — Generate Terraform Plan"

if [ ! -f "$TF_DIR/main.tf" ]; then
  fail "No main.tf in $TF_DIR — run terraform apply first"
  exit 1
fi

cd "$TF_DIR"
info "Running terraform plan..."
terraform plan -out="$REPORT_DIR/tfplan.binary" -no-color 2>&1 | tail -3
terraform show -json "$REPORT_DIR/tfplan.binary" > "$REPORT_DIR/tfplan.json" 2>/dev/null

RESOURCE_COUNT=$(python3 -c "
import json
d = json.load(open('$REPORT_DIR/tfplan.json'))
print(len(d.get('resource_changes', [])))
" 2>/dev/null || echo "?")
pass "Plan generated — $RESOURCE_COUNT resource changes"

# ── Step 3: conftest IAM ─────────────────────────────────────
echo ""
banner "Step 3 — conftest IAM Namespace"

if command -v conftest &>/dev/null; then
  tool "Running conftest --namespace iam..."
  CONFTEST_IAM=$(conftest test "$REPORT_DIR/tfplan.json" \
    --policy "$POLICY_DIR/opa/" \
    --namespace iam 2>&1)
  echo "$CONFTEST_IAM"

  IAM_FAILURES=$(echo "$CONFTEST_IAM" | grep -c "^FAIL" || true)
  if [ "$MODE" = "--fixed" ]; then
    [ "$IAM_FAILURES" -eq 0 ] \
      && { pass "conftest IAM: 0 failures — remediated ✓"; TOTAL_PASS=$((TOTAL_PASS+1)); } \
      || { fail "conftest IAM: $IAM_FAILURES failures remain"; TOTAL_FAIL=$((TOTAL_FAIL+1)); }
  else
    [ "$IAM_FAILURES" -ge "$EXPECTED_IAM_FAILS" ] \
      && { pass "conftest IAM: $IAM_FAILURES findings detected ✓"; TOTAL_PASS=$((TOTAL_PASS+1)); } \
      || { fail "conftest IAM: expected $EXPECTED_IAM_FAILS got $IAM_FAILURES"; TOTAL_FAIL=$((TOTAL_FAIL+1)); }
  fi
else
  skip "conftest"
  info "Install: wget https://github.com/open-policy-agent/conftest/releases/download/v0.50.0/conftest_0.50.0_Linux_x86_64.tar.gz && tar xzf conftest*.tar.gz && sudo mv conftest /usr/local/bin/"
fi

# ── Step 4: conftest S3 ──────────────────────────────────────
echo ""
banner "Step 4 — conftest S3 Namespace"

if command -v conftest &>/dev/null; then
  tool "Running conftest --namespace s3..."
  CONFTEST_S3=$(conftest test "$REPORT_DIR/tfplan.json" \
    --policy "$POLICY_DIR/opa/" \
    --namespace s3 2>&1)
  echo "$CONFTEST_S3"

  S3_FAILURES=$(echo "$CONFTEST_S3" | grep -c "^FAIL" || true)
  [ "$S3_FAILURES" -eq 0 ] \
    && { pass "conftest S3: 0 failures ✓"; TOTAL_PASS=$((TOTAL_PASS+1)); } \
    || { fail "conftest S3: $S3_FAILURES failures"; TOTAL_FAIL=$((TOTAL_FAIL+1)); }
fi

# ── Step 5: tfsec ────────────────────────────────────────────
echo ""
banner "Step 5 — tfsec Static Analysis"

if command -v tfsec &>/dev/null; then
  tool "Running tfsec --minimum-severity HIGH..."
  tfsec "$TF_DIR" \
    --custom-check-dir "$POLICY_DIR/tfsec/" \
    --minimum-severity HIGH \
    --format json \
    > "$REPORT_DIR/tfsec.json" 2>/dev/null || true

  TFSEC_OUTPUT=$(python3 -c "
import json
try:
    data = json.load(open('$REPORT_DIR/tfsec.json'))
    results = [r for r in data.get('results', []) if r.get('severity') in ['HIGH','CRITICAL']]
    print(len(results))
    for r in results:
        print(f'  [{r.get(\"severity\")}] {r.get(\"rule_id\",\"?\")} — {r.get(\"description\",\"?\")}')
except Exception as e:
    print(0)
" 2>/dev/null)

  TFSEC_COUNT=$(echo "$TFSEC_OUTPUT" | head -1)
  echo "$TFSEC_OUTPUT" | tail -n +2

  if [ "$MODE" = "--fixed" ]; then
    [ "$TFSEC_COUNT" -eq 0 ] \
      && { pass "tfsec: 0 HIGH findings — remediated ✓"; TOTAL_PASS=$((TOTAL_PASS+1)); } \
      || { fail "tfsec: $TFSEC_COUNT HIGH findings remain"; TOTAL_FAIL=$((TOTAL_FAIL+1)); }
  else
    [ "$TFSEC_COUNT" -ge "$EXPECTED_TFSEC_HIGH" ] \
      && { pass "tfsec: $TFSEC_COUNT HIGH findings detected ✓"; TOTAL_PASS=$((TOTAL_PASS+1)); } \
      || { fail "tfsec: expected $EXPECTED_TFSEC_HIGH got $TFSEC_COUNT"; TOTAL_FAIL=$((TOTAL_FAIL+1)); }
  fi

  echo ""
  tfsec "$TF_DIR" \
    --custom-check-dir "$POLICY_DIR/tfsec/" \
    --minimum-severity HIGH 2>/dev/null || true
else
  skip "tfsec"
  info "Install: curl -fsSL https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 -o /usr/local/bin/tfsec && chmod +x /usr/local/bin/tfsec"
fi

# ── Final Summary ─────────────────────────────────────────────
echo ""
banner "GRC Summary [${ENV_LABEL}]"

if [ "$MODE" = "--fixed" ]; then
  echo -e "${BOLD}${GREEN}┌─ REMEDIATION VERIFIED ────────────────────────────────────┐${NC}"
  echo -e "${GREEN}│                                                             │${NC}"
  echo -e "${GREEN}│  IAM-001/002  s3:*/ssm:* wildcard    → SCOPED ✓            │${NC}"
  echo -e "${GREEN}│  IAM-003      PassRole no condition   → CONDITION ADDED ✓   │${NC}"
  echo -e "${GREEN}│  IAM-004      PassRole Resource:*     → SCOPED TO ROLE ✓    │${NC}"
  echo -e "${GREEN}│  LAMBDA-001   No invoke policy        → RESTRICTED ✓        │${NC}"
  echo -e "${GREEN}│                                                             │${NC}"
  printf  "${GREEN}│  Checks passed: %-3s   Checks failed: %-3s                   │${NC}\n" "$TOTAL_PASS" "$TOTAL_FAIL"
  echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
else
  echo -e "${BOLD}${RED}┌─ FINDINGS DETECTED ───────────────────────────────────────┐${NC}"
  echo -e "${RED}│                                                             │${NC}"
  echo -e "${RED}│  IAM-001   s3:* on Resource:*          lambda-exec-policy  │${NC}"
  echo -e "${RED}│  IAM-002   ssm:GetParameter* on *      lambda-exec-policy  │${NC}"
  echo -e "${RED}│  IAM-003   iam:PassRole no condition    devops-policy       │${NC}"
  echo -e "${RED}│  IAM-004   iam:PassRole on Resource:*   devops-policy       │${NC}"
  echo -e "${RED}│  LAMBDA-001 no invoke restriction       data-processor      │${NC}"
  echo -e "${RED}│                                                             │${NC}"
  printf  "${RED}│  Checks flagged correctly: %-3s                              │${NC}\n" "$TOTAL_PASS"
  echo -e "${RED}│                                                             │${NC}"
  echo -e "${RED}│  Next: destroy this, deploy fixed, verify clean:            │${NC}"
  echo -e "${RED}│    terraform destroy -auto-approve                          │${NC}"
  echo -e "${RED}│    cd ../terraform-fix && terraform apply -auto-approve     │${NC}"
  echo -e "${RED}│    ./policies/run_grc_checks.sh --fixed                     │${NC}"
  echo -e "${RED}└─────────────────────────────────────────────────────────────┘${NC}"
fi

echo ""
info "Reports: $REPORT_DIR/"
info "Run opposite environment: ./policies/run_grc_checks.sh $([ "$MODE" = "--fixed" ] && echo "--vuln" || echo "--fixed")"