#!/bin/bash
# 04_compare_roles.sh
# Usage: ./scripts/04_compare_roles.sh [--vuln|--fixed]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh" "${1:---vuln}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}\n"; }
info()   { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

try() {
  local out
  out=$("$@" 2>&1)
  if echo "$out" | grep -qiE "AccessDenied|403|Forbidden|404|Not Found|NoSuchBucket|does not exist|ParameterNotFound"; then
    echo "DENY"
  else
    echo "ALLOW"
  fi
}

print_row() {
  local action="$1" allowed_r="$2" attacker_r="$3"
  local ac at
  [ "$allowed_r"  = "ALLOW" ] && ac="${GREEN}" || ac="${RED}"
  [ "$attacker_r" = "DENY"  ] && at="${GREEN}" || at="${RED}"
  printf "  %-44s ${ac}%-8s${NC}  ${at}%-8s${NC}\n" "$action" "$allowed_r" "$attacker_r"
}

REPORT="/tmp/iam_compare_${ENV_LABEL}_$$.csv"
echo "Action,Allowed(111111111111),Attacker(222222222222)" > "$REPORT"

banner "TEST 04 — Account Comparison [${ENV_LABEL}] | Bucket: ${BUCKET}"

printf "  ${BOLD}%-44s %-8s  %-8s${NC}\n" "Action" "Allowed" "Attacker"
printf "  %s\n" "$(printf '─%.0s' {1..62})"

A=$(try aws s3 cp "s3://${BUCKET}/credentials/db-creds.txt" - --profile allowed)
B=$(try aws s3 cp "s3://${BUCKET}/credentials/db-creds.txt" - --profile attacker)
print_row "s3:GetObject credentials/db-creds.txt" "$A" "$B"
echo "s3:GetObject credentials/db-creds.txt,$A,$B" >> "$REPORT"

A=$(try aws s3 cp "s3://${BUCKET}/credentials/api-keys.txt" - --profile allowed)
B=$(try aws s3 cp "s3://${BUCKET}/credentials/api-keys.txt" - --profile attacker)
print_row "s3:GetObject credentials/api-keys.txt" "$A" "$B"
echo "s3:GetObject credentials/api-keys.txt,$A,$B" >> "$REPORT"

A=$(try aws s3 cp "s3://${BUCKET}/pii/employees.csv" - --profile allowed)
B=$(try aws s3 cp "s3://${BUCKET}/pii/employees.csv" - --profile attacker)
print_row "s3:GetObject pii/employees.csv" "$A" "$B"
echo "s3:GetObject pii/employees.csv,$A,$B" >> "$REPORT"

A=$(try aws s3api list-objects-v2 --bucket "$BUCKET" --profile allowed)
B=$(try aws s3api list-objects-v2 --bucket "$BUCKET" --profile attacker)
print_row "s3:ListBucket" "$A" "$B"
echo "s3:ListBucket,$A,$B" >> "$REPORT"

A=$(try aws s3api put-object --bucket "$BUCKET" --key "write-test.txt" --body /dev/null --profile allowed)
B=$(try aws s3api put-object --bucket "$BUCKET" --key "write-test.txt" --body /dev/null --profile attacker)
print_row "s3:PutObject" "$A" "$B"
echo "s3:PutObject,$A,$B" >> "$REPORT"

A=$(try aws s3api delete-object --bucket "$BUCKET" --key "write-test.txt" --profile allowed)
B=$(try aws s3api delete-object --bucket "$BUCKET" --key "write-test.txt" --profile attacker)
print_row "s3:DeleteObject" "$A" "$B"
echo "s3:DeleteObject,$A,$B" >> "$REPORT"

printf "  %s\n" "$(printf '─%.0s' {1..62})"

A=$(try aws s3 cp "s3://${BUCKET}/public/notice.txt" - --profile allowed)
B=$(try aws s3 cp "s3://${BUCKET}/public/notice.txt" - --profile attacker)
print_row "s3:GetObject public/notice.txt (open)" "$A" "$B"
echo "s3:GetObject public/notice.txt,$A,$B" >> "$REPORT"

printf "  %s\n" "$(printf '─%.0s' {1..62})"

A=$(try aws ssm get-parameter --name /prod/db/password --with-decryption --profile allowed)
B=$(try aws ssm get-parameter --name /prod/db/password --with-decryption --profile attacker)
print_row "ssm:GetParameter /prod/db/password" "$A" "$B"
echo "ssm:GetParameter /prod/db/password,$A,$B" >> "$REPORT"

A=$(try aws ssm get-parameters-by-path --path /prod/ --recursive --with-decryption --profile allowed)
B=$(try aws ssm get-parameters-by-path --path /prod/ --recursive --with-decryption --profile attacker)
print_row "ssm:GetParametersByPath /prod/" "$A" "$B"
echo "ssm:GetParametersByPath /prod/,$A,$B" >> "$REPORT"

echo ""

FINDINGS=$(grep ",ALLOW$" "$REPORT" | wc -l)
if [ "$FINDINGS" -eq 0 ]; then
  echo -e "  ${GREEN}${BOLD}All attacker actions correctly denied. ✓${NC}"
else
  echo -e "  ${RED}${BOLD}Attacker ALLOW findings: ${FINDINGS}${NC}"
  grep ",ALLOW$" "$REPORT" | while IFS=',' read -r action allowed attacker; do
    echo -e "  ${RED}  • $action (attacker=ALLOW)${NC}"
  done
fi

echo ""
info "CSV report: $REPORT"
