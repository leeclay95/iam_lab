#!/bin/bash
# env.sh — shared environment config sourced by all scripts
# Usage: source scripts/env.sh [--vuln|--fixed]

export AWS_ENDPOINT_URL=http://localhost:4566

MODE="${1:---vuln}"

if [ "$MODE" = "--fixed" ]; then
  export BUCKET="company-secrets-vault-fixed"
  export LAMBDA_NAME="data-processor-fixed"
  export ENV_LABEL="FIXED"
  export IAM_EXEC_ROLE="lambda-correctly-scoped-role"
  export DEVOPS_ROLE="devops-role-fixed"
else
  export BUCKET="company-secrets-vault"
  export LAMBDA_NAME="data-processor"
  export ENV_LABEL="VULNERABLE"
  export IAM_EXEC_ROLE="lambda-overpermissive-role"
  export DEVOPS_ROLE="devops-role"
fi

echo -e "\033[1;33m[ENV]\033[0m Target: ${ENV_LABEL} | Bucket: ${BUCKET} | Lambda: ${LAMBDA_NAME}"
