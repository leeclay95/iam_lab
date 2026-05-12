#!/bin/bash
# destroy.sh — safely destroys the lab by pre-emptying versioned buckets
# Usage: ./scripts/destroy.sh [--vuln|--fixed]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh" "${1:---vuln}"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566

TF_DIR="$(dirname "$SCRIPT_DIR")/$([ "$MODE" = "--fixed" ] && echo "terraform-fix" || echo "terraform")"

echo "[*] Pre-emptying bucket: $BUCKET"

# Remove all objects
aws s3 rm "s3://${BUCKET}" --recursive 2>/dev/null || true

# Remove all versions and delete markers
aws s3api list-object-versions \
  --bucket "$BUCKET" \
  --query '[Versions,DeleteMarkers]' \
  --output json 2>/dev/null | python3 -c "
import json,sys,subprocess,os
data = json.load(sys.stdin)
count = 0
for group in data:
    if not group: continue
    for obj in group:
        subprocess.run([
            'aws','s3api','delete-object',
            '--bucket','${BUCKET}',
            '--key', obj['Key'],
            '--version-id', obj['VersionId'],
            '--endpoint-url','http://localhost:4566'
        ], capture_output=True)
        count += 1
print(f'Deleted {count} versions/markers')
" || true

echo "[*] Running terraform destroy..."
cd "$TF_DIR"
terraform destroy -auto-approve -refresh=false

echo "[*] Done."
