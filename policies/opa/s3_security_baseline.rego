# policies/opa/s3_security_baseline.rego
#
# Enforces S3 security baseline controls.
#
# conftest test tfplan.json --policy policies/opa/ --namespace s3

package s3

# ── RULE 1: Versioning must be enabled ───────────────────────
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_versioning"

  config := resource.change.after.versioning_configuration[_]
  config.status != "Enabled"

  msg := sprintf(
    "FINDING [S3-001]: Bucket versioning is not Enabled (got: '%s')",
    [config.status]
  )
}

# ── RULE 2: Encryption must be configured ────────────────────
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"

  bucket_name := resource.change.after.bucket
  not encryption_exists(input.resource_changes)

  msg := sprintf(
    "FINDING [S3-002]: Bucket '%s' has no server-side encryption configuration",
    [bucket_name]
  )
}

encryption_exists(resources) {
  r := resources[_]
  r.type == "aws_s3_bucket_server_side_encryption_configuration"
  r.change.actions[_] != "delete"
}

# ── RULE 3: Warn on force_destroy ────────────────────────────
warn[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.after.force_destroy == true

  msg := sprintf(
    "WARNING [S3-003]: Bucket '%s' has force_destroy=true — remove before production",
    [resource.change.after.bucket]
  )
}

# ── RULE 4: Warn when public access block is partially open ──
# (acceptable when bucket policy contains explicit Deny)
warn[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"

  resource.change.after.restrict_public_buckets == false
  resource.change.after.block_public_policy == false

  msg := sprintf(
    "WARNING [S3-004]: Bucket '%s' has block_public_policy and restrict_public_buckets both false — verify bucket policy has explicit Deny",
    [resource.change.after.bucket]
  )
}
