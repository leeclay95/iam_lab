# policies/opa/iam_no_wildcard_resources.rego
#
# Catches IAM role policies that use Resource: "*" on sensitive actions.
#
# Test first:
#   opa test policies/opa/ -v
#
# Run against Terraform plan JSON:
#   terraform plan -out=tfplan.binary
#   terraform show -json tfplan.binary > tfplan.json
#   conftest test tfplan.json --policy policies/opa/ --namespace iam

package iam

# ── Helpers ──────────────────────────────────────────────────

# Returns true if the action string starts with a sensitive service prefix
sensitive_action(action) {
  startswith(action, "s3:")
}

sensitive_action(action) {
  startswith(action, "ssm:")
}

sensitive_action(action) {
  startswith(action, "secretsmanager:")
}

sensitive_action(action) {
  startswith(action, "kms:")
}

sensitive_action(action) {
  action == "iam:PassRole"
}

sensitive_action(action) {
  action == "iam:CreateRole"
}

sensitive_action(action) {
  action == "iam:AttachRolePolicy"
}

sensitive_action(action) {
  action == "sts:AssumeRole"
}

# ── RULE 1: Wildcard resource on sensitive actions ────────────
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"

  policy := json.unmarshal(resource.change.after.policy)
  stmt   := policy.Statement[_]

  stmt.Effect == "Allow"
  action := stmt.Action[_]
  sensitive_action(action)
  stmt.Resource == "*"

  msg := sprintf(
    "FINDING [IAM-001/002]: Role policy '%s' allows '%s' on Resource:* — scope to specific ARN",
    [resource.change.after.name, action]
  )
}

# ── RULE 2: iam:PassRole without PassedToService condition ────
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"

  policy := json.unmarshal(resource.change.after.policy)
  stmt   := policy.Statement[_]

  stmt.Effect == "Allow"
  action := stmt.Action[_]
  action == "iam:PassRole"

  not stmt.Condition.StringEquals["iam:PassedToService"]

  msg := sprintf(
    "FINDING [IAM-003]: Role policy '%s' allows iam:PassRole without iam:PassedToService condition — privesc risk",
    [resource.change.after.name]
  )
}

# ── RULE 3: iam:PassRole on Resource:* ───────────────────────
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"

  policy := json.unmarshal(resource.change.after.policy)
  stmt   := policy.Statement[_]

  stmt.Effect == "Allow"
  action := stmt.Action[_]
  action == "iam:PassRole"
  stmt.Resource == "*"

  msg := sprintf(
    "FINDING [IAM-004]: Role policy '%s' allows iam:PassRole on Resource:* — scope to specific role ARN",
    [resource.change.after.name]
  )
}

# ── RULE 4: Lambda with no resource-based invoke policy ──────
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_lambda_function"

  func_name := resource.change.after.function_name
  not lambda_has_permission(func_name, input.resource_changes)

  msg := sprintf(
    "FINDING [LAMBDA-001]: Lambda '%s' has no aws_lambda_permission — any principal can invoke it",
    [func_name]
  )
}

lambda_has_permission(func_name, resources) {
  r := resources[_]
  r.type == "aws_lambda_permission"
  r.change.after.function_name == func_name
}
