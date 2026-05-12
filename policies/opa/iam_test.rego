# policies/opa/iam_test.rego
# Unit tests for iam_no_wildcard_resources.rego
#
# Run with:
#   opa test policies/opa/ -v

package iam

# ── Test data ────────────────────────────────────────────────

mock_vulnerable_s3 := {
  "resource_changes": [{
    "type": "aws_iam_role_policy",
    "change": {
      "after": {
        "name": "lambda-overpermissive-policy",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],\"Resource\":\"*\"}]}"
      }
    }
  }]
}

mock_vulnerable_passrole := {
  "resource_changes": [{
    "type": "aws_iam_role_policy",
    "change": {
      "after": {
        "name": "devops-policy",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\"],\"Resource\":\"*\"}]}"
      }
    }
  }]
}

mock_fixed_s3 := {
  "resource_changes": [{
    "type": "aws_iam_role_policy",
    "change": {
      "after": {
        "name": "lambda-scoped-policy",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::my-bucket/app/*\"}]}"
      }
    }
  }]
}

mock_fixed_passrole := {
  "resource_changes": [{
    "type": "aws_iam_role_policy",
    "change": {
      "after": {
        "name": "devops-fixed-policy",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\"],\"Resource\":\"arn:aws:iam::000000000000:role/lambda-deploy-only\",\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"lambda.amazonaws.com\"}}}]}"
      }
    }
  }]
}

mock_lambda_no_permission := {
  "resource_changes": [{
    "type": "aws_lambda_function",
    "change": {
      "after": {
        "function_name": "data-processor"
      }
    }
  }]
}

mock_lambda_with_permission := {
  "resource_changes": [
    {
      "type": "aws_lambda_function",
      "change": {
        "after": {
          "function_name": "data-processor-fixed"
        }
      }
    },
    {
      "type": "aws_lambda_permission",
      "change": {
        "after": {
          "function_name": "data-processor-fixed",
          "principal": "arn:aws:iam::111111111111:root"
        }
      }
    }
  ]
}

# ── Tests: vulnerable cases should produce deny messages ─────

test_s3_wildcard_is_flagged {
  count(deny) > 0
    with input as mock_vulnerable_s3
}

test_passrole_wildcard_is_flagged {
  count(deny) > 0
    with input as mock_vulnerable_passrole
}

test_passrole_no_condition_is_flagged {
  msgs := deny with input as mock_vulnerable_passrole
  msg := msgs[_]
  contains(msg, "IAM-003")
}

test_passrole_resource_wildcard_is_flagged {
  msgs := deny with input as mock_vulnerable_passrole
  msg := msgs[_]
  contains(msg, "IAM-004")
}

test_lambda_no_permission_is_flagged {
  msgs := deny with input as mock_lambda_no_permission
  msg := msgs[_]
  contains(msg, "LAMBDA-001")
}

# ── Tests: fixed cases should produce NO deny messages ───────

test_scoped_s3_passes {
  count(deny) == 0
    with input as mock_fixed_s3
}

test_scoped_passrole_with_condition_passes {
  count(deny) == 0
    with input as mock_fixed_passrole
}

test_lambda_with_permission_passes {
  count(deny) == 0
    with input as mock_lambda_with_permission
}
