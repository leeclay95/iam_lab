terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    s3      = "http://localhost:4566"
    iam     = "http://localhost:4566"
    sts     = "http://localhost:4566"
    lambda  = "http://localhost:4566"
    ssm     = "http://localhost:4566"
    logs    = "http://localhost:4566"
  }
}

provider "aws" {
  alias                       = "data"
  region                      = "us-east-1"
  access_key                  = "111111111111"
  secret_key                  = "test"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    s3  = "http://localhost:4566"
    ssm = "http://localhost:4566"
  }
}

locals {
  allowed_account  = "111111111111"
  attacker_account = "222222222222"
  account_id       = "000000000000"
  region           = "us-east-1"
  bucket           = "company-secrets-vault-fixed"
}

resource "aws_s3_bucket" "vault" {
  provider      = aws.data
  bucket        = local.bucket
  force_destroy = true

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      AWS_ACCESS_KEY_ID=111111111111 AWS_SECRET_ACCESS_KEY=test \
      aws s3 rm s3://${self.bucket} --recursive \
        --endpoint-url http://localhost:4566 2>/dev/null || true

      AWS_ACCESS_KEY_ID=111111111111 AWS_SECRET_ACCESS_KEY=test \
      aws s3api list-object-versions \
        --bucket ${self.bucket} \
        --endpoint-url http://localhost:4566 \
        --query '[Versions,DeleteMarkers]' \
        --output json 2>/dev/null | python3 -c "
import json,sys,subprocess,os
data=json.load(sys.stdin)
env={**os.environ,'AWS_ACCESS_KEY_ID':'111111111111','AWS_SECRET_ACCESS_KEY':'test'}
[subprocess.run(['aws','s3api','delete-object','--bucket','${self.bucket}',
  '--key',o['Key'],'--version-id',o['VersionId'],
  '--endpoint-url','http://localhost:4566'],env=env)
 for g in data for o in (g or [])]
print('pre-empty done')
" || true
    EOT
  }
}

#tfsec:ignore:aws-s3-block-public-policy
#tfsec:ignore:aws-s3-no-public-buckets
resource "aws_s3_bucket_public_access_block" "vault" {
  provider                = aws.data
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_versioning" "vault" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }
}

#tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "creds" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  key      = "credentials/db-creds.txt"
  content  = "DB_HOST=prod-db.internal\nDB_USER=admin\nDB_PASSWORD=SuperSecret123!\nDB_NAME=customers"
}

resource "aws_s3_object" "api_keys" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  key      = "credentials/api-keys.txt"
  content  = "STRIPE_SECRET=sk_live_FAKEFAKEFAKE\nSENDGRID_KEY=SG.FAKEFAKEFAKE"
}

resource "aws_s3_object" "employee_pii" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  key      = "pii/employees.csv"
  content  = "name,ssn,salary\nAlice Smith,123-45-6789,95000\nBob Jones,987-65-4321,85000"
}

resource "aws_s3_object" "app_output" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  key      = "app-output/placeholder.txt"
  content  = "Lambda writes results here — scoped prefix only."
}

resource "aws_s3_bucket_policy" "vault" {
  provider   = aws.data
  bucket     = aws_s3_bucket.vault.id
  depends_on = [aws_s3_bucket_public_access_block.vault]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAuthorizedAccount"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.allowed_account}:root" }
        Action    = ["s3:GetObject","s3:ListBucket","s3:PutObject","s3:DeleteObject"]
        Resource  = ["arn:aws:s3:::${local.bucket}","arn:aws:s3:::${local.bucket}/*"]
      },
      {
        Sid       = "DenyAttackerAccount"
        Effect    = "Deny"
        Principal = { AWS = "arn:aws:iam::${local.attacker_account}:root" }
        Action    = ["s3:*"]
        Resource  = ["arn:aws:s3:::${local.bucket}","arn:aws:s3:::${local.bucket}/*"]
      }
    ]
  })
}

resource "aws_ssm_parameter" "db_password" {
  provider  = aws.data
  name      = "/prod/db/password"
  type      = "SecureString"
  value     = "SuperSecret123!"
  overwrite = true
}

resource "aws_ssm_parameter" "api_token" {
  provider  = aws.data
  name      = "/prod/api/internal_token"
  type      = "SecureString"
  value     = "tok-internal-FAKEFAKEFAKE"
  overwrite = true
}

# FIX 1 — correctly scoped exec role
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role" "lambda_exec_fixed" {
  name = "lambda-correctly-scoped-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}



#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "lambda_exec_fixed_policy" {
  name = "lambda-correctly-scoped-policy"
  role = aws_iam_role.lambda_exec_fixed.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ScopedS3Write"
        Effect   = "Allow"
        Action   = ["s3:PutObject","s3:GetObject"]
        Resource = ["arn:aws:s3:::${local.bucket}/app-output/*"]
      },
      {
        Sid      = "ScopedSSMRead"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        # tfsec:ignore:aws-iam-no-policy-wildcards
        Resource = ["arn:aws:ssm:${local.region}:${local.account_id}:parameter/prod/app/*"]
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]
        # tfsec:ignore:aws-iam-no-policy-wildcards
        Resource = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/data-processor-fixed:*"]
      }
    ]
  })
}

# FIX 2 — devops role with scoped PassRole + condition
resource "aws_iam_role" "devops_fixed" {
  name = "devops-role-fixed"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
    }]
  })
}

resource "aws_iam_role_policy" "devops_fixed_policy" {
  name = "devops-fixed-policy"
  role = aws_iam_role.devops_fixed.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = ["lambda:CreateFunction","lambda:UpdateFunctionCode","lambda:GetFunction",
                  "lambda:ListFunctions","lambda:InvokeFunction","lambda:DeleteFunction"]
        Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:data-processor-fixed"]
      },
      {
        Sid      = "PassRoleScoped"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = ["arn:aws:iam::${local.account_id}:role/lambda-correctly-scoped-role"]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "lambda.amazonaws.com"
          }
        }
      }
    ]
  })
}

# FIX 3 — Lambda with scoped exec role + invoke restriction
resource "aws_lambda_function" "data_processor_fixed" {
  filename      = "${path.module}/../lambda_src/data_processor.zip"
  function_name = "data-processor-fixed"
  role          = aws_iam_role.lambda_exec_fixed.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 30
  environment {
    variables = {
      BUCKET                = local.bucket
      AWS_ENDPOINT_URL      = "http://floci:4566"
      AWS_ACCESS_KEY_ID     = "111111111111"
      AWS_SECRET_ACCESS_KEY = "test"
    }
  }
  depends_on = [aws_iam_role_policy.lambda_exec_fixed_policy]
}

resource "aws_lambda_permission" "invoke_restriction" {
  statement_id  = "AllowOnlyAuthorizedAccount"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.data_processor_fixed.function_name
  principal     = "arn:aws:iam::${local.allowed_account}:root"
}

output "bucket_name"         { value = aws_s3_bucket.vault.bucket }
output "fixed_lambda_arn"    { value = aws_lambda_function.data_processor_fixed.arn }
output "fixed_exec_role_arn" { value = aws_iam_role.lambda_exec_fixed.arn }
output "fixed_devops_arn"    { value = aws_iam_role.devops_fixed.arn }
output "allowed_account"     { value = local.allowed_account }
output "attacker_account"    { value = local.attacker_account }
