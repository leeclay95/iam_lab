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
  region           = "us-east-1"
  bucket           = "company-secrets-vault"
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
  content  = "STRIPE_SECRET=sk_live_FAKEFAKEFAKE\nSENDGRID_KEY=SG.FAKEFAKEFAKE\nINTERNAL_API_TOKEN=eyJhbGciOiJIUzI1NiJ9.FAKE"
}

resource "aws_s3_object" "employee_pii" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  key      = "pii/employees.csv"
  content  = "name,ssn,salary\nAlice Smith,123-45-6789,95000\nBob Jones,987-65-4321,85000"
}

resource "aws_s3_object" "public_notice" {
  provider = aws.data
  bucket   = aws_s3_bucket.vault.id
  key      = "public/notice.txt"
  content  = "This is a public file. No sensitive data here."
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
        Sid       = "AllowPublicPrefixToAnyone"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = ["arn:aws:s3:::${local.bucket}/public/*"]
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

resource "aws_iam_role" "lambda_exec" {
  name = "lambda-overpermissive-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_exec_policy" {
  name = "lambda-overpermissive-policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid="OverpermissiveS3",  Effect="Allow", Action=["s3:*"], Resource="*" },
      { Sid="OverpermissiveSSM", Effect="Allow",
        Action=["ssm:GetParameter","ssm:GetParameters","ssm:GetParametersByPath"],
        Resource="*" },
      { Sid="Logs", Effect="Allow",
        Action=["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
        Resource="*" }
    ]
  })
}

resource "aws_iam_role" "devops" {
  name = "devops-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::000000000000:root" }
    }]
  })
}

resource "aws_iam_role_policy" "devops_policy" {
  name = "devops-policy"
  role = aws_iam_role.devops.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = ["lambda:CreateFunction","lambda:UpdateFunctionCode","lambda:GetFunction",
                  "lambda:ListFunctions","lambda:InvokeFunction","lambda:DeleteFunction"]
        Resource = "*"
      },
      { Sid="PassRoleUnscoped", Effect="Allow", Action=["iam:PassRole"], Resource="*" }
    ]
  })
}

resource "aws_lambda_function" "data_processor" {
  filename      = "${path.module}/../lambda_src/data_processor.zip"
  function_name = "data-processor"
  role          = aws_iam_role.lambda_exec.arn
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
  depends_on = [aws_iam_role_policy.lambda_exec_policy]
}

output "bucket_name"             { value = aws_s3_bucket.vault.bucket }
output "lambda_arn"              { value = aws_lambda_function.data_processor.arn }
output "overpermissive_role_arn" { value = aws_iam_role.lambda_exec.arn }
output "devops_role_arn"         { value = aws_iam_role.devops.arn }
