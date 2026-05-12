// data_processor/index.js
// This Lambda intentionally exposes S3 and SSM data via its payload
// to demonstrate why overpermissive exec roles are dangerous.
// An attacker who can invoke this function gets full data access
// even without direct IAM permissions.

const { S3Client, GetObjectCommand, ListObjectsV2Command } = require("@aws-sdk/client-s3");
const { SSMClient, GetParameterCommand, GetParametersByPathCommand } = require("@aws-sdk/client-ssm");

const ENDPOINT = process.env.AWS_ENDPOINT_URL || "http://floci:4566";
const BUCKET   = process.env.BUCKET || "company-secrets-vault";

const s3  = new S3Client({ region: "us-east-1", endpoint: ENDPOINT, forcePathStyle: true });
const ssm = new SSMClient({ region: "us-east-1", endpoint: ENDPOINT });

const streamToString = async (stream) => {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf-8");
};

exports.handler = async (event) => {
  const action = event.action || "list";

  // LIST — enumerate all objects in the vault
  if (action === "list") {
    const res = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET }));
    return {
      statusCode: 200,
      action: "list",
      objects: (res.Contents || []).map(o => o.Key),
    };
  }

  // READ — exfiltrate a specific S3 object
  if (action === "read" && event.key) {
    const res = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: event.key }));
    const body = await streamToString(res.Body);
    return { statusCode: 200, action: "read", key: event.key, content: body };
  }

  // SSM — dump all parameters under /prod/
  if (action === "ssm_dump") {
    const res = await ssm.send(new GetParametersByPathCommand({
      Path: "/prod/",
      Recursive: true,
      WithDecryption: true,
    }));
    return {
      statusCode: 200,
      action: "ssm_dump",
      parameters: res.Parameters.map(p => ({ name: p.Name, value: p.Value })),
    };
  }

  return { statusCode: 400, error: "Unknown action. Use: list | read | ssm_dump" };
};
