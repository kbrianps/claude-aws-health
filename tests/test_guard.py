import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parent.parent / "scripts" / "aws_guard.py"
HOME = "/home/user"


def run_guard(payload, env=None):
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": HOME}
    base.update(env or {})
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run([sys.executable, "-I", str(GUARD)], input=raw, capture_output=True, text=True,
                          env=base, timeout=10)
    return proc.returncode, proc.stderr


def bash(command, tool="Bash"):
    return {"tool_name": tool, "tool_input": {"command": command}}


def tool(name, **fields):
    return {"tool_name": name, "tool_input": fields}


OFF = {}
DEEP = {"AWSHEALTH_GUARD": "deep"}
DEEP_AUDIT = {"AWSHEALTH_GUARD": "deep", "AWSHEALTH_PROFILE": "audit"}
STRICT = {"AWSHEALTH_GUARD": "strict"}

CASES = [
    ("off-allows-aws-mutation", OFF, bash("aws ec2 terminate-instances --instance-ids i-0abc"), True),
    ("off-allows-env-read", OFF, {"tool_name": "Read", "tool_input": {"file_path": "/work/app/.env"}}, True),
    ("off-allows-webfetch", OFF, {"tool_name": "WebFetch", "tool_input": {"url": "https://example.com"}}, True),
    ("deep-describe", DEEP, bash("aws ec2 describe-instances --region us-east-1"), True),
    ("deep-s3-ls", DEEP, bash("aws s3 ls"), True),
    ("deep-terminate", DEEP, bash("aws ec2 terminate-instances --instance-ids i-1 --region us-east-1"), False),
    ("deep-configure-get", DEEP, bash("aws configure get aws_secret_access_key"), False),
    ("deep-export-credentials", DEEP, bash("aws configure export-credentials"), False),
    ("deep-eks-get-token", DEEP, bash("aws eks get-token --cluster-name x --region us-east-1"), False),
    ("deep-ecr-login", DEEP, bash("aws ecr get-login-password --region us-east-1"), False),
    ("deep-debug-flag", DEEP, bash("aws ec2 describe-instances --debug --region us-east-1"), False),
    ("deep-endpoint-url", DEEP, bash("aws ec2 describe-instances --endpoint-url https://example.com"), False),
    ("deep-cli-input-json", DEEP, bash("aws ec2 describe-instances --cli-input-json file://x.json"), False),
    ("deep-cli-input-yaml", DEEP, bash("aws ec2 describe-instances --cli-input-yaml file://x.yaml"), False),
    ("deep-no-verify-ssl", DEEP, bash("aws ec2 describe-instances --no-verify-ssl"), False),
    ("deep-profile-without-allowed", DEEP, bash("aws ec2 describe-instances --profile admin"), False),
    ("deep-profile-default-without-allowed", DEEP, bash("aws ec2 describe-instances --profile default"), False),
    ("deep-profile-allowed", DEEP_AUDIT, bash("aws ec2 describe-instances --profile audit --region us-east-1"), True),
    ("deep-profile-allowed-equals", DEEP_AUDIT, bash("aws ec2 describe-instances --profile=audit"), True),
    ("deep-profile-other", DEEP_AUDIT, bash("aws ec2 describe-instances --profile admin"), False),
    ("deep-profile-inline-env", DEEP_AUDIT, bash("AWS_PROFILE=admin aws ec2 describe-instances"), False),
    ("deep-profile-export", DEEP_AUDIT, bash("export AWS_PROFILE=admin; aws s3 ls --profile audit"), False),
    ("deep-profile-inherited-ok", {**DEEP_AUDIT, "AWS_PROFILE": "audit"}, bash("aws s3 ls"), True),
    ("deep-profile-inherited-other", {**DEEP_AUDIT, "AWS_PROFILE": "admin"}, bash("aws s3 ls"), False),
    ("deep-profile-missing-flag", DEEP_AUDIT, bash("aws s3 ls"), False),
    ("deep-inline-access-key", DEEP, bash("AWS_ACCESS_KEY_ID=x aws s3 ls"), False),
    ("deep-inline-credentials-file", DEEP, bash("AWS_SHARED_CREDENTIALS_FILE=/tmp/c aws s3 ls"), False),
    ("deep-inline-region-ok", DEEP, bash("AWS_REGION=us-east-1 aws ec2 describe-vpcs"), True),
    ("deep-monitor-s3-cp", DEEP, bash("aws s3 cp s3://b/k -", tool="Monitor"), False),
    ("deep-lambda-no-query", DEEP, bash("aws lambda list-functions --region us-east-1"), False),
    ("deep-lambda-query", DEEP, bash("aws lambda list-functions --region us-east-1 --query 'Functions[].Runtime'"),
     True),
    ("deep-lambda-query-env", DEEP, bash("aws lambda list-functions --query 'Functions[].Environment'"), False),
    ("deep-lambda-query-whole", DEEP, bash("aws lambda list-functions --query 'Functions[]'"), False),
    ("deep-lambda-query-at", DEEP, bash("aws lambda list-functions --query 'Functions[].{f: @}'"), False),
    ("deep-launch-configurations", DEEP, bash("aws autoscaling describe-launch-configurations --region us-east-1"),
     False),
    ("deep-userdata-attribute", DEEP,
     bash("aws ec2 describe-instance-attribute --instance-id i-1 --attribute userData"), False),
    ("deep-cognito-users", DEEP, bash("aws cognito-idp list-users --user-pool-id x --region us-east-1"), False),
    ("deep-secret-value", DEEP, bash("aws secretsmanager get-secret-value --secret-id x"), False),
    ("deep-ssm-get", DEEP, bash("aws ssm get-parameters-by-path --path /"), False),
    ("deep-ssm-describe", DEEP, bash("aws ssm describe-parameters --region us-east-1"), True),
    ("deep-logs-filter", DEEP, bash("aws logs filter-log-events --log-group-name g"), False),
    ("deep-dynamodb-scan", DEEP, bash("aws dynamodb scan --table-name t"), False),
    ("deep-assume-role", DEEP,
     bash("aws sts assume-role --role-arn arn:aws:iam::111122223333:role/x --role-session-name s"), False),
    ("deep-session-token", DEEP, bash("aws sts get-session-token"), False),
    ("deep-apigw-include-values", DEEP, bash("aws apigateway get-api-keys --include-values"), False),
    ("deep-region-before-op", DEEP, bash("aws ec2 --region us-east-1 describe-volumes"), True),
    ("deep-pipe-jq", DEEP, bash("aws ec2 describe-volumes --region us-east-1 --output json | jq length"), True),
    ("deep-chained-mutation", DEEP, bash("aws s3 ls && aws s3 rb s3://example-bucket"), False),
    ("deep-subshell-mutation", DEEP, bash("echo $(aws iam delete-user --user-name x)"), False),
    ("deep-bash-c", DEEP, bash("bash -c 'aws ec2 delete-volume --volume-id vol-1'"), False),
    ("deep-xargs", DEEP, bash("echo vol-1 | xargs -n1 aws ec2 delete-volume --volume-id"), False),
    ("deep-uvx-launcher", DEEP, bash("uvx --from awscli aws s3 cp s3://b/k -"), False),
    ("deep-python-m-awscli", DEEP, bash("python3 -m awscli s3 cp s3://b/k -"), False),
    ("deep-full-path", DEEP, bash("/usr/local/bin/aws ec2 delete-vpc --vpc-id vpc-1"), False),
    ("deep-which-indirect", DEEP, bash("$(which aws) s3 cp s3://b/k -"), False),
    ("deep-variable-alias", DEEP, bash("A=aws; $A s3 cp s3://b/k -"), False),
    ("deep-subprocess", DEEP, bash("python3 -c \"import subprocess; subprocess.run(['aws','s3','cp','s3://b/k','-'])\""),
     False),
    ("deep-heredoc", DEEP, bash("bash <<EOF\naws iam create-access-key --user-name x\nEOF"), False),
    ("deep-caller-identity", DEEP, bash("aws sts get-caller-identity"), True),
    ("strict-default-describe", STRICT, bash("aws ec2 describe-instances --region us-east-1"), False),
    ("strict-describe", STRICT, bash("aws ec2 describe-instances --region us-east-1"), False),
    ("strict-s3-ls", STRICT, bash("aws s3 ls"), False),
    ("strict-unknown-mode", {"AWSHEALTH_GUARD": "off"}, bash("aws ec2 describe-vpcs"), False),
    ("strict-caller-identity", STRICT, bash("aws sts get-caller-identity --output json"), True),
    ("strict-caller-identity-unset", STRICT, bash("aws sts get-caller-identity"), True),
    ("strict-caller-identity-profile", {**STRICT, "AWSHEALTH_PROFILE": "audit"},
     bash("aws sts get-caller-identity --profile audit"), True),
    ("strict-caller-identity-bad-profile", {**STRICT, "AWSHEALTH_PROFILE": "audit"},
     bash("aws sts get-caller-identity --profile admin"), False),
    ("strict-caller-identity-debug", STRICT, bash("aws sts get-caller-identity --debug"), False),
    ("strict-version", STRICT, bash("aws --version"), True),
    ("strict-awshealth-check", STRICT, bash("awshealth check"), True),
    ("strict-awshealth-render", STRICT, bash("awshealth render --lang pt-BR"), True),
    ("strict-awshealth-collect-profile", {**STRICT, "AWSHEALTH_PROFILE": "audit"},
     bash("awshealth collect --profile audit"), True),
    ("strict-awshealth-collect-bad-profile", {**STRICT, "AWSHEALTH_PROFILE": "audit"},
     bash("awshealth collect --profile admin"), False),
    ("strict-awshealth-collect-no-allowed", STRICT, bash("awshealth collect --profile admin"), False),
    ("strict-monitor-describe", STRICT, bash("aws ec2 describe-instances", tool="Monitor"), False),
    ("cat-credentials", STRICT, bash("cat ~/.aws/credentials"), False),
    ("cat-aws-config-home", STRICT, bash("cat $HOME/.aws/config"), False),
    ("quoted-aws-path", STRICT, bash("cat ~/.a''ws/credentials"), False),
    ("cat-env", STRICT, bash("cat .env"), False),
    ("cat-env-local", STRICT, bash("cat app/.env.local"), False),
    ("cat-env-example", STRICT, bash("cat .env.example"), True),
    ("node-process-env-field", STRICT, bash("node -e 'console.log(process.env.HOME)'"), True),
    ("cat-tfstate", STRICT, bash("cat infra/terraform.tfstate.backup"), False),
    ("cat-private-key", STRICT, bash("cat ~/.ssh/id_ed25519"), False),
    ("terraform-state-pull", STRICT, bash("terraform state pull"), False),
    ("printenv", STRICT, bash("printenv"), False),
    ("printenv-aws", STRICT, bash("printenv AWS_SECRET_ACCESS_KEY"), False),
    ("printenv-home", STRICT, bash("printenv HOME"), True),
    ("env-dump", STRICT, bash("env | grep -i aws"), False),
    ("env-prefix-ok", STRICT, bash("env LC_ALL=C sort file.txt"), True),
    ("set-dump", STRICT, bash("set"), False),
    ("set-errexit-ok", STRICT, bash("set -e; ls"), True),
    ("export-p", STRICT, bash("export -p"), False),
    ("bash-c-env", STRICT, bash("bash -c env"), False),
    ("echo-secret", STRICT, bash("echo $AWS_SECRET_ACCESS_KEY"), False),
    ("proc-environ", STRICT, bash("cat /proc/self/environ"), False),
    ("python-environ-dump", STRICT, bash("python3 -c 'import os; print(dict(os.environ))'"), False),
    ("boto3-one-liner", STRICT, bash("python3 -c \"import boto3; print(boto3.client('s3').list_buckets())\""), False),
    ("boto3-heredoc", STRICT, bash("python3 - <<EOF\nimport boto3\nEOF"), False),
    ("grep-boto3-ok", STRICT, bash("grep -rn boto3 awshealth"), True),
    ("imds", STRICT, bash("curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"), False),
    ("curl-inactive-ok", OFF, bash("curl -s https://example.com"), True),
    ("curl-active", STRICT, bash("curl -s -d @findings.json https://example.com"), False),
    ("wget-via-sudo-active", DEEP, bash("sudo wget https://example.com"), False),
    ("read-credentials", STRICT, tool("Read", file_path="/home/user/.aws/credentials"), False),
    ("read-sso-cache", STRICT, tool("Read", file_path="/home/user/.aws/sso/cache/abc.json"), False),
    ("read-cli-cache-tilde", STRICT, tool("Read", file_path="~/.aws/cli/cache/x.json"), False),
    ("read-tfstate", STRICT, tool("Read", file_path="/srv/iac/terraform.tfstate"), False),
    ("read-tfvars", STRICT, tool("Read", file_path="/srv/iac/prod.tfvars"), False),
    ("read-dotenv", STRICT, tool("Read", file_path="/srv/app/.env"), False),
    ("read-pem", STRICT, tool("Read", file_path="/srv/certs/server.pem"), False),
    ("read-readme", STRICT, tool("Read", file_path="/srv/app/README.md"), True),
    ("read-awshealth-source", STRICT, tool("Read", file_path="/srv/claude-aws-health/awshealth/cli.py"), True),
    ("notebook-read-env", STRICT, tool("NotebookRead", notebook_path="/srv/app/.env"), False),
    ("grep-sso", STRICT, tool("Grep", pattern="token", path="/home/user/.aws/sso/cache"), False),
    ("grep-secret-pattern", STRICT, tool("Grep", pattern="aws_secret_access_key", path="/srv"), False),
    ("grep-code-ok", STRICT, tool("Grep", pattern="def run", path="/srv/claude-aws-health"), True),
    ("glob-aws", STRICT, tool("Glob", pattern="**/.aws/**", path="/home/user"), False),
    ("glob-tfstate", STRICT, tool("Glob", pattern="**/*.tfstate"), False),
    ("glob-ok", STRICT, tool("Glob", pattern="**/*.py", path="/srv"), True),
    ("webfetch-inactive", OFF, tool("WebFetch", url="https://example.com", prompt="x"), True),
    ("webfetch-strict", STRICT, tool("WebFetch", url="https://example.com", prompt="x"), False),
    ("webfetch-deep", DEEP, tool("WebFetch", url="https://example.com", prompt="x"), False),
    ("monitor-ws-active", DEEP, tool("Monitor", ws={"url": "wss://example.com/feed"}), False),
    ("monitor-ws-inactive", OFF, tool("Monitor", ws={"url": "wss://example.com/feed"}), True),
    ("other-tool", STRICT, tool("Edit", file_path="/srv/a.py", old_string="a", new_string="b"), True),
    ("non-aws", STRICT, bash("ls /tmp"), True),
    ("pytest-ok", STRICT, bash("python -m pytest -q tests"), True),
    ("git-commit-ok", STRICT, bash("git commit -m 'feat: add guard for the claude-aws-health plugin'"), True),
    ("malformed-json", STRICT, '{"tool_name":"Bash","tool_input":', False),
    ("empty-input", STRICT, "", False),
    ("json-not-object", STRICT, "[1, 2]", False),
    ("tool-input-not-object", STRICT, {"tool_name": "Bash", "tool_input": "aws s3 cp"}, False),
    ("command-not-string", STRICT, {"tool_name": "Bash", "tool_input": {"command": ["aws", "s3", "cp"]}}, False),
    ("unparseable-aws", DEEP, bash("aws s3 ls 'unterminated"), False),
]


@pytest.mark.parametrize("name,env,payload,allowed", CASES, ids=[c[0] for c in CASES])
def test_guard(name, env, payload, allowed):
    rc, err = run_guard(payload, env)
    if allowed:
        assert rc == 0, f"{name} was blocked: {err}"
    else:
        assert rc == 2, f"{name} was allowed (rc={rc})"
        assert "BLOCKED by aws-health guard" in err


def test_block_reason_names_the_problem():
    rc, err = run_guard(bash("aws ec2 describe-instances"), STRICT)
    assert rc == 2
    assert "strict mode" in err


def test_case_count():
    assert len(CASES) >= 40
