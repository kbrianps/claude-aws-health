#!/usr/bin/env python3
import json
import os
import re
import shlex
import sys

ALLOWED_PREFIXES = ("describe-", "list-", "get-", "lookup-", "search-", "batch-get-", "batch-describe-")
ALLOWED_EXACT = {
    "generate-credential-report",
    "generate-service-last-accessed-details",
    "simulate-principal-policy",
    "simulate-custom-policy",
    "help",
}
S3_ALLOWED = {"ls"}
CONFIGURE_ALLOWED = {"list", "list-profiles"}
BLOCKED_OPS = {
    "get-secret-value", "batch-get-secret-value", "get-random-password", "get-object", "get-object-attributes",
    "get-object-torrent", "get-object-acl", "get-parameter", "get-parameters", "get-parameters-by-path",
    "get-parameter-history", "get-log-events", "get-log-record", "get-query-results", "get-password-data",
    "get-console-output", "get-console-screenshot", "get-item", "batch-get-item", "get-records",
    "get-shard-iterator", "get-media", "get-export", "get-session-token", "get-federation-token",
    "get-authorization-token", "get-login-password", "get-login", "get-function", "get-function-configuration",
    "get-layer-version", "get-layer-version-by-arn", "get-template", "get-secret", "get-key-pair", "get-data-key",
    "get-instance-access-details", "get-credentials-for-identity", "get-open-id-token",
    "get-open-id-token-for-developer-identity", "get-id", "get-role-credentials", "get-token",
    "get-cluster-credentials", "get-cluster-credentials-with-iam", "list-api-keys", "list-users",
    "list-users-in-group", "describe-user-pool-client", "describe-configuration-settings",
    "get-knowledge-base-documents", "get-query-execution", "get-execution-history", "describe-execution",
    "get-data-access", "export-credentials", "get-metric-widget-image", "get-launch-template-data",
    "get-vpn-connection-device-sample-configuration", "get-file", "get-blob", "get-folder",
    "get-download-url-for-layer", "get-job-output", "get-primary-email", "get-alternate-contact",
    "get-contact-information", "get-signin-token", "get-access-token",
}
FORBIDDEN_FLAGS = {
    "--debug", "--endpoint-url", "--cli-input-json", "--cli-input-yaml", "--no-verify-ssl", "--ca-bundle",
    "--include-values", "--include-value", "--with-decryption", "--show-secrets",
}
SENSITIVE_QUERY = r"environment|variables|userdata|secret|password|passwd|token|credential|privatekey|private_key"
REQUIRE_QUERY = {
    ("lambda", "list-functions"): "",
    ("lambda", "list-versions-by-function"): "",
    ("ecs", "describe-task-definition"): "",
    ("ec2", "describe-launch-template-versions"): "",
    ("ec2", "describe-vpn-connections"): "|customergatewayconfiguration|options",
    ("batch", "describe-job-definitions"): "",
    ("sagemaker", "describe-endpoint-config"): "",
    ("sagemaker", "describe-training-job"): "",
    ("sagemaker", "describe-model"): "",
    ("glue", "get-jobs"): "",
    ("glue", "get-job"): "",
    ("glue", "get-connections"): "|connectionproperties",
    ("glue", "get-connection"): "|connectionproperties",
    ("autoscaling", "describe-launch-configurations"): "",
    ("codebuild", "batch-get-projects"): "",
    ("apprunner", "describe-service"): "",
    ("amplify", "list-apps"): "|basicauth",
    ("amplify", "get-app"): "|basicauth",
    ("amplify", "list-branches"): "|basicauth",
    ("amplify", "get-branch"): "|basicauth",
    ("emr", "describe-cluster"): "|configurations",
    ("elasticbeanstalk", "describe-environments"): "",
}
OPTS_WITH_VALUE = {
    "--profile", "--region", "--output", "--query", "--endpoint-url", "--color", "--cli-read-timeout",
    "--cli-connect-timeout", "--ca-bundle", "--cli-binary-format",
}
SEPARATORS = {";", "|", "&", "&&", "||", "(", ")", "|&", ";;"}
PREFIX_WORDS = {"do", "then", "else", "elif", "if", "while", "until", "!", "{", "}"}
WRAPPERS = {
    "sudo", "doas", "env", "time", "nohup", "exec", "command", "xargs", "timeout", "nice", "ionice", "stdbuf",
    "watch", "uvx", "npx", "pipx", "uv", "poetry", "pdm", "hatch", "parallel", "ssh", "flock", "strace",
    "script", "chronic", "unbuffer", "setsid", "caffeinate", "systemd-run", "builtin",
}
INTERPRETER = re.compile(r"^(python[\d.]*|ipython[\d.]*|pypy[\d.]*|node|nodejs|deno|bun|ruby|perl|php)$")
NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "scp", "http", "https", "xh"}
ALLOWED_AWS_ENV = {"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PAGER", "AWS_DEFAULT_OUTPUT", "AWS_MAX_ATTEMPTS",
                   "AWS_RETRY_MODE"}
PROFILE_ENV = {"AWS_PROFILE", "AWS_DEFAULT_PROFILE"}
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
AWS_WORD = re.compile(r"(?<![\w.-])aws(?![\w.-])")
LB = r"(?:^|[\s/~\"'=:(<>])"
RB = r"(?=$|[\s/\"';|&)<>*])"
SECRET_PATHS = re.compile(
    rf"{LB}\.aws{RB}"
    r"|\.tfstate|\.tfvars"
    rf"|{LB}\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?{RB}"
    rf"|{LB}\.envrc{RB}"
    rf"|{LB}\.ssh/"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)"
    rf"|[\w-]\.(?:pem|p12|pfx|ppk|jks|keystore){RB}"
    rf"|priv(?:ate)?[_-]?key[\w-]*\.\w+{RB}"
    r"|/proc/[^/\s]+/environ"
)
SECRET_CONTENT = re.compile(r"(?i)aws_secret_access_key|aws_session_token|aws_security_token|private key-----"
                            r"|BEGIN [A-Z ]*PRIVATE KEY")
METADATA_HOSTS = re.compile(r"169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|instance-data(?:\.ec2\.internal)?\b")
ENV_REFS = re.compile(r"\$\{?AWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN)|\bAWS_SECRET_ACCESS_KEY\b"
                      r"|\bAWS_SESSION_TOKEN\b|os\.environ(?![\[.\w])|os\.environ\.(?:items|copy|values)\b"
                      r"|process\.env(?![.\[\w])|\bENV\.to_h\b")
STATE_DUMPS = re.compile(r"\bterraform\s+(?:state\s+pull|show|output)\b|\bpulumi\s+stack\s+export\b")
BOTO = re.compile(r"\b(?:boto3|botocore|aiobotocore)\b")
SCRIPTING = re.compile(r"\b(?:python[\d.]*|ipython|pypy[\d.]*|uv\s+run|poetry\s+run|pdm\s+run)\b|<<")
INLINE_EXEC = re.compile(r"subprocess|os\.system|os\.popen|os\.exec|child_process|execSync|spawnSync|\bsystem\s*\(|`")
INDIRECT = re.compile(r"(?:\$\(|`)\s*(?:which|type|whereis|command\s+-v|readlink|realpath)\b[^)`]*" + AWS_WORD.pattern)


def block(reason):
    print(f"BLOCKED by aws-health guard: {reason}", file=sys.stderr)
    sys.exit(2)


def guard_active():
    return os.environ.get("AWSHEALTH_GUARD", "") != ""


def guard_mode():
    return "deep" if os.environ.get("AWSHEALTH_GUARD", "") == "deep" else "strict"


def allowed_profile():
    return os.environ.get("AWSHEALTH_PROFILE") or None


def tokenize(command):
    lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=";|&()")
    lexer.whitespace_split = True
    return list(lexer)


def split_simple(tokens):
    out, cur = [], []
    for t in tokens:
        if t in SEPARATORS:
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out


def target_of(tok):
    base = os.path.basename(tok)
    return base if base in {"aws", "awshealth"} else None


def find_invocation(cmd):
    i = 0
    while i < len(cmd) and (ASSIGN.match(cmd[i]) or cmd[i] in PREFIX_WORDS):
        i += 1
    if i >= len(cmd):
        return None, None, i
    prog = os.path.basename(cmd[i])
    if target_of(cmd[i]):
        return target_of(cmd[i]), i, i
    if INTERPRETER.match(prog) and "-m" in cmd[i + 1:]:
        mod = cmd[cmd.index("-m", i + 1) + 1] if cmd.index("-m", i + 1) + 1 < len(cmd) else ""
        if mod == "awscli":
            return "aws", cmd.index("-m", i + 1) + 1, i
        if mod.split(".")[0] == "awshealth":
            return "awshealth", cmd.index("-m", i + 1) + 1, i
    if prog in WRAPPERS:
        for j in range(i + 1, len(cmd)):
            if target_of(cmd[j]):
                return target_of(cmd[j]), j, i
    return None, None, i


def option_values(args, name):
    vals = []
    for n, a in enumerate(args):
        if a == name:
            vals.append(args[n + 1] if n + 1 < len(args) else "")
        elif a.startswith(name + "="):
            vals.append(a.split("=", 1)[1])
    return vals


def check_assignments(cmd):
    for t in cmd:
        m = ASSIGN.match(t)
        if not m:
            continue
        name, value = m.group(1), m.group(2)
        if target_of(value.strip()) == "aws" or AWS_WORD.fullmatch(value.strip()):
            block("aliasing the aws CLI through a variable is not allowed")
        if not name.startswith("AWS_") or name in ALLOWED_AWS_ENV:
            continue
        if name in PROFILE_ENV:
            if value != allowed_profile():
                block(profile_message(value))
            continue
        block(f"setting {name} is not allowed during the audit")


def profile_message(value):
    allowed = allowed_profile()
    if allowed:
        return f"profile {value!r} is not allowed; only AWSHEALTH_PROFILE={allowed!r} may be used"
    return f"profile {value!r} is not allowed; set AWSHEALTH_PROFILE before starting Claude Code to allow one"


def check_profile(args, cmd):
    explicit = option_values(args, "--profile")
    inline = [ASSIGN.match(t).group(2) for t in cmd if ASSIGN.match(t) and ASSIGN.match(t).group(1) in PROFILE_ENV]
    allowed = allowed_profile()
    for v in explicit + inline:
        if v != allowed:
            block(profile_message(v))
    if allowed and not explicit and not inline:
        inherited = os.environ.get("AWS_PROFILE") or os.environ.get("AWS_DEFAULT_PROFILE") or "default"
        if inherited != allowed:
            block(f"add --profile {allowed} (the session would use profile {inherited!r})")


def check_query(service, op, args):
    queries = option_values(args, "--query")
    if not queries:
        block(f"'aws {service} {op}' can return secrets; add a --query projection that names only safe fields")
    banned = re.compile(f"(?i){SENSITIVE_QUERY}{REQUIRE_QUERY[(service, op)]}")
    for q in queries:
        if banned.search(q) or "@" in q or "*" in q or re.search(r"\b(?:values|to_string|to_array|merge)\s*\(", q):
            block(f"the --query for 'aws {service} {op}' could return secret-bearing fields")
        if not re.search(r"\]\s*\.\s*[A-Za-z{\[]|\{", q):
            block(f"the --query for 'aws {service} {op}' must select named fields, for example Items[].Name")


def operation_of(rest):
    n = 0
    while n < len(rest):
        a = rest[n]
        if a.startswith("-"):
            n += 2 if a in OPTS_WITH_VALUE else 1
            continue
        return a
    return None


def check_aws(args, cmd):
    for a in args:
        flag = a.split("=", 1)[0]
        if flag in FORBIDDEN_FLAGS:
            block(f"flag {flag} is not allowed during the audit")
    check_profile(args, cmd)
    k = 0
    while k < len(args) and args[k].startswith("-"):
        k += 2 if args[k] in OPTS_WITH_VALUE else 1
    if k >= len(args):
        return
    service = args[k]
    rest = args[k + 1:]
    op = operation_of(rest)
    if service == "help" or op == "help":
        return
    if (service, op) == ("sts", "get-caller-identity"):
        return
    if guard_mode() == "strict":
        name = " ".join(x for x in ("aws", service, op) if x)
        block(f"'{name}' is blocked in strict mode; use awshealth, "
              "or start Claude Code with AWSHEALTH_GUARD=deep after the user agrees to deep mode")
    if op is None:
        block(f"could not determine the operation for 'aws {service}'")
    if service == "s3":
        if op not in S3_ALLOWED:
            block(f"'aws s3 {op}' is not allowed (only 'aws s3 ls')")
        return
    if service == "configure":
        if op not in CONFIGURE_ALLOWED:
            block(f"'aws configure {op}' is not allowed")
        return
    if op in BLOCKED_OPS:
        block(f"'aws {service} {op}' reads secrets, mints credentials or reads data-plane content")
    if service == "ssm" and op.startswith("get-"):
        block(f"'aws ssm {op}' may return SecureString values; use describe-parameters")
    if service == "logs" and op in {"filter-log-events", "start-query", "start-live-tail", "tail"}:
        block(f"'aws logs {op}' reads log content")
    if service == "dynamodb" and op in {"scan", "query", "execute-statement", "batch-execute-statement"}:
        block("DynamoDB data-plane reads are not allowed")
    if not (op.startswith(ALLOWED_PREFIXES) or op in ALLOWED_EXACT):
        block(f"'aws {service} {op}' is not a read-only verb (allowed: describe-/list-/get-/lookup-/search-)")
    if (service, op) in REQUIRE_QUERY:
        check_query(service, op, rest)
    if service == "ec2" and op == "describe-instance-attribute" and any("userdata" in a.lower() for a in rest):
        block("instance userData may contain secrets")


def check_awshealth(args, cmd):
    if "collect" in args:
        check_profile(args, cmd)


def check_env_dump(cmd, i):
    prog = os.path.basename(cmd[i]) if i < len(cmd) else ""
    args = cmd[i + 1:]
    if prog == "printenv":
        if not args or any(re.search(r"(?i)aws|secret|token|key|pass|cred", a) for a in args):
            block("printing environment variables is not allowed during the audit")
    if prog == "env" and all(a.startswith("-") or ASSIGN.match(a) for a in args):
        block("printing environment variables is not allowed during the audit")
    if prog == "set" and (not args or all(a in {"-o", "+o"} for a in args)):
        block("printing shell variables is not allowed during the audit")
    if prog in {"export", "declare", "typeset"} and (not args or any(a in {"-p", "-x", "-px", "-xp"} for a in args)):
        block("printing exported variables is not allowed during the audit")
    if prog == "compgen" and any(a in {"-e", "-v", "-A"} for a in args):
        block("listing environment variables is not allowed during the audit")


def scan(command, depth=0):
    if depth > 4:
        block("command nesting is too deep to verify")
    try:
        tokens = tokenize(command)
    except ValueError:
        if AWS_WORD.search(command) or "awshealth" in command:
            block("could not parse a command that calls aws")
        return
    if INDIRECT.search(command):
        block("indirect invocation of the aws CLI is not allowed")
    for cmd in split_simple(tokens):
        check_assignments(cmd)
        target, idx, prog_idx = find_invocation(cmd)
        check_env_dump(cmd, prog_idx)
        prog = os.path.basename(cmd[prog_idx]) if prog_idx < len(cmd) else ""
        if len(prog) > 1 and prog.startswith("$") and AWS_WORD.search(command):
            block("indirect invocation of the aws CLI is not allowed")
        if guard_active():
            tools = {prog} | ({os.path.basename(t) for t in cmd[prog_idx + 1:]} if prog in WRAPPERS else set())
            for net in sorted(tools & NETWORK_TOOLS):
                block(f"'{net}' is a network exfiltration channel and is blocked while AWSHEALTH_GUARD is set")
        if INTERPRETER.match(prog) and target is None:
            joined = " ".join(cmd[prog_idx + 1:])
            if INLINE_EXEC.search(joined) and AWS_WORD.search(joined):
                block("calling the aws CLI from an inline script is not allowed")
        if target == "aws":
            check_aws(cmd[idx + 1:], cmd)
        elif target == "awshealth":
            check_awshealth(cmd[idx + 1:], cmd)
        for n, t in enumerate(cmd):
            if " " in t or (n > 0 and cmd[n - 1] in {"-c", "eval"}):
                scan(t, depth + 1)


def check_command(command):
    if SECRET_PATHS.search(command):
        block("commands touching credential, key, state or .env files are not allowed")
    if METADATA_HOSTS.search(command):
        block("instance and container metadata endpoints can mint credentials and are not allowed")
    if ENV_REFS.search(command):
        block("printing AWS secrets or the whole environment is not allowed")
    if STATE_DUMPS.search(command):
        block("dumping infrastructure state can print secrets and is not allowed")
    if BOTO.search(command) and SCRIPTING.search(command):
        block("boto3/botocore scripts are not allowed; use awshealth or read-only aws CLI verbs")
    if "--show-secrets" in command:
        block("--show-secrets is not allowed")
    try:
        tokens = tokenize(command)
    except ValueError:
        tokens = []
    if any(SECRET_PATHS.search(t) or METADATA_HOSTS.search(t) for t in tokens):
        block("commands touching credential, key, state or .env files are not allowed")
    scan(command)


def expand(value):
    return os.path.expandvars(os.path.expanduser(value))


def check_path_tool(tool, ti):
    for key in ("file_path", "notebook_path", "path", "pattern", "glob"):
        v = ti.get(key)
        if v is None:
            continue
        if not isinstance(v, str):
            block(f"{tool} input {key} is not a string")
        if SECRET_PATHS.search(expand(v)) or SECRET_PATHS.search(v):
            block(f"{tool} on credential, key, state or .env files is not allowed")
    if tool == "Grep" and SECRET_CONTENT.search(str(ti.get("pattern") or "")):
        block("searching for secret material is not allowed")


def main():
    if not os.environ.get("AWSHEALTH_GUARD"):
        return
    raw = sys.stdin.read()
    data = json.loads(raw)
    if not isinstance(data, dict):
        block("hook input is not a JSON object")
    tool = data.get("tool_name")
    ti = data.get("tool_input")
    if not isinstance(tool, str) or not isinstance(ti, dict):
        block("hook input has no tool_name or tool_input")
    if tool in {"Read", "Grep", "Glob", "NotebookRead"}:
        check_path_tool(tool, ti)
        return
    if tool == "WebFetch":
        if guard_active():
            block("WebFetch is blocked while AWSHEALTH_GUARD is set; it is an exfiltration channel")
        return
    if tool not in {"Bash", "Monitor"}:
        return
    if tool == "Monitor" and ti.get("ws") is not None:
        if guard_active():
            block("Monitor WebSocket watches are blocked while AWSHEALTH_GUARD is set")
        return
    command = ti.get("command", "")
    if not isinstance(command, str):
        block("command is not a string")
    check_command(command)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:
        block(f"guard error, failing closed: {type(exc).__name__}")
    sys.exit(0)
