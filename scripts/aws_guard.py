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
    "get-cluster-credentials", "get-cluster-credentials-with-iam", "list-api-keys", "describe-user-pool-client",
    "describe-configuration-settings",
    "get-knowledge-base-documents", "get-query-execution", "get-execution-history", "describe-execution",
    "get-data-access", "export-credentials", "get-metric-widget-image", "get-launch-template-data",
    "get-vpn-connection-device-sample-configuration", "get-file", "get-blob", "get-folder",
    "get-download-url-for-layer", "get-job-output", "get-primary-email", "get-alternate-contact",
    "get-contact-information", "get-signin-token", "get-access-token",
    "get-relational-database-master-user-password", "get-instance-access", "get-web-identity-token",
    "get-statement-result", "get-statement-result-v2", "get-hls-streaming-session-url",
    "get-dash-streaming-session-url", "get-clip", "get-activity-task", "get-usage-plan-keys",
}
SERVICE_BLOCKED_OPS = {("cognito-idp", "list-users"), ("cognito-idp", "list-users-in-group")}
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
    ("codebuild", "batch-get-builds"): "",
    ("batch", "describe-jobs"): "|container|properties|parameters",
    ("ecs", "describe-tasks"): "|overrides",
    ("sagemaker", "describe-processing-job"): "|appspecification",
    ("ec2", "describe-spot-instance-requests"): "|launchspecification",
    ("ec2", "describe-spot-fleet-requests"): r"|launchspecification|spotfleetrequestconfig(?!\w|\s*\.)",
    ("emr", "list-instance-groups"): "|configurations",
    ("cloudfront", "list-distributions"): "|customheaders|origins",
    ("cloudfront", "get-distribution"): "|customheaders|origins",
    ("cloudfront", "get-distribution-config"): "|customheaders|origins",
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
    "script", "chronic", "unbuffer", "setsid", "caffeinate", "systemd-run", "builtin", "coproc", "find",
}
STDIN_ARG_WRAPPERS = {"xargs", "parallel"}
INTERPRETER = re.compile(r"^(python[\d.]*|ipython[\d.]*|pypy[\d.]*|node|nodejs|deno|bun|ruby|perl|php)$")
NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "scp", "http", "https", "xh",
                 "ssh", "rsync", "dig", "nslookup", "host"}
GIT_NETWORK_VERBS = {"push", "pull", "fetch", "clone", "remote", "ls-remote", "send-email", "submodule"}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
ALLOWED_AWS_ENV = {"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PAGER", "AWS_DEFAULT_OUTPUT", "AWS_MAX_ATTEMPTS",
                   "AWS_RETRY_MODE"}
PROFILE_ENV = {"AWS_PROFILE", "AWS_DEFAULT_PROFILE"}
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?(\+?)=(.*)$", re.S)
AWS_WORD = re.compile(r"(?<![\w.-])aws(?![\w.-])")
LB = r"(?:^|[\s/~\"'=:(<>])"
RB = r"(?=$|[\s/\"';|&)<>*])"
SECRET_PATHS = re.compile(
    rf"(?i){LB}\.aws{RB}"
    r"|\.tfstate|\.tfvars"
    rf"|{LB}\.env(?:\.(?!example|sample|template|dist)[\w.-]+)?{RB}"
    rf"|{LB}\.envrc{RB}"
    rf"|{LB}\.ssh/"
    r"|id_(?:rsa|dsa|ecdsa|ed25519)"
    rf"|[\w-]\.(?:pem|p12|pfx|ppk|jks|keystore){RB}"
    rf"|priv(?:ate)?[_-]?key[\w-]*\.\w+{RB}"
    r"|/proc/\S*(?:environ|[*?\[])"
    rf"|/proc/(?:self|thread-self|\d+)(?:/task/\d+)?/?{RB}"
)
SECRET_CONTENT = re.compile(r"(?i)aws_secret_access_key|aws_session_token|aws_security_token|private key-----"
                            r"|BEGIN [A-Z ]*PRIVATE KEY")
METADATA_HOSTS = re.compile(r"169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|instance-data(?:\.ec2\.internal)?\b")
ENV_REFS = re.compile(r"\$\{?AWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN)|\bAWS_SECRET_ACCESS_KEY\b"
                      r"|\bAWS_SESSION_TOKEN\b|os\.environ(?![\[.\w])|os\.environ\.(?:items|copy|values)\b"
                      r"|process\.env(?![.\[\w])|\bENV\.to_h\b|\$\{!|\bENVIRON\b")
STATE_DUMPS = re.compile(r"\bterraform\s+(?:state\s+pull|show|output)\b|\bpulumi\s+stack\s+export\b")
BOTO = re.compile(r"\b(?:boto3|botocore|aiobotocore)\b")
SCRIPTING = re.compile(r"\b(?:python[\d.]*|ipython|pypy[\d.]*|uv\s+run|poetry\s+run|pdm\s+run)\b|<<")
INLINE_EXEC = re.compile(r"subprocess|os\.system|os\.popen|os\.exec|child_process|execSync|spawnSync|\bsystem\s*\(|`")
PY_HEREDOC = re.compile(r"\b(?:python[\d.]*|ipython[\d.]*|pypy[\d.]*)\b[^\n;|&]*<<")
ONE_LINER_ENV = re.compile(r"\benviron\b|\bENV\b|\bprocess\s*\[|\.env\b(?!\s*\.\s*[A-Za-z_])")
NET_LIBS = re.compile(r"\burllib\d?\b|\brequests\b|\bhttpx\b|\baiohttp\b|\bsocket\b|\bhttp\.(?:client|server)\b"
                      r"|\b(?:from|import)\s+http\b|\b(?:ftplib|smtplib|telnetlib|xmlrpc)\b|\bfetch\s*\("
                      r"|require\s*\(\s*['\"](?:node:)?(?:https?|net|dgram|tls)['\"]|IO::Socket|\bLWP\b|Net::HTTP"
                      r"|open-uri|TCPSocket")
DEV_SOCKETS = re.compile(r"/dev/(?:tcp|udp)/")
OBFUSCATED_WORD = re.compile(r"[$*?\[{`]")
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


def is_separator(tok):
    return tok in SEPARATORS or (tok != "" and set(tok) <= set(";|&()"))


def split_simple(tokens):
    out, cur = [], []
    for t in tokens:
        if is_separator(t):
            if cur:
                out.append((cur, t))
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append((cur, ""))
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


def wrapped_word(cmd, i):
    for t in cmd[i + 1:]:
        if t.startswith("-") or ASSIGN.match(t) or re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", t):
            continue
        return t
    return ""


def git_verb(args):
    n = 0
    while n < len(args):
        a = args[n]
        if not a.startswith("-"):
            return a
        n += 2 if a in GIT_OPTS_WITH_VALUE else 1
    return ""


def check_command_word(cmd, prog_idx, sep):
    if prog_idx >= len(cmd):
        return
    word = cmd[prog_idx]
    if len(cmd) == 1 and sep.startswith(")"):
        return
    words = [word] + ([wrapped_word(cmd, prog_idx)] if os.path.basename(word) in WRAPPERS else [])
    for w in words:
        if w not in {"[", "[["} and OBFUSCATED_WORD.search(w):
            block(f"command name {w!r} uses expansion or globbing; write the command name literally")


def check_network(cmd, prog_idx, prog):
    names = [prog] + ([os.path.basename(t) for t in cmd[prog_idx + 1:]] if prog in WRAPPERS else [])
    for net in sorted(set(names) & NETWORK_TOOLS):
        block(f"'{net}' is a network exfiltration channel and is blocked while AWSHEALTH_GUARD is set")
    if "git" in names:
        g = prog_idx if prog == "git" else prog_idx + 1 + names[1:].index("git")
        verb = git_verb(cmd[g + 1:])
        if verb in GIT_NETWORK_VERBS:
            block(f"'git {verb}' talks to a remote and is blocked while AWSHEALTH_GUARD is set")


def check_interpreter(cmd, prog_idx, command):
    args = cmd[prog_idx + 1:]
    joined = " ".join(args)
    if INLINE_EXEC.search(joined) and AWS_WORD.search(joined):
        block("calling the aws CLI from an inline script is not allowed")
    one_liner = any(re.fullmatch(r"-[A-Za-z]*[cep]|-r|--eval|--print", a) for a in args)
    reads_stdin = not [a for a in args if not a.startswith("-")] or "-" in args
    text = joined if one_liner or "-m" in args else command if reads_stdin else ""
    if ONE_LINER_ENV.search(text):
        block("reading the environment from an inline script is not allowed during the audit")
    if NET_LIBS.search(text):
        block("network libraries in inline scripts are blocked while AWSHEALTH_GUARD is set")


def abbreviates(arg, name):
    flag = arg.split("=", 1)[0]
    return flag.startswith("--") and len(flag) >= 3 and name.startswith(flag)


def takes_value(arg):
    return "=" not in arg and any(abbreviates(arg, o) for o in OPTS_WITH_VALUE)


def option_values(args, name):
    vals = []
    for n, a in enumerate(args):
        if not abbreviates(a, name):
            continue
        if "=" in a:
            vals.append(a.split("=", 1)[1])
        else:
            vals.append(args[n + 1] if n + 1 < len(args) else "")
    return vals


def check_assignments(cmd):
    for t in cmd:
        m = ASSIGN.match(t)
        if not m:
            continue
        name, append, value = m.group(1), m.group(2), m.group(3)
        if target_of(value.strip()) == "aws" or AWS_WORD.fullmatch(value.strip()):
            block("aliasing the aws CLI through a variable is not allowed")
        if not name.startswith("AWS_") or name in ALLOWED_AWS_ENV:
            continue
        if name in PROFILE_ENV:
            if append or value != allowed_profile():
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
    inline = [ASSIGN.match(t).group(3) for t in cmd if ASSIGN.match(t) and ASSIGN.match(t).group(1) in PROFILE_ENV]
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
        if any(c in q for c in "\"\\$"):
            block(f"the --query for 'aws {service} {op}' may not use quoted identifiers, backslashes or variables")
        if banned.search(q) or "@" in q or "*" in q or re.search(r"\b(?:values|to_string|to_array|merge)\s*\(", q):
            block(f"the --query for 'aws {service} {op}' could return secret-bearing fields")
        if not re.search(r"\]\s*\.\s*[A-Za-z{\[]|\{", q):
            block(f"the --query for 'aws {service} {op}' must select named fields, for example Items[].Name")


def operation_of(rest):
    n = 0
    while n < len(rest):
        a = rest[n]
        if a.startswith("-"):
            n += 2 if takes_value(a) else 1
            continue
        return a
    return None


def check_aws(args, cmd):
    for a in args:
        flag = a.split("=", 1)[0]
        if flag in FORBIDDEN_FLAGS:
            block(f"flag {flag} is not allowed during the audit")
        for full in sorted(FORBIDDEN_FLAGS | {"--profile"}):
            if flag != full and abbreviates(a, full):
                block(f"abbreviated flag {flag} is not allowed; write the full option name")
    check_profile(args, cmd)
    k = 0
    while k < len(args) and args[k].startswith("-"):
        k += 2 if takes_value(args[k]) else 1
    if k >= len(args):
        if "--version" in args:
            return
        block("'aws' without a service and operation is not allowed")
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
    if op in BLOCKED_OPS or (service, op) in SERVICE_BLOCKED_OPS:
        block(f"'aws {service} {op}' reads secrets, mints credentials or reads data-plane content")
    if service == "ssm" and op.startswith("get-"):
        block(f"'aws ssm {op}' may return SecureString values; use describe-parameters")
    if (service, op) == ("ssm", "list-command-invocations") and any(abbreviates(a, "--details") for a in rest):
        block("'aws ssm list-command-invocations --details' returns command output")
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
        if not args or any(a.startswith("-") or re.search(r"(?i)aws|secret|token|key|pass|cred", a) for a in args):
            block("printing environment variables is not allowed during the audit")
    if prog == "env":
        for a in args:
            if a.startswith("-"):
                block("env options are not allowed during the audit")
            if not ASSIGN.match(a):
                break
        else:
            block("printing environment variables is not allowed during the audit")
    if prog == "set" and (not args or all(a in {"-o", "+o"} for a in args)):
        block("printing shell variables is not allowed during the audit")
    if prog in {"export", "declare", "typeset"} and (not args or any(a in {"-p", "-x", "-px", "-xp"} for a in args)):
        block("printing exported variables is not allowed during the audit")
    if prog == "compgen" and any(a in {"-e", "-v", "-A"} for a in args):
        block("listing environment variables is not allowed during the audit")


def scan(command, depth=0, executed=True):
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
    for n_cmd, (cmd, sep) in enumerate(split_simple(tokens)):
        check_assignments(cmd)
        target, idx, prog_idx = find_invocation(cmd)
        check_env_dump(cmd, prog_idx)
        if executed or n_cmd > 0:
            check_command_word(cmd, prog_idx, sep)
        prog = os.path.basename(cmd[prog_idx]) if prog_idx < len(cmd) else ""
        check_network(cmd, prog_idx, prog)
        if INTERPRETER.match(prog) and target is None:
            check_interpreter(cmd, prog_idx, command)
        if target and any("$" in a or "`" in a for a in cmd[idx + 1:]):
            block(f"variables and command substitution in {target} arguments are not allowed; write the values out")
        if target and prog in STDIN_ARG_WRAPPERS:
            block(f"running {target} through {prog} adds arguments the guard cannot see")
        if target == "aws":
            check_aws(cmd[idx + 1:], cmd)
        elif target == "awshealth":
            check_awshealth(cmd[idx + 1:], cmd)
        for n, t in enumerate(cmd):
            runs = (n > 0 and cmd[n - 1] in {"-c", "eval"}) or (prog == "watch" and n > prog_idx)
            if " " in t or runs:
                scan(t, depth + 1, runs)


def check_command(command):
    if "$'" in command:
        block("ANSI-C quoting ($'...') can hide command names and paths; write the text literally")
    if DEV_SOCKETS.search(command):
        block("/dev/tcp and /dev/udp are network channels and are blocked while AWSHEALTH_GUARD is set")
    if PY_HEREDOC.search(command) and (ONE_LINER_ENV.search(command) or NET_LIBS.search(command)):
        block("the inline Python script reads the environment or uses the network")
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
    if tool in {"Read", "Grep", "Glob", "NotebookRead", "Write", "Edit", "MultiEdit", "NotebookEdit"}:
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
