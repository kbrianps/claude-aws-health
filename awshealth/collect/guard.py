from __future__ import annotations

from collections.abc import Iterable

DENY_PREFIXES = (
    "Create", "Put", "Delete", "Update", "Modify", "Start", "Stop", "Terminate", "Reboot", "Run", "Attach", "Detach",
    "Associate", "Disassociate", "Tag", "Untag", "Enable", "Disable", "Register", "Deregister", "Invoke", "Send",
    "Publish", "Receive", "Purge", "Restore", "Copy", "Import", "Export", "Accept", "Reject", "Cancel", "Authorize",
    "Revoke", "Release", "Allocate", "Set", "Reset", "Replace", "Rotate", "Decrypt", "Encrypt", "Sign", "Assume",
)
DENY_NAMES = frozenset({
    "GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath", "GetObject",
    "GetFunction", "GetPasswordData", "GetConsoleOutput", "GetAuthorizationToken", "GetSessionToken",
    "GetFederationToken", "GetClusterCredentials", "GetTemplate", "GetLogEvents", "FilterLogEvents", "StartQuery",
    "GetQueryResults", "GetItem", "Query", "Scan", "ListApiKeys", "GetMetricWidgetImage",
})
DENY_PAIRS = frozenset({("cognito-idp", "ListUsers")})


class AllowlistViolation(Exception):
    pass


def is_denied(service: str, operation: str) -> bool:
    return operation.startswith(DENY_PREFIXES) or operation in DENY_NAMES or (service, operation) in DENY_PAIRS


class Guard:
    def __init__(self, allowed: Iterable[tuple[str, str]]):
        self.allowed = frozenset(allowed)
        self.unique_id = f"awshealth-allowlist-{id(self)}"

    def check(self, service: str, operation: str) -> None:
        if is_denied(service, operation):
            raise AllowlistViolation(f"{service}:{operation} is on the denylist")
        if (service, operation) not in self.allowed:
            raise AllowlistViolation(f"{service}:{operation} is not in the allowlist")

    def before_call(self, model, **kwargs) -> None:
        self.check(model.service_model.service_name, model.name)

    def install(self, events) -> None:
        events.register_first("before-call.*.*", self.before_call, unique_id=self.unique_id)
