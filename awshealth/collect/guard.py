from __future__ import annotations

from collections.abc import Iterable

READ_PREFIXES = ("Describe", "List", "Get", "Search", "Lookup", "BatchGet")
READ_NAMES = frozenset({"GenerateCredentialReport"})
PSEUDO_CALLS = frozenset({("aws", "IpRanges")})
DENY_NAMES = frozenset({
    "GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath",
    "GetParameterHistory", "GetObject", "GetFunction", "GetFunctionConfiguration", "GetPasswordData",
    "GetConsoleOutput", "GetAuthorizationToken", "GetSessionToken", "GetFederationToken", "GetClusterCredentials",
    "GetClusterCredentialsWithIAM", "GetTemplate", "GetLogEvents", "FilterLogEvents", "StartQuery",
    "GetQueryResults", "GetItem", "BatchGetItem", "Query", "Scan", "ExecuteStatement", "SelectObjectContent",
    "ListApiKeys", "GetMetricWidgetImage", "GetDownloadUrlForLayer", "GetRoleCredentials",
    "GetCredentialsForIdentity", "GetCredentials", "GenerateDataKey", "GetRelationalDatabaseMasterUserPassword",
    "GetInstanceAccess", "GetWebIdentityToken", "GetLaunchTemplateData", "GetHLSStreamingSessionURL",
    "GetActivityTask", "GetStatementResult", "GetUsagePlanKeys",
    "GetApiKey", "GetApiKeys", "GetDecryptedAPIKey", "GetResourceApiKey", "GetLayerVersion", "GetLayerVersionByArn",
    "GetJobOutput", "GetObjectTorrent", "GetConsoleScreenshot", "GetRawMessageContent", "GetArchiveMessageContent",
    "GetDocumentContent", "GetLogRecord", "GetLogObject", "GetContainerLog", "GetRelationalDatabaseLogEvents",
    "GetSystemLogsForJobRun", "GetSystemLogsForSession", "GetAttachmentDownloadLink", "GetBucketAccessKeys",
    "GetStreamKey", "GetChallengePassword", "GetScopedCredentials", "GetDelegatedAccessToken",
    "GetEnvironmentCredentials", "GetClusterSessionCredentials", "GetManagedEndpointSessionCredentials",
    "GetSpaceCredentialsForOrganization", "GetTemporaryDataLocationCredentials", "GetTemporaryGlueFunctionCredentials",
    "GetTemporaryGluePartitionCredentials", "GetTemporaryGlueTableCredentials", "GetComputeAccess",
    "GetComputeAuthToken", "GetIdentityCenterAuthToken", "GetAccessToken", "GetClientToken", "GetDerivedToken",
    "GetTokensFromRefreshToken", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity", "GetWorkloadAccessToken",
    "GetWorkloadAccessTokenForJWT", "GetWorkloadAccessTokenForUserId", "GetResourceOauth2Token",
})
DENY_PAIRS = frozenset({("cognito-idp", "ListUsers")})


class AllowlistViolation(Exception):
    pass


def is_read(service: str, operation: str) -> bool:
    return (service, operation) in PSEUDO_CALLS or operation in READ_NAMES or operation.startswith(READ_PREFIXES)


def is_denied(service: str, operation: str) -> bool:
    return not is_read(service, operation) or operation in DENY_NAMES or (service, operation) in DENY_PAIRS


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
