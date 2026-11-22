from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from typing import Any

from . import calls_compute as _cc
from .registry import call

_STMT = "{effect: Effect, action: Action, resource: Resource}"

ADDRESSES = _cc.ADDRESSES
ENI_PUBLIC_IPS = _cc.NETWORK_INTERFACES
ELBV2 = _cc.LOAD_BALANCERS
INSTANCES = _cc.INSTANCES
FUNCTIONS = _cc.FUNCTIONS
DB_INSTANCES = _cc.RDS_INSTANCES
GD_DETECTORS = _cc.GUARDDUTY_DETECTORS

HOSTED_ZONES = call("route53", "ListHostedZones",
                    keep="HostedZones[].{id: Id, name: Name, private: Config.PrivateZone}",
                    result_key="HostedZones", scope="global")
RECORD_SETS = call("route53", "ListResourceRecordSets",
                   keep="ResourceRecordSets[?AliasTarget || contains(['A', 'AAAA', 'CNAME'], Type)]"
                        ".{name: Name, type: Type, ttl: TTL, set_id: SetIdentifier, "
                        "values: ResourceRecords[].Value, alias: AliasTarget}",
                   result_key="ResourceRecordSets", scope="global",
                   per_item=("route53", "ListHostedZones", "[].id", "HostedZoneId"))
ELB_CLASSIC = call("elb", "DescribeLoadBalancers",
                   keep="LoadBalancerDescriptions[].{name: LoadBalancerName, dns: DNSName}",
                   result_key="LoadBalancerDescriptions")

BUCKETS = call("s3", "ListBuckets", keep="Buckets[].Name", result_key="Buckets", scope="global")
BUCKET_POLICY = call("s3", "GetBucketPolicy", keep="Policy", scope="global", paginate=False,
                     per_item=("s3", "ListBuckets", "[]", "Bucket"))
BUCKET_BPA = call("s3", "GetPublicAccessBlock", keep="PublicAccessBlockConfiguration", scope="global",
                  paginate=False, per_item=("s3", "ListBuckets", "[]", "Bucket"))
ACCOUNT_BPA = call("s3control", "GetPublicAccessBlock", keep="PublicAccessBlockConfiguration",
                   params={"AccountId": "{account}"}, scope="home", paginate=False)

AUTH_DETAILS = call(
    "iam", "GetAccountAuthorizationDetails",
    keep="{users: UserDetailList[].{name: UserName, arn: Arn, created: CreateDate, groups: GroupList, "
         "attached: AttachedManagedPolicies[].PolicyArn, "
         f"inline: UserPolicyList[].to_array(PolicyDocument.Statement)[].{_STMT}, tags: Tags}}, "
         "groups: GroupDetailList[].{name: GroupName, attached: AttachedManagedPolicies[].PolicyArn, "
         f"inline: GroupPolicyList[].to_array(PolicyDocument.Statement)[].{_STMT}}}, "
         "roles: RoleDetailList[].{name: RoleName, arn: Arn, path: Path, created: CreateDate, "
         "last_used: RoleLastUsed.LastUsedDate, attached: AttachedManagedPolicies[].PolicyArn, "
         f"inline: RolePolicyList[].to_array(PolicyDocument.Statement)[].{_STMT}, "
         "trust: to_array(AssumeRolePolicyDocument.Statement)[].{effect: Effect, principal: Principal, "
         "condition_keys: values(Condition || `{}`)[].keys(@)[]}, tags: Tags}, "
         "policies: Policies[?!contains(Arn, `:iam::aws:policy/`)].{arn: Arn, name: PolicyName, "
         f"statements: PolicyVersionList[?IsDefaultVersion] | [0].to_array(Document.Statement)[].{_STMT}}}}}",
    scope="global",
)
USERS = call("iam", "ListUsers",
             keep="Users[].{name: UserName, arn: Arn, created: CreateDate, password_last_used: PasswordLastUsed}",
             result_key="Users", scope="global")
ACCESS_KEYS = call("iam", "ListAccessKeys",
                   keep="AccessKeyMetadata[].{id: AccessKeyId, status: Status, created: CreateDate}",
                   result_key="AccessKeyMetadata", scope="global",
                   per_item=("iam", "ListUsers", "[].name", "UserName"))
KEY_LAST_USED = call("iam", "GetAccessKeyLastUsed",
                     keep="{user: UserName, last_used: AccessKeyLastUsed.LastUsedDate, "
                          "service: AccessKeyLastUsed.ServiceName}",
                     scope="global", paginate=False,
                     per_item=("iam", "ListAccessKeys", "values(@)[].id", "AccessKeyId"))
LOGIN_PROFILE = call("iam", "GetLoginProfile", keep="LoginProfile.{created: CreateDate}", scope="global",
                     paginate=False, per_item=("iam", "ListUsers", "[].name", "UserName"))
MFA_DEVICES = call("iam", "ListMFADevices", keep="length(MFADevices)", result_key="MFADevices", scope="global",
                   per_item=("iam", "ListUsers", "[].name", "UserName"))

GD_DETECTOR = call("guardduty", "GetDetector", keep="{status: Status}", paginate=False,
                   per_item=("guardduty", "ListDetectors", "[]", "DetectorId"))
CONFIG_RECORDERS = call("config", "DescribeConfigurationRecorderStatus",
                        keep="ConfigurationRecordersStatus[].{name: name, recording: recording, last: lastStatus}",
                        paginate=False)
ANALYZERS = call("accessanalyzer", "ListAnalyzers", keep="analyzers[].{name: name, type: type, status: status}",
                 result_key="analyzers")
SECURITY_HUB = call("securityhub", "DescribeHub", keep="{arn: HubArn}", paginate=False)
TRAILS = call("cloudtrail", "DescribeTrails",
              keep="trailList[].{name: Name, arn: TrailARN, multi: IsMultiRegionTrail, home: HomeRegion, "
                   "validation: LogFileValidationEnabled, org: IsOrganizationTrail}",
              scope="home", paginate=False)
TRAIL_STATUS = call("cloudtrail", "GetTrailStatus", keep="{logging: IsLogging}", scope="home", paginate=False,
                    per_item=("cloudtrail", "DescribeTrails", "[].arn", "Name"))

BACKUP_PLANS = call("backup", "ListBackupPlans", keep="BackupPlansList[].{id: BackupPlanId, name: BackupPlanName}",
                    result_key="BackupPlansList")
BACKUP_PLAN = call("backup", "GetBackupPlan", keep="BackupPlan.Rules[].TargetBackupVaultName", paginate=False,
                   per_item=("backup", "ListBackupPlans", "[].id", "BackupPlanId"))
BACKUP_SELECTIONS = call("backup", "ListBackupSelections",
                         keep="BackupSelectionsList[].{id: SelectionId, plan: BackupPlanId, name: SelectionName}",
                         result_key="BackupSelectionsList",
                         per_item=("backup", "ListBackupPlans", "[].id", "BackupPlanId"))
BACKUP_SELECTION = call("backup", "GetBackupSelection",
                        keep="{plan: BackupPlanId, id: SelectionId, name: BackupSelection.SelectionName, "
                             "resources: BackupSelection.Resources, not_resources: BackupSelection.NotResources, "
                             "list_of_tags: BackupSelection.ListOfTags, conditions: BackupSelection.Conditions}",
                        paginate=False,
                        per_item=("backup", "ListBackupSelections",
                                  "values(@)[].{BackupPlanId: plan, SelectionId: id}", "*"))
BACKUP_VAULTS = call("backup", "ListBackupVaults",
                     keep="BackupVaultList[].{name: BackupVaultName, recovery_points: NumberOfRecoveryPoints}",
                     result_key="BackupVaultList")
PROTECTED = call("backup", "ListProtectedResources",
                 keep="Results[].{arn: ResourceArn, type: ResourceType, last: LastBackupTime}", result_key="Results")
TAGGED_RESOURCES = call("resourcegroupstaggingapi", "GetResources",
                        keep="ResourceTagMappingList[].{arn: ResourceARN, tags: Tags}",
                        result_key="ResourceTagMappingList")
DYNAMO_TABLES = call("dynamodb", "ListTables", keep="TableNames", result_key="TableNames")
DYNAMO_PITR = call("dynamodb", "DescribeContinuousBackups",
                   keep="ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus",
                   paginate=False, per_item=("dynamodb", "ListTables", "[]", "TableName"))
EFS = call("efs", "DescribeFileSystems", keep="FileSystems[].{id: FileSystemId, arn: FileSystemArn, name: Name, "
                                             "tags: Tags}", result_key="FileSystems")

ALARMS = call("cloudwatch", "DescribeAlarms",
              keep="MetricAlarms[].{name: AlarmName, arn: AlarmArn, state: StateValue, updated: StateUpdatedTimestamp, "
                   "actions: AlarmActions, enabled: ActionsEnabled, treat_missing: TreatMissingData}",
              result_key="MetricAlarms")
TOPICS = call("sns", "ListTopics", keep="Topics[].TopicArn", result_key="Topics")
TOPIC_ATTRS = call("sns", "GetTopicAttributes",
                   keep="Attributes.{confirmed: SubscriptionsConfirmed, pending: SubscriptionsPending}",
                   paginate=False, per_item=("sns", "ListTopics", "[]", "TopicArn"))
RULES = call("events", "ListRules", keep="Rules[].{name: Name, arn: Arn, state: State}", result_key="Rules")
RULE_TARGETS = call("events", "ListTargetsByRule", keep="Targets[].{id: Id, arn: Arn}", result_key="Targets",
                    per_item=("events", "ListRules", "[?state=='ENABLED'].name", "Rule"))
QUEUES = call("sqs", "ListQueues", keep="QueueUrls", result_key="QueueUrls")
QUEUE_ATTRS = call("sqs", "GetQueueAttributes",
                   keep="Attributes.{redrive: RedrivePolicy, retention: MessageRetentionPeriod, arn: QueueArn}",
                   params={"AttributeNames": ["RedrivePolicy", "MessageRetentionPeriod", "QueueArn"]},
                   paginate=False, per_item=("sqs", "ListQueues", "[]", "QueueUrl"))
FUNCTION_URLS = call("lambda", "ListFunctionUrlConfigs",
                     keep="FunctionUrlConfigs[].{url: FunctionUrl, auth: AuthType, origins: Cors.AllowOrigins}",
                     result_key="FunctionUrlConfigs",
                     per_item=("lambda", "ListFunctions", "[].name", "FunctionName"))
SECRETS = call("secretsmanager", "ListSecrets",
               keep="SecretList[].{name: Name, arn: ARN, rotation: RotationEnabled, changed: LastChangedDate, "
                    "accessed: LastAccessedDate, created: CreatedDate, owner: OwningService, tags: Tags}",
               result_key="SecretList")
BUDGETS = call("budgets", "DescribeBudgets",
               keep="Budgets[].{name: BudgetName, type: BudgetType, unit: TimeUnit, limit: BudgetLimit.Amount}",
               params={"AccountId": "{account}"}, result_key="Budgets", scope="home")
BUDGET_HISTORY = call("budgets", "DescribeBudgetPerformanceHistory",
                      keep="BudgetPerformanceHistory.BudgetedAndActualAmountsList[].{budgeted: BudgetedAmount.Amount, "
                           "actual: ActualAmount.Amount, start: TimePeriod.Start}",
                      params={"AccountId": "{account}"}, scope="home", paginate=False,
                      per_item=("budgets", "DescribeBudgets", "[].name", "BudgetName"))
ANOMALY_MONITORS = call("ce", "GetAnomalyMonitors", keep="AnomalyMonitors[].{name: MonitorName, type: MonitorType}",
                        result_key="AnomalyMonitors", scope="home")

ADMIN_POLICY_ARN_SUFFIX = ":iam::aws:policy/AdministratorAccess"
BREAK_GLASS = re.compile(r"break[-_ ]?glass|emergency", re.I)
_PROD_WORD = re.compile(r"(^|[^a-z])(prod|production|prd)([^a-z]|$)", re.I)
_ENV_KEYS = {"env", "environment", "stage", "tier"}


def parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        d = value
    else:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def days_since(value: Any, now: datetime) -> int | None:
    d = parse_ts(value)
    return None if d is None else (now - d).days


def tag_dict(tags: Any) -> dict[str, str]:
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    return {t.get("Key", ""): t.get("Value", "") for t in tags or [] if isinstance(t, dict)}


def is_prod(tags: Any = None, *names: str) -> bool:
    for k, v in tag_dict(tags).items():
        if k.lower() in _ENV_KEYS and v.lower() in ("prod", "production", "prd"):
            return True
    return any(n and _PROD_WORD.search(n) for n in names)


def is_break_glass(name: str, tags: Any = None) -> bool:
    pairs = [f"{k}={v}" for k, v in tag_dict(tags).items()]
    return any(BREAK_GLASS.search(text) for text in [name or "", *pairs])


def entry_error(snap, c, region: str = "") -> str:
    r = "global" if c.scope == "global" else (region or snap.home_region)
    return (snap.data.get(c.key, {}).get(r) or {}).get("error", "")


def per_item_error(value: Any) -> str:
    return value.get("__error__", "") if isinstance(value, dict) else ""


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def full_access(statements: Any) -> bool:
    for s in as_list(statements):
        if not isinstance(s, dict) or s.get("effect") != "Allow":
            continue
        if "*" in as_list(s.get("action")) and "*" in as_list(s.get("resource")):
            return True
    return False


def admin_policy_arns(auth: dict[str, Any]) -> set[str]:
    return {p["arn"] for p in auth.get("policies") or [] if full_access(p.get("statements"))}


def admin_reason(entity: dict[str, Any], admin_arns: set[str], groups: dict[str, dict[str, Any]] | None = None) -> str:
    for arn in entity.get("attached") or []:
        if arn.endswith(ADMIN_POLICY_ARN_SUFFIX) or arn in admin_arns:
            return f"policy {arn.split('/')[-1]}"
    if full_access(entity.get("inline")):
        return "inline policy with Action * on Resource *"
    for g in entity.get("groups") or []:
        grp = (groups or {}).get(g)
        if grp and admin_reason(grp, admin_arns):
            return f"group {g}"
    return ""


def iam_admins(auth: dict[str, Any]) -> dict[str, str]:
    admin_arns = admin_policy_arns(auth)
    groups = {g["name"]: g for g in auth.get("groups") or []}
    out = {}
    for u in auth.get("users") or []:
        reason = admin_reason(u, admin_arns, groups)
        if reason:
            out[u["name"]] = reason
    return out


_BACKUP_TYPES = re.compile(
    r"^arn:aws[a-z-]*:(?:rds:[^:]*:\d*:(?:db|cluster):|dynamodb:[^:]*:\d*:table/|elasticfilesystem:[^:]*:\d*:file-system/"
    r"|ec2:[^:]*:\d*:(?:volume|instance)/|fsx:[^:]*:\d*:file-system/|redshift:[^:]*:\d*:cluster:|s3:::[^/]+$)")


def backup_supported(arn: str) -> bool:
    return bool(_BACKUP_TYPES.match(arn or ""))


def tag_key(condition_key: str) -> str:
    return condition_key.split("/", 1)[1] if condition_key.lower().startswith("aws:resourcetag/") else condition_key


def _arn_match(patterns: Any, arn: str) -> bool:
    return any(fnmatch.fnmatchcase(arn, p) for p in as_list(patterns))


def _condition_ok(op: str, actual: str | None, want: str) -> bool:
    if op == "StringEquals":
        return actual == want
    if op == "StringNotEquals":
        return actual != want
    if op == "StringLike":
        return actual is not None and fnmatch.fnmatchcase(actual, want)
    if op == "StringNotLike":
        return actual is None or not fnmatch.fnmatchcase(actual, want)
    return False


def selection_matches(sel: dict[str, Any], arn: str, tags: Any) -> bool:
    tags = tag_dict(tags)
    if _arn_match(sel.get("not_resources"), arn):
        return False
    resources, list_of_tags = as_list(sel.get("resources")), as_list(sel.get("list_of_tags"))
    if resources or list_of_tags:
        by_tag = any(tags.get(tag_key(t.get("ConditionKey", ""))) == t.get("ConditionValue") for t in list_of_tags)
        if not (_arn_match(resources, arn) or by_tag):
            return False
    for op, conditions in (sel.get("conditions") or {}).items():
        for c in as_list(conditions):
            if not _condition_ok(op, tags.get(tag_key(c.get("ConditionKey", ""))), c.get("ConditionValue", "")):
                return False
    return True


def wanted_tags(sel: dict[str, Any]) -> list[tuple[str, str]]:
    out = [(tag_key(t.get("ConditionKey", "")), t.get("ConditionValue", "")) for t in as_list(sel.get("list_of_tags"))]
    for op in ("StringEquals", "StringLike"):
        out += [(tag_key(c.get("ConditionKey", "")), c.get("ConditionValue", ""))
                for c in as_list((sel.get("conditions") or {}).get(op))]
    return out


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def near_miss(want_key: str, want_value: str, tags: Any) -> str:
    for k, v in tag_dict(tags).items():
        if k == want_key:
            if v != want_value and v.lower() == want_value.lower():
                return f"{k}={v}"
            continue
        if k.lower() == want_key.lower() or (len(want_key) >= 5 and edit_distance(k.lower(), want_key.lower()) <= 2):
            return f"{k}={v}"
    return ""
