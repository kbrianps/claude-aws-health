from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .prices import price
from .registry import call

VOLUMES = call(
    "ec2", "DescribeVolumes",
    keep="Volumes[].{id: VolumeId, state: State, size: Size, type: VolumeType, iops: Iops, throughput: Throughput, "
         "created: CreateTime, attachments: Attachments[].InstanceId, tags: Tags}",
    result_key="Volumes",
)
SNAPSHOTS = call(
    "ec2", "DescribeSnapshots",
    params={"OwnerIds": ["self"]},
    keep="Snapshots[].{id: SnapshotId, volume: VolumeId, size: VolumeSize, start: StartTime, tier: StorageTier, "
         "aws_backup: contains(Description || '', 'created by the AWS Backup service'), tags: Tags}",
    result_key="Snapshots",
)
IMAGES = call(
    "ec2", "DescribeImages",
    params={"Owners": ["self"], "IncludeDeprecated": True, "IncludeDisabled": True},
    keep="Images[].{id: ImageId, snapshots: BlockDeviceMappings[].Ebs.SnapshotId}",
    result_key="Images",
)
ADDRESSES = call(
    "ec2", "DescribeAddresses",
    keep="Addresses[].{ip: PublicIp, allocation: AllocationId, association: AssociationId, instance: InstanceId, "
         "eni: NetworkInterfaceId, pool: PublicIpv4Pool, tags: Tags}",
    paginate=False,
)
INSTANCES = call(
    "ec2", "DescribeInstances",
    keep="Reservations[].Instances[].{id: InstanceId, state: State.Name, reason: StateTransitionReason, "
         "type: InstanceType, public_ip: PublicIpAddress, volumes: BlockDeviceMappings[].Ebs.VolumeId, tags: Tags}",
    result_key="Reservations",
)
NETWORK_INTERFACES = call(
    "ec2", "DescribeNetworkInterfaces",
    keep="NetworkInterfaces[].{id: NetworkInterfaceId, type: InterfaceType, public_ip: Association.PublicIp, "
         "ip_owner: Association.IpOwnerId, requester_managed: RequesterManaged, description: Description, "
         "instance: Attachment.InstanceId, groups: Groups[].GroupId}",
    result_key="NetworkInterfaces",
)
SECURITY_GROUPS = call(
    "ec2", "DescribeSecurityGroups",
    keep="SecurityGroups[].{id: GroupId, name: GroupName, vpc: VpcId, ingress: IpPermissions[].{proto: IpProtocol, "
         "from: FromPort, to: ToPort, v4: IpRanges[].CidrIp, v6: Ipv6Ranges[].CidrIpv6}}",
    result_key="SecurityGroups",
)
LOAD_BALANCERS = call(
    "elbv2", "DescribeLoadBalancers",
    keep="LoadBalancers[].{arn: LoadBalancerArn, name: LoadBalancerName, dns: DNSName, type: Type, scheme: Scheme, "
         "state: State.Code, created: CreatedTime}",
    result_key="LoadBalancers",
)
TARGET_GROUPS = call(
    "elbv2", "DescribeTargetGroups",
    keep="TargetGroups[].{arn: TargetGroupArn, name: TargetGroupName, type: TargetType, lbs: LoadBalancerArns}",
    result_key="TargetGroups",
)
TARGET_HEALTH = call(
    "elbv2", "DescribeTargetHealth",
    keep="TargetHealthDescriptions[].{id: Target.Id, state: TargetHealth.State}",
    paginate=False,
    per_item=("elbv2", "DescribeTargetGroups", "[].arn", "TargetGroupArn"),
)
LISTENERS = call(
    "elbv2", "DescribeListeners",
    keep="Listeners[].{port: Port, protocol: Protocol, actions: DefaultActions[].Type}",
    result_key="Listeners",
    per_item=("elbv2", "DescribeLoadBalancers", "[].arn", "LoadBalancerArn"),
)
LOG_GROUPS = call(
    "logs", "DescribeLogGroups",
    keep="logGroups[].{name: logGroupName, arn: arn, retention: retentionInDays, bytes: storedBytes}",
    result_key="logGroups",
)
FUNCTIONS = call(
    "lambda", "ListFunctions",
    keep="Functions[].{name: FunctionName, arn: FunctionArn, runtime: Runtime, modified: LastModified}",
    result_key="Functions",
)
RDS_INSTANCES = call(
    "rds", "DescribeDBInstances",
    keep="DBInstances[].{id: DBInstanceIdentifier, arn: DBInstanceArn, engine: Engine, version: EngineVersion, "
         "cls: DBInstanceClass, cluster: DBClusterIdentifier, lifecycle: EngineLifecycleSupport, "
         "encrypted: StorageEncrypted, multi_az: MultiAZ, retention: BackupRetentionPeriod, "
         "public: PubliclyAccessible, deletion_protection: DeletionProtection, "
         "replica_of: ReadReplicaSourceDBInstanceIdentifier, tags: TagList}",
    result_key="DBInstances",
)
RDS_CLUSTERS = call(
    "rds", "DescribeDBClusters",
    keep="DBClusters[].{id: DBClusterIdentifier, arn: DBClusterArn, engine: Engine, version: EngineVersion, "
         "mode: EngineMode, lifecycle: EngineLifecycleSupport, encrypted: StorageEncrypted, multi_az: MultiAZ, "
         "retention: BackupRetentionPeriod, deletion_protection: DeletionProtection, "
         "members: DBClusterMembers[].DBInstanceIdentifier, tags: TagList}",
    result_key="DBClusters",
)
RDS_MAJOR_VERSIONS = call(
    "rds", "DescribeDBMajorEngineVersions",
    keep="DBMajorEngineVersions[].{engine: Engine, major: MajorEngineVersion, "
         "lifecycles: SupportedEngineLifecycles[].{name: LifecycleSupportName, start: LifecycleSupportStartDate, "
         "end: LifecycleSupportEndDate}}",
    result_key="DBMajorEngineVersions",
)
CERTIFICATES = call(
    "acm", "ListCertificates",
    params={"Includes": {"keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1",
                                      "EC_secp384r1", "EC_secp521r1"]}},
    keep="CertificateSummaryList[].{arn: CertificateArn, domain: DomainName, type: Type, status: Status, "
         "not_after: NotAfter, in_use: InUse, renewal: RenewalEligibility}",
    result_key="CertificateSummaryList",
)
CACHE_UPDATE_ACTIONS = call(
    "elasticache", "DescribeUpdateActions",
    params={"UpdateActionStatus": ["not-applied", "waiting-to-start", "in-progress"]},
    keep="UpdateActions[].{update: ServiceUpdateName, severity: ServiceUpdateSeverity, status: UpdateActionStatus, "
         "apply_by: ServiceUpdateRecommendedApplyByDate, sla_met: SlaMet, group: ReplicationGroupId, "
         "cluster: CacheClusterId, engine: Engine}",
    result_key="UpdateActions",
)
ECS_CLUSTERS = call("ecs", "ListClusters", keep="clusterArns", result_key="clusterArns")
GUARDDUTY_DETECTORS = call("guardduty", "ListDetectors", keep="DetectorIds", result_key="DetectorIds")

EBS_PRICE_KEYS = {
    "gp2": "ebs_gp2_gb_month",
    "gp3": "ebs_gp3_gb_month",
    "io1": "ebs_io1_gb_month",
    "st1": "ebs_st1_gb_month",
    "sc1": "ebs_sc1_gb_month",
    "standard": "ebs_standard_gb_month",
}

PROD_VALUES = {"prod", "production", "prd"}
NONPROD_VALUES = {"staging", "stage", "stg", "dev", "development", "test", "testing", "qa", "sandbox", "uat"}
ENV_KEYS = {"env", "environment", "stage", "tier"}


def ebs_gb_month(volume_type: str | None) -> float | None:
    key = EBS_PRICE_KEYS.get(volume_type or "")
    return price(key) if key else None


def tag_map(tags: Any) -> dict[str, str]:
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    return {t.get("Key", ""): t.get("Value", "") for t in tags or [] if isinstance(t, dict)}


def env_of(tags: Any) -> str | None:
    for k, v in tag_map(tags).items():
        if k.lower() not in ENV_KEYS:
            continue
        if v.lower() in PROD_VALUES:
            return "prod"
        if v.lower() in NONPROD_VALUES:
            return "nonprod"
    return None


def parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        d = value
    elif isinstance(value, (int, float)):
        d = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    else:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
