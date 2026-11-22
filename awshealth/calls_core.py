from .registry import call

IP_RANGES = call("aws", "IpRanges", keep="@", scope="global", paginate=False)
ENABLED_REGIONS = call("ec2", "DescribeRegions", keep="Regions[].RegionName", scope="home", paginate=False)
CALLER = call("sts", "GetCallerIdentity", keep="{account: Account, arn: Arn}", scope="home", paginate=False)
