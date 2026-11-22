PRICES_AS_OF = "2026-11-21"

PRICES = {
    "eks_cluster_standard_hour": {"usd": 0.10, "source": "https://aws.amazon.com/eks/pricing/"},
    "eks_cluster_extended_hour": {"usd": 0.60, "source": "https://aws.amazon.com/eks/pricing/"},
    "ebs_gp2_gb_month": {"usd": 0.10, "source": "https://aws.amazon.com/ebs/pricing/"},
    "ebs_gp3_gb_month": {"usd": 0.08, "source": "https://aws.amazon.com/ebs/pricing/"},
    "ebs_io1_gb_month": {"usd": 0.125, "source": "https://aws.amazon.com/ebs/pricing/"},
    "ebs_st1_gb_month": {"usd": 0.045, "source": "https://aws.amazon.com/ebs/pricing/"},
    "ebs_sc1_gb_month": {"usd": 0.015, "source": "https://aws.amazon.com/ebs/pricing/"},
    "ebs_standard_gb_month": {"usd": 0.05, "source": "https://aws.amazon.com/ebs/pricing/"},
    "ebs_snapshot_gb_month": {"usd": 0.05, "source": "https://aws.amazon.com/ebs/pricing/"},
    "public_ipv4_hour": {"usd": 0.005, "source": "https://aws.amazon.com/vpc/pricing/"},
    "nlb_hour": {"usd": 0.0225, "source": "https://aws.amazon.com/elasticloadbalancing/pricing/"},
    "alb_hour": {"usd": 0.0225, "source": "https://aws.amazon.com/elasticloadbalancing/pricing/"},
    "clb_hour": {"usd": 0.025, "source": "https://aws.amazon.com/elasticloadbalancing/pricing/"},
    "cloudwatch_logs_gb_month": {"usd": 0.03, "source": "https://aws.amazon.com/cloudwatch/pricing/"},
    "secretsmanager_secret_month": {"usd": 0.40, "source": "https://aws.amazon.com/secrets-manager/pricing/"},
    "rds_extended_support_vcpu_hour_y1": {"usd": 0.100, "source": "https://aws.amazon.com/rds/postgresql/pricing/"},
    "rds_extended_support_vcpu_hour_y3": {"usd": 0.200, "source": "https://aws.amazon.com/rds/postgresql/pricing/"},
}

HOURS_PER_MONTH = 730


def price(key: str) -> float:
    return PRICES[key]["usd"]


def source(key: str) -> str:
    return PRICES[key]["source"]
