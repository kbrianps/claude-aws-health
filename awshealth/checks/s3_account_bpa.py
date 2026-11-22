from __future__ import annotations

from shlex import quote

from ..calls_security import ACCOUNT_BPA, entry_error
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "s3-account-bpa"
FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


@check(
    id=CHECK_ID,
    category="security",
    severity="high",
    title={"en": "Account-level S3 Block Public Access is off",
           "pt-BR": "Block Public Access do S3 desligado no nível da conta"},
    requires=[ACCOUNT_BPA],
    catalog_ids=["s3-public-buckets"],
)
def run(snap, ctx):
    region = snap.home_region
    cfg = snap.get(ACCOUNT_BPA, region)
    if cfg is None:
        if "NoSuchPublicAccessBlockConfiguration" not in entry_error(snap, ACCOUNT_BPA, region):
            return []
        cfg = {}
    off = [f for f in FLAGS if not cfg.get(f)]
    if not off:
        return []
    account = ctx.account_id
    missing = not cfg
    severity = "high" if len(off) == len(FLAGS) else "medium"
    off_txt = ", ".join(off)
    what_en = ("The account has no S3 Block Public Access configuration." if missing
               else f"Account-level Block Public Access has these settings off: {off_txt}.")
    what_pt = ("A conta não tem configuração de Block Public Access do S3." if missing
               else f"O Block Public Access no nível da conta está com estas opções desligadas: {off_txt}.")
    return [Finding(
        check_id=CHECK_ID,
        resource=f"arn:aws:s3:{region}:{account}:account",
        severity=severity,
        category="security",
        region="global",
        text={
            "en": {
                "title": f"S3 Block Public Access is {'not configured' if missing else 'partly off'} for account "
                         f"{account}",
                "what": what_en,
                "risk": "Any bucket in the account can be made public by one policy or ACL change, with nothing at "
                        "the account level to stop it.",
                "fix": "Turn on all four settings at the account level. If one bucket must stay public, serve it "
                       "through CloudFront with Origin Access Control instead.",
            },
            "pt-BR": {
                "title": "O Block Public Access do S3 está "
                         f"{'sem configuração' if missing else 'parcialmente desligado'} na conta {account}",
                "what": what_pt,
                "risk": "Qualquer bucket da conta pode virar público com uma única mudança de política ou ACL, sem "
                        "nada no nível da conta para impedir.",
                "fix": "Ligar as quatro opções no nível da conta. Se um bucket precisa ser público, servir pelo "
                       "CloudFront com Origin Access Control.",
            },
        },
        claims=[Claim(f"s3control:GetPublicAccessBlock@{region}", f"PublicAccessBlockConfiguration.{f}",
                      cfg.get(f, False))
                for f in FLAGS],
        verify=[
            f"aws s3control get-public-access-block --account-id {quote(account)} --region {quote(region)} --query "
            "'PublicAccessBlockConfiguration' --output table",
        ],
    )]
