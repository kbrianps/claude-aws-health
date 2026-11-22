from __future__ import annotations

import fnmatch
import json
from shlex import quote

from ..calls_security import ACCOUNT_BPA, BUCKET_BPA, BUCKET_POLICY, BUCKETS, as_list
from ..model import Claim, Finding
from ..registry import check

CHECK_ID = "s3-public-policy"
RESTRICTING = {"aws:sourceip", "aws:sourcevpce", "aws:sourcevpc", "aws:principalorgid", "aws:sourcearn",
               "aws:sourceaccount", "aws:principalaccount", "aws:principalarn", "aws:sourceorgid"}
SPOOFABLE = {"aws:referer", "aws:useragent"}
SENSITIVE_ACTIONS = ("s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket")


def _everyone(principal) -> bool:
    if principal == "*":
        return True
    return isinstance(principal, dict) and "*" in as_list(principal.get("AWS"))


def _condition_keys(statement) -> set[str]:
    return {k.lower() for op in (statement.get("Condition") or {}).values() if isinstance(op, dict) for k in op}


def _actions(statement) -> list[str]:
    patterns = [a.lower() for a in as_list(statement.get("Action"))]
    return [a for a in SENSITIVE_ACTIONS if any(fnmatch.fnmatchcase(a.lower(), p) for p in patterns)]


def public_statements(policy: dict) -> tuple[list[str], set[str]]:
    statements = as_list(policy.get("Statement"))
    for s in statements:
        if s.get("Effect") == "Deny" and _everyone(s.get("Principal")) and _condition_keys(s) & RESTRICTING:
            return [], set()
    actions, spoofable = [], set()
    for s in statements:
        if s.get("Effect") != "Allow" or not _everyone(s.get("Principal")):
            continue
        keys = _condition_keys(s)
        if keys & RESTRICTING:
            continue
        for a in _actions(s):
            if a not in actions:
                actions.append(a)
        spoofable |= keys & SPOOFABLE
    return actions, spoofable


def _restricted(cfg) -> bool:
    return isinstance(cfg, dict) and bool(cfg.get("RestrictPublicBuckets"))


@check(
    id=CHECK_ID,
    category="security",
    severity="high",
    title={"en": "S3 bucket policy grants access to everyone",
           "pt-BR": "Política do bucket S3 libera acesso para qualquer pessoa"},
    requires=[BUCKETS, BUCKET_POLICY, BUCKET_BPA, ACCOUNT_BPA],
    catalog_ids=["s3-public-buckets"],
)
def run(snap, ctx):
    if _restricted(snap.get(ACCOUNT_BPA)):
        return []
    bpa = snap.per_item(BUCKET_BPA, "global")
    findings = []
    for bucket, raw in snap.per_item(BUCKET_POLICY, "global").items():
        if not isinstance(raw, str) or _restricted(bpa.get(bucket)):
            continue
        try:
            policy = json.loads(raw)
        except ValueError:
            continue
        actions, spoofable = public_statements(policy)
        if not actions:
            continue
        acts = ", ".join(actions)
        if spoofable:
            keys = ", ".join(sorted(spoofable))
            cond_en = f" The only conditions are {keys}, which any client can set, so this is still public."
            cond_pt = f" As únicas condições são {keys}, que qualquer cliente consegue forjar, então continua público."
        else:
            cond_en = cond_pt = ""
        findings.append(Finding(
            check_id=CHECK_ID,
            resource=f"arn:aws:s3:::{bucket}",
            severity="high",
            category="security",
            region="global",
            text={
                "en": {
                    "title": f"Bucket {bucket} allows {acts} to anyone on the internet",
                    "what": f"The bucket policy of {bucket} has an Allow statement for Principal * covering {acts} "
                            "with no source IP, VPC endpoint, organization or source ARN condition, and Block "
                            f"Public Access does not restrict public buckets.{cond_en}",
                    "risk": "Anyone who knows or guesses the bucket name can read (or write) the objects. Data "
                            "exposure and unexpected transfer bills.",
                    "fix": "If the content must be public, serve it through CloudFront with Origin Access Control "
                           "and remove Principal * from the policy. Otherwise remove the statement and turn on "
                           "Block Public Access.",
                },
                "pt-BR": {
                    "title": f"O bucket {bucket} libera {acts} para qualquer pessoa na internet",
                    "what": f"A política do bucket {bucket} tem um Allow para Principal * em {acts}, sem condição de "
                            "IP de origem, VPC endpoint, organização ou ARN de origem, e o Block Public Access não "
                            f"restringe buckets públicos.{cond_pt}",
                    "risk": "Quem souber ou adivinhar o nome do bucket consegue ler (ou gravar) os objetos. "
                            "Vazamento de dados e conta de transferência inesperada.",
                    "fix": "Se o conteúdo precisa ser público, servir pelo CloudFront com Origin Access Control e "
                           "tirar o Principal * da política. Se não, remover a instrução e ligar o Block Public "
                           "Access.",
                },
            },
            claims=[
                Claim("s3:GetBucketPolicy@global", f"{bucket}.Statement[?Principal=='*'].Action", actions),
                Claim("s3:GetPublicAccessBlock@global", f"{bucket}.RestrictPublicBuckets",
                      bpa[bucket].get("RestrictPublicBuckets") if isinstance(bpa.get(bucket), dict) else None),
            ],
            owner_question={
                "en": f"Is {bucket} meant to be public, for example a static website?",
                "pt-BR": f"O bucket {bucket} deveria ser público, por exemplo um site estático?",
            },
            verify=[
                f"aws s3api get-bucket-policy-status --bucket {quote(bucket)} --region us-east-1 --query "
                "'PolicyStatus.IsPublic' --output text",
                f"aws s3api get-public-access-block --bucket {quote(bucket)} --region us-east-1 --query "
                "'PublicAccessBlockConfiguration' --output table",
                f"aws s3api get-bucket-policy --bucket {quote(bucket)} --region us-east-1 --query Policy --output text",
            ],
        ))
    return findings
