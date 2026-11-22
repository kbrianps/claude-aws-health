from awshealth.calls_compute import CERTIFICATES
from awshealth.testing import run_one, snap_with


def cert(name, not_after, in_use=True, ctype="AMAZON_ISSUED", status="ISSUED", renewal="ELIGIBLE"):
    return {"arn": f"arn:aws:acm:us-east-1:111122223333:certificate/{name}", "domain": f"{name}.example.com",
            "type": ctype, "status": status, "not_after": not_after, "in_use": in_use, "renewal": renewal}


def snap(*certs):
    return snap_with({CERTIFICATES: {"us-east-1": list(certs)}})


def test_in_use_amazon_cert_expiring_is_medium_and_imported_is_high():
    found = {f.resource.rsplit("/", 1)[1]: f for f in run_one("acm-expiry", snap(
        cert("api", "2026-02-14T12:00:00Z"), cert("legacy", "2026-02-14T12:00:00Z", ctype="IMPORTED",
                                                   renewal="INELIGIBLE")))}
    assert found["api"].severity == "medium"
    assert "30 days" in found["api"].t("title")
    assert found["api"].deadline.startswith("2026-02-14")
    assert found["legacy"].severity == "high"
    assert "never renews imported" in found["legacy"].t("fix")
    assert "importado" in found["legacy"].t("what", "pt-BR")


def test_unused_expiring_cert_is_quiet_and_expired_unused_is_low_cleanup():
    assert run_one("acm-expiry", snap(cert("spare", "2026-02-01T00:00:00Z", in_use=False))) == []
    [f] = run_one("acm-expiry", snap(cert("gone", "2025-06-01T00:00:00Z", in_use=False, status="EXPIRED")))
    assert f.severity == "low"
    assert f.category == "zombie"
    assert f.deadline == ""


def test_expired_cert_still_in_use_is_high():
    [f] = run_one("acm-expiry", snap(cert("live", "2026-01-10T00:00:00Z", status="EXPIRED")))
    assert f.severity == "high"
    assert "still in use" in f.t("title")


def test_far_expiry_is_quiet():
    assert run_one("acm-expiry", snap(cert("ok", "2026-09-01T00:00:00Z"))) == []
