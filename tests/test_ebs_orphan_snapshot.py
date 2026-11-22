from awshealth.calls_compute import IMAGES, SNAPSHOTS, VOLUMES
from awshealth.testing import run_one, snap_with


def snapshot(sid, volume="vol-gone", size=100, tags=None, aws_backup=False):
    return {"id": sid, "volume": volume, "size": size, "start": "2024-01-01T00:00:00Z", "tier": "standard",
            "aws_backup": aws_backup, "tags": tags or []}


def snap(snapshots, images=None, volumes=None):
    return snap_with({
        SNAPSHOTS: {"us-east-1": snapshots},
        VOLUMES: {"us-east-1": volumes or []},
        IMAGES: {"us-east-1": images if images is not None else []},
    })


def test_flags_orphans_with_upper_bound_dollars():
    [f] = run_one("ebs-orphan-snapshot", snap([snapshot("snap-01", size=100), snapshot("snap-02", size=60)]))
    assert f.monthly_usd == 8.0
    assert "upper bound" in f.usd_calc
    assert "2 EBS snapshots" in f.t("title")
    assert len(f.resources) == 2
    assert f.owner_question["en"]
    assert any("--owner-ids self" in c for c in f.verify)


def test_ami_dlm_backup_and_live_volume_snapshots_are_skipped():
    snaps = [
        snapshot("snap-ami"),
        snapshot("snap-dlm", tags=[{"Key": "aws:dlm:lifecycle-policy-id", "Value": "policy-0abc"}]),
        snapshot("snap-bk-tag", tags=[{"Key": "aws:backup:source-resource", "Value": "arn:aws:ec2:x"}]),
        snapshot("snap-bk-desc", aws_backup=True),
        snapshot("snap-live", volume="vol-live"),
    ]
    images = [{"id": "ami-0abc", "snapshots": ["snap-ami", None]}]
    volumes = [{"id": "vol-live", "state": "in-use", "size": 8, "type": "gp3"}]
    assert run_one("ebs-orphan-snapshot", snap(snaps, images, volumes)) == []


def test_images_not_collected_means_no_guess():
    s = snap_with({SNAPSHOTS: {"us-east-1": [snapshot("snap-01")]}, VOLUMES: {"us-east-1": []},
                   IMAGES: {"us-east-1": {"__status__": "denied"}}})
    assert run_one("ebs-orphan-snapshot", s) == []


def test_no_snapshots_is_quiet():
    assert run_one("ebs-orphan-snapshot", snap([])) == []
