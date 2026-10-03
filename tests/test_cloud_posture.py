"""Hermetic tests for cloud_posture."""

from aegis.engines.base import ScanContext
from aegis.engines.cloud_posture import CloudPosture

CLEAN = {
    "s3_buckets": [{"name": "private-data", "public_read": False}],
    "security_groups": [
        {"id": "sg-web", "ingress": [{"port": 443, "cidr": "0.0.0.0/0"}]}
    ],
    "iam_policies": [
        {"name": "readonly", "actions": ["s3:GetObject", "s3:ListBucket"]}
    ],
    "volumes": [{"id": "vol-1", "encrypted": True}],
}


def ctx(cloud):
    return ScanContext(data={"cloud": cloud})


def test_public_s3_bucket():
    cloud = {"s3_buckets": [{"name": "leaky", "public_read": True}]}
    f = CloudPosture().scan(ctx(cloud))
    assert len(f) == 1
    assert f[0].score == 80
    assert f[0].severity == "high"
    assert f[0].entities["bucket"] == "leaky"


def test_open_ssh_to_world():
    cloud = {
        "security_groups": [
            {"id": "sg-1", "ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]}
        ]
    }
    f = CloudPosture().scan(ctx(cloud))
    assert len(f) == 1
    assert f[0].score == 90
    assert f[0].severity == "critical"


def test_open_rdp_to_world():
    cloud = {
        "security_groups": [
            {"id": "sg-2", "ingress": [{"port": 3389, "cidr": "0.0.0.0/0"}]}
        ]
    }
    f = CloudPosture().scan(ctx(cloud))
    assert f[0].score == 90


def test_https_open_to_world_is_fine():
    # 443 is not in the sensitive-port set
    cloud = {
        "security_groups": [
            {"id": "sg-web", "ingress": [{"port": 443, "cidr": "0.0.0.0/0"}]}
        ]
    }
    assert CloudPosture().scan(ctx(cloud)) == []


def test_ssh_open_to_private_range_is_fine():
    cloud = {
        "security_groups": [
            {"id": "sg-3", "ingress": [{"port": 22, "cidr": "10.0.0.0/8"}]}
        ]
    }
    assert CloudPosture().scan(ctx(cloud)) == []


def test_wildcard_iam_action():
    cloud = {"iam_policies": [{"name": "admin-ish", "actions": ["*"]}]}
    f = CloudPosture().scan(ctx(cloud))
    assert len(f) == 1
    assert f[0].score == 85
    assert f[0].severity == "high"


def test_unencrypted_volume():
    cloud = {"volumes": [{"id": "vol-9", "encrypted": False}]}
    f = CloudPosture().scan(ctx(cloud))
    assert len(f) == 1
    assert f[0].score == 55
    assert f[0].severity == "medium"


def test_clean_snapshot_no_findings():
    assert CloudPosture().scan(ctx(CLEAN)) == []


def test_multiple_issues_all_reported():
    cloud = {
        "s3_buckets": [{"name": "leaky", "public_read": True}],
        "security_groups": [
            {"id": "sg-1", "ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]}
        ],
        "iam_policies": [{"name": "bad", "actions": ["*"]}],
        "volumes": [{"id": "vol-9", "encrypted": False}],
    }
    f = CloudPosture().scan(ctx(cloud))
    assert len(f) == 4
    assert sorted(x.score for x in f) == [55, 80, 85, 90]


def test_missing_sections_tolerated():
    assert CloudPosture().scan(ScanContext(data={})) == []
    assert CloudPosture().scan(ctx({"s3_buckets": []})) == []
