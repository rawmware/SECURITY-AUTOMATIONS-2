"""Hermetic tests for cve_watch."""

from aegis.engines.base import ScanContext
from aegis.engines.cve_watch import CveWatch, parse_version, version_matches

FEED = [
    {
        "cve_id": "CVE-2021-44228",
        "package": "log4j-core",
        "affected": "<2.15.0",
        "cvss": 10.0,
        "summary": "Remote code execution via JNDI lookups.",
        "fixed_in": "2.15.0",
    },
    {
        "cve_id": "CVE-2024-0001",
        "package": "acme-lib",
        "affected": "<=2.0",
        "cvss": 7.5,
        "summary": "Auth bypass.",
        "fixed_in": "2.0.1",
    },
    {
        "cve_id": "CVE-2024-0002",
        "package": "pinned-lib",
        "affected": "==1.0.0",
        "cvss": 5.0,
        "summary": "Info disclosure.",
        "fixed_in": "1.0.1",
    },
]


def ctx(sbom, feed=FEED):
    return ScanContext(data={"sbom": sbom, "cve_feed": feed})


def test_vulnerable_version_matched():
    f = CveWatch().scan(ctx([{"name": "log4j-core", "version": "2.14.1"}]))
    assert len(f) == 1
    assert f[0].evidence["cve_id"] == "CVE-2021-44228"
    assert f[0].score == 100
    assert f[0].severity == "critical"
    assert f[0].evidence["fixed_in"] == "2.15.0"
    assert f[0].evidence["summary"]


def test_patched_version_clean():
    f = CveWatch().scan(ctx([{"name": "log4j-core", "version": "2.17.0"}]))
    assert f == []


def test_boundary_version_not_affected():
    # affected is <2.15.0, so exactly 2.15.0 is safe
    f = CveWatch().scan(ctx([{"name": "log4j-core", "version": "2.15.0"}]))
    assert f == []


def test_different_package_not_matched():
    f = CveWatch().scan(ctx([{"name": "log4j-api", "version": "2.14.1"}]))
    assert f == []


def test_lte_spec_matched():
    f = CveWatch().scan(ctx([{"name": "acme-lib", "version": "2.0"}]))
    assert len(f) == 1
    assert f[0].score == 75


def test_lte_spec_boundary_clean():
    f = CveWatch().scan(ctx([{"name": "acme-lib", "version": "2.0.1"}]))
    assert f == []


def test_eq_spec_matched_and_clean():
    f = CveWatch().scan(ctx([{"name": "pinned-lib", "version": "1.0.0"}]))
    assert len(f) == 1
    assert f[0].score == 50
    f2 = CveWatch().scan(ctx([{"name": "pinned-lib", "version": "1.0.1"}]))
    assert f2 == []


def test_case_insensitive_package_match():
    f = CveWatch().scan(ctx([{"name": "Log4J-Core", "version": "2.14.1"}]))
    assert len(f) == 1


def test_empty_sbom_and_feed():
    assert CveWatch().scan(ScanContext(data={})) == []
    assert CveWatch().scan(ctx([])) == []


def test_parse_version_strips_suffixes():
    assert parse_version("1.2.3-beta") == (1, 2, 3)
    assert parse_version("2.0") == (2, 0)
    assert version_matches("1.2.3-beta", "<1.2.4")
    assert not version_matches("1.2.3-beta", "<1.2.3")
