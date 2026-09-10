"""CloudTrail arrives gzipped, in tar bundles, and invoked by services -- not only as
the tidy ``*.json`` the first adapter read.

Every test here was motivated by a measured number from the flaws.cloud public trail
(M14 step 0 probe, 2026-09-10): the dataset ships as a tar of ``.json.gz`` members, and
57,912 of its 1.94M records -- every service-invoked ``AssumeRole`` -- were dropped as
"no usable principal" because ``userIdentity`` for an ``AWSService`` caller names the
service only in ``invokedBy``.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from ath.schema import EVENT_LOGON
from ath.telemetry.cloudtrail_source import (
    CloudTrailSource,
    _normalise_auth_record,
    _principal,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cloudtrail"
FIXTURE_FILE = FIXTURE / "CloudTrail_us-east-1_2026-08-17.json"


@pytest.fixture(scope="module")
def plain():
    return CloudTrailSource(FIXTURE).load()


def _gz_bytes() -> bytes:
    return gzip.compress(FIXTURE_FILE.read_bytes())


def test_gzipped_delivery_files_read_identically(tmp_path, plain) -> None:
    """S3 delivery writes one ``.json.gz`` per hour; the counts must not change."""
    (tmp_path / "trail.json.gz").write_bytes(_gz_bytes())
    result = CloudTrailSource(tmp_path).load()
    assert result.rows_read == plain.rows_read
    assert result.rows_kept == plain.rows_kept
    assert result.rows_dropped == plain.rows_dropped


def test_tar_bundle_of_gzipped_members_reads_without_extraction(tmp_path, plain) -> None:
    """A research dump is a tar of gz members; nothing is written to disk to read it."""
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as archive:
        payload = _gz_bytes()
        info = tarfile.TarInfo("logs/CloudTrail_us-east-1_2026-08-17.json.gz")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
        # A non-CloudTrail member must be skipped, not counted as a bad file.
        readme = b"not telemetry"
        info = tarfile.TarInfo("logs/README.txt")
        info.size = len(readme)
        archive.addfile(info, io.BytesIO(readme))
    result = CloudTrailSource(tmp_path).load()
    assert result.rows_read == plain.rows_read
    assert result.rows_kept == plain.rows_kept
    # Only the CloudTrail member was read; the README produced no issue of its own.
    assert result.rows_dropped == plain.rows_dropped
    # Nothing was extracted beside the archive.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bundle.tar"]


def test_tar_member_provenance_names_the_archive_and_the_member(tmp_path) -> None:
    """``source_ref`` must still lead back to one record in one file inside one tar."""
    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as archive:
        payload = _gz_bytes()
        info = tarfile.TarInfo("CloudTrail_x.json.gz")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    result = CloudTrailSource(tmp_path).load()
    refs = result.tables[EVENT_LOGON]["source_ref"]
    assert refs.str.contains("File=bundle.tar:CloudTrail_x.json.gz").all()


def test_corrupt_gzip_is_one_issue_not_a_crash(tmp_path) -> None:
    (tmp_path / "bad.json.gz").write_bytes(b"\x1f\x8b definitely not gzip")
    (tmp_path / "good.json").write_bytes(FIXTURE_FILE.read_bytes())
    result = CloudTrailSource(tmp_path).load()
    assert any("not valid JSON" in i.reason and i.raw_reference == "bad.json.gz"
               for i in result.issues)
    assert result.rows_kept > 0


def test_service_invoked_calls_are_attributed_to_the_service() -> None:
    """An ``AWSService`` identity carries its name only in ``invokedBy``."""
    identity = {"type": "AWSService", "invokedBy": "config.amazonaws.com"}
    assert _principal(identity) == "config.amazonaws.com"


def test_human_identities_still_win_over_invoked_by() -> None:
    """``invokedBy`` is the last resort; a real user name must not be displaced by it."""
    identity = {
        "type": "IAMUser", "userName": "ops_bob",
        "arn": "arn:aws:iam::123456789012:user/ops_bob", "invokedBy": "signin.amazonaws.com",
    }
    assert _principal(identity) == "ops_bob"


def test_service_invoked_assume_role_becomes_a_logon_row() -> None:
    record = {
        "eventTime": "2020-05-01T00:00:00Z", "eventName": "AssumeRole",
        "eventSource": "sts.amazonaws.com", "awsRegion": "us-east-1",
        "sourceIPAddress": "config.amazonaws.com",
        "userIdentity": {"type": "AWSService", "invokedBy": "config.amazonaws.com"},
        "errorCode": "AccessDenied", "errorMessage": "not authorized",
        "eventID": "svc-0001", "recipientAccountId": "811596193553",
    }
    row, issue = _normalise_auth_record(record, "f.json", 0)
    assert issue is None
    assert row is not None
    assert row["user"] == "config.amazonaws.com"
    assert row["action"] == "failure"
