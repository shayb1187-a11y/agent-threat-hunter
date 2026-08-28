"""Tests for process identity -- what a binary is, versus what it is called.

The attack these exist to stop: an attacker names their payload after a trusted
product and inherits its reputation. Before signature and path were carried, that
worked -- `is_known_security_tool` matched on image name alone, so a file called
`MsMpEng.exe` contributed the largest single benign signal available.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ath.environment import build_environment_model
from ath.schema import SIG_UNSIGNED, SIG_VALID
from ath.telemetry import GeneratorConfig, generate_telemetry, write_telemetry
from ath.telemetry.identity import derive_identity
from ath.telemetry.loader import Telemetry, load_telemetry

DEFENDER_PATH = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24\MsMpEng.exe"
TEMP_PATH = r"C:\Users\jdoe\AppData\Local\Temp\MsMpEng.exe"


@pytest.fixture(scope="module")
def telemetry(tmp_path_factory):
    tables, gt = generate_telemetry(GeneratorConfig())
    out = tmp_path_factory.mktemp("identity_data")
    write_telemetry(tables, gt, out)
    return load_telemetry(out)


def _with_impostor(telemetry: Telemetry) -> Telemetry:
    """The same environment plus one binary impersonating Defender from a temp dir."""
    sha, signer, status = derive_identity("MsMpEng.exe", TEMP_PATH)
    row = telemetry.processes.iloc[0].copy()
    row["event_id"] = "evt-IMPOSTOR"
    row["device"], row["user"] = "PC01", "jdoe"
    row["process_name"], row["file_path"] = "MsMpEng.exe", TEMP_PATH
    row["sha256"], row["signer"], row["signature_status"] = sha, signer, status
    return Telemetry(
        processes=pd.concat(
            [telemetry.processes, pd.DataFrame([row])], ignore_index=True
        ),
        network=telemetry.network,
        logons=telemetry.logons,
    )


# ======================================================================================
# Deriving identity
# ======================================================================================


def test_known_binary_in_its_real_location_is_signed() -> None:
    _, signer, status = derive_identity("MsMpEng.exe", DEFENDER_PATH)
    assert signer == "Microsoft Corporation"
    assert status == SIG_VALID


def test_same_name_elsewhere_is_unsigned() -> None:
    """The name earns nothing on its own -- location has to agree with it."""
    _, signer, status = derive_identity("MsMpEng.exe", TEMP_PATH)
    assert signer == ""
    assert status == SIG_UNSIGNED


def test_impostor_gets_a_different_hash() -> None:
    """Content identity must not collide with the thing being impersonated."""
    real, _, _ = derive_identity("MsMpEng.exe", DEFENDER_PATH)
    fake, _, _ = derive_identity("MsMpEng.exe", TEMP_PATH)
    assert real != fake


def test_identity_is_stable_across_hosts() -> None:
    """Same binary, same hash, or prevalence over hashes would be noise."""
    first, _, _ = derive_identity("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    second, _, _ = derive_identity("CHROME.EXE", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    assert first == second


def test_lolbins_are_genuinely_signed(telemetry) -> None:
    """The honest limit of signature checking, asserted rather than glossed over.

    `powershell.exe` and `rundll32.exe` are validly Microsoft-signed while running the
    attacker's payload in this very dataset. Signature answers "is this file what it
    claims to be", never "is what it is doing legitimate" -- which is why the triage
    vetoes, not the signature, remain the load-bearing control.
    """
    procs = telemetry.processes
    for image in ("powershell.exe", "rundll32.exe"):
        rows = procs[procs["process_name"].str.lower() == image]
        assert not rows.empty
        assert set(rows["signature_status"]) == {SIG_VALID}
        assert set(rows["signer"]) == {"Microsoft Corporation"}


# ======================================================================================
# The environment model refuses to trust a name
# ======================================================================================


def test_genuine_tool_is_recognised(telemetry) -> None:
    env = build_environment_model(telemetry)
    assert env.is_known_security_tool("MsMpEng.exe") == "Microsoft Defender Antivirus"
    assert env.identity_conflict("MsMpEng.exe") is None


def test_impersonation_revokes_recognition(telemetry) -> None:
    """One unsigned copy anywhere makes the whole name untrustworthy.

    Not just the impostor's own events: the name has stopped being a reliable
    identifier in this environment, so nothing may rest on it.
    """
    env = build_environment_model(_with_impostor(telemetry))
    assert env.is_known_security_tool("MsMpEng.exe") is None


def test_impersonation_is_reported_as_a_conflict(telemetry) -> None:
    env = build_environment_model(_with_impostor(telemetry))
    conflict = env.identity_conflict("MsMpEng.exe")
    assert conflict is not None
    assert "Microsoft Corporation" in conflict
    assert "unsigned" in conflict


def test_profile_records_every_signer_and_hash(telemetry) -> None:
    env = build_environment_model(_with_impostor(telemetry))
    profile = env.processes["msmpeng.exe"]
    assert len(profile.hashes) == 2, "impostor and genuine binary must not share a hash"
    assert not profile.consistently_signed


def test_untouched_environment_stays_consistent(telemetry) -> None:
    """The guard must not fire on ordinary data, or it is just noise."""
    env = build_environment_model(telemetry)
    inconsistent = [
        name for name, profile in env.processes.items()
        if profile.signers and not profile.consistently_signed
    ]
    assert not inconsistent, f"unexpected identity conflicts: {inconsistent}"
