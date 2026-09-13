"""Detections over authentication telemetry.

Authentication data is where lateral movement becomes visible. It is also where naive
rules generate the most noise, so both rules here are built around *shape* rather than
raw counts.
"""

from __future__ import annotations

from ath.hunting.base import Detector, register
from ath.hunting.episodes import find_episodes as _find_bursts
from ath.hunting.finding import Evidence, Finding, Severity
from ath.schema import EVENT_LOGON, describe_logon_type
from ath.telemetry.loader import Telemetry


@register
class BruteForceThenSuccess(Detector):
    """ATH-005 -- A burst of failed logons followed by a success.

    Attacker behaviour
    ------------------
    Password guessing against one account produces many failures in a short time from
    one source. The event that matters is the **transition**: failures, failures,
    failures, then a success from the same source for the same account. That transition
    is the difference between "someone tried and failed" (noise) and "someone tried and
    got in" (an incident).

    Detection shape
    ---------------
    * group by ``(device, user, source_ip)`` -- one account, one target, one origin
    * find a sliding window containing >= ``bruteforce_min_failures`` failures
    * look for a success from the same triple within ``bruteforce_success_window``
    * severity CRITICAL if a success followed, MEDIUM if it did not

    Why the success condition decides the grade
    -------------------------------------------
    The success is the rule's own stated condition; a burst without one is the "tried
    and failed" half of the paragraph above. It is still worth an analyst's look (a
    stale service password, a scanner, or genuine guessing that has not landed yet),
    but grading it HIGH said nothing about outcome and defeated the layers downstream:
    a lone HIGH finding is raised as a case on its own and the benign layer defers to
    HIGH, so on 3.7 years of a real trail 35 of 36 bursts with no success each became
    an uncorroborated, untriageable case (flaws.cloud, M14). MEDIUM keeps the finding
    and lets severity carry the information it is supposed to carry.

    Choosing the threshold
    ----------------------
    The default of 10 failures in 10 minutes is set deliberately above human error. In
    this dataset every ordinary user mistypes their password once or twice and then
    succeeds -- exactly the same *shape* as an attack, at a harmless *magnitude*. A
    threshold of 3 would alert on all of them. This is the core tuning trade-off in
    detection engineering, and the number is a policy decision, not a fact.

    Related technique worth knowing: **password spraying** inverts this, trying one
    common password against many accounts to stay under per-account lockout thresholds.
    It would not trip this rule -- you would group by source IP and count *distinct
    accounts* instead. Worth naming in an interview as a known gap.
    """

    rule_id = "ATH-005"
    title = "Failed logon burst followed by successful authentication"
    severity = Severity.HIGH
    description = "Detects password-guessing bursts and whether they succeeded."
    fields_used = (
        "device", "user", "source_ip", "source_device", "action",
        "failure_reason", "logon_type", "timestamp",
    )
    tables = frozenset({EVENT_LOGON})
    optional_fields = frozenset({"logon_type", "source_device", "failure_reason"})
    """Detection keys on ``action`` (``logons["action"] == "failure"``/``"success"``)
    grouped by ``(device, user, source_ip)``; none of these three appears in any
    filter. ``logon_type`` is read only inside
    ``describe_logon_type(row["logon_type"])`` when phrasing evidence,
    ``failure_reason`` only in the parenthetical after it, and ``source_device``
    only in the finding's metadata. This is what lets ATH-005 be reported as
    working on CloudTrail, where the Windows logon type does not exist and the
    adapter correctly leaves it null."""
    false_positives = (
        "A service account with a stale cached password retrying automatically -- by "
        "far the most common cause of failure bursts in real environments.",
        "A user whose phone or mapped drive holds an old password after a reset.",
        "Vulnerability scanners or pen-test tooling performing authenticated checks.",
        "A misconfigured application retrying authentication in a tight loop.",
        "Account lockout thresholds causing repeated failures after a single mistake.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        logons = telemetry.logons
        if logons.empty:
            return []

        failures = logons[logons["action"] == "failure"]
        successes = logons[logons["action"] == "success"]
        findings: list[Finding] = []

        for (device, user, source_ip), group in failures.groupby(
            ["device", "user", "source_ip"], dropna=False
        ):
            group = group.sort_values("timestamp").reset_index(drop=True)
            stamps = group["timestamp"].tolist()

            for start, end in _find_bursts(
                stamps, self.config.bruteforce_min_failures, self.config.bruteforce_window
            ):
                burst = group.iloc[start : end + 1]
                burst_start, burst_end = stamps[start], stamps[end]

                # Did the same account, from the same source, succeed shortly after?
                follow_up = successes[
                    (successes["device"] == device)
                    & (successes["user"] == user)
                    & (successes["source_ip"] == source_ip)
                    & (successes["timestamp"] >= burst_start)
                    & (successes["timestamp"] <= burst_end + self.config.bruteforce_success_window)
                ].sort_values("timestamp")

                evidence = [
                    Evidence(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        summary=(
                            f"Failed {describe_logon_type(row['logon_type'])} logon for "
                            f"'{user}' on {device} from {source_ip}"
                            + (f" ({row['failure_reason']})" if row["failure_reason"] else "")
                        ),
                    )
                    for _, row in burst.iterrows()
                ]

                if not follow_up.empty:
                    win = follow_up.iloc[0]
                    evidence.append(
                        Evidence(
                            event_id=win["event_id"],
                            timestamp=win["timestamp"],
                            summary=(
                                f"SUCCESSFUL {describe_logon_type(win['logon_type'])} logon "
                                f"for '{user}' on {device} from {source_ip}"
                            ),
                        )
                    )
                    severity = Severity.CRITICAL
                    outcome = (
                        f"A successful logon followed at {win['timestamp'].strftime('%H:%M:%S')}, "
                        f"{int((win['timestamp'] - burst_end).total_seconds())}s after the last "
                        "failure. This may indicate the credential was successfully guessed and "
                        "the account is now compromised."
                    )
                else:
                    severity = Severity.MEDIUM
                    outcome = (
                        "No successful logon was observed from this source within the "
                        "correlation window, so the attempt appears unsuccessful and "
                        "is graded on the guessing alone, not on a compromise."
                    )

                findings.append(
                    self.make_finding(
                        device=device,
                        user=user,
                        evidence=tuple(evidence),
                        severity=severity,
                        reason=(
                            f"{len(burst)} failed logons for '{user}' on {device} from "
                            f"{source_ip} within "
                            f"{int((burst_end - burst_start).total_seconds())}s. {outcome}"
                        ),
                        metadata={
                            "failure_count": len(burst),
                            "source_ip": source_ip,
                            "source_device": str(burst.iloc[0]["source_device"]),
                            "burst_start": burst_start,
                            "burst_end": burst_end,
                            "succeeded": not follow_up.empty,
                        },
                    )
                )
        return findings


@register
class ForeignHostAuthentication(Detector):
    """ATH-006 -- An account authenticated *from* a host it does not belong on.

    Attacker behaviour
    ------------------
    Lateral movement means using credentials obtained on one machine to authenticate to
    another. The revealing detail is not usually *where the credentials went* -- it is
    *where they came from*. Credentials stolen from Alice's laptop get used from
    Alice's laptop, because that is where the attacker has code execution.

    So: a service account that normally runs on a server suddenly authenticating to the
    file server **from a user workstation** is a strong signal, even though both the
    account and the destination are entirely normal in isolation.

    Detection shape
    ---------------
    1. Build host ownership from the data: for each device, which accounts have an
       *interactive* session there (logon types 2, 7, 11 -- console, unlock, cached)?
       RDP (type 10) is deliberately excluded, because an attacker with stolen
       credentials can RDP in, so RDP does not establish ownership.
    2. Find network/remote logons (types 3, 10) whose ``source_device`` is a host we
       have ownership data for.
    3. Alert when the authenticating account is **not** one of that host's owners.

    Why not simply count distinct destination hosts?
    ------------------------------------------------
    The obvious rule -- "alert when one account authenticates to N+ hosts in a short
    window" -- is tempting and *worse*. In this dataset it fires on the IT
    administrator legitimately touching three servers from her own workstation, while
    the actual attacker touches only one host and is missed entirely. Counting hosts
    measures how busy an account is; modelling ownership measures whether the
    credential is being used from somewhere it has no business being. Be ready to
    explain that difference -- it is the kind of reasoning the role is testing for.

    Serious caveat
    --------------
    Ownership here is inferred from a four-hour window of the same dataset. Real
    self-baselining needs weeks of history and an explicit exclusion list for jump
    boxes, admin workstations and PAW infrastructure. This is a demonstration of the
    technique, not a tuned production rule.
    """

    rule_id = "ATH-006"
    title = "Account authenticated from a host where it has no session"
    severity = Severity.HIGH
    description = "Detects credential use originating from a host the account does not own."
    fields_used = (
        "device", "user", "source_device", "source_ip", "logon_type", "action", "timestamp",
    )
    tables = frozenset({EVENT_LOGON})
    optional_fields = frozenset({"source_ip"})
    """Read only to name the origin in the evidence summary
    (``f"({row['source_ip']}) via "``). ``logon_type`` and ``source_device`` are
    deliberately NOT optional: both are hard filters (``logon_type.isin(...)`` for
    ownership and remote logons, ``source_device.fillna("") != ""``), which is why
    this rule correctly declines to fire on control-plane telemetry."""
    false_positives = (
        "Jump boxes, bastion hosts and admin workstations where many accounts "
        "legitimately authenticate outward.",
        "Shared or kiosk machines with no single owning user.",
        "'runas /netonly' and other legitimate alternate-credential workflows.",
        "Scheduled tasks or agents running under service accounts on user endpoints.",
        "A genuinely new employee or a device reassigned to a different owner, where "
        "the ownership baseline is simply out of date.",
    )

    def detect(self, telemetry: Telemetry) -> list[Finding]:
        logons = telemetry.logons
        if logons.empty:
            return []

        successes = logons[logons["action"] == "success"]

        # -- Step 1: infer host ownership from interactive sessions ----------------
        interactive = successes[
            successes["logon_type"].isin(list(self.config.ownership_logon_types))
        ]
        if interactive.empty:
            return []
        owners: dict[str, set[str]] = (
            interactive.groupby("device")["user"].agg(lambda s: set(s)).to_dict()
        )

        # -- Step 2: remote logons that originate from a host we have a baseline for
        remote = successes[
            successes["logon_type"].isin(list(self.config.remote_logon_types))
            & (successes["source_device"].fillna("") != "")
        ]

        findings: list[Finding] = []
        for (source_device, user), group in remote.groupby(
            ["source_device", "user"], dropna=False
        ):
            host_owners = owners.get(source_device)
            if not host_owners:
                continue  # no ownership baseline for this source; cannot judge
            if user in host_owners:
                continue  # the account belongs on this host

            group = group.sort_values("timestamp")
            targets = sorted(set(group["device"]))

            evidence = tuple(
                Evidence(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    summary=(
                        f"'{user}' authenticated to {row['device']} from {source_device} "
                        f"({row['source_ip']}) via "
                        f"{describe_logon_type(row['logon_type'])}"
                    ),
                )
                for _, row in group.iterrows()
            )

            findings.append(
                self.make_finding(
                    device=targets[0] if len(targets) == 1 else source_device,
                    user=user,
                    evidence=evidence,
                    reason=(
                        f"Account '{user}' authenticated to {', '.join(targets)} from "
                        f"{source_device}, but has no interactive session on "
                        f"{source_device} (observed owner(s): "
                        f"{', '.join(sorted(host_owners))}). Credential use originating "
                        "from a host the account does not operate on is consistent with "
                        "lateral movement using stolen credentials, though legitimate "
                        "alternate-credential workflows produce the same pattern."
                    ),
                    metadata={
                        "source_device": source_device,
                        "source_host_owners": sorted(host_owners),
                        "target_devices": targets,
                        "logon_count": len(group),
                        # Surfaced so the ATT&CK layer can distinguish SMB lateral
                        # movement (type 3) from RDP (type 10) rather than guessing.
                        "logon_types": sorted({int(t) for t in group["logon_type"]}),
                    },
                )
            )
        return findings
