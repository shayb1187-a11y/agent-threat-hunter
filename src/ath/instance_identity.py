"""Process-*instance* identity: which run of a program, not which program.

Why this module exists
----------------------
``(device, process_id)`` is not an identifier. A PID is a small integer the operating
system reissues within minutes, so the pair names a *slot* rather than a process, and
every claim built on it -- "this process opened that connection", "this process spawned
that child" -- inherits the ambiguity silently.

The size of it was measured, not assumed. On the held-out COMISET slice
(``reports/m17/H4_FROZEN.json``) 589,359 of 589,477 network rows matched *a* process row
by ``(device, process_id)`` -- 99.98%, which reads like a solved problem -- while **86.5%
of those keys were ambiguous**, the worst one covering 27 distinct process instances. Two
cross-channel claims in three were therefore unsubstantiable, and the corpus had carried
the answer all along: Sysmon writes a ``ProcessGuid`` on event 1 *and* on event 3, and
ingestion discarded it (defect M17-3).

The invariant
-------------
**A process instance has one identity per identity authority.**

* When the source provides its own instance identifier, that is the identity --
  :data:`SCHEME_SYSMON` for a Sysmon ``ProcessGuid``, taken verbatim (braces stripped,
  lower-cased) because it is the authority's value and not ours to reshape.
* Otherwise, when the source records the instance's **creation time**, the identity is a
  deterministic key over ``(device, pid, creation time)`` -- :data:`SCHEME_START`.
* Otherwise it is the empty string. An empty identity is a real, reportable gap; it is
  never a guess.

The last clause is the whole discipline. Nothing here derives an identity from an
event's own timestamp unless *the event is the creation of the process it names* --
Sysmon 1 or Security 4688 for the process created, a Defender ``ProcessCreationTime``
column for the process the row is about. A Sysmon 3 network-connection event carries the
time the socket opened, which is not when the process started, so a network row without a
``ProcessGuid`` gets ``""`` rather than a plausible-looking key that would silently fail
to join.

Identities are comparable only within a scheme
-----------------------------------------------
A ``sysmon`` GUID and a ``start`` key are answers from two different authorities to the
same question, and neither can confirm the other. So the scheme is part of the value --
``"<scheme>:<parts>"`` -- and two identities from different schemes can never compare
equal even if their id text is byte-identical. That is why this is one string column and
not a bare GUID: a bare GUID column silently invites ``==`` across authorities.

An identity is an opaque key. It is compared, grouped and counted; it is never parsed
back apart by anything downstream.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Final

import pandas as pd

SCHEME_SYSMON: Final[str] = "sysmon"
"""The source's own instance identifier: a Sysmon ``ProcessGuid``.

Globally unique by construction (Sysmon derives it from the machine GUID, the process
start time and the PID), so it needs no device component and is comparable across hosts.
"""

SCHEME_START: Final[str] = "start"
"""A deterministic key over ``(device, pid, creation time)``.

Used only where the source records when the instance began. Two runs that reuse one PID
on one device differ in creation time and therefore in identity, which is precisely the
ambiguity ``(device, pid)`` cannot express.
"""

IDENTITY_SCHEMES: Final[tuple[str, ...]] = (SCHEME_SYSMON, SCHEME_START)

SCHEME_SEPARATOR: Final[str] = ":"
PART_SEPARATOR: Final[str] = "|"


class UnknownIdentityScheme(ValueError):
    """Raised when an identity is requested under a scheme this module does not define.

    Loud rather than permissive on purpose: a typo'd scheme name would mint identities
    that compare equal to nothing, and a column of values that never join looks exactly
    like a column of honest gaps.
    """


def instance_identity(scheme: str, *parts: Any) -> str:
    """Format one process-instance identity under ``scheme``.

    The single place the ``"<scheme>:<part>|<part>"`` shape is written, so no two
    callers can disagree about it, and so the scheme prefix is impossible to omit.

    Args:
        scheme: One of :data:`IDENTITY_SCHEMES`.
        *parts: The scheme's components, already normalised by the caller
            (:func:`sysmon_identity` and :func:`start_identity` are those callers).

    Returns:
        The identity, or ``""`` when **any** part is empty -- a partial identity is not
        a weaker identity, it is a different process's key waiting to happen.

    Raises:
        UnknownIdentityScheme: if ``scheme`` is not a declared scheme.
    """
    if scheme not in IDENTITY_SCHEMES:
        raise UnknownIdentityScheme(
            f"Unknown identity scheme {scheme!r}; expected one of {IDENTITY_SCHEMES}"
        )
    rendered = ["" if part is None else str(part).strip() for part in parts]
    if not rendered or any(part == "" for part in rendered):
        return ""
    return f"{scheme}{SCHEME_SEPARATOR}{PART_SEPARATOR.join(rendered)}"


def sysmon_identity(process_guid: Any) -> str:
    """The :data:`SCHEME_SYSMON` identity of a Sysmon ``ProcessGuid``.

    Sysmon and the pipelines that carry it disagree only about presentation: DEDALE's
    Winlogbeat export writes ``{416dd0c5-6a1f-676a-0300-000000000800}`` into
    ``process.entity_id``, COMISET's Elastic pipeline strips the braces and upper-cases
    the hex. Both are the same authority's value for the same instance, so the braces go
    and the hex is lower-cased -- normalisation of presentation, never of content.

    Args:
        process_guid: The raw GUID as the source wrote it.

    Returns:
        The identity, or ``""`` when the source carried no GUID.
    """
    text = "" if process_guid is None else str(process_guid).strip()
    if text in ("", "-", "null", "nan", "<NA>"):
        return ""
    return instance_identity(SCHEME_SYSMON, text.strip("{}").lower())


def start_identity(device: Any, process_id: Any, created: Any) -> str:
    """The :data:`SCHEME_START` identity of an instance whose creation time is known.

    Args:
        device: Host the instance ran on. Lower-cased, because adapters already
            normalise host names to a short lower-case form and an identity that
            differed by casing would split one machine in two.
        process_id: The OS PID, rendered as a plain integer so ``4820``, ``"4820"`` and
            ``4820.0`` -- all of which reach here from different readers -- agree.
        created: When the instance began. Rendered as ISO-8601 UTC to the millisecond,
            which is the resolution Sysmon, the Security log and Defender all record;
            finer digits are noise that would make two readings of one event disagree.

    Returns:
        The identity, or ``""`` if the device, the PID or the creation time is missing
        or unusable -- including a creation time this module cannot parse, which is a
        gap and not a reason to fall back to something weaker.
    """
    host = "" if device is None else str(device).strip().lower()
    return instance_identity(SCHEME_START, host, _pid(process_id), _iso_milliseconds(created))


def scheme_of(identity: Any) -> str:
    """The scheme an identity was minted under, or ``""`` for an empty identity.

    Exists so measurement can report population *by authority* without any script
    re-deriving the string shape this module owns.
    """
    text = "" if identity is None else str(identity)
    scheme, separator, _ = text.partition(SCHEME_SEPARATOR)
    return scheme if separator and scheme in IDENTITY_SCHEMES else ""


def _pid(value: Any) -> str:
    """``4820``, ``"4820"``, ``4820.0`` -> ``"4820"``; anything unusable -> ``""``."""
    if value is None or value is pd.NA:
        return ""
    try:
        if isinstance(value, float) and value != value:  # NaN
            return ""
        return str(int(str(value).strip()))
    except (TypeError, ValueError):
        try:
            return str(int(value))
        except (TypeError, ValueError):
            return ""


def _iso_milliseconds(value: Any) -> str:
    """``2026-08-17T08:00:00.000Z`` from whatever shape the reader produced, or ``""``."""
    if value is None or value is pd.NaT:
        return ""
    try:
        stamp = value if isinstance(value, pd.Timestamp) else pd.Timestamp(value)
    except (TypeError, ValueError):
        return ""
    if stamp is pd.NaT or pd.isna(stamp):
        return ""
    stamp = stamp.tz_localize("UTC") if stamp.tzinfo is None else stamp.tz_convert("UTC")
    return f"{stamp.strftime('%Y-%m-%dT%H:%M:%S')}.{stamp.microsecond // 1000:03d}Z"


# ======================================================================================
# Joining on identity, and saying so when the join is not on identity
# ======================================================================================

INFERRED_FROM_PID: Final[str] = "inferred from pid"
"""The label every surface uses for a join that fell back to ``(device, pid)``.

One string, so a reader who greps for it finds every claim in the system that rests on a
slot rather than on an instance -- and so no surface can invent a softer phrasing.
"""

RESOLVED_BY_IDENTITY: Final[str] = "identity"
"""The label for a join both sides asserted an identity for, under one scheme."""


@dataclass(frozen=True)
class InstanceKey:
    """What one telemetry row says about *which process instance* it is about.

    Attributes:
        identity: The row's :mod:`instance identity <ath.instance_identity>`, or ``""``
            when the source asserted none.
        device: Host the row was observed on, used only by the fallback.
        process_id: The OS PID, used only by the fallback. ``None`` when absent.

    Equality is *exact key* equality, over :attr:`tag`: an identity key is the tagged
    pair ``("identity", <identity>)`` and a fallback key the tagged triple
    ``("pid", <device>, <pid>)``, so no identity can ever collide with a fallback, and
    two identities minted under different schemes cannot collide either (the scheme is
    inside the identity string). That is what makes this safe as a ``dict`` key.

    Equality is **not** the join relation -- see :meth:`joins`. The join is deliberately
    not an equivalence: an identified row and an unidentified row on the same slot join
    by pid, while two *identified* rows on that slot do not join at all. That relation
    is not transitive, so it cannot be ``__eq__`` without corrupting every dictionary
    this key is used in. Keeping them separate is the point: grouping uses equality,
    evidence uses :meth:`joins`, and the caller can always see which it asked for.
    """

    identity: str
    device: str
    process_id: int | None

    @property
    def scheme(self) -> str:
        """The authority that minted :attr:`identity`, or ``""`` when there is none."""
        return scheme_of(self.identity)

    @property
    def has_identity(self) -> bool:
        return bool(self.identity)

    @property
    def tag(self) -> tuple[Any, ...]:
        """The exact-equality key: identity when there is one, else device and pid."""
        if self.identity:
            return ("identity", self.identity)
        return ("pid", self.device, self.process_id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, InstanceKey) and self.tag == other.tag

    def __hash__(self) -> int:
        return hash(self.tag)

    def __str__(self) -> str:
        return self.identity or f"{self.device}|{self.process_id} ({INFERRED_FROM_PID})"

    def joins(self, other: "InstanceKey") -> tuple[bool, bool]:
        """Whether these two rows describe the same process instance, and how we know.

        Returns:
            ``(joined, inferred)``.

            * Both sides carry an identity under **the same scheme**: the answer is the
              identity comparison and nothing else, and ``inferred`` is ``False``. Two
              different identities on one ``(device, pid)`` are two different processes,
              and no amount of pid agreement makes them one -- that is exactly the
              silent false attribution this key exists to stop.
            * Either side asserted no identity, or the two came from different
              authorities (a Sysmon GUID and a creation-time key are answers to the same
              question from sources that cannot confirm each other): the comparison
              falls back to ``(device, pid)`` and ``inferred`` is ``True``. The join is
              still made -- refusing it would discard every cross-channel attribution on
              a corpus whose network rows carry no GUID -- but the caller is now *told*,
              and must say so wherever the result surfaces.
        """
        if self.identity and other.identity and self.scheme == other.scheme:
            return self.identity == other.identity, False
        if self.process_id is None or other.process_id is None or not self.device:
            return False, False
        return (
            self.device == other.device and self.process_id == other.process_id,
            True,
        )


def instance_key(identity: Any, device: Any, process_id: Any) -> InstanceKey | None:
    """The :class:`InstanceKey` of one row, or ``None`` when the row names no instance.

    ``None`` -- rather than a key that joins to nothing -- because a row with neither an
    identity nor a PID is not a weak witness about a process, it is not a witness at all,
    and counting it as one inflates every denominator downstream.
    """
    text = "" if identity is None else str(identity).strip()
    if text and scheme_of(text) == "":
        # A value shaped like nothing this module mints. Treat it as absent rather than
        # as an identity that would never compare equal to anything.
        text = ""
    pid_text = _pid(process_id)
    pid = int(pid_text) if pid_text else None
    if not text and pid is None:
        return None
    return InstanceKey(identity=text, device=str(device or "").strip(), process_id=pid)


def match_keys(
    left: Collection["InstanceKey"], right: Collection["InstanceKey"]
) -> tuple[bool, bool]:
    """Whether any key on the left names the same instance as any key on the right.

    Returns:
        ``(joined, inferred)``. ``inferred`` is ``True`` only when the join was made and
        **every** matching pair fell back to ``(device, pid)``. One identity-backed
        match is enough to make the relationship an observed one, so a single honest
        witness is never downgraded by the presence of a weaker one.
    """
    joined = False
    identity_backed = False
    for a in left:
        for b in right:
            ok, inferred = a.joins(b)
            if ok:
                joined = True
                if not inferred:
                    identity_backed = True
    return joined, joined and not identity_backed
