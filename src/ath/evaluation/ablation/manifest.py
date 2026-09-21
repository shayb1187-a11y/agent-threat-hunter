"""The frozen case manifest: what every arm is required to have seen.

The invariant this module exists to enforce
--------------------------------------------
An ablation between a deterministic arm and a model arm is only a comparison if both
arms saw *the same thing*. That is not a promise anyone can keep by intention: a corpus
is re-loaded from disk hours apart, a rule changes, a correlator groups one finding
differently, and the two arms are now answers to two different questions -- with no
error anywhere, because nothing in a pipeline objects to being run on different data.

So the input is pinned as data, before any arm other than the deterministic one runs:

* ``telemetry_hash`` -- a content digest over the four canonical tables, so a single
  changed cell in a million rows changes the hash;
* ``finding_ids`` and ``evidence_ids`` -- what the detection layer produced for this
  case, so a case that still exists but is made of different findings is refused;
* ``manifest_hash`` -- a digest over every entry, recorded on every arm's result.

:func:`~ath.evaluation.ablation.arms.run_arm` refuses to run against telemetry whose
hash differs, and refuses a case whose findings no longer match. A refusal is the point:
the alternative is a comparison table whose rows quietly came from different inputs.

Why the hash is order-sensitive
--------------------------------
Rows are hashed in the order the adapter produced them, not as an order-independent set.
Two loads that differ only in row order would produce different hashes and be refused --
which is correct here, because correlation reads row order: a corpus that re-orders is a
corpus whose cases may differ, and that must surface as a refusal rather than as a
silently different case set.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd

from ath.correlation.chain import InvestigationCase
from ath.schema import EVENT_CONTROL, EVENT_LOGON, EVENT_NETWORK, EVENT_PROCESS
from ath.telemetry.loader import Telemetry

# Rows hashed per update() call. Bounds memory on a million-row corpus; it has no effect
# on the digest, which is a pure function of the rows and their order.
_HASH_CHUNK_ROWS = 25_000

# Timestamps are rendered explicitly rather than left to pandas' default, so a digest
# does not move when a pandas release changes how it prints a tz-aware Timestamp.
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"

# The row terminator is pinned for the same reason, and it is CRLF for a historical one:
# ``to_csv`` defaults to ``os.linesep``, every hash this project has pinned (the M19
# manifest, the M19b and local-model manifests) was computed on Windows, and a digest
# that verifies only on the platform that wrote it is not a claim anyone can check.
# Pinning "\r\n" makes every recorded hash verify everywhere without re-pinning frozen
# artifacts; pinning "\n" would have changed every one of them for no gain in content.
_LINE_TERMINATOR = "\r\n"

_TABLES: tuple[tuple[str, str], ...] = (
    ("process", EVENT_PROCESS),
    ("network", EVENT_NETWORK),
    ("logon", EVENT_LOGON),
    ("control", EVENT_CONTROL),
)


def table_digest(frame: pd.DataFrame) -> str:
    """A stable content digest over one canonical table.

    Columns are sorted by name so that a column added at a different position does not
    change the digest of unchanged data; every value is rendered as text, so the digest
    is a statement about content rather than about a dtype's in-memory layout. The
    timestamp format and the row terminator are both pinned (see the constants above),
    so the digest is a function of the rows alone and not of the platform hashing them.
    """
    digest = hashlib.sha256()
    columns = sorted(str(c) for c in frame.columns)
    digest.update(("columns:" + "|".join(columns) + "\n").encode("utf-8"))
    digest.update(f"rows:{len(frame)}\n".encode("utf-8"))
    if frame.empty:
        return digest.hexdigest()

    ordered = frame[columns]
    for start in range(0, len(ordered), _HASH_CHUNK_ROWS):
        chunk = ordered.iloc[start : start + _HASH_CHUNK_ROWS]
        digest.update(
            chunk.to_csv(
                index=False, header=False, date_format=_TIME_FORMAT,
                lineterminator=_LINE_TERMINATOR,
            ).encode("utf-8")
        )
    return digest.hexdigest()


def telemetry_hash(telemetry: Telemetry) -> str:
    """One digest over all four canonical tables of a corpus."""
    digest = hashlib.sha256()
    for name, event_type in _TABLES:
        digest.update(f"{name}:{table_digest(telemetry.table(event_type))}\n".encode())
    return digest.hexdigest()


DIGEST_VERSIONS: tuple[int, ...] = (1, 2)
"""Telemetry digest versions. 1 is the CSV-text digest every frozen manifest carries; 2 is
the canonical-value digest that does not depend on the pandas or numpy release."""

_NULL = "\x00NULL"
_NAN = "\x00NAN"
_CELL = "\x1f"


def _float_text(value: Any) -> str:
    number = float(value)
    if number != number:
        return _NAN
    if number in (float("inf"), float("-inf")):
        return "\x00INF" if number > 0 else "\x00-INF"
    if number == 0.0:
        return "0.0"
    return repr(number)


def _datetime_text(series: pd.Series) -> tuple[str, pd.Series]:
    tz = getattr(series.dt, "tz", None)
    tag = "datetime" if tz is not None else "datetime-naive"
    utc = series.dt.tz_convert(None) if tz is not None else series
    values = utc.to_numpy(dtype="datetime64[ns]")
    missing = np.isnat(values)
    text = values.astype("int64").astype(str)
    return tag, pd.Series(np.where(missing, _NULL, text), index=series.index, dtype="string")


def _cell_text(value: Any) -> str:
    """One cell of an object column, tagged by its own type."""
    if value is None or value is pd.NA or value is pd.NaT:
        return _NULL
    if isinstance(value, (bool, np.bool_)):
        return "bool:" + ("1" if value else "0")
    if isinstance(value, (int, np.integer)):
        return f"int:{int(value)}"
    if isinstance(value, (float, np.floating)):
        return _NULL if value != value else "float:" + _float_text(value)
    if isinstance(value, str):
        return "str:" + unicodedata.normalize("NFC", value)
    if isinstance(value, (pd.Timestamp, np.datetime64)):
        stamp = pd.Timestamp(value)
        if stamp is pd.NaT:
            return _NULL
        if stamp.tzinfo is not None:
            stamp = stamp.tz_convert(None)
        return f"datetime:{stamp.value}"
    return f"{type(value).__name__}:{value!r}"


def canonical_column(series: pd.Series) -> tuple[str, pd.Series]:
    """A column as ``(type tag, text per cell)`` that two runtimes agree on.

    Every null kind becomes one sentinel; integers are decimal; floats are the shortest
    round-trip repr with ``-0.0`` folded into ``0.0`` and NaN/inf as sentinels; datetimes
    are UTC nanoseconds, a naive column tagged so the assumption is in the hash; strings
    are NFC-normalised; an object column that mixes types tags every cell.
    """
    dtype = series.dtype
    missing = series.isna()
    if pd.api.types.is_bool_dtype(dtype):
        text = series.astype("boolean").map({True: "1", False: "0"}).astype("string")
        return "bool", text.where(~missing, _NULL)
    if pd.api.types.is_integer_dtype(dtype):
        text = series.astype("Int64").astype("string")
        return "int", text.where(~missing, _NULL)
    if pd.api.types.is_float_dtype(dtype):
        text = series.map(_float_text).astype("string")
        return "float", text.where(~missing, _NULL)
    if pd.api.types.is_datetime64_any_dtype(dtype):
        return _datetime_text(series)
    present = series[~missing]
    if isinstance(dtype, pd.StringDtype) or (pd.api.types.is_object_dtype(dtype) and present.map(type).eq(str).all()):
        text = present.astype("string").str.normalize("NFC")
        return "str", text.reindex(series.index).astype("string").where(~missing, _NULL)
    text = series.map(_cell_text).astype("string")
    return "object", text.where(~missing, _NULL)


def table_digest_v2(frame: pd.DataFrame) -> str:
    """Version 2 of :func:`table_digest`: the same shape and order rules, values rendered
    by :func:`canonical_column` instead of by ``to_csv``."""
    digest = hashlib.sha256()
    columns = sorted(str(c) for c in frame.columns)
    tagged = {name: canonical_column(frame[name]) for name in columns}
    header = "columns:" + "|".join(f"{name}={tagged[name][0]}" for name in columns)
    digest.update((header + "\n").encode("utf-8"))
    digest.update(f"rows:{len(frame)}\n".encode("utf-8"))
    if frame.empty:
        return digest.hexdigest()
    encoded = pd.DataFrame({name: tagged[name][1] for name in columns}, index=frame.index)
    for start in range(0, len(encoded), _HASH_CHUNK_ROWS):
        chunk = encoded.iloc[start : start + _HASH_CHUNK_ROWS]
        rows = chunk.astype(object).agg(_CELL.join, axis=1)
        digest.update(("\n".join(rows.tolist()) + "\n").encode("utf-8"))
    return digest.hexdigest()


def column_digests(frame: pd.DataFrame, version: int = 2) -> dict[str, str]:
    """Per-column digests under either version, for naming what moved between runtimes."""
    out: dict[str, str] = {}
    for name in sorted(str(c) for c in frame.columns):
        if version == 1:
            text = frame[[name]].to_csv(
                index=False, header=False, date_format=_TIME_FORMAT, lineterminator=_LINE_TERMINATOR,
            )
        else:
            tag, cells = canonical_column(frame[name])
            text = tag + "\n" + "\n".join(cells.astype(object).tolist())
        out[name] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return out


def telemetry_digest(telemetry: Telemetry, version: int = 1) -> str:
    """The corpus digest under ``version``: 1 is :func:`telemetry_hash`, unchanged."""
    if version == 1:
        return telemetry_hash(telemetry)
    if version != 2:
        raise ValueError(f"unknown telemetry digest version {version!r}; known: {DIGEST_VERSIONS}")
    digest = hashlib.sha256()
    digest.update(b"digest_version:2\n")
    for name, event_type in _TABLES:
        digest.update(f"{name}:{table_digest_v2(telemetry.table(event_type))}\n".encode())
    return digest.hexdigest()


def telemetry_rows(telemetry: Telemetry) -> dict[str, int]:
    """Row counts per canonical table -- reported next to the hash, never instead."""
    return {
        name: int(len(telemetry.table(event_type))) for name, event_type in _TABLES
    }


@dataclass(frozen=True)
class CaseManifest:
    """One case, pinned: which corpus, which findings, which evidence, which telemetry.

    Attributes:
        corpus: Corpus key. Each synthetic incident is its own corpus because each
            carries its own telemetry and therefore its own hash.
        case_id: ``InvestigationCase.case_id`` as the correlator assigned it.
        rule_ids: Rules whose findings make up the case.
        leading_rule: The rule the case is *about* -- highest severity, earliest, tie
            broken by rule id. The stratification key, recorded so the strata can be
            recomputed rather than trusted.
        finding_ids: Member finding ids, sorted.
        evidence_ids: Every telemetry event id the member findings cite, sorted.
        telemetry_hash: Digest of the corpus this case is investigated against.
        selection: Why this case is in the manifest, in words.
        labels: Ground truth where it exists and nothing where it does not -- the
            capture's ATT&CK technique for ``attack_data_aws``, the incident id for a
            synthetic case, empty for flaws.cloud and COMISET.
    """

    corpus: str
    case_id: str
    rule_ids: tuple[str, ...]
    leading_rule: str
    finding_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    telemetry_hash: str
    selection: str = ""
    labels: dict[str, Any] = field(default_factory=dict)
    digest_version: int = 1
    """Which telemetry digest ``telemetry_hash`` was computed with. Serialised only when it
    is not 1, so every manifest frozen before versions existed hashes exactly as before."""

    @property
    def key(self) -> str:
        return f"{self.corpus}/{self.case_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "case_id": self.case_id,
            "rule_ids": list(self.rule_ids),
            "leading_rule": self.leading_rule,
            "finding_ids": list(self.finding_ids),
            "evidence_ids": list(self.evidence_ids),
            "telemetry_hash": self.telemetry_hash,
            "selection": self.selection,
            "labels": dict(self.labels),
            **({"digest_version": self.digest_version} if self.digest_version != 1 else {}),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CaseManifest":
        return cls(
            corpus=str(payload["corpus"]),
            case_id=str(payload["case_id"]),
            rule_ids=tuple(payload.get("rule_ids", ())),
            leading_rule=str(payload.get("leading_rule", "")),
            finding_ids=tuple(payload.get("finding_ids", ())),
            evidence_ids=tuple(payload.get("evidence_ids", ())),
            telemetry_hash=str(payload["telemetry_hash"]),
            selection=str(payload.get("selection", "")),
            labels=dict(payload.get("labels", {})),
            digest_version=int(payload.get("digest_version", 1)),
        )


def leading_rule_of(case: InvestigationCase) -> str:
    """The rule a case is about: highest severity first, then earliest, then rule id.

    Used as the stratification key. A case's rule *set* is not a stratum -- a case
    carrying five rules would belong to five strata and be sampled five times -- so one
    rule has to stand for the case, and the most severe evidence is what an analyst
    would say the case is about.
    """
    leader = min(
        case.findings,
        key=lambda f: (-f.severity.rank, f.first_seen, f.rule_id),
    )
    return leader.rule_id


def build_manifest(
    corpus_name: str,
    telemetry: Telemetry,
    cases: Sequence[InvestigationCase],
    *,
    selection: str = "",
    labels: dict[str, dict[str, Any]] | None = None,
    digest_version: int = 1,
) -> list[CaseManifest]:
    """Pin ``cases`` against ``telemetry``.

    Args:
        corpus_name: Corpus key recorded on every entry.
        telemetry: The canonical tables the cases were built from; hashed once.
        cases: The cases to pin, in the order they should appear.
        selection: Why these cases (not the corpus's others) are here.
        labels: Optional per-case-id ground truth to carry alongside.
        digest_version: Which telemetry digest to pin the cases with (see ``DIGEST_VERSIONS``).

    Returns:
        One :class:`CaseManifest` per case, in the order given.
    """
    digest = telemetry_digest(telemetry, digest_version)
    labels = labels or {}
    return [
        CaseManifest(
            corpus=corpus_name,
            case_id=case.case_id,
            rule_ids=case.rule_ids,
            leading_rule=leading_rule_of(case),
            finding_ids=tuple(sorted(f.finding_id for f in case.findings)),
            evidence_ids=case.event_ids,
            telemetry_hash=digest,
            selection=selection,
            labels=dict(labels.get(case.case_id, {})),
            digest_version=digest_version,
        )
        for case in cases
    ]


def manifest_hash(entries: Iterable[CaseManifest]) -> str:
    """A digest over every pinned entry, independent of the order they are listed in.

    Sorted by ``key`` first: the manifest is a *set* of pinned cases, and listing them
    in a different order is not a different experiment. Everything else about an entry
    is inside the digest, so removing a finding id, swapping a corpus's telemetry or
    renaming a case all change it.
    """
    payload = json.dumps(
        [entry.to_dict() for entry in sorted(entries, key=lambda e: e.key)],
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_manifest(payload: dict[str, Any]) -> list[CaseManifest]:
    """Entries from a written ``MANIFEST.json`` payload."""
    return [CaseManifest.from_dict(entry) for entry in payload.get("cases", [])]
