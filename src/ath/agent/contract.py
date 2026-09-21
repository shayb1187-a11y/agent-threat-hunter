"""What a prompt may carry: no raw telemetry fields, and attacker-controlled text marked.

The agent layer already never sends the dataset (``tools.py`` explains why). This module
turns two of the remaining rules from test assertions into a runtime check:

* **No raw schema fields.** A rendered prompt that names canonical columns such as
  ``process_id`` or ``command_line`` is a prompt that has started to carry rows instead
  of claims and observations. :func:`check_prompt_contract` names every such field it
  finds, outside a short allow-list of words the prompts legitimately use (``device``,
  ``user``, the ids). Behind ``prompt_contract=True`` on the loop configs, a violation
  is recorded in ``llm_errors`` and the call is not sent.
* **Untrusted text is marked.** A command line, a user name, a URL: the model reads
  strings an attacker wrote. :func:`wrap_untrusted` puts one inside an envelope the
  system prompt can be told to treat as data. Applying it changes prompt bytes, so it
  belongs to a new prompt version (D2), never to D1 v3.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ath.schema import TABLE_COLUMNS

SCHEMA_FIELD_NAMES: frozenset[str] = frozenset(
    name for columns in TABLE_COLUMNS.values() for name in columns
)
"""Every canonical column name across the four tables."""

PROMPT_ALLOWED_FIELDS: frozenset[str] = frozenset({
    # Words the prompts use as words, and the identifiers a claim must be able to cite.
    "device", "user", "action", "event_id", "timestamp", "source", "protocol",
    "process_name", "parent_process_name", "remote_ip", "source_ip", "source_device",
    "verb", "actor", "resource_type", "resource_name", "region", "outcome",
})

UNTRUSTED_OPEN = "<untrusted {label}>"
UNTRUSTED_CLOSE = "</untrusted>"


class PromptContractViolation(ValueError):
    """A rendered prompt names raw schema fields it must not carry."""


def check_prompt_contract(prompt: str, *, allowed: Iterable[str] = PROMPT_ALLOWED_FIELDS) -> list[str]:
    """The schema field names ``prompt`` mentions as whole words, minus ``allowed``.

    Empty means the prompt keeps the contract. Matching is on identifier boundaries, so
    ``process_id`` matches ``process_id=5`` and ``'process_id'`` but not ``process_identity``.
    """
    forbidden = SCHEMA_FIELD_NAMES - set(allowed)
    found = []
    for name in sorted(forbidden):
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", prompt):
            found.append(name)
    return found


def assert_prompt_contract(prompt: str, *, allowed: Iterable[str] = PROMPT_ALLOWED_FIELDS) -> None:
    found = check_prompt_contract(prompt, allowed=allowed)
    if found:
        raise PromptContractViolation(
            f"prompt names {len(found)} raw schema field(s): {', '.join(found[:6])}"
        )


def wrap_untrusted(text: str, label: str = "text") -> str:
    """``text`` inside a marked envelope; the envelope's own markers inside ``text`` are
    neutralised so the string cannot close it early."""
    body = str(text).replace("</untrusted", "<\\/untrusted")
    return f"{UNTRUSTED_OPEN.format(label=label)}{body}{UNTRUSTED_CLOSE}"
