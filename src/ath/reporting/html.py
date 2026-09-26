"""Render a :class:`~ath.reporting.models.Report` as one self-contained HTML page.

Same content and the same calibration rules as :mod:`ath.reporting.markdown`, for a
reader who wants a page rather than a text file: verdict first, then the investigation
tree, the model's reasoning (labelled as model output), and the evidence.

Every string that came from telemetry or from a model is untrusted
-------------------------------------------------------------------
A command line is attacker-controlled text; a model explanation is text a model was
free to write. Both reach this page, and either could carry markup. So every value
rendered here -- not only the ones that look dangerous -- goes through :func:`_e`
(``html.escape`` with ``quote=True``), and the page itself carries no script, no event
handler attribute, and no external asset: inline CSS only. A link in the run index is
emitted only for a relative or http(s) target; anything else (``javascript:``) is shown
as text.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable
from dataclasses import dataclass

from ath.reporting.language import render_claim
from ath.reporting.models import Report
from ath.reporting.verdict import MODEL_TEXT_NOTE, NO_CONFIDENCE_NOTE, no_reasoning_note

_INLINE_EVIDENCE_LIMIT = 6

_CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#5f6368;--line:#dcdcd8;--card:#ffffff;
--code:#f1f1ee;--mal:#b3261e;--ben:#1e7a3c;--abs:#8a5a00;--inc:#5f6368;--quote:#eef2f8}
@media (prefers-color-scheme: dark){:root{--bg:#161618;--fg:#e8e8e6;--muted:#a0a0a8;
--line:#34343a;--card:#1f1f23;--code:#26262b;--mal:#f2877f;--ben:#6fcf8f;--abs:#e7b75a;
--inc:#a0a0a8;--quote:#232a36}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.5rem;line-height:1.25;margin:0 0 8px}
h2{font-size:1.15rem;margin:32px 0 10px;padding-bottom:4px;border-bottom:1px solid var(--line)}
p,li{overflow-wrap:anywhere}
.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;overflow-wrap:anywhere}
.badge{display:inline-block;font-weight:700;padding:2px 10px;border-radius:999px;
border:2px solid currentColor}
.v-malicious{color:var(--mal)}.v-benign{color:var(--ben)}.v-abstain{color:var(--abs)}
.v-incomplete{color:var(--inc)}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;background:var(--code);
padding:1px 4px;border-radius:4px;overflow-wrap:anywhere}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}
ul.tree,ul.tree ul{list-style:none;margin:0;padding-left:18px}
ul.tree{padding-left:0}
ul.tree ul li{position:relative;border-left:1px solid var(--line);padding:4px 0 8px 14px}
ul.tree ul li:last-child{border-left-color:transparent}
ul.tree ul li::before{content:"";position:absolute;left:0;top:0;width:10px;height:14px;
border-left:1px solid var(--line);border-bottom:1px solid var(--line)}
.arrow{color:var(--muted);padding:2px 0 2px 6px}
.node{font-weight:600}
blockquote.model{margin:6px 0;padding:8px 12px;background:var(--quote);
border-left:3px solid var(--muted);border-radius:4px}
.tag{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.ok{color:var(--ben)}.no{color:var(--mal)}
"""


def _e(value: object) -> str:
    """Escape anything for HTML text or a quoted attribute. Applied to every value."""
    return html.escape(str(value), quote=True)


def _page(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<meta name=\"color-scheme\" content=\"light dark\">\n"
        f"<title>{_e(title)}</title>\n<style>{_CSS}</style>\n</head>\n<body>\n<main>\n"
        f"{body}\n</main>\n</body>\n</html>\n"
    )


def _ids(ids: tuple[str, ...], verified: tuple[str, ...] | None = None) -> str:
    parts = []
    for event_id in ids[:_INLINE_EVIDENCE_LIMIT]:
        mark = ""
        if verified is not None:
            mark = (' <span class="ok">(retrieved)</span>' if event_id in verified
                    else ' <span class="no">(NOT retrieved)</span>')
        parts.append(f"<code>{_e(event_id)}</code>{mark}")
    if len(ids) > _INLINE_EVIDENCE_LIMIT:
        parts.append(f"+{len(ids) - _INLINE_EVIDENCE_LIMIT} more")
    return ", ".join(parts)


def _meta(rows: list[tuple[str, str]]) -> str:
    """A definition list. Values are passed already escaped (they may hold markup)."""
    inner = "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in rows)
    return f'<dl class="meta">{inner}</dl>'


def _table(headers: tuple[str, ...], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_html(report: Report) -> str:
    """Render the full report as one self-contained HTML page."""
    sections = [
        _header(report), _verdict(report), _tree(report), _reasoning(report),
        _section("Executive Summary", f"<p>{_e(report.executive_summary)}</p>"),
        _timeline(report), _findings(report), _recommended(report), _limitations(report),
        _trace(report), _appendix(report),
    ]
    title = f"Incident: {report.title or report.case_id}"
    return _page(title, "\n".join(s for s in sections if s))


def _section(title: str, body: str) -> str:
    return f"<section>\n<h2>{_e(title)}</h2>\n{body}\n</section>"


def _header(report: Report) -> str:
    sources = ", ".join(report.data_sources) or "unknown source"
    rows = [
        ("Case", _e(report.case_id)),
        ("Generated", _e(report.generated_at.strftime("%Y-%m-%d %H:%M:%S") + " UTC")),
        ("Status", _e(report.status)),
        ("Severity", _e(report.severity.value.upper())),
        ("Grouping confidence", _e(report.grouping_confidence)
         + ' <span class="muted">(how strongly findings are linked, not whether an intrusion occurred)</span>'),
        ("Hosts", _e(", ".join(report.devices))),
        ("Accounts", _e(", ".join(report.users))),
        ("Window", _e(f"{report.start_time.strftime('%Y-%m-%d %H:%M:%S')} -> "
                      f"{report.end_time.strftime('%H:%M:%S')} UTC ({report.duration_seconds}s)")),
        ("Telemetry", _e(sources)),
    ]
    return (
        f"<header>\n<h1>Incident: {_e(report.title or report.case_id)}</h1>\n"
        f'<div class="card">{_meta(rows)}</div>\n'
        f'<p class="muted">This report was produced by an automated investigation. It presents '
        "evidence-backed findings for analyst review and does not authorise or perform any "
        "response action.</p>\n</header>"
    )


def _verdict(report: Report) -> str:
    verdict = report.verdict
    if verdict is None:
        return ""
    badge = (f'<span class="badge v-{_e(verdict.disposition.lower())}">'
             f"{_e(verdict.disposition)}</span>")
    rows = [("Disposition", badge)]
    if not verdict.complete:
        rows.append(("Why incomplete", _e("; ".join(verdict.incomplete_reasons))))
        if verdict.model_disposition:
            rows.append(("Model's provisional disposition",
                         _e(f"{verdict.model_disposition} (not a verdict: the run did not complete)")))
    if verdict.disposition_source:
        rows.append(("Decided by", _e(verdict.disposition_source)))
    rows += [
        ("Engine", _e(verdict.engine)), ("Profile", _e(verdict.profile)),
        ("Model", _e(verdict.model)), ("Evidence basis", _e(verdict.evidence_basis)),
    ]
    if verdict.evidence_gap:
        rows.append(("Evidence gap", '<span class="tag">model-written</span> '
                     f"&ldquo;{_e(verdict.evidence_gap)}&rdquo;"))
    if verdict.supporting_event_ids:
        rows.append(("Supporting event ids",
                     _ids(verdict.supporting_event_ids, verdict.verified_event_ids)))
    elif verdict.complete:
        rows.append(("Supporting event ids", "none cited by the concluding explanations"))
    else:
        rows.append(("Supporting event ids",
                     "none; no final disposition was reached, so nothing is cited in support of one"))
    body = (f'<div class="card" id="verdict">{_meta(rows)}</div>\n'
            f'<p class="muted">{_e(NO_CONFIDENCE_NOTE)}</p>')
    return _section("Verdict", body)


def _tree(report: Report) -> str:
    tree = report.investigation_tree
    if tree is None:
        return ""
    steps = []
    for step in tree.steps:
        if step.kind == "refused_probe":
            steps.append(f"<li><span class=\"node\">{_e(step.name)}</span> "
                         '<span class="muted">requested by the model but not on its menu; not run</span></li>')
            continue
        head = f'<span class="node">{_e(step.name)}</span>'
        if step.arguments:
            head += f" <code>{_e(step.arguments)}</code>"
        detail = []
        if step.reason and step.reason_source == "model":
            detail.append(f'<span class="tag">model\'s reason</span> &ldquo;{_e(step.reason)}&rdquo;')
        elif step.reason:
            detail.append(f'<span class="tag">why</span> {_e(step.reason)}')
        if step.kind == "specialist" and step.tools:
            detail.append(f'<span class="tag">tools</span> {_e(", ".join(step.tools))}')
        if step.new_event_ids or step.new_event_count:
            shown = f"; shown: {_ids(step.new_event_ids)}" if step.new_event_ids else ""
            detail.append(f'<span class="tag">new events</span> {_e(step.new_event_count)} retrieved{shown}')
        steps.append(f"<li>{head}" + "".join(f"<div>{d}</div>" for d in detail) + "</li>")
    if not steps:
        steps.append('<li class="muted">no ' + ("probes" if tree.engine == "d1" else "steps") + " run</li>")
    stop = f'<div class="muted">stopped: {_e(tree.stop_reason)}</div>' if tree.stop_reason else ""
    disposition = report.verdict.disposition if report.verdict else "not derived"
    body = (
        '<ul class="tree">\n'
        f'<li><span class="node">Initial alert:</span> {_e(tree.alert_title)}'
        f'<div class="muted">rules {_e(", ".join(tree.rule_ids))}; '
        f"{_e(len(tree.seed_event_ids))} seed event(s): {_ids(tree.seed_event_ids)}</div></li>\n"
        '<li class="arrow" aria-hidden="true">&darr;</li>\n'
        f'<li><span class="node">ATH investigation</span> <span class="muted">(engine {_e(tree.engine)})</span>'
        f"<ul>{''.join(steps)}</ul>{stop}</li>\n"
        '<li class="arrow" aria-hidden="true">&darr;</li>\n'
        f'<li><span class="node">Verdict:</span> {_e(disposition)}</li>\n</ul>'
    )
    return _section("Investigation Tree", body)


def _reasoning(report: Report) -> str:
    if report.verdict is None:
        return ""
    if not report.reasoning_summary:
        return _section("Reasoning Summary", f"<p>{_e(no_reasoning_note(report.verdict.engine))}</p>")
    items = []
    for item in report.reasoning_summary:
        items.append(
            f"<li><div><span class=\"tag\">model label</span> <strong>{_e(item.label)}</strong> "
            f'<span class="muted">verifier: {_e(item.status)}</span></div>'
            f'<blockquote class="model"><span class="tag">model wrote</span><br>{_e(item.statement)}</blockquote>'
            f"<div>Cited: {_ids(item.evidence_ids, item.verified_ids) or 'no event ids'}</div></li>"
        )
    body = f'<p class="muted">{_e(MODEL_TEXT_NOTE)}</p>\n<ol>{"".join(items)}</ol>'
    return _section("Reasoning Summary", body)


def _timeline(report: Report) -> str:
    if not report.timeline:
        return ""
    rows = []
    for entry in report.timeline:
        rows.append([
            _e(entry.timestamp.strftime("%H:%M:%S")), _e(entry.rule_id), _e(entry.severity.value),
            _e(entry.user), _e(entry.movement or entry.device),
            _e(", ".join(entry.techniques) or "-"), _ids(entry.event_ids),
        ])
    return _section("Attack Timeline", _table(
        ("Time", "Rule", "Severity", "User", "Host / Movement", "ATT&CK", "Events"), rows))


def _findings(report: Report) -> str:
    parts = []
    for label, claims in (("Confirmed (FACT)", report.facts),
                          ("Assessed (INFERENCE)", report.inferences),
                          ("Unconfirmed Hypotheses", report.hypotheses)):
        items = "".join(
            f"<li>{_e(render_claim(c))}"
            + (f"<div class=\"muted\">Evidence: {_ids(c.evidence_ids)}</div>" if c.evidence_ids else "")
            + "</li>"
            for c in claims
        ) or "<li class=\"muted\">None.</li>"
        parts.append(f"<h3>{_e(label)} ({len(claims)})</h3><ul>{items}</ul>")
    if report.rejected_claim_count:
        parts.append(f"<p class=\"muted\">{_e(report.rejected_claim_count)} candidate claim(s) failed "
                     "evidence verification and were discarded. They do not appear above.</p>")
    return _section("Findings", "\n".join(parts))


def _recommended(report: Report) -> str:
    if not report.recommended_actions:
        return ""
    items = "".join(
        f"<li><strong>{_e(a.action)}</strong><div>Rationale: {_e(a.rationale)}</div>"
        + (f'<div class="muted">Based on: {_e(a.based_on)}</div>' if a.based_on else "") + "</li>"
        for a in report.recommended_actions
    )
    return _section("Recommended Next Steps",
                    '<p class="muted">Investigative recommendations for a human analyst. No response '
                    f"action has been taken or is authorised by this report.</p><ol>{items}</ol>")


def _limitations(report: Report) -> str:
    if not report.limitations:
        return ""
    return _section("Limitations & Scope",
                    "<ul>" + "".join(f"<li>{_e(x)}</li>" for x in report.limitations) + "</ul>")


def _trace(report: Report) -> str:
    items = "".join(f"<li>{_e(step)}</li>" for step in report.investigation_path)
    return _section("Investigation Trace",
                    f"<p class=\"muted\">Agents run: {_e(', '.join(report.agents_run) or '(none)')}; "
                    f"tool calls made: {_e(report.tool_call_count)}</p><ul>{items}</ul>")


def _appendix(report: Report) -> str:
    if not report.evidence_appendix:
        return ""
    rows = [[f"<code>{_e(e.event_id)}</code>", _e(e.timestamp.strftime("%H:%M:%S")),
             _e(e.device), _e(e.user), _e(e.summary)] for e in report.evidence_appendix]
    return _section("Evidence Appendix",
                    f"<p class=\"muted\">All {len(rows)} telemetry events underlying this report, "
                    "chronologically.</p>"
                    + _table(("Event ID", "Time", "Device", "User", "Summary"), rows))


# -- run index ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndexEntry:
    """One row of a run index: a case, its verdict, and where its page is.

    Attributes:
        label: What the row is (case id, plus arm or sample when a batch has several).
        href: Link to the per-case page. Only relative or http(s) targets are linked.
        verdict: The report's verdict label.
        complete: Whether the verdict is anything other than Incomplete.
        elapsed_seconds: Wall-clock run time, when recorded.
        expected: The expected label, when the batch is scored. Shown for scoring only;
            never an input to the investigation.
        title: The case title.
    """

    label: str
    href: str
    verdict: str
    complete: bool
    elapsed_seconds: float | None = None
    expected: str | None = None
    title: str = ""

    @classmethod
    def from_report(cls, report: Report, href: str, *, expected: str | None = None,
                    label: str | None = None) -> IndexEntry:
        verdict = report.verdict
        return cls(
            label=label or report.case_id, href=href,
            verdict=verdict.disposition if verdict else "Incomplete",
            complete=verdict.complete if verdict else False,
            elapsed_seconds=report.elapsed_seconds, expected=expected, title=report.title,
        )


_SCHEME = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9+.\-]*):")


def _safe_href(href: str) -> str | None:
    """The href if it is relative or http(s); ``None`` for any other scheme."""
    match = _SCHEME.match(href)
    if match and match.group(1).lower() not in ("http", "https"):
        return None
    return href


def render_index(entries: Iterable[IndexEntry], title: str = "Investigation run") -> str:
    """Render a batch/run index page linking each per-case report."""
    entries = list(entries)
    scored = any(e.expected is not None for e in entries)
    headers = ("Case", "Title") + (("Expected (scoring only)",) if scored else ()) + (
        "Verdict", "Complete", "Elapsed", "Report")
    rows = []
    for entry in entries:
        href = _safe_href(entry.href)
        link = f'<a href="{_e(href)}">open</a>' if href is not None else f"<code>{_e(entry.href)}</code>"
        elapsed = f"{entry.elapsed_seconds:.1f}s" if entry.elapsed_seconds is not None else "not recorded"
        row = [_e(entry.label), _e(entry.title)]
        if scored:
            row.append(_e(entry.expected if entry.expected is not None else "-"))
        row += [f'<span class="badge v-{_e(entry.verdict.lower())}">{_e(entry.verdict)}</span>',
                "yes" if entry.complete else "no", _e(elapsed), link]
        rows.append(row)
    complete = sum(e.complete for e in entries)
    body = (
        f"<h1>{_e(title)}</h1>\n"
        f'<p class="muted">{len(entries)} report(s); {complete} with a complete verdict. '
        "Verdicts carry no confidence score; open a report for its evidence basis.</p>\n"
        + _table(headers, rows)
    )
    return _page(title, body)
