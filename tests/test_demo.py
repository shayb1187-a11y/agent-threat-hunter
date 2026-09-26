"""``ath demo``: the offline two-minute tour, and the recorded gallery it ships.

The demo is what a reader with no API key sees first, so these tests pin the promises
it makes: it runs with the network blocked and without touching ``data/raw``; every
relative link on its pages resolves; it carries only the allow-listed recorded rows
(no Kubernetes case, whose source licence is unrecorded); every string on the landing
page is escaped; and its headline numbers match the results document.
"""

import copy
import importlib.util
import json
import re
import socket
import sys
import time
from html.parser import HTMLParser
from pathlib import Path

import pytest

from ath import cli, demo
from ath.config import PROJECT_ROOT

TIME_BOUND_SECONDS = 90  # measured at ~2 s; generous for slow CI runners
RECORDED = PROJECT_ROOT / "docs" / "demo" / "recorded"
RESULTS_DOC = PROJECT_ROOT / "docs" / "holdout-v1-windows-results.md"
ALLOWED_KEYS = {"sample-01", "sample-02", "sample-03", "h05", "h07", "h14"}
EXCLUDED_KEYS = ("h01", "h02", "h03", "h04", "h06", "h08", "h09", "h10", "h11", "h12",
                 "h13", "h15", "h16", "h17", "h18")
EXTERNAL_LINKS = ("https://github.com/shayb1187-a11y/agentic-threat-hunter/",
                  "https://dedale.inria.fr/", "https://doi.org/10.57745/Y5JLDG")


def _curate():
    """The curation script as a module (it is a script, not part of the package)."""
    if "curate_demo_rows" not in sys.modules:
        path = PROJECT_ROOT / "scripts" / "curate_demo_rows.py"
        spec = importlib.util.spec_from_file_location("curate_demo_rows", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["curate_demo_rows"] = module  # dataclasses resolve their module by name
        spec.loader.exec_module(module)
    return sys.modules["curate_demo_rows"]


def _raw_snapshot():
    raw = PROJECT_ROOT / "data" / "raw"
    return {p.name: p.stat().st_mtime_ns for p in raw.iterdir()} if raw.exists() else {}


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    """One demo run with every outbound connection refused, timed end to end."""
    out = tmp_path_factory.mktemp("demo") / "out"
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise OSError("network disabled by test_demo")

    before = _raw_snapshot()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(socket.socket, "connect", refuse)
        mp.setattr(socket.socket, "connect_ex", refuse)
        mp.setattr(socket, "create_connection", refuse)
        started = time.perf_counter()
        code = cli.main(["demo", "--out", str(out)])
        elapsed = time.perf_counter() - started
    return {"out": out, "code": code, "elapsed": elapsed, "attempts": attempts,
            "raw_before": before, "raw_after": _raw_snapshot()}


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs, self.tags, self.attrs = [], [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            self.attrs.append(name)
            if name == "href":
                self.hrefs.append(value)


def _parse(path: Path) -> _Links:
    parser = _Links()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def test_demo_runs_offline_fast_and_leaves_the_repository_alone(run):
    """The audience has no network, no key and two minutes. The demo must finish with
    sockets refused, well inside the bound, and write only under --out: the committed
    telemetry in data/raw keeps its files and mtimes."""
    assert run["code"] == 0
    assert run["elapsed"] < TIME_BOUND_SECONDS
    assert run["attempts"] == []
    assert run["raw_after"] == run["raw_before"]
    out = run["out"]
    assert (out / "index.html").is_file() and (out / "telemetry" / "ground_truth.json").is_file()
    for key in ("sample-01", "sample-02", "sample-03"):
        for ext in ("html", "md"):
            assert (out / "investigations" / "cases" / key / "04-report" / f"report.{ext}").is_file()


def test_every_relative_link_resolves_and_pages_carry_no_script_or_asset(run):
    """A broken link in front of an interviewer reads as a broken project. Every relative
    href on the landing page and the two indexes must name a file in the output. External
    links may only point at the repository or the DEDALE citation, and no page loads a
    script or an external asset."""
    out = run["out"]
    for page in (out / "index.html", out / "investigations" / "index.html", out / "recorded" / "index.html"):
        parsed = _parse(page)
        assert parsed.hrefs, page
        assert not {"script", "link", "img", "iframe", "object"} & set(parsed.tags), page
        assert "src" not in parsed.attrs and not any(a.startswith("on") for a in parsed.attrs), page
        for href in parsed.hrefs:
            if href.startswith("#"):
                continue
            if href.startswith("http"):
                assert href.startswith(EXTERNAL_LINKS), href
                continue
            assert (page.parent / href).is_file(), f"{page.name}: {href}"


def test_landing_page_links_the_results_and_preregistration_that_exist(run):
    """Section 5 cites two documents on GitHub; both must exist in this checkout."""
    hrefs = _parse(run["out"] / "index.html").hrefs
    for name in ("holdout-v1-windows-preregistration.md", "holdout-v1-windows-results.md"):
        assert f"{demo.REPO}docs/{name}" in hrefs
        assert (PROJECT_ROOT / "docs" / name).is_file()


def test_gallery_holds_only_allow_listed_rows_and_no_kubernetes_content():
    """The run's other rows include Kubernetes cases whose licence is unrecorded, and the
    JSON rows embed full state. The committed gallery must hold only the allow-listed
    .html/.md reports, match the sha256s the curation recorded, and pass the leak scan."""
    curate = _curate()
    files = sorted(p for p in RECORDED.rglob("*") if p.is_file())
    names = {p.relative_to(RECORDED).as_posix() for p in files}
    assert {"index.html", "ATTRIBUTION.md", "SOURCES.json"} <= names
    rows = [p for p in files if p.parent.name == "rows"]
    assert rows and all(p.suffix in (".html", ".md") for p in rows)
    assert {p.name.split("_")[0] for p in rows} == ALLOWED_KEYS
    assert {f"{a.stem}{ext}" for a in curate.ALLOW for ext in curate.EXTENSIONS} == {p.name for p in rows}
    sources = json.loads((RECORDED / "SOURCES.json").read_text(encoding="utf-8"))
    for entry in sources["files"]:
        assert curate._sha256(RECORDED / entry["file"]) == entry["sha256"], entry["file"]
    assert len(sources["files"]) == len(rows)
    for path in files:
        text = path.read_text(encoding="utf-8")
        if path.parent.name == "rows" or path.name == "index.html":
            assert curate.leaks(text) == [], path.name
            assert not re.search(r"(?i)k8s|kubernetes", text), path.name
        for key in EXCLUDED_KEYS:
            assert not re.search(rf"\b{key}_", text), (path.name, key)
    total = sum(p.stat().st_size for p in files)
    assert total < 1_000_000  # measured ~0.4 MB; the gallery stays small


def test_leak_scan_catches_audit_ids_but_allows_sysmon_guids():
    """The scan is the last guard against a Kubernetes row slipping in. It must flag a
    random UUID (the shape of an auditID) and any Kubernetes string, and must not flag the
    ``sysmon:``-prefixed process GUIDs every DEDALE Windows report contains."""
    curate = _curate()
    assert curate.leaks("process_guid='sysmon:416dd0c5-12ee-6770-2904-000000000c00'") == []
    assert curate.leaks("auditID=0b7c3d1e-7f2a-4c1e-9d3b-5a6f7e8d9c0b")
    assert curate.leaks("ref 0b7c3d1e-7f2a-4c1e-9d3b-5a6f7e8d9c0b")
    assert curate.leaks("sysmon:0b7c3d1e-7f2a-4c1e-9d3b-5a6f7e8d9c0b")  # RFC 4122 anywhere
    assert curate.leaks("namespace kube-system")


def test_gallery_labels_are_derived_from_recorded_scores():
    """A row labelled 'correct' that was wrong would be the worst possible demo claim.
    The label is derived from expected vs decision; the committed catalogue must agree."""
    curate = _curate()
    assert curate.category("malicious", "benign") == curate.UNSAFE_CLEAR
    assert curate.category("malicious", "abstain") == curate.SAFE_ABSTAIN
    assert curate.category("benign", "malicious") == curate.FALSE_ACCUSATION
    assert curate.category("abstain", "malicious") == curate.OVER_CALL
    sources = json.loads((RECORDED / "SOURCES.json").read_text(encoding="utf-8"))
    for row in sources["rows"]:
        assert curate.category(row["expected"], row["decision"]) == row["shows"], row["key"]
    assert any(r["shows"] == curate.UNSAFE_CLEAR for r in sources["rows"])  # the failure stays in view


def _poison(value, marker):
    if isinstance(value, str):
        return value + marker
    if isinstance(value, dict):
        return {k: _poison(v, marker) for k, v in value.items()}
    if isinstance(value, list):
        return [_poison(v, marker) for v in value]
    return value


def test_every_string_on_the_landing_page_is_escaped(run):
    """Command lines, hostnames and model text are untrusted. Append markup to every
    string the page renders; none of it may survive unescaped."""
    data = json.loads((run["out"] / "demo.json").read_text(encoding="utf-8"))
    marker = "<i>x</i>\"'&"
    page = demo.render_landing(_poison(copy.deepcopy(data), marker))
    assert "<i>x</i>" not in page
    assert page.count("&lt;i&gt;x&lt;/i&gt;") > 50
    assert "<script" not in page.lower()


def test_measured_numbers_match_the_results_document():
    """Section 5 is the project's honest headline. Its numbers live in one constant; each
    is parsed back out of docs/holdout-v1-windows-results.md so they cannot drift."""
    doc = RESULTS_DOC.read_text(encoding="utf-8")
    h = demo.HOLDOUT_V1_WINDOWS

    def one(pattern):
        match = re.search(pattern, doc)
        assert match, pattern
        return match.groups()

    mal_ok, mal_n, ben_ok, ben_n = map(int, one(r"malicious (\d+)/(\d+), benign (\d+)/(\d+)"))
    assert (mal_ok, mal_n, ben_ok, ben_n) == (h["malicious_correct"], h["malicious_cases"],
                                              h["benign_correct"], h["benign_cases"])
    assert int(one(r"\| 2\. unsafe clears \| [^|]+ \| \*\*(\d+)\*\*")[0]) == h["unsafe_clears"]
    assert int(one(r"\| 3\. false accusations \| [^|]+ \| (\d+) \|")[0]) == h["false_accusations"]
    assert float(one(r"\*\*(0\.\d+)\*\*; malicious")[0]) == h["balanced_accuracy"]
    assert int(one(r"deterministic arm abstained on all (\d+) cases")[0]) == h["deterministic_abstained"]
    assert int(one(r"All (\d+) rows \((\d+) cases")[1]) == h["deterministic_rows"]
    assert int(one(r"on (\d+) fresh, balanced Windows cases")[0]) == h["cases"]
    assert one(r"Colab T4 run `([^`]+)`")[0] == h["run_id"]
    assert "investigative value on windows not demonstrated" in doc.lower()
    assert "Kubernetes malicious discrimination was not evaluated" in doc


def test_landing_page_states_the_headline_and_its_limits(run):
    """The page must say NOT demonstrated, show the failure numbers from the constant,
    and state the Kubernetes and v7 limits, not only link to them."""
    page = (run["out"] / "index.html").read_text(encoding="utf-8")
    h = demo.HOLDOUT_V1_WINDOWS
    assert "NOT demonstrated" in page
    for text in (f"{h['malicious_correct']}/{h['malicious_cases']}", f"{h['benign_correct']}/{h['benign_cases']}",
                 f"{h['deterministic_abstained']}/{h['deterministic_rows']}", f"{h['balanced_accuracy']:.2f}"):
        assert text in page
    assert "Kubernetes malicious discrimination was <b>not evaluated</b>" in page
    assert "v7 safety fix is in progress" in page and "fresh" in page


def test_demo_refuses_a_folder_it_did_not_write(tmp_path):
    """--out may be mistyped. A non-empty folder without the demo marker is refused and
    left untouched; only a previous demo's folder is rebuilt."""
    keep = tmp_path / "notes.txt"
    keep.write_text("mine", encoding="utf-8")
    assert cli.main(["demo", "--out", str(tmp_path)]) == 2
    assert keep.read_text(encoding="utf-8") == "mine"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["notes.txt"]
