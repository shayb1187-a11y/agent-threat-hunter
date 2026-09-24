"""Build the self-contained operational-v5 Colab notebook from the reviewed application source.

Only Python source, package metadata and named offline regression tests are bundled.
No environment files, credentials, downloaded data, or existing results are included.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import textwrap
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build():
    paths = sorted((ROOT / "src" / "ath").rglob("*.py"))
    paths += [ROOT / name for name in (
        "pyproject.toml", "main.py", "tests/_builders.py",
        "tests/test_observation_references.py", "tests/test_auth_execution.py",
        "tests/test_evidence_verification.py", "tests/test_d1_investigator.py",
    )]
    buffer = io.BytesIO()
    contents = {p.relative_to(ROOT).as_posix(): p.read_bytes().replace(b"\r\n", b"\n") for p in paths}
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 9, 23, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    bundle = buffer.getvalue()
    bundle_hash = hashlib.sha256(bundle).hexdigest()
    source_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()
                     if name.startswith("src/ath/")}
    source_hash = hashlib.sha256(json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    cells = []

    def add(kind, source):
        cell = {"cell_type": kind, "metadata": {}, "source": textwrap.dedent(source).strip().splitlines(keepends=True)}
        # splitlines retains newlines except on the final line, as notebook JSON expects.
        if kind == "code":
            cell.update(execution_count=None, outputs=[])
        cells.append(cell)

    add("markdown", """
        # Agentic Threat Hunter — corrected 9B evaluation on Colab GPU

        **Start a fresh session: Runtime → Change runtime type → T4 GPU, then Run all.**
        This notebook includes the corrected ATH source; no GitHub push or companion
        ZIP is needed. It pulls only `qwen3.5:9b` and checks full GPU residency.

        Operational-v5 keeps checked observation references: the model selects
        references, and Python binds the predicates and event citations. As in v4,
        each reference shows the recorded host, account, program, command line and
        signer of its events. New in v5: references are short and stable (R1, R2, ...),
        because 9B mis-copied a 12-character reference in the v4 run; a reply citing an
        unknown reference gets one repair request naming it (unknown references still
        never bind); and a wrapper script is judged by the child commands it ran.
        Interpretations remain inferences.

        This is a **new exploratory experiment**, with a 300-second case deadline,
        two probes and 1,536 output tokens. Old 4B/9B/v3/v4 results remain separate. v5
        was written after inspecting v3 results on all nine synthetic cases and the v4
        development run, so this is not held-out validation. Its freeze declares, before any model call, that equal
        evidence recovery counts when the baseline already cites every available event.
        Completion and classification improvements must be measured, not assumed.
    """)
    add("code", f'''
        from pathlib import Path
        import sys, os, json, subprocess, hashlib, time, urllib.request

        MODEL = "qwen3.5:9b"
        PROFILE = "operational-v5"
        OLLAMA_VERSION = "0.34.1"
        BUNDLE_SHA256 = "{bundle_hash}"
        EXPECTED_SOURCE_SHA256 = "{source_hash}"
        RUN_ID = "9b-v5-" + BUNDLE_SHA256[:12]
        REPO = Path("/content") / ("ath-source-" + BUNDLE_SHA256[:12])
        OUTPUT = Path("/content") / ("ath-results-" + RUN_ID)
        DEV, HELDOUT = OUTPUT / "dev", OUTPUT / "heldout"
        RESTORE_CHECKPOINT = False  # Only set True for this exact notebook's checkpoint.
        print({{"model": MODEL, "profile": PROFILE, "output": str(OUTPUT)}})
    ''')
    add("markdown", "## 1. Check the Colab GPU and install the bundled source\nRun this in a fresh session to avoid importing an older ATH version.")
    add("code", f'''
        #@title Verify GPU and install the corrected application
        import base64, io, zipfile, shutil
        assert shutil.which("nvidia-smi"), "Select a T4 GPU runtime and reconnect."
        gpu_info = subprocess.check_output(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"], text=True)
        print(gpu_info)
        assert not any(key == "ath" or key.startswith("ath.") for key in sys.modules), "Restart the session before reinstalling ATH."
        payload = base64.b64decode({base64.b64encode(bundle).decode()!r})
        assert hashlib.sha256(payload).hexdigest() == BUNDLE_SHA256, "Source bundle is damaged."
        REPO.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for member in archive.infolist():
                target = (REPO / member.filename).resolve()
                assert REPO.resolve() in target.parents, "Invalid source path"
                data = archive.read(member)
                if target.exists():
                    assert target.read_bytes() == data, f"Source changed: {{target}}; use a fresh runtime."
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as handle: handle.write(data)
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-e", str(REPO), "pandas==2.2.3", "pytest>=7.4"], check=True)
        sys.path.insert(0, str(REPO / "src"))
        from ath.evaluation.auth_execution import source_hash
        assert source_hash() == EXPECTED_SOURCE_SHA256, "Source identity differs."
        subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_observation_references.py", "tests/test_auth_execution.py"], cwd=REPO, check=True)
        print("Corrected source verified; offline contract tests passed.")
    ''')
    cells[-1]["metadata"]["cellView"] = "form"
    add("markdown", "## 2. Install Ollama and download 9B\nIncludes the zstd dependency needed by the installer. No API key is required.")
    add("code", '''
        def get_json(path):
            with urllib.request.urlopen("http://127.0.0.1:11434" + path, timeout=10) as response:
                return json.load(response)

        def daemon_up():
            try: return bool(get_json("/api/version").get("version"))
            except Exception: return False

        if not shutil.which("zstd"):
            subprocess.run(["apt-get", "-qq", "update"], check=True)
            subprocess.run(["apt-get", "-qq", "install", "-y", "zstd"], check=True)
        if not shutil.which("ollama"):
            subprocess.run(f"curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION={OLLAMA_VERSION} sh", shell=True, check=True)
        if not daemon_up():
            with open("/content/ollama-ath-v5.log", "ab") as handle:
                subprocess.Popen(["ollama", "serve"], stdout=handle, stderr=subprocess.STDOUT,
                                 start_new_session=True,
                                 env={**os.environ, "OLLAMA_NUM_PARALLEL": "1", "OLLAMA_KEEP_ALIVE": "-1"})
            for _ in range(120):
                if daemon_up(): break
                time.sleep(1)
            else: raise RuntimeError("Ollama failed to start; inspect /content/ollama-ath-v5.log")
        assert get_json("/api/version")["version"] == OLLAMA_VERSION, "Use a fresh session with the pinned daemon."
        subprocess.run(["ollama", "pull", MODEL], check=True)
    ''')
    add("markdown", "## 3. Optional restore and result export\nOnly this notebook's v5 checkpoints are accepted. Existing files cannot be overwritten with conflicting contents.")
    add("code", '''
        from google.colab import files
        OUTPUT.mkdir(parents=True, exist_ok=True)
        if RESTORE_CHECKPOINT:
            for name, blob in files.upload().items():
                with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                    pending = []
                    for member in archive.infolist():
                        target = (Path("/content") / member.filename).resolve()
                        assert OUTPUT.resolve() in target.parents, "Wrong experiment or invalid path"
                        if member.is_dir(): continue
                        data = archive.read(member)
                        if target.exists():
                            assert target.read_bytes() == data, f"Conflicting checkpoint file: {target}"
                        else: pending.append((target, data))
                    for target, data in pending:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open("xb") as handle: handle.write(data)

        def export_results(stage):
            from datetime import datetime, timezone
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            target = Path("/content") / f"ath_{RUN_ID}_{stage}_{stamp}.zip"
            with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
                for path in sorted(OUTPUT.rglob("*")):
                    if path.is_file(): archive.write(path, path.relative_to("/content"))
            print("Saved", target)
            files.download(str(target))

        def ath(*args, allow=(0,)):
            command = [sys.executable, "-m", "ath.evaluation.auth_execution", *map(str, args)]
            print("+", " ".join(command), flush=True)
            result = subprocess.run(command, cwd=REPO)
            if result.returncode not in allow: raise RuntimeError(f"Evaluator exited {result.returncode}")
            return result.returncode
    ''')
    add("markdown", "## 4. Freeze and preload before timed cases\nWeights are loaded with an empty request, not an investigation prompt. Placement and loading time are recorded separately.")
    add("code", '''
        from ath.evaluation.auth_execution import _client, profile_for
        profile = profile_for(PROFILE)
        client = _client(MODEL, profile)
        for path, split, repeats in ((DEV, "dev", 1), (HELDOUT, "heldout", 2)):
            if (path / "FREEZE.json").exists():
                frozen = json.loads((path / "FREEZE.json").read_text())
                assert frozen["profile"] == profile.to_dict()
                assert frozen["model_configuration"] == client.configuration()
                assert (frozen["split"], frozen["repeats"]) == (split, repeats)
                ath("summarise", "--out", path)
            else:
                ath("freeze", "--out", path, "--split", split, "--repeats", repeats, "--model", MODEL, "--profile", PROFILE)
        context = {"run_id": RUN_ID, "model": MODEL, "profile": profile.to_dict(),
                   "source_sha256": source_hash(), "bundle_sha256": BUNDLE_SHA256,
                   "fresh_holdout": False, "study": "exploratory corrected-contract follow-up",
                   "preload_before_cases": True}
        context_path = OUTPUT / "RUN_CONTEXT.json"
        if context_path.exists(): assert json.loads(context_path.read_text()) == context
        else:
            with context_path.open("x") as handle: json.dump(context, handle, indent=2)
        source_copy = OUTPUT / "SOURCE.zip"
        if source_copy.exists(): assert source_copy.read_bytes() == payload
        else:
            with source_copy.open("xb") as handle: handle.write(payload)
        request = urllib.request.Request("http://127.0.0.1:11434/api/generate",
            data=json.dumps({"model": MODEL, "stream": False, "keep_alive": -1,
                             "options": {"num_ctx": client.num_ctx}}).encode(),
            headers={"Content-Type": "application/json"})
        started = time.perf_counter()
        with urllib.request.urlopen(request, timeout=600) as response: loaded = json.load(response)
        assert not loaded.get("error"), loaded
        residency = client.residency()
        from datetime import datetime, timezone
        record = {"gpu": gpu_info, "model": MODEL, "residency": residency,
                  "load_seconds": time.perf_counter() - started, "task_prompt_sent": False}
        preloads = OUTPUT / "preloads"
        preloads.mkdir(exist_ok=True)
        with (preloads / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")).open("x") as handle:
            json.dump(record, handle, indent=2)
        print(json.dumps(record, indent=2))
        subprocess.run(["ollama", "ps"], check=True)
        assert residency["size"] and residency["size_vram"] >= residency["size"], "Model is not fully on GPU. Use a fresh T4 GPU session; do not start a CPU run."
    ''')
    add("markdown", "## 5. Run development and download its checkpoint\nEvery failed row is preserved. The checkpoint downloads before the success gate is checked.")
    add("code", '''
        try:
            ath("run", "--out", DEV, "--arm", "both", allow=(0, 3))
        finally:
            try: ath("summarise", "--out", DEV)
            finally: export_results("dev_checkpoint")
        development = json.loads((DEV / "SUMMARY.json").read_text())
        print(json.dumps(development, indent=2))
        for path in sorted((DEV / "rows").glob("*_d1_*.json")):
            row = json.loads(path.read_text())
            if not row["scores"]["complete"]:
                print(path.name, row["state"]["investigation"]["operational"]["reasons"])
        assert development["complete_comparison"] and development["arms"]["d1"]["complete"] == development["arms"]["d1"]["rows"] == 3, "Development did not complete successfully. Keep the downloaded checkpoint for review; do not delete failed rows."
    ''')
    add("markdown", "## 6. Optional continuation on the previously inspected evaluation cases\nRun all proceeds only after successful development. This stage retains the historical split name `heldout`; it is an exploratory repeat, not fresh validation.")
    add("code", '''
        ath("summarise", "--out", DEV)
        development = json.loads((DEV / "SUMMARY.json").read_text())
        assert development["complete_comparison"] and development["arms"]["d1"]["complete"] == development["arms"]["d1"]["rows"] == 3, "Development must pass before evaluation."
        try:
            ath("run", "--out", HELDOUT, "--arm", "both", allow=(0, 3))
        finally:
            try: ath("summarise", "--out", HELDOUT)
            finally: export_results("evaluation_results")
        result = json.loads((HELDOUT / "SUMMARY.json").read_text())
        print(json.dumps(result, indent=2))
        print("Rows present:", result["complete_comparison"], "Successful model investigations:", result["arms"]["d1"]["complete"], "/ 12")
    ''')
    add("markdown", """
        ## What to send back
        Keep the downloaded development checkpoint and, if development passed, the
        evaluation-results ZIP. They include frozen settings, source snapshot, full
        bounded model replies, resolved observation catalogs, GPU preload records,
        reports and summaries. Do not replace previous 4B/9B artifacts with these.

        A passing development gate proves execution completed, not that every decision
        was correct. The verifier checks the selected predicates and references, not
        arbitrary model prose or intent. Read accuracy, false accusations, abstention,
        recovered evidence and latency alongside completion. No AI improvement is
        established until the live results are reviewed.
    """)
    notebook = {"cells": cells, "metadata": {"accelerator": "GPU",
        "colab": {"name": "ath_auth_execution_gpu_v5.ipynb", "provenance": []},
        "kernelspec": {"display_name": "Python 3", "name": "python3"},
        "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
    target = ROOT / "notebooks" / "ath_auth_execution_gpu_v5.ipynb"
    # open(newline=) rather than write_text(newline=), which needs Python 3.10+.
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(notebook, indent=1, ensure_ascii=False) + "\n")
    print(f"Built {target.name}: {len(bundle):,} source ZIP bytes; sha256 {bundle_hash}")
    return target


if __name__ == "__main__":
    build()
