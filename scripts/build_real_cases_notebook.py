"""Build the self-contained Colab notebook that runs a sealed real-case bundle on a GPU.

The notebook embeds the application source (Python, package metadata and named offline
tests only), installs Ollama, asks for the case-bundle ZIP built locally with
``python -m ath.evaluation.real_cases build``, and runs:

1. the three synthetic development cases as a smoke gate (the stack works on this GPU);
2. the bundle's investigable real cases, both arms, under the frozen profile.

No telemetry, labels, credentials or results are embedded; the case bundle is uploaded
at run time and copied into the exported results so they are self-contained.

It now emits the holdout-v1-windows notebook. The earlier v6 regression notebook
(tag ``v6-regression-frozen``) is a historical artifact kept outside the repository;
this builder no longer regenerates it, because its embedded source must stay
byte-identical to the run it belongs to.
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
TARGET = ROOT / "notebooks" / "ath_holdout_gpu.ipynb"
TESTS = ("tests/_builders.py", "tests/test_real_cases.py", "tests/test_control_plane_v6.py", "tests/test_observation_references.py",
         "tests/test_auth_execution.py", "tests/test_evidence_verification.py", "tests/test_d1_investigator.py")


def source_bundle():
    paths = sorted((ROOT / "src" / "ath").rglob("*.py"))
    paths += [ROOT / name for name in ("pyproject.toml", "main.py", *TESTS)]
    contents = {p.relative_to(ROOT).as_posix(): p.read_bytes().replace(b"\r\n", b"\n") for p in paths}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 9, 24, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    bundle = buffer.getvalue()
    source_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()
                     if name.startswith("src/ath/")}
    source_hash = hashlib.sha256(json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return bundle, hashlib.sha256(bundle).hexdigest(), source_hash


def build(target: Path = TARGET) -> Path:
    bundle, bundle_hash, source_hash = source_bundle()
    cells = []

    def add(kind, source):
        cell = {"cell_type": kind, "metadata": {}, "source": textwrap.dedent(source).strip().splitlines(keepends=True)}
        if kind == "code":
            cell.update(execution_count=None, outputs=[])
        cells.append(cell)

    add("markdown", """
        # Agentic Threat Hunter — holdout-v1-windows evaluation on Colab GPU

        **Start a fresh session: Runtime → Change runtime type → T4 GPU, then Run all.**
        You will be asked to upload one ZIP: the case bundle you built locally with
        `python -m ath.evaluation.real_cases build --spec <spec.json> --bundle <dir>`.
        Zip the bundle folder as it is; the notebook finds its `BUNDLE.json`.

        The notebook first runs the three synthetic development cases as a smoke gate.
        Only if all three complete does it run the bundle's investigable real cases,
        comparing deterministic specialists with `qwen3.5:9b` under the frozen
        operational-v6 profile. Undetected, ambiguous and unresolved-label cases are
        listed in the results, never dropped.

        A bundle built with `"seed_mode": "analyst"` is **analyst-seeded investigation,
        not end-to-end ATH**: each case starts from its labelled anchor events whether or
        not ATH detection raised it. The notebook prints the mode, and every summary
        records it.

        **Disconnects.** With `USE_DRIVE = True` (the default) every result is written to
        your Google Drive as it is produced, under `MyDrive/ath-holdout-runs/`. If Colab
        disconnects, reconnect a T4 runtime and choose Run all again: saved rows are
        validated and skipped, the bundle is reused from Drive without a new upload, and
        the run continues with the next unfinished case. Keep the tab open while it runs.
        Each stage's duration is printed and appended to `timings.log` in the results.

        **Holdout-v1-windows.** The headline verdict covers the 12 primary Windows cases
        only, under rules sealed in the freeze before any model call. The Kubernetes
        cases are a benign-only secondary check reported apart from the verdict, and
        Kubernetes malicious discrimination was not evaluated. The summary states this.

        **RAM guard.** If free host RAM falls below the guard's floor, the blocked row is
        recorded as an attempt stub, Ollama is restarted, the page cache dropped, the
        model preloaded again, and the run resumes. At most two restarts.

        Results are exploratory unless the cases were sealed before any prompt change.
        The verifier checks cited evidence, not the model's prose or intent.
    """)
    add("code", f'''
        from pathlib import Path
        import sys, os, json, subprocess, hashlib, time, urllib.request

        MODEL = "qwen3.5:9b"
        PROFILE = "operational-v6"
        OLLAMA_VERSION = "0.34.1"
        BUNDLE_SHA256 = "{bundle_hash}"
        EXPECTED_SOURCE_SHA256 = "{source_hash}"
        RUN_ID = "holdout-9b-v6-" + BUNDLE_SHA256[:12]
        REPO = Path("/content") / ("ath-source-" + BUNDLE_SHA256[:12])
        USE_DRIVE = True  # Save results to Google Drive as they are produced; survives disconnects.
        DRIVE_ROOT = Path("/content/drive/MyDrive/ath-holdout-runs")
        if USE_DRIVE:
            from google.colab import drive
            drive.mount("/content/drive")
        OUTPUT = (DRIVE_ROOT if USE_DRIVE else Path("/content")) / ("ath-results-" + RUN_ID)
        OUTPUT.mkdir(parents=True, exist_ok=True)
        DEV, REAL = OUTPUT / "dev-gate", OUTPUT / "real"
        RESTORE_CHECKPOINT = False  # Only for USE_DRIVE = False: restore this notebook's checkpoint ZIP.

        STARTED = [time.perf_counter(), time.perf_counter()]
        def stage_done(name):
            now = time.perf_counter()
            line = f"{{time.strftime('%Y-%m-%d %H:%M:%S')}} {{name}}: {{now - STARTED[1]:.0f}} s (session total {{now - STARTED[0]:.0f}} s)"
            STARTED[1] = now
            print(line, flush=True)
            with (OUTPUT / "timings.log").open("a", encoding="utf-8") as handle: handle.write(line + "\\n")

        print({{"model": MODEL, "profile": PROFILE, "output": str(OUTPUT)}})
        print("Resuming: rows already saved will be validated and skipped." if (REAL / "FREEZE.json").exists() else "New run.")
    ''')
    add("markdown", "## 1. Check the GPU and install the bundled source\nRun this in a fresh session to avoid importing an older ATH version.")
    add("code", f'''
        #@title Verify GPU and install the application
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
        tests_marker = OUTPUT / "TESTS_PASSED"
        if tests_marker.exists():
            print("Offline contract tests already passed for this source; skipping them on resume.")
        else:
            subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_real_cases.py", "tests/test_control_plane_v6.py",
                            "tests/test_observation_references.py", "tests/test_auth_execution.py"], cwd=REPO, check=True)
            tests_marker.write_text(EXPECTED_SOURCE_SHA256, encoding="utf-8")
        print("Source verified; offline contract tests passed.")
        stage_done("install and verify source")
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
        def start_daemon():
            with open("/content/ollama-ath-real.log", "ab") as handle:
                subprocess.Popen(["ollama", "serve"], stdout=handle, stderr=subprocess.STDOUT,
                                 start_new_session=True,
                                 env={**os.environ, "OLLAMA_NUM_PARALLEL": "1", "OLLAMA_KEEP_ALIVE": "-1"})
            for _ in range(120):
                if daemon_up(): break
                time.sleep(1)
            else: raise RuntimeError("Ollama failed to start; inspect /content/ollama-ath-real.log")

        def restart_daemon():
            """Release host memory held by the daemon and the page cache; weights stay on disk."""
            subprocess.run(["pkill", "-f", "ollama serve"], check=False)
            for _ in range(30):
                if not daemon_up(): break
                time.sleep(1)
            subprocess.run("sync; echo 3 > /proc/sys/vm/drop_caches", shell=True, check=False)
            start_daemon()

        if not daemon_up():
            start_daemon()
        assert get_json("/api/version")["version"] == OLLAMA_VERSION, "Use a fresh session with the pinned daemon."
        subprocess.run(["ollama", "pull", MODEL], check=True)
        stage_done("install Ollama and pull the model")
    ''')
    add("markdown", "## 3. Upload the sealed case bundle\nUpload one ZIP of the bundle folder. Its seal and every case's telemetry digest are checked before anything runs.")
    add("code", '''
        from google.colab import files
        from ath.evaluation.real_cases import read_bundle, real_cases
        saved_zip = OUTPUT / "CASES.zip"
        if saved_zip.exists():
            zip_bytes = saved_zip.read_bytes()
            print("Reusing the case bundle saved with this run:", saved_zip)
        else:
            uploaded = files.upload()
            assert len(uploaded) == 1, "Upload exactly one case-bundle ZIP."
            (zip_name, zip_bytes), = uploaded.items()
            with saved_zip.open("xb") as handle: handle.write(zip_bytes)
        CASES_ZIP_SHA256 = hashlib.sha256(zip_bytes).hexdigest()
        CASES_ROOT = Path("/content") / ("ath-cases-" + CASES_ZIP_SHA256[:12])
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            for member in archive.infolist():
                target = (CASES_ROOT / member.filename).resolve()
                assert CASES_ROOT.resolve() in target.parents or target == CASES_ROOT.resolve(), "Invalid path in ZIP"
                if member.is_dir(): continue
                data = archive.read(member)
                if target.exists():
                    assert target.read_bytes() == data, f"Conflicting file: {target}"
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as handle: handle.write(data)
        found = sorted(p.parent for p in CASES_ROOT.rglob("BUNDLE.json"))
        assert len(found) == 1, f"Expected one BUNDLE.json in the ZIP, found {len(found)}"
        CASE_BUNDLE = found[0]
        case_bundle = read_bundle(CASE_BUNDLE)
        investigable = real_cases(CASE_BUNDLE)
        statuses = {}
        for entry in case_bundle["cases"]:
            statuses[entry["status"]] = statuses.get(entry["status"], 0) + 1
        SEED_MODE = case_bundle.get("seed_mode", "detection")
        print(json.dumps({"bundle": case_bundle["name"], "bundle_sha256": case_bundle["bundle_sha256"],
                          "seed_mode": SEED_MODE, "statuses": statuses}, indent=2))
        if SEED_MODE == "analyst":
            print("ANALYST-SEEDED INVESTIGATION, NOT END-TO-END ATH: cases start from the labelled anchor "
                  "events, whatever ATH detection raised. Results measure investigation, not detection.")
        assert investigable, "No investigable case in this bundle (detection mode: ATH raised none of the labelled incidents)."
        stage_done("load and verify the case bundle")
    ''')
    add("markdown", "## 4. Optional restore and result export\nOnly this notebook's checkpoints are accepted. Existing files cannot be overwritten with conflicting contents.")
    add("code", '''
        if RESTORE_CHECKPOINT and not USE_DRIVE:
            for name, blob in files.upload().items():
                with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                    pending = []
                    for member in archive.infolist():
                        target = (OUTPUT.parent / member.filename).resolve()
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
                    if path.is_file(): archive.write(path, path.relative_to(OUTPUT.parent))
            print("Saved", target)
            try:
                files.download(str(target))
            except Exception as exc:
                print(f"Browser download failed ({type(exc).__name__}); download it from the Files pane.")
            if USE_DRIVE:
                print("All results are also in Google Drive:", OUTPUT)

        def run_module(module, *args, allow=(0,)):
            command = [sys.executable, "-m", module, *map(str, args)]
            print("+", " ".join(command), flush=True)
            result = subprocess.run(command, cwd=REPO)
            if result.returncode not in allow: raise RuntimeError(f"Evaluator exited {result.returncode}")
            return result.returncode

        pilot = lambda *a, **k: run_module("ath.evaluation.auth_execution", *a, **k)
        real = lambda *a, **k: run_module("ath.evaluation.real_cases", "--bundle", CASE_BUNDLE, *a, **k)
    ''')
    add("markdown", "## 5. Freeze and preload before timed cases\nWeights are loaded with an empty request, not an investigation prompt. Placement and loading time are recorded separately.")
    add("code", '''
        from ath.evaluation.auth_execution import _client, profile_for
        profile = profile_for(PROFILE)
        client = _client(MODEL, profile)
        if (DEV / "FREEZE.json").exists(): pilot("summarise", "--out", DEV)
        else: pilot("freeze", "--out", DEV, "--split", "dev", "--repeats", 1, "--model", MODEL, "--profile", PROFILE)
        if (REAL / "FREEZE.json").exists(): real("summarise", "--out", REAL)
        else: real("freeze", "--out", REAL, "--repeats", 1, "--model", MODEL, "--profile", PROFILE)
        for path in (DEV, REAL):
            frozen = json.loads((path / "FREEZE.json").read_text())
            assert frozen["profile"] == profile.to_dict() and frozen["model_configuration"] == client.configuration()
        context = {"run_id": RUN_ID, "model": MODEL, "profile": profile.to_dict(),
                   "source_sha256": source_hash(), "bundle_sha256": BUNDLE_SHA256,
                   "case_bundle_sha256": case_bundle["bundle_sha256"], "case_zip_sha256": CASES_ZIP_SHA256,
                   "preload_before_cases": True}
        context_path = OUTPUT / "RUN_CONTEXT.json"
        if context_path.exists(): assert json.loads(context_path.read_text()) == context, "Different bundle or source for this run"
        else:
            with context_path.open("x") as handle: json.dump(context, handle, indent=2)
        for name, data in (("SOURCE.zip", payload), ("CASES.zip", zip_bytes)):
            copy = OUTPUT / name
            if copy.exists(): assert copy.read_bytes() == data
            else:
                with copy.open("xb") as handle: handle.write(data)
        def preload(reason="initial"):
            request = urllib.request.Request("http://127.0.0.1:11434/api/generate",
                data=json.dumps({"model": MODEL, "stream": False, "keep_alive": -1,
                                 "options": {"num_ctx": client.num_ctx}}).encode(),
                headers={"Content-Type": "application/json"})
            started = time.perf_counter()
            with urllib.request.urlopen(request, timeout=600) as response: loaded = json.load(response)
            assert not loaded.get("error"), loaded
            residency = client.residency()
            from datetime import datetime, timezone
            record = {"gpu": gpu_info, "model": MODEL, "residency": residency, "reason": reason,
                      "load_seconds": time.perf_counter() - started, "task_prompt_sent": False}
            preloads = OUTPUT / "preloads"
            preloads.mkdir(exist_ok=True)
            with (preloads / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")).open("x") as handle:
                json.dump(record, handle, indent=2)
            print(json.dumps(record, indent=2))
            assert residency["size"] and residency["size_vram"] >= residency["size"], "Model is not fully on GPU. Use a fresh T4 GPU session; do not start a CPU run."

        preload()
        stage_done("freeze and preload the model")
    ''')
    add("markdown", "## 6. Smoke gate: the three synthetic development cases\nThe checkpoint downloads before the gate is checked. Every failed row is preserved.")
    add("code", '''
        try:
            pilot("run", "--out", DEV, "--arm", "both", allow=(0, 3))
        finally:
            try: pilot("summarise", "--out", DEV)
            finally: export_results("gate_checkpoint")
        gate = json.loads((DEV / "SUMMARY.json").read_text())
        print(json.dumps(gate["arms"]["d1"], indent=2))
        stage_done("smoke gate")
        assert gate["complete_comparison"] and gate["arms"]["d1"]["complete"] == gate["arms"]["d1"]["rows"] == 3, "Smoke gate failed. Keep the checkpoint for review; do not delete failed rows."
    ''')
    add("markdown", "## 7. Real cases\nRuns only after the gate passes. The results ZIP includes the case bundle, so it is self-contained.")
    add("code", '''
        gate = json.loads((DEV / "SUMMARY.json").read_text())
        assert gate["arms"]["d1"]["complete"] == gate["arms"]["d1"]["rows"] == 3, "Smoke gate must pass first."
        MAX_RESTARTS = 2
        try:
            for attempt in range(MAX_RESTARTS + 1):
                code = real("run", "--out", REAL, "--arm", "both", allow=(0, 3))
                if code == 0 or attempt == MAX_RESTARTS: break
                # The blocked row is already recorded as an attempt stub; it is retried, not skipped.
                print(f"RAM guard blocked a row; restarting Ollama ({attempt + 1}/{MAX_RESTARTS}) and resuming.", flush=True)
                restart_daemon()
                preload(reason=f"restart after RAM guard block {attempt + 1}")
        finally:
            try: real("summarise", "--out", REAL)
            finally: export_results("real_results")
        result = json.loads((REAL / "SUMMARY.json").read_text())
        print(json.dumps({k: result.get(k) for k in ("evaluation", "conclusion", "holdout", "secondary_check", "not_evaluated",
                                                     "blocked_rows", "errored_rows", "investigable_cases",
                                                     "not_investigable_counts", "arms")}, indent=2))
        stage_done("real cases")
    ''')
    add("markdown", """
        ## What to send back
        Keep the gate checkpoint and the real-results ZIP; with Drive on, the same files are
        in `MyDrive/ath-holdout-runs/`. They include `timings.log` and the frozen
        settings, source snapshot, the case bundle, full bounded model replies, GPU
        preload records, reports and summaries.

        Read accuracy, malicious cases cleared as benign, false accusations, abstention
        and the not-investigable counts together. A case ATH never detected tells you
        about detection coverage, not about the model.
    """)
    notebook = {"cells": cells, "metadata": {"accelerator": "GPU",
        "colab": {"name": target.name, "provenance": []},
        "kernelspec": {"display_name": "Python 3", "name": "python3"},
        "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(notebook, indent=1, ensure_ascii=False) + "\n")
    print(f"Built {target.name}: {len(bundle):,} source ZIP bytes; sha256 {bundle_hash}")
    return target


if __name__ == "__main__":
    build()
