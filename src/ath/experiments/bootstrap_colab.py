"""Everything a Colab session did in twelve cells of plumbing, as functions.

Nothing here is Colab-specific in principle: an Ollama daemon, a checksummed telemetry
cache, row files that travel as zips, an export at the end. What was Colab-specific in
practice -- ``google.colab.files`` -- is imported inside the one function that needs it,
so a notebook that skipped the upload cell no longer fails at the download cell.

Rows are restored *through the layout*: a zip member counts only when it sits directly
under this experiment's ``rows/<arm>_<model>/m<manifest>_<prompt>/`` directory, so a zip
from another manifest, or a zip built with a different root, copies nothing rather than
the wrong thing.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ath.experiments.paths import ROOT, Layout

CACHED_SUBDIRS = ("flaws_cloud", "dedale")
Log = Callable[[str], None]


def _stderr(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


# -- daemon ---------------------------------------------------------------------------------


def daemon_up(base_url: str, timeout: float = 2.0) -> bool:
    try:
        urllib.request.urlopen(base_url.rstrip("/") + "/api/version", timeout=timeout)
        return True
    except Exception:  # noqa: BLE001 -- any failure means "not up"
        return False


def ensure_ollama(base_url: str, *, log_path: Path, wait_seconds: int = 120, log: Log = _stderr) -> str:
    """Install Ollama if absent, start the daemon if down, return its version."""
    if shutil.which("ollama") is None:
        log("installing ollama ...")
        subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=True)
    if not daemon_up(base_url):
        handle = open(log_path, "ab")  # noqa: SIM115 -- the daemon outlives this call
        subprocess.Popen(["ollama", "serve"], stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(wait_seconds):
            if daemon_up(base_url):
                break
            time.sleep(1)
        else:
            raise SystemExit(f"ollama daemon did not start; see {log_path}")
    version = json.load(urllib.request.urlopen(base_url.rstrip("/") + "/api/version"))["version"]
    log(f"ollama {version} is up at {base_url}")
    return str(version)


def pull_model(model: str, log: Log = _stderr) -> None:
    log(f"ollama pull {model}")
    subprocess.run(["ollama", "pull", model], check=True)


def install_tools(log: Log = _stderr) -> None:
    if shutil.which("zstd") is None and shutil.which("apt-get") is not None:
        subprocess.run(["apt-get", "-qq", "install", "-y", "zstd"], check=True, capture_output=True)
        log("installed zstd")


# -- telemetry cache ------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_tree(root: Path, subdirs: Iterable[str] = CACHED_SUBDIRS) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for sub in subdirs:
        for path in sorted((root / sub).rglob("*")):
            if path.is_file():
                out[str(path.relative_to(root)).replace("\\", "/")] = {
                    "bytes": path.stat().st_size, "sha256": sha256_file(path),
                }
    return out


def cache_is_valid(cache_root: Path, *, full: bool = True, log: Log = _stderr) -> bool:
    """Sizes of every file and, by default, the sha256 of every file too.

    The earlier notebook hashed a 25-file sample "because a full hash on Drive is slow";
    the cache is local now, and a restore hashes the whole tree anyway.
    """
    checksums = cache_root / "CHECKSUMS.json"
    data = cache_root / "data_external"
    if not checksums.exists() or not data.exists():
        return False
    recorded = json.loads(checksums.read_text(encoding="utf-8"))["files"]
    if not recorded:
        return False
    for rel, meta in recorded.items():
        path = data / rel
        if not path.exists() or path.stat().st_size != meta["bytes"]:
            log(f"cache invalid: size mismatch or missing {rel}")
            return False
    names = sorted(recorded) if full else sorted(recorded)[::max(1, len(recorded) // 25)]
    for rel in names:
        if sha256_file(data / rel) != recorded[rel]["sha256"]:
            log(f"cache invalid: sha256 mismatch {rel}")
            return False
    return True


def restore_telemetry_cache(cache_root: Path, external: Path, log: Log = _stderr) -> int:
    data = cache_root / "data_external"
    recorded = json.loads((cache_root / "CHECKSUMS.json").read_text(encoding="utf-8"))["files"]
    for sub in CACHED_SUBDIRS:
        shutil.copytree(data / sub, external / sub, dirs_exist_ok=True)
    restored = checksum_tree(external)
    bad = [r for r in recorded if restored.get(r, {}).get("sha256") != recorded[r]["sha256"]]
    if bad:
        raise SystemExit(
            f"restored copy differs from the cache checksums for {len(bad)} file(s), e.g. {bad[:3]}; "
            "delete the cache and refetch"
        )
    log(f"restored and verified {len(restored)} telemetry file(s) into {external}")
    return len(restored)


def have_telemetry(external: Path) -> bool:
    return all((external / s).is_dir() and any((external / s).iterdir()) for s in CACHED_SUBDIRS)


def fetch_telemetry(log: Log = _stderr) -> None:
    log("fetching telemetry (several minutes) ...")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "fetch_external.py"), "flaws_cloud"], check=True, cwd=ROOT)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "dedale_fetch_hours.py"), "--days", "2"], check=True, cwd=ROOT)


def ensure_telemetry(external: Path, cache_root: Path | None, log: Log = _stderr) -> str:
    """Cache if valid, else what is already on disk, else a fetch. Returns which."""
    if cache_root is not None and cache_root.exists() and cache_is_valid(cache_root, log=log):
        restore_telemetry_cache(cache_root, external, log=log)
        return "cache"
    if have_telemetry(external):
        log(f"telemetry already present under {external}")
        return "present"
    fetch_telemetry(log=log)
    return "fetched"


def build_telemetry_cache(external: Path, cache_root: Path, log: Log = _stderr) -> Path:
    if cache_root.exists():
        shutil.rmtree(cache_root)
    (cache_root / "data_external").mkdir(parents=True)
    for sub in CACHED_SUBDIRS:
        shutil.copytree(external / sub, cache_root / "data_external" / sub)
    files = checksum_tree(cache_root / "data_external")
    (cache_root / "CHECKSUMS.json").write_text(json.dumps({
        "source": "data/external as fetched by scripts/fetch_external.py flaws_cloud and scripts/dedale_fetch_hours.py --days 2",
        "subdirs": list(CACHED_SUBDIRS), "files": files,
    }, indent=1), encoding="utf-8")
    log(f"telemetry cache built at {cache_root}: {len(files)} file(s)")
    return cache_root


# -- rows in and out --------------------------------------------------------------------------


def unpack_uploads(uploads: Path, log: Log = _stderr) -> list[Path]:
    """Telemetry cache zips are unpacked in place; row zips are left for restore_rows."""
    zips = sorted(uploads.glob("*.zip"))
    for path in zips:
        if path.name.startswith("telemetry_cache"):
            with zipfile.ZipFile(path) as archive:
                archive.extractall(uploads)
            log(f"unpacked {path.name}")
    return zips


def _relative_rows_dir(layout: Layout) -> str:
    return str(layout.rows_dir.relative_to(layout.out_dir)).replace("\\", "/")


def _member_belongs(name: str, rel: str) -> bool:
    """A zip member is this experiment's row when it sits *directly* under ``rel``."""
    posix = name.replace("\\", "/")
    marker = "/" + rel + "/"
    index = posix.find(marker)
    if index < 0 and posix.startswith(rel + "/"):
        index = -1
        marker = rel + "/"
    if index < 0 and not posix.startswith(rel + "/"):
        return False
    tail = posix[(index + len(marker)) if index >= 0 else len(marker):]
    return "/" not in tail and tail.endswith(".json") and not tail.endswith(".reason.json")


def restore_rows(layout: Layout, zips: Iterable[Path], results_roots: Iterable[Path] = (), log: Log = _stderr) -> dict[str, int]:
    """Copy this identity's row files out of the zips and results folders. Never overwrites;
    ``validate-rows`` decides afterwards whether a restored row belongs."""
    dest = layout.rows_dir
    dest.mkdir(parents=True, exist_ok=True)
    rel = _relative_rows_dir(layout)
    copied = skipped = 0
    for path in zips:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not _member_belongs(name, rel):
                    continue
                target = dest / Path(name).name
                if target.exists():
                    skipped += 1
                    continue
                target.write_bytes(archive.read(name))
                copied += 1
    for root in results_roots:
        source_dir = Path(root) / layout.manifest_digest[:12] / rel
        if not source_dir.is_dir():
            continue
        for source in sorted(source_dir.glob("*.json")):
            if source.name.endswith(".reason.json"):
                continue
            target = dest / source.name
            if target.exists():
                skipped += 1
                continue
            shutil.copy2(source, target)
            copied += 1
    log(f"{layout.model}: restored {copied} row file(s) into {rel}, {skipped} already present")
    return {"copied": copied, "skipped": skipped}


def save_results(layout: Layout, results_root: Path, repeat: int, log: Log = _stderr) -> Path:
    """Rows + quarantine + freeze + summary + manifest + run records under
    ``results_root/<manifest12>/``, mirroring the dev tree. Existing files are kept."""
    target = Path(results_root) / layout.manifest_digest[:12]
    rel = _relative_rows_dir(layout)
    rows_dst = target / rel
    rows_dst.mkdir(parents=True, exist_ok=True)
    if layout.rows_dir.is_dir():
        shutil.copytree(layout.rows_dir, rows_dst, dirs_exist_ok=True)
    if layout.quarantine_dir.is_dir():
        shutil.copytree(layout.quarantine_dir, rows_dst.with_name(rows_dst.name + ".quarantine"), dirs_exist_ok=True)
    if layout.runs_dir.is_dir():
        shutil.copytree(layout.runs_dir, target / "runs", dirs_exist_ok=True)
    for source in (
        layout.out_dir / "MANIFEST.json", layout.out_dir / "MANIFEST.md", layout.environment_path,
        layout.summary_json(repeat), layout.summary_md(repeat),
    ):
        if source.exists() and not (target / source.name).exists():
            shutil.copy2(source, target / source.name)
    rows = sum(1 for _ in rows_dst.glob("*.json"))
    log(f"saved {layout.model}: {rows} row(s) + records under {target}")
    return target


def export_zip(name: str, sources: Iterable[Path], *, workdir: Path, download: bool = True, log: Log = _stderr) -> Path:
    """Zip ``sources`` (relative to ``workdir``) and, in Colab, trigger the browser download."""
    zip_path = workdir / f"{name}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sources:
            source = Path(source)
            if not source.exists():
                continue
            for path in sorted(source.rglob("*")) if source.is_dir() else [source]:
                if path.is_file():
                    archive.write(path, str(path.relative_to(workdir)))
    log(f"{zip_path} ({zip_path.stat().st_size / 1e6:.1f} MB)")
    if download:
        try:
            from google.colab import files  # type: ignore[import-not-found]
        except ImportError:
            log("not in Colab: no browser download; the zip is on disk")
        else:
            files.download(str(zip_path))
    return zip_path


def write_session(target: Path, layout: Layout, *, base_url: str, models: Iterable[str], extra: dict[str, Any] | None = None) -> Path:
    """What this session was, read from the run records rather than typed by hand."""
    from ath.evaluation.ablation.local import available_ram_bytes, gpu_summary
    from ath.experiments.runs import git_tree

    records = []
    if layout.runs_dir.is_dir():
        for path in sorted(layout.runs_dir.glob("RUN_*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            records.append({k: payload.get(k) for k in ("run_id", "subcommand", "status", "exit_code", "started_at", "ended_at", "counts")})
    session = {
        "exported_at": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "manifest_hash": layout.manifest_digest,
        "tree": git_tree(),
        "models": list(models),
        "gpus": gpu_summary(),
        "ram_available_bytes": available_ram_bytes(),
        "ollama_version": json.load(urllib.request.urlopen(base_url.rstrip("/") + "/api/version"))["version"] if daemon_up(base_url) else None,
        "runs": records,
        **(extra or {}),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(session, indent=1, default=str) + "\n", encoding="utf-8")
    return target


# -- the one call ----------------------------------------------------------------------------


def bootstrap(
    *, base_url: str, external: Path, uploads: Path, models: Iterable[str],
    daemon_log: Path, skip_fetch: bool = False, inject: bool = True, log: Log = _stderr,
) -> dict[str, Any]:
    """Tools, daemon, telemetry, injected cases, manifest. Rows are restored per model
    after the manifest exists (``restore_rows``), because the layout needs its hash."""
    from ath.experiments.manifest_build import build_dev_manifest, inject_cases

    install_tools(log=log)
    version = ensure_ollama(base_url, log_path=daemon_log, log=log)
    for model in models:
        pull_model(model, log=log)
    uploads.mkdir(parents=True, exist_ok=True)
    zips = unpack_uploads(uploads, log=log)
    telemetry = "skipped" if skip_fetch else ensure_telemetry(external, uploads / "telemetry_cache", log=log)
    if inject:
        code = inject_cases(external=external)
        if code != 0:
            raise SystemExit(f"local_inject_dedale.py exited {code}")
    payload = build_dev_manifest(external=external, log=log)
    return {
        "ollama_version": version, "telemetry": telemetry, "zips": [z.name for z in zips],
        "manifest_hash": payload["manifest_hash"], "cases": len(payload["cases"]),
    }
