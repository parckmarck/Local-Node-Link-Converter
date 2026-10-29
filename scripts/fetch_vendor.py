"""Fetch pinned build inputs, never called by the running application."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent.parent
CORE_VERSION = "v1.19.33"
CORE_ARCHIVE = "mihomo-windows-amd64-v1-v1.19.33.zip"
CORE_SHA256 = "fb0b960eff568459502d4ebe53e9cca203053d86ec9024fe935f19615d74d9aa"
LUCIDE_VERSION = "0.468.0"
ICONS = [
    "network", "server", "link", "settings-2", "plus", "check", "play", "square",
    "copy", "folder-open", "power", "refresh-cw", "pencil", "trash-2", "activity",
    "shield-check", "globe", "triangle-alert", "x", "circle-check", "circle-x",
    "download", "upload", "search", "chevron-right", "chevron-down", "arrow-right",
    "file-text", "ellipsis", "rotate-cw", "filter", "check-check", "eye", "eye-off",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", default="")
    args = parser.parse_args()
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    def fetch(url: str) -> bytes:
        for attempt in range(3):
            try:
                opener = build_opener(ProxyHandler(proxies))
                with opener.open(Request(url, headers={"User-Agent": "NodeDesk-build/1.0"}), timeout=45) as response:
                    return response.read(128 * 1024 * 1024)
            except HTTPError as error:
                if error.code < 500 and error.code != 429:
                    raise
                if attempt == 2:
                    raise
            except (URLError, TimeoutError, ConnectionError):
                if attempt == 2:
                    raise
            time.sleep(1 + attempt)
        raise RuntimeError("Download failed.")

    vendor = ROOT / "vendor"
    icons = ROOT / "assets" / "icons"
    licenses = ROOT / "licenses"
    for directory in (vendor, icons, licenses):
        directory.mkdir(parents=True, exist_ok=True)
    archive_path = vendor / CORE_ARCHIVE
    archive = archive_path.read_bytes() if archive_path.exists() else fetch(
        f"https://github.com/MetaCubeX/mihomo/releases/download/{CORE_VERSION}/{CORE_ARCHIVE}"
    )
    if hashlib.sha256(archive).hexdigest() != CORE_SHA256:
        raise RuntimeError("Mihomo download did not match the pinned SHA256.")
    archive_path.write_bytes(archive)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        executables = [name for name in bundle.namelist() if name.endswith(".exe")]
        if len(executables) != 1:
            raise RuntimeError("Unexpected core archive.")
        executable = bundle.read(executables[0])
    if not executable.startswith(b"MZ"):
        raise RuntimeError("Expected a Windows PE binary.")
    (vendor / "mihomo.exe").write_bytes(executable)
    core_license = fetch(f"https://raw.githubusercontent.com/MetaCubeX/mihomo/{CORE_VERSION}/LICENSE")
    (licenses / "mihomo-LICENSE.txt").write_bytes(core_license)
    (licenses / "lucide-LICENSE.txt").write_bytes(fetch(
        f"https://raw.githubusercontent.com/lucide-icons/lucide/{LUCIDE_VERSION}/LICENSE"
    ))

    def fetch_icon(name: str):
        cached = icons / f"{name}.svg"
        data = cached.read_bytes() if cached.exists() else fetch(
            f"https://raw.githubusercontent.com/lucide-icons/lucide/{LUCIDE_VERSION}/icons/{name}.svg"
        )
        if b"<svg" not in data:
            raise RuntimeError(f"Invalid icon: {name}")
        (icons / f"{name}.svg").write_bytes(data)
        return name, hashlib.sha256(data).hexdigest()

    with ThreadPoolExecutor(max_workers=3) as pool:
        icon_hashes = dict(pool.map(fetch_icon, ICONS))
    manifest = {
        "mihomo": {"version": CORE_VERSION, "archive": CORE_ARCHIVE, "sha256": CORE_SHA256,
                   "executable_sha256": hashlib.sha256(executable).hexdigest()},
        "lucide": {"version": LUCIDE_VERSION, "sha256": icon_hashes},
    }
    (vendor / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Verified core {CORE_VERSION}; fetched {len(icon_hashes)} Lucide icons.")


if __name__ == "__main__":
    main()
