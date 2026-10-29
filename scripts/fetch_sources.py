"""Fetch provenance materials from official upstream sources for local packaging."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [
    (
        "mihomo-v1.19.33-source.tar.gz",
        "https://codeload.github.com/MetaCubeX/mihomo/tar.gz/refs/tags/v1.19.33", None,
    ),
    (
        "mihomo-v1.19.33-vendor.tar.gz",
        "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/vendor.tar.gz",
        "7ac4d4da0e6a29ef6ed18d2cf8f4c58d361d049ae364fd841acc883aa3a9e1cc",
    ),
    (
        "mihomo-v1.19.33-toolchain.tar.gz",
        "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/toolchain.tar.gz",
        "a827640a1ae37475583ed82eb762ed563d40a4eeb83461acfb5ee8ff10fe4a55",
    ),
]
LICENSES = [
    ("Qt-LGPL-3.0.txt", "https://raw.githubusercontent.com/qt/qtbase/v6.11.0/LICENSES/LGPL-3.0-only.txt"),
    ("Qt-GPL-3.0.txt", "https://raw.githubusercontent.com/qt/qtbase/v6.11.0/LICENSES/GPL-3.0-only.txt"),
    ("PySide-BSD-3-Clause.txt", "https://raw.githubusercontent.com/qtproject/pyside-pyside-setup/v6.11.0/LICENSES/BSD-3-Clause.txt"),
    ("PyYAML-MIT.txt", "https://raw.githubusercontent.com/yaml/pyyaml/6.0.2/LICENSE"),
    ("PyInstaller-License.txt", "https://raw.githubusercontent.com/pyinstaller/pyinstaller/v6.21.0/COPYING.txt"),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", default="")
    args = parser.parse_args()
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}
    output, licenses = ROOT / "third_party_sources", ROOT / "licenses"
    output.mkdir(exist_ok=True)
    licenses.mkdir(exist_ok=True)

    def download(url):
        for attempt in range(3):
            try:
                opener = build_opener(ProxyHandler(proxies))
                with opener.open(Request(url, headers={"User-Agent": "NodeDesk-build/1.0"}), timeout=90) as response:
                    return response.read(256 * 1024 * 1024)
            except HTTPError as error:
                if error.code < 500 or attempt == 2:
                    raise
            except (URLError, TimeoutError, ConnectionError):
                if attempt == 2:
                    raise
            time.sleep(attempt + 1)
        raise RuntimeError("Download failed.")

    manifest = {}
    for name, url, checksum in SOURCES:
        path = output / name
        data = path.read_bytes() if path.exists() else download(url)
        actual = hashlib.sha256(data).hexdigest()
        if checksum is not None and actual != checksum:
            raise RuntimeError(f"Checksum mismatch: {name}")
        path.write_bytes(data)
        manifest[name] = {"url": url, "sha256": actual, "bytes": len(data)}
        print(f"Source ready: {name} ({len(data)} bytes)", flush=True)
    for name, url in LICENSES:
        path = licenses / name
        data = path.read_bytes() if path.exists() else download(url)
        if len(data) < 500:
            raise RuntimeError(f"Unexpected license payload: {name}")
        path.write_bytes(data)
        print(f"License ready: {name}", flush=True)
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if python_license.is_file():
        shutil.copyfile(python_license, licenses / "Python-License.txt")
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print("Provenance materials are ready.")


if __name__ == "__main__":
    main()
