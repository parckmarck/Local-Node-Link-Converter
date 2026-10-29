# Third-Party Notices

Node Desk uses independently maintained open-source components. This file
records provenance and build inputs; it does not replace their license texts.
No upstream proxy protocol implementation was copied into the Python adapters.

| Component | Pinned Build Input | License / Source |
| --- | --- | --- |
| Mihomo | v1.19.33, Windows amd64-v1 | GPL-3.0; https://github.com/MetaCubeX/mihomo/tree/v1.19.33 |
| Python | 3.12.2 in this local build | PSF and included third-party terms; https://www.python.org/downloads/release/python-3122/ |
| PySide6 / Shiboken / Qt | 6.11.0 | LGPL-3.0 or GPL alternatives; https://code.qt.io/cgit/pyside/pyside-setup.git/tree/?h=v6.11.0 and https://download.qt.io/official_releases/qt/6.11/6.11.0/ |
| PyYAML | 6.0.2 | MIT; https://github.com/yaml/pyyaml/tree/6.0.2 |
| Lucide icons | 0.468.0 | ISC / included Feather attribution; https://github.com/lucide-icons/lucide/tree/0.468.0 |
| PyInstaller bootloader | 6.21.0 | GPL-2.0-or-later with the upstream distribution exception; https://github.com/pyinstaller/pyinstaller/tree/v6.21.0 |

Qt libraries are dynamically bundled in the `_internal` directory of the
portable build. The Python application sources, dependency versions, build
script, and spec file are supplied alongside this project. No protection
against replacing or debugging these dynamically linked libraries is added.
Keep license texts and these notices with copies of the application.

The Mihomo executable is an unmodified separate process, used only for
user-initiated tests. The binary archive's SHA256 is pinned in
`scripts/fetch_vendor.py` and `vendor/manifest.json`. It is fetched from the
official release, not a third-party binary mirror.

`scripts/fetch_sources.py` retrieves the matching Mihomo tagged source and
release-supplied `vendor.tar.gz` / `toolchain.tar.gz`, together with license
texts for the used Qt/Python components. It writes only project-local files.
The fetched source archive manifest records checksums and upstream URLs.
Keep these materials available when redistributing the separate GPL core.
Do not replace the source reference with Mihomo's unrelated default branch.

Additional dependency license files collected by PyInstaller remain in
`_internal` when present. Microsoft runtime files distributed by Python/Qt
retain their original terms and are not authored by Node Desk.
