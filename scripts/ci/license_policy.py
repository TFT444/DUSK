#!/usr/bin/env python3
"""Enforce the approved licences for the dependencies shipped by DUSK."""

import re
import subprocess
from pathlib import Path
from shutil import which

ALLOWED = (
    "Apache-2.0;BSD License;BSD-2-Clause;BSD-3-Clause;"
    "GNU General Public License v2 (GPLv2);MIT;MIT License;"
    "MPL-2.0;PSF-2.0;Python Software Foundation License;"
    "Apache-2.0 OR BSD-2-Clause"
)
LOCKS = (Path("ci/requirements.lock"), Path("ci/example-requirements.lock"))


def main() -> None:
    packages: set[str] = set()
    for lock in LOCKS:
        packages.update(re.findall(r"(?m)^([A-Za-z0-9_.-]+)==", lock.read_text(encoding="utf-8")))
    if not packages:
        raise SystemExit("no locked packages found for licence validation")
    executable = which("pip-licenses")
    if executable is None:
        raise SystemExit("pip-licenses is not installed")
    subprocess.run(  # noqa: S603 - names are restricted by ENTRY's package-name grammar.
        [executable, "--packages", *sorted(packages), "--allow-only", ALLOWED],
        check=True,
    )


if __name__ == "__main__":
    main()
