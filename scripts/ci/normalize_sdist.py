#!/usr/bin/env python3
"""Rewrite an sdist with deterministic tar and gzip metadata."""

import argparse
import gzip
import os
import tarfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("epoch", type=int)
    args = parser.parse_args()
    output = args.archive.with_suffix(args.archive.suffix + ".normalized")
    with tarfile.open(args.archive, "r:gz") as source:
        members = sorted(source.getmembers(), key=lambda member: member.name)
        with output.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=args.epoch) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as target:
                    for member in members:
                        member.uid = 0
                        member.gid = 0
                        member.uname = "root"
                        member.gname = "root"
                        member.mtime = args.epoch
                        member.pax_headers = {}
                        content = source.extractfile(member) if member.isfile() else None
                        target.addfile(member, content)
    os.replace(output, args.archive)


if __name__ == "__main__":
    main()
