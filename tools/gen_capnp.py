#!/usr/bin/env python3

import os
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: gen_capnp.py <schema_dir> <out_dir> <source>", file=sys.stderr)
        return 1

    schema_dir, out_dir, source = sys.argv[1:]
    os.makedirs(out_dir, exist_ok=True)

    cmd = [
        "capnp",
        "compile",
        "-I",
        schema_dir,
        "-o",
        f"c++:{out_dir}",
        source,
    ]
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
