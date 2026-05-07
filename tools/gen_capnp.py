#!/usr/bin/env python3
import os
import subprocess
import sys

def main() -> int:
    if len(sys.argv) != 4:
        print("usage: gen_capnp.py <schema_dir> <out_dir> <source>", file=sys.stderr)
        return 1
    schema_dir, out_dir, source = sys.argv[1:]
    # Fix double v8 path issue
    import re
    source = re.sub(r'/v8/\.\./\.\./v8/', '/v8/', source)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [
        "capnp",
        "compile",
        "-I/usr/include",
        "--src-prefix=" + os.path.dirname(source),
        "-o",
        f"c++:{out_dir}",
        source,
    ]
    return subprocess.call(cmd)

if __name__ == "__main__":
    sys.exit(main())
