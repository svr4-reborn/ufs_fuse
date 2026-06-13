#!/usr/bin/env python3
"""Reference BFS formatter for the Rust differential test.

`format <out> <size>` writes a BFS image of `size` bytes containing a fixed set
of files (kept in sync with differential_format.rs) using the Python reference
`build_bfs_filesystem_image`. Run with PYTHONPATH pointed at the host-tools pkg.
"""
import sys

from host_tools.fs.bfs import build_bfs_filesystem_image

FILES = [('unix', b'K' * 5000), ('boot', b'BL'), ('empty', b'')]


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] != 'format':
        print('usage: bfs_tool.py format <out> <size>', file=sys.stderr)
        return 2
    out, size = sys.argv[2], int(sys.argv[3])
    data = build_bfs_filesystem_image(size, FILES, timestamp=0)
    with open(out, 'wb') as handle:
        handle.write(data)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
