#!/usr/bin/env python3
"""Build a populated UFS image and a manifest of its tree, for the Rust
differential read test.

Run from the repo's `host-tools/` directory (so `import host_tools` works):

    python3 gen_ufs_image.py <image_out> <manifest_out>

The image is produced with the *Python* UFS writer, and the manifest is produced
by the *Python* UFS reader walking that image. The Rust reader must reproduce the
manifest byte-for-byte, which pins the Rust read path against the reference.
"""
from __future__ import annotations

import hashlib
import json
import sys

from host_tools.fs.ufs import (
    UFS_IFDIR,
    UFS_IFLNK,
    UFS_IFMT,
    UFS_IFREG,
    UFS_ROOT_INODE,
    create_ufs_file,
    detect_ufs_at_start,
    format_ufs_filesystem,
    iter_ufs_directory_entries,
    link_ufs_path,
    make_ufs_directory,
    read_ufs_file,
    read_ufs_inode,
    symlink_ufs_path,
)


def build_image() -> tuple[bytearray, object]:
    # ~8 MiB, 4 KiB blocks => nindir = 1024, so a file just over
    # (12 + 1024) * 4096 bytes exercises the double-indirect path.
    image = bytearray(8 * 1024 * 1024)
    filesystem = format_ufs_filesystem(image, block_size=4096, timestamp=0)

    make_ufs_directory(image, filesystem, '/dir', mode=0o755)
    make_ufs_directory(image, filesystem, '/dir/sub', mode=0o700)

    block_size = int(filesystem.details['bsize'])
    nindir = int(filesystem.details['nindir'])

    cases = {
        '/empty': b'',
        '/dir/small': b'hello world\n',
        '/dir/frag': bytes(range(256)) * 3,                       # < one block
        '/dir/oneblock': b'B' * block_size,                       # exactly one block
        '/dir/multiblock': b'M' * (block_size * 5 + 123),         # several direct blocks
        '/dir/sub/indirect': bytes((i * 7) & 0xFF for i in range(block_size * 20)),  # single indirect
        # > (12 + nindir) blocks -> reaches the double-indirect tree.
        '/dir/sub/big': bytes((i * 31) & 0xFF for i in range((12 + nindir + 5) * block_size)),
    }
    for path, data in cases.items():
        create_ufs_file(image, filesystem, path, data, mode=0o644)

    symlink_ufs_path(image, filesystem, 'dir/small', '/link-to-small')
    link_ufs_path(image, filesystem, '/dir/small', '/dir/hardlink')

    return image, filesystem


def node_record(image, filesystem, inode) -> dict:
    mode = int(inode['mode'])
    file_type = mode & UFS_IFMT
    record = {
        'mode': mode,
        'nlink': int(inode['nlink']),
        'uid': int(inode['uid']),
        'gid': int(inode['gid']),
        'size': int(inode['size']),
    }
    if file_type == UFS_IFDIR:
        record['type'] = 'dir'
    elif file_type == UFS_IFLNK:
        record['type'] = 'link'
        target = read_ufs_file(image, filesystem.start_offset, filesystem.details, inode)
        record['target'] = target.decode('ascii', errors='replace')
    elif file_type == UFS_IFREG:
        record['type'] = 'file'
        content = read_ufs_file(image, filesystem.start_offset, filesystem.details, inode)
        record['sha256'] = hashlib.sha256(content).hexdigest()
    else:
        record['type'] = f'other(0o{file_type:o})'
    return record


def walk(image, filesystem, path, inode, out) -> None:
    out[path or '/'] = node_record(image, filesystem, inode)
    if (int(inode['mode']) & UFS_IFMT) != UFS_IFDIR:
        return
    for entry in iter_ufs_directory_entries(image, filesystem, inode):
        name = str(entry['name'])
        if name in ('.', '..'):
            continue
        child = read_ufs_inode(image, filesystem.start_offset, filesystem.details, int(entry['inode']))
        if child is None:
            continue
        walk(image, filesystem, f'{path}/{name}', child, out)


def main() -> int:
    image_out, manifest_out = sys.argv[1], sys.argv[2]
    image, filesystem = build_image()

    with open(image_out, 'wb') as handle:
        handle.write(image)

    root = read_ufs_inode(image, filesystem.start_offset, filesystem.details, UFS_ROOT_INODE)
    manifest: dict[str, dict] = {}
    walk(image, filesystem, '', root, manifest)

    with open(manifest_out, 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
