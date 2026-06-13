#!/usr/bin/env python3
"""Helper for the Rust UFS write-path gate test.

Subcommands (run with PYTHONPATH=host-tools):

  blank <image_out>
      Write a freshly-formatted, empty UFS image (8 MiB, 4 KiB blocks).

  check <image_in> <manifest_out>
      Run the Python fsck reimplementation on the image; if it reports any issue
      or a summary-total mismatch, print details and exit 2. Otherwise walk the
      tree with the Python reader and emit a JSON manifest (same schema as
      gen_ufs_image.py) so the Rust test can compare.

This makes the *Python* tools (writer's formatter, fsck, and reader) the
reference the Rust write path is graded against.
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
    build_ufs_filesystem_image,
    detect_ufs_at_start,
    format_ufs_filesystem,
    iter_ufs_directory_entries,
    read_ufs_file,
    read_ufs_inode,
)
from host_tools.fs.ufs_fsck import analyze_ufs_filesystem
from host_tools.disk.create import (
    DISK_ADDRESSING_CHS,
    RawDiskGeometry,
    create_raw_image_skeleton,
)
from host_tools.disk.structures import SECTOR_SIZE, VtocPartition
from pathlib import Path


def cmd_blank(image_out: str) -> int:
    image = bytearray(8 * 1024 * 1024)
    format_ufs_filesystem(image, block_size=4096, timestamp=0)
    with open(image_out, 'wb') as handle:
        handle.write(image)
    return 0


def cmd_format_raw(args: list[str]) -> int:
    """format-raw <out> <size> <block_size> <bytes_per_inode> [<tracks> <sectors>]

    Write a Python-formatted bare UFS image (slice at offset 0) for the Rust
    formatter's byte-identity differential test.
    """
    out, size, block_size, bytes_per_inode = args[0], int(args[1]), int(args[2]), int(args[3])
    tracks = int(args[4]) if len(args) > 4 else None
    sectors = int(args[5]) if len(args) > 5 else None
    image = bytearray(size)
    build_ufs_filesystem_image(
        size,
        target_image=image,
        timestamp=0,
        block_size=block_size,
        bytes_per_inode=bytes_per_inode,
        tracks_per_cylinder=tracks,
        sectors_per_track=sectors,
    )
    with open(out, 'wb') as handle:
        handle.write(image)
    return 0


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def cmd_disk_blank(image_out: str) -> int:
    """Build a fully-geometried VTOC disk image with a formatted UFS root slice.

    Mirrors the layout the real `tasks/make_image.py` build produces (a
    cylinder-aligned UFS root slice inside a UNIX partition), so the resulting
    image is the kind the on-disk tooling and fsck oracle expect — not a bare
    superblock at offset 0. Prints the root slice's absolute *byte* offset to
    stdout so the caller (the Rust populate gate) can mount/populate there.
    """
    geometry = RawDiskGeometry(cylinders=512, heads=4, sectors_per_track=17)
    sectors_per_cylinder = geometry.heads * geometry.sectors_per_track
    unix_partition_start = 1
    unix_partition_size = geometry.total_sectors - unix_partition_start

    stand_start = _align_up(64, sectors_per_cylinder)
    stand_count = _align_up((1 * 1024 * 1024) // SECTOR_SIZE, sectors_per_cylinder)
    swap_start = _align_up(_align_up(stand_start + stand_count, 68), sectors_per_cylinder)
    swap_count = _align_up((1 * 1024 * 1024) // SECTOR_SIZE, sectors_per_cylinder)
    root_start = _align_up(_align_up(swap_start + swap_count, 68), sectors_per_cylinder)
    root_count = ((geometry.total_sectors - root_start) // sectors_per_cylinder) * sectors_per_cylinder

    slices = [
        VtocPartition(index=0, tag=0x05, flag=0x201, start_sector=unix_partition_start, sector_count=unix_partition_size),
        VtocPartition(index=1, tag=0x02, flag=0x200, start_sector=root_start, sector_count=root_count),
        VtocPartition(index=2, tag=0x03, flag=0x201, start_sector=swap_start, sector_count=swap_count),
        VtocPartition(index=10, tag=0x09, flag=0x200, start_sector=stand_start, sector_count=stand_count),
    ]

    out = Path(image_out)
    create_raw_image_skeleton(
        out,
        geometry,
        unix_partition_start,
        unix_partition_size,
        'SVR4',
        slices,
        None,
        DISK_ADDRESSING_CHS,
    )

    # Format the UFS root slice with geometry matching the disk, then write it
    # back at the slice offset.
    root_offset = root_start * SECTOR_SIZE
    root_span = root_count * SECTOR_SIZE
    slice_image = bytearray(root_span)
    format_ufs_filesystem(
        slice_image,
        timestamp=0,
        block_size=4096,
        bytes_per_inode=8192,
        tracks_per_cylinder=geometry.heads,
        sectors_per_track=geometry.sectors_per_track,
    )
    with open(out, 'r+b') as handle:
        handle.seek(root_offset)
        handle.write(slice_image)

    print(root_offset)
    return 0


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
        record['target'] = read_ufs_file(image, filesystem.start_offset, filesystem.details, inode).decode('ascii', 'replace')
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
        if child is not None:
            walk(image, filesystem, f'{path}/{name}', child, out)


def cmd_check(image_in: str, manifest_out: str, start_offset: int = 0) -> int:
    image = bytearray(open(image_in, 'rb').read())
    filesystem = detect_ufs_at_start(image, start_offset)
    if filesystem is None:
        print(f'check: no UFS superblock detected at offset {start_offset}', file=sys.stderr)
        return 2

    report = analyze_ufs_filesystem(image, filesystem)
    if report.issues:
        print(f'check: fsck reported {len(report.issues)} issue(s):', file=sys.stderr)
        for issue in report.issues:
            print(f'  {issue}', file=sys.stderr)
        return 2
    if report.superblock_totals != report.recomputed_totals:
        print('check: superblock totals disagree with recomputed totals:', file=sys.stderr)
        print(f'  superblock:  {report.superblock_totals}', file=sys.stderr)
        print(f'  recomputed:  {report.recomputed_totals}', file=sys.stderr)
        return 2

    root = read_ufs_inode(image, filesystem.start_offset, filesystem.details, UFS_ROOT_INODE)
    manifest: dict[str, dict] = {}
    walk(image, filesystem, '', root, manifest)
    with open(manifest_out, 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print('usage: ufs_tool.py blank|check|disk-blank|disk-check ...', file=sys.stderr)
        return 2
    command = sys.argv[1]
    if command == 'blank':
        return cmd_blank(sys.argv[2])
    if command == 'check':
        return cmd_check(sys.argv[2], sys.argv[3])
    if command == 'format-raw':
        return cmd_format_raw(sys.argv[2:])
    if command == 'disk-blank':
        return cmd_disk_blank(sys.argv[2])
    if command == 'disk-check':
        # disk-check <image> <start_offset> <manifest_out>
        return cmd_check(sys.argv[2], sys.argv[4], int(sys.argv[3]))
    print(f'unknown command {command!r}', file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
