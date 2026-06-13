//! Pure-Rust round-trip tests for the disk layer: build a skeleton image, parse
//! it back, and check the metadata and validation behaviour. No Python needed,
//! so these run anywhere.

use svr4_disk::create::{
    build_geometry, build_slice_layout, create_raw_image_skeleton, RawDiskGeometry,
    SliceLayoutOptions, DISK_ADDRESSING_CHS, DISK_ADDRESSING_LBA28,
};
use svr4_disk::inspect::inspect_disk_metadata;
use svr4_disk::structures::{VtocPartition, UNIXWARE_PARTITION_TYPE, VALID_PD, VTOC_SANE};
use svr4_disk::svr4::partition_tag_name;

fn sample_slices() -> Vec<VtocPartition> {
    vec![
        VtocPartition {
            index: 0,
            tag: 0x05,
            flag: 0x0201,
            start_sector: 1,
            sector_count: 1087,
        },
        VtocPartition {
            index: 1,
            tag: 0x02,
            flag: 0x0200,
            start_sector: 64,
            sector_count: 128,
        },
        VtocPartition {
            index: 10,
            tag: 0x09,
            flag: 0x0200,
            start_sector: 32,
            sector_count: 32,
        },
    ]
}

fn build_sample(path: &std::path::Path) {
    let geometry = RawDiskGeometry {
        cylinders: 16,
        heads: 4,
        sectors_per_track: 17,
    };
    create_raw_image_skeleton(
        path,
        &geometry,
        1,
        geometry.total_sectors() as u32 - 1,
        "SVR4",
        &sample_slices(),
        None,
        DISK_ADDRESSING_CHS,
    )
    .expect("skeleton creation succeeds");
}

#[test]
fn build_geometry_derives_cylinders_from_size() {
    // Mirrors tasks/make_image.py:_build_geometry. 324 MiB at 16/63 rounds up to
    // 659 cylinders (664272 sectors).
    let geom = build_geometry(324, 16, 63, DISK_ADDRESSING_CHS).expect("324 MiB chs");
    assert_eq!(
        geom,
        RawDiskGeometry {
            cylinders: 659,
            heads: 16,
            sectors_per_track: 63,
        }
    );
    assert_eq!(geom.total_sectors(), 664272);

    // The 1024-cylinder cap is enforced in CHS mode but not in LBA28 mode.
    let err = build_geometry(2000, 16, 63, DISK_ADDRESSING_CHS).unwrap_err();
    assert!(err.contains("exceeds the CHS limit of 1024"), "{err}");
    let big = build_geometry(2000, 16, 63, DISK_ADDRESSING_LBA28).expect("2000 MiB lba28");
    assert_eq!(big.cylinders, 4064);
}

#[test]
fn slice_layout_matches_make_image_defaults() {
    // Reference values come from tasks/make_image.py:_build_slice_layout for a
    // 324 MiB / 16 / 63 disk with the default knobs.
    let geom = build_geometry(324, 16, 63, DISK_ADDRESSING_CHS).unwrap();
    let layout = build_slice_layout(
        &geom,
        &SliceLayoutOptions {
            stand_start_sector: 64,
            stand_size_mb: 16,
            swap_size_mb: 64,
            root_align_sectors: 2048,
        },
    )
    .expect("layout fits");
    assert_eq!(layout.unix_partition_start, 1);
    assert_eq!(layout.unix_partition_size, 664271);
    // (index, tag, flag, start, size)
    let expected = [
        (0u32, 0x05u16, 0x201u16, 1i64, 664271i64),
        (1, 0x02, 0x200, 168336, 495936),
        (2, 0x03, 0x201, 35280, 132048),
        (10, 0x09, 0x200, 1008, 33264),
    ];
    assert_eq!(layout.slices.len(), expected.len());
    for (slice, (index, tag, flag, start, size)) in layout.slices.iter().zip(expected) {
        assert_eq!(
            (slice.index, slice.tag, slice.flag, slice.start_sector, slice.sector_count),
            (index, tag, flag, start, size)
        );
    }

    // A disk too small to fit stand + swap + a root slice is rejected.
    let tiny = build_geometry(64, 16, 63, DISK_ADDRESSING_CHS).unwrap();
    let err = build_slice_layout(
        &tiny,
        &SliceLayoutOptions {
            stand_start_sector: 64,
            stand_size_mb: 16,
            swap_size_mb: 64,
            root_align_sectors: 2048,
        },
    )
    .unwrap_err();
    assert!(err.contains("root slice"), "{err}");
}

#[test]
fn skeleton_parses_back_to_expected_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("skel.raw");
    build_sample(&path);

    let report = inspect_disk_metadata(&path).expect("inspect succeeds");

    assert_eq!(report.mbr.signature, 0xAA55);
    assert_eq!(report.file_size, 16 * 4 * 17 * 512);

    let active = report.active_unix_partition.expect("active UNIX partition");
    assert_eq!(active.partition_type, UNIXWARE_PARTITION_TYPE);
    assert_eq!(active.start_lba, 1);
    assert!(active.bootable);

    let pdinfo = report.pdinfo.expect("pdinfo present");
    assert_eq!(pdinfo.sanity, VALID_PD);
    assert_eq!(pdinfo.cylinders, 16);
    assert_eq!(pdinfo.tracks, 4);
    assert_eq!(pdinfo.sectors, 17);
    assert_eq!(pdinfo.bytes_per_sector, 512);

    let vtoc = report.vtoc.expect("vtoc present");
    assert_eq!(vtoc.sanity, VTOC_SANE);
    assert_eq!(vtoc.volume, "SVR4");

    // The three populated slices come back in the listing with their tags.
    let listed: Vec<(u32, String, i64, i64)> = report
        .slice_filesystems
        .iter()
        .map(|s| {
            (
                s.slice_index,
                partition_tag_name(s.tag),
                s.start_sector,
                s.sector_count,
            )
        })
        .collect();
    assert_eq!(
        listed,
        vec![
            (0, "backup".into(), 1, 1087),
            (1, "root".into(), 64, 128),
            (10, "stand".into(), 32, 32),
        ]
    );
    // Phase 1 has no FS detection, so every slice reports no filesystem.
    assert!(report
        .slice_filesystems
        .iter()
        .all(|s| s.filesystem.is_none() && s.root_entries.is_empty()));
}

#[test]
fn skeleton_creation_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.raw");
    let b = dir.path().join("b.raw");
    build_sample(&a);
    build_sample(&b);
    assert_eq!(
        std::fs::read(&a).unwrap(),
        std::fs::read(&b).unwrap(),
        "skeleton bytes must be reproducible"
    );
}

#[test]
fn validation_rejects_duplicate_slice_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dup.raw");
    let geometry = RawDiskGeometry {
        cylinders: 16,
        heads: 4,
        sectors_per_track: 17,
    };
    let slices = vec![
        VtocPartition {
            index: 1,
            tag: 0x02,
            flag: 0,
            start_sector: 64,
            sector_count: 16,
        },
        VtocPartition {
            index: 1,
            tag: 0x09,
            flag: 0,
            start_sector: 80,
            sector_count: 16,
        },
    ];
    let err = create_raw_image_skeleton(
        &path,
        &geometry,
        1,
        geometry.total_sectors() as u32 - 1,
        "SVR4",
        &slices,
        None,
        DISK_ADDRESSING_CHS,
    )
    .unwrap_err();
    assert_eq!(err, "error: duplicate slice index 1");
}

#[test]
fn validation_rejects_slice_past_unix_partition() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oob.raw");
    let geometry = RawDiskGeometry {
        cylinders: 16,
        heads: 4,
        sectors_per_track: 17,
    };
    let slices = vec![VtocPartition {
        index: 2,
        tag: 0x02,
        flag: 0,
        start_sector: 64,
        sector_count: 100_000,
    }];
    let err = create_raw_image_skeleton(
        &path,
        &geometry,
        1,
        geometry.total_sectors() as u32 - 1,
        "SVR4",
        &slices,
        None,
        DISK_ADDRESSING_CHS,
    )
    .unwrap_err();
    assert_eq!(err, "error: slice 2 exceeds the UNIX partition bounds");
}

#[test]
fn lba28_addressing_saturates_chs_for_large_disks() {
    // A disk larger than the CHS limit is allowed under lba28 and the CHS
    // fields saturate rather than erroring.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.raw");
    let geometry = RawDiskGeometry {
        cylinders: 2048,
        heads: 16,
        sectors_per_track: 63,
    };
    create_raw_image_skeleton(
        &path,
        &geometry,
        1,
        4096,
        "SVR4",
        &[],
        None,
        DISK_ADDRESSING_LBA28,
    )
    .expect("lba28 skeleton creation succeeds");
    // chs addressing would reject the same geometry.
    let err = create_raw_image_skeleton(
        &path,
        &geometry,
        1,
        4096,
        "SVR4",
        &[],
        None,
        DISK_ADDRESSING_CHS,
    )
    .unwrap_err();
    assert!(err.contains("CHS cylinder limit"), "got: {err}");
}
