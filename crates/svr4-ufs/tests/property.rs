//! Randomized, model-based stress of the UFS write path — fully self-contained
//! (an in-memory image, the Rust formatter, write path, reader, and the
//! `check_filesystem` oracle; no Python/C).
//!
//! Each run formats a fresh filesystem, then applies a random but always-valid
//! sequence of mkdir / create / symlink / hardlink / unlink / rmdir / rename
//! operations while mirroring them in an in-memory model. After every operation
//! the filesystem must pass `check_filesystem` (structural consistency,
//! incremental count maintenance), and at the end the reader's view of the whole
//! tree must match the model exactly (content, type, symlink targets). This is
//! the net for "silly" off-by-one bugs that survive a simple round-trip.

use std::collections::BTreeMap;

use svr4_ufs::{
    check_filesystem, create_file, format, link, make_directory, read_inode, read_inode_bytes,
    read_symlink_target, remove_directory, rename_in_parent, resolve_path, symlink, unlink,
    FormatOptions, Ufs,
};

/// Tiny deterministic xorshift RNG (no external crates).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, v: &'a [String]) -> &'a str {
        &v[self.below(v.len())]
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Node {
    Dir,
    File(Vec<u8>),
    Sym(String),
}

struct Model {
    nodes: BTreeMap<String, Node>,
}

impl Model {
    fn new() -> Self {
        Model { nodes: BTreeMap::new() } // "/" is implicit
    }
    fn dirs(&self) -> Vec<String> {
        let mut v = vec!["/".to_string()];
        v.extend(self.nodes.iter().filter(|(_, n)| **n == Node::Dir).map(|(p, _)| p.clone()));
        v
    }
    fn files(&self) -> Vec<String> {
        self.nodes.iter().filter(|(_, n)| matches!(n, Node::File(_))).map(|(p, _)| p.clone()).collect()
    }
    fn removable(&self) -> Vec<String> {
        // files or symlinks (anything but a directory)
        self.nodes.iter().filter(|(_, n)| !matches!(n, Node::Dir)).map(|(p, _)| p.clone()).collect()
    }
    fn empty_dirs(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|(p, n)| **n == Node::Dir && !self.has_children(p))
            .map(|(p, _)| p.clone())
            .collect()
    }
    fn has_children(&self, dir: &str) -> bool {
        let prefix = format!("{dir}/");
        self.nodes.keys().any(|k| k.starts_with(&prefix))
    }
    fn child_path(dir: &str, name: &str) -> String {
        if dir == "/" {
            format!("/{name}")
        } else {
            format!("{dir}/{name}")
        }
    }
}

fn split_parent(path: &str) -> (String, String) {
    let idx = path.rfind('/').unwrap();
    let parent = if idx == 0 { "/".to_string() } else { path[..idx].to_string() };
    (parent, path[idx + 1..].to_string())
}

fn parent_ino(image: &[u8], ufs: &Ufs, dir: &str) -> i64 {
    let p = if dir == "/" { "" } else { dir };
    resolve_path(image, ufs, p).unwrap().0 as i64
}

/// Move a model subtree rooted at `src` to `dst` (re-keying descendants).
fn model_rename(model: &mut Model, src: &str, dst: &str) {
    let keys: Vec<String> = model.nodes.keys().cloned().collect();
    let src_prefix = format!("{src}/");
    let mut moved: Vec<(String, Node)> = Vec::new();
    for k in keys {
        if k == src {
            let n = model.nodes.remove(&k).unwrap();
            moved.push((dst.to_string(), n));
        } else if k.starts_with(&src_prefix) {
            let n = model.nodes.remove(&k).unwrap();
            moved.push((format!("{dst}/{}", &k[src_prefix.len()..]), n));
        }
    }
    for (k, n) in moved {
        model.nodes.insert(k, n);
    }
}

fn run_one(seed: u64, ops: usize) {
    // 16 MiB, 4 KiB blocks: enough inodes/space for a churny run, and a few
    // files can reach single-indirect size.
    let size = 64u64 * 16 * 32 * 512;
    let mut image = vec![0u8; size as usize];
    let opts = FormatOptions {
        block_size: 4096,
        tracks_per_cylinder: Some(16),
        sectors_per_track: Some(32),
        ..FormatOptions::default()
    };
    let ufs = format(&mut image, 0, size, &opts).unwrap();

    let mut model = Model::new();
    let mut rng = Rng(seed | 1);
    let mut counter = 0usize;
    let mut name = |rng: &mut Rng| {
        counter += 1;
        format!("n{counter}_{}", rng.below(1000))
    };

    for step in 0..ops {
        let choice = rng.below(100);
        let mut desc = String::new();
        let result: Result<(), String> = (|| {
            if choice < 22 {
                // mkdir
                let dirs = model.dirs();
                let parent = rng.pick(&dirs).to_string();
                let nm = name(&mut rng);
                let path = Model::child_path(&parent, &nm);
                desc = format!("mkdir {path}");
                make_directory(&mut image, &ufs, &path, 0o755, 0, 0, 0)?;
                model.nodes.insert(path, Node::Dir);
                Ok(())
            } else if choice < 55 {
                // create file (varied size, occasionally large)
                let dirs = model.dirs();
                let parent = rng.pick(&dirs).to_string();
                let nm = name(&mut rng);
                let path = Model::child_path(&parent, &nm);
                let size = if rng.below(20) == 0 {
                    rng.below(120_000) // occasionally crosses into indirect
                } else {
                    rng.below(6000)
                };
                let data: Vec<u8> =
                    (0..size).map(|i| ((i ^ (step * 7)).wrapping_mul(31) & 0xff) as u8).collect();
                desc = format!("create {path} ({size}b)");
                create_file(&mut image, &ufs, &path, &data, 0o644, 0, 0, 0)?;
                model.nodes.insert(path, Node::File(data));
                Ok(())
            } else if choice < 67 {
                // symlink
                let dirs = model.dirs();
                let parent = rng.pick(&dirs).to_string();
                let nm = name(&mut rng);
                let path = Model::child_path(&parent, &nm);
                let target = format!("../t{}", rng.below(1000));
                desc = format!("symlink {path} -> {target}");
                symlink(&mut image, &ufs, &target, &path, 0o777, 0, 0, 0)?;
                model.nodes.insert(path, Node::Sym(target));
                Ok(())
            } else if choice < 77 {
                // hard link an existing file
                let files = model.files();
                if files.is_empty() {
                    desc = "hardlink(skip)".into();
                    return Ok(());
                }
                let src = rng.pick(&files).to_string();
                let dirs = model.dirs();
                let parent = rng.pick(&dirs).to_string();
                let nm = name(&mut rng);
                let dst = Model::child_path(&parent, &nm);
                desc = format!("link {src} -> {dst}");
                link(&mut image, &ufs, &src, &dst)?;
                let content = match &model.nodes[&src] {
                    Node::File(c) => c.clone(),
                    _ => unreachable!(),
                };
                model.nodes.insert(dst, Node::File(content));
                Ok(())
            } else if choice < 88 {
                // unlink a file/symlink
                let rem = model.removable();
                if rem.is_empty() {
                    desc = "unlink(skip)".into();
                    return Ok(());
                }
                let path = rng.pick(&rem).to_string();
                desc = format!("unlink {path}");
                unlink(&mut image, &ufs, &path)?;
                model.nodes.remove(&path);
                Ok(())
            } else if choice < 94 {
                // rmdir an empty dir
                let empties: Vec<String> =
                    model.empty_dirs().into_iter().filter(|d| d != "/").collect();
                if empties.is_empty() {
                    desc = "rmdir(skip)".into();
                    return Ok(());
                }
                let path = rng.pick(&empties).to_string();
                desc = format!("rmdir {path}");
                remove_directory(&mut image, &ufs, &path)?;
                model.nodes.remove(&path);
                Ok(())
            } else {
                // rename
                let all: Vec<String> = model.nodes.keys().cloned().collect();
                if all.is_empty() {
                    desc = "rename(skip)".into();
                    return Ok(());
                }
                let src = rng.pick(&all).to_string();
                let dirs = model.dirs();
                let parent = rng.pick(&dirs).to_string();
                // don't move a directory into its own subtree
                if parent == src || parent.starts_with(&format!("{src}/")) {
                    desc = "rename(skip-subtree)".into();
                    return Ok(());
                }
                let nm = name(&mut rng);
                let dst = Model::child_path(&parent, &nm);
                let (sp, sn) = split_parent(&src);
                let (dp, dn) = split_parent(&dst);
                let sp_ino = parent_ino(&image, &ufs, &sp);
                let dp_ino = parent_ino(&image, &ufs, &dp);
                desc = format!("rename {src} -> {dst}");
                rename_in_parent(&mut image, &ufs, sp_ino, &sn, dp_ino, &dn)?;
                model_rename(&mut model, &src, &dst);
                Ok(())
            }
        })();
        result.unwrap_or_else(|e| panic!("seed {seed} step {step} ({desc}): op failed: {e}"));

        let problems = check_filesystem(&image, &ufs);
        assert!(
            problems.is_empty(),
            "seed {seed} step {step} after {desc}: inconsistent:\n  {}",
            problems.join("\n  ")
        );
    }

    // Final: the reader's whole-tree view must equal the model.
    verify_tree_matches_model(&image, &ufs, &model, seed);
}

fn verify_tree_matches_model(image: &[u8], ufs: &Ufs, model: &Model, seed: u64) {
    for (path, node) in &model.nodes {
        let resolved = resolve_path(image, ufs, path)
            .unwrap_or_else(|| panic!("seed {seed}: model path {path} not found in image"));
        let inode = read_inode(image, ufs, resolved.0 as i64).unwrap();
        match node {
            Node::Dir => assert!(inode.is_directory(), "seed {seed}: {path} should be a dir"),
            Node::Sym(target) => {
                assert!(inode.is_symlink(), "seed {seed}: {path} should be a symlink");
                assert_eq!(&read_symlink_target(image, ufs, &inode), target, "seed {seed}: {path} target");
            }
            Node::File(content) => {
                assert!(inode.is_regular(), "seed {seed}: {path} should be a file");
                assert_eq!(&read_inode_bytes(image, ufs, &inode), content, "seed {seed}: {path} content");
            }
        }
    }
}

#[test]
fn randomized_operations_stay_consistent() {
    for seed in 1u64..=10 {
        run_one(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), 120);
    }
}
