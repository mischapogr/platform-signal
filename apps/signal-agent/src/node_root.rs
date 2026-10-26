//! Read-only rooted filesystem primitives. The node producer must run these
//! synchronous operations in one retained physical worker under original budgets.
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat};
use signal_collector_sdk::kubernetes_log::LogIdentity;
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid node log root or discovery limits")]
    Configuration,
    #[error("unsafe node log filesystem entry")]
    Unsafe,
    #[error("node log discovery capacity exceeded; scan incomplete")]
    Capacity,
    #[error("node log generation changed; complete rescan required")]
    Changed,
    #[error("node log filesystem operation failed")]
    Io(#[source] std::io::Error),
}
fn io(error: rustix::io::Errno) -> Error {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        Error::Unsafe
    } else {
        Error::Io(error.into())
    }
}
fn directory(parent: &File, name: &std::ffi::OsStr) -> Result<File, Error> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io)?;
    Ok(File::from(fd))
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: usize,
    pub max_active: usize,
    pub max_rotated: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_active: 16,
            max_rotated: 128,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if !(1..=16384).contains(&self.max_entries)
            || !(1..=16).contains(&self.max_active)
            || self.max_rotated > 256
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Candidate {
    pub source: LogIdentity,
    pub file_name: String,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub compressed: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanMetrics {
    pub examined: usize,
    pub rejected_names: usize,
    pub active: usize,
    pub rotated: usize,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub active: Vec<Candidate>,
    pub rotated: Vec<Candidate>,
    pub metrics: ScanMetrics,
}
/// An opened root capability, retained across path renames. Every descendant
/// open is relative to an owned descriptor and refuses final symlinks.
pub struct Root {
    directory: File,
    device: u64,
    inode: u64,
    limits: Limits,
}
impl Root {
    pub fn open(path: &Path, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if !path.is_absolute()
            || path.as_os_str().as_encoded_bytes().len() > 4096
            || path.components().take(129).count() > 128
        {
            return Err(Error::Configuration);
        }
        let mut parent = File::open("/").map_err(Error::Io)?;
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => parent = directory(&parent, name)?,
                _ => return Err(Error::Configuration),
            }
        }
        let metadata = parent.metadata().map_err(Error::Io)?;
        Ok(Self {
            directory: parent,
            device: metadata.dev(),
            inode: metadata.ino(),
            limits,
        })
    }
    pub fn identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
    fn child_directory(&self, parent: &File, name: &str) -> Result<File, Error> {
        let file = directory(parent, std::ffi::OsStr::new(name))?;
        if file.metadata().map_err(Error::Io)?.dev() != self.device {
            return Err(Error::Unsafe);
        }
        Ok(file)
    }
    fn names(&self, parent: &File, metrics: &mut ScanMetrics) -> Result<Vec<Vec<u8>>, Error> {
        let entries = Dir::read_from(parent).map_err(io)?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io)?;
            metrics.examined = metrics.examined.checked_add(1).ok_or(Error::Capacity)?;
            if metrics.examined > self.limits.max_entries {
                return Err(Error::Capacity);
            }
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if name.len() > 255 {
                return Err(Error::Unsafe);
            }
            names.push(name.to_vec());
        }
        names.sort();
        Ok(names)
    }
    fn regular(&self, parent: &File, name: &str) -> Result<File, Error> {
        // Refuse ordinary special entries before opening; final descriptor
        // checks still detect replacement. Privileged host mutation is outside
        // this configured root's trust boundary.
        let before = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_nlink != 1
            || before.st_dev != self.device
        {
            return Err(Error::Unsafe);
        }
        let fd = openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
        let file = File::from(fd);
        let metadata = file.metadata().map_err(Error::Io)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.dev() != self.device {
            return Err(Error::Unsafe);
        }
        if metadata.dev() != before.st_dev || metadata.ino() != before.st_ino {
            return Err(Error::Changed);
        }
        Ok(file)
    }
    /// A failed scan returns no prefix snapshot and cannot establish absence.
    /// Sorting is only presentation; durable source-slot allocation is separate.
    pub fn scan(&self) -> Result<Snapshot, Error> {
        self.scan_namespace(None)
    }
    /// Select a trusted kubelet namespace; every examined root entry remains charged.
    pub fn scan_namespace(&self, namespace: Option<&str>) -> Result<Snapshot, Error> {
        if namespace.is_some_and(|n| !valid_namespace(n)) {
            return Err(Error::Configuration);
        }
        let mut result = Snapshot {
            active: Vec::new(),
            rotated: Vec::new(),
            metrics: ScanMetrics::default(),
        };
        for raw_pod in self.names(&self.directory, &mut result.metrics)? {
            let Ok(pod) = std::str::from_utf8(&raw_pod) else {
                result.metrics.rejected_names += 1;
                continue;
            };
            let identity = match LogIdentity::from_relative(pod, "fixture", "0.log") {
                Ok(i) => i,
                Err(_) => {
                    result.metrics.rejected_names += 1;
                    continue;
                }
            };
            if namespace.is_some_and(|n| n != identity.namespace) {
                continue;
            }
            let pod_dir = self.child_directory(&self.directory, pod)?;
            for raw_container in self.names(&pod_dir, &mut result.metrics)? {
                let Ok(container) = std::str::from_utf8(&raw_container) else {
                    result.metrics.rejected_names += 1;
                    continue;
                };
                if LogIdentity::from_relative(pod, container, "0.log").is_err() {
                    result.metrics.rejected_names += 1;
                    continue;
                }
                let container_dir = self.child_directory(&pod_dir, container)?;
                for raw_file in self.names(&container_dir, &mut result.metrics)? {
                    let Ok(name) = std::str::from_utf8(&raw_file) else {
                        result.metrics.rejected_names += 1;
                        continue;
                    };
                    let Some((active_name, rotated)) = log_name(name) else {
                        result.metrics.rejected_names += 1;
                        continue;
                    };
                    let Ok(source) = LogIdentity::from_relative(pod, container, &active_name)
                    else {
                        result.metrics.rejected_names += 1;
                        continue;
                    };
                    let file = self.regular(&container_dir, name)?;
                    let metadata = file.metadata().map_err(Error::Io)?;
                    let candidate = Candidate {
                        source,
                        file_name: name.into(),
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        length: metadata.len(),
                        compressed: name.ends_with(".gz"),
                    };
                    let (items, capacity) = if rotated {
                        (&mut result.rotated, self.limits.max_rotated)
                    } else {
                        (&mut result.active, self.limits.max_active)
                    };
                    if items.len() >= capacity {
                        return Err(Error::Capacity);
                    }
                    items.push(candidate);
                }
            }
        }
        result.metrics.active = result.active.len();
        result.metrics.rotated = result.rotated.len();
        Ok(result)
    }
    /// Reopen exactly a scanned generation. Size regression or a replaced inode
    /// refuses; the producer must additionally validate its durable offset anchor.
    /// Compressed candidates are retained only to report unavailable recovery.
    pub fn open_candidate(&self, candidate: &Candidate) -> Result<File, Error> {
        let [pod, container, active] = candidate
            .source
            .relative_components()
            .map_err(|_| Error::Configuration)?;
        let (derived, rotated) = log_name(&candidate.file_name).ok_or(Error::Configuration)?;
        if derived != active
            || candidate.compressed
            || candidate.file_name.ends_with(".gz")
            || (!rotated && candidate.file_name != active)
        {
            return Err(Error::Configuration);
        }
        let pod_dir = self.child_directory(&self.directory, &pod)?;
        let container_dir = self.child_directory(&pod_dir, &container)?;
        let file = self.regular(&container_dir, &candidate.file_name)?;
        let metadata = file.metadata().map_err(Error::Io)?;
        if metadata.dev() != candidate.device
            || metadata.ino() != candidate.inode
            || metadata.len() < candidate.length
        {
            return Err(Error::Changed);
        }
        Ok(file)
    }
}
pub(crate) fn log_name(name: &str) -> Option<(String, bool)> {
    if name.len() > 128 {
        return None;
    }
    let (count, suffix) = name.split_once(".log")?;
    let restart = count.parse::<u32>().ok()?;
    if restart.to_string() != count {
        return None;
    }
    if !suffix.is_empty()
        && (!suffix.starts_with('.')
            || suffix.len() < 2
            || !suffix
                .bytes()
                .skip(1)
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
    {
        return None;
    }
    Some((format!("{restart}.log"), !suffix.is_empty()))
}

pub(crate) fn valid_namespace(value: &str) -> bool {
    value.len() <= 63
        && LogIdentity::from_relative(&format!("{value}_fixture_runtime"), "fixture", "0.log")
            .is_ok_and(|i| i.namespace == value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        os::unix::fs::symlink,
        path::PathBuf,
    };
    const POD: &str = "team_workload_runtime-uid";
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("pods");
        let container = root.join(POD).join("main");
        fs::create_dir_all(&container).unwrap();
        fs::write(container.join("0.log"), b"original\n").unwrap();
        (temp, root, container)
    }
    #[test]
    fn discovery_is_bounded_readonly_and_identifies_active_and_rotated_generations() {
        let (_temp, path, container) = fixture();
        fs::write(container.join("0.log.20261025-120000"), b"rotated\n").unwrap();
        fs::write(container.join("0.log.20261024-120000.gz"), b"compressed").unwrap();
        let root = Root::open(&path, Limits::default()).unwrap();
        let first = root.scan().unwrap();
        assert_eq!(first.active.len(), 1);
        assert_eq!(first.rotated.len(), 2);
        assert_eq!(first.metrics.active, 1);
        assert!(first.metrics.examined <= Limits::default().max_entries);
        let mut file = root.open_candidate(&first.active[0]).unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text, "original\n");
        assert!(file.write_all(b"forbidden").is_err());
        let compressed = first.rotated.iter().find(|c| c.compressed).unwrap();
        assert!(root.open_candidate(compressed).is_err());
        let again = root.scan().unwrap();
        assert_eq!(again.active[0].inode, first.active[0].inode);
        assert_eq!(again.metrics.examined, first.metrics.examined);
    }
    #[test]
    fn every_parent_and_final_symlink_refuses() {
        for depth in 0..4 {
            let (temp, path, container) = fixture();
            let target = temp.path().join("outside");
            let replace = match depth {
                0 => path.clone(),
                1 => path.join(POD),
                2 => container.clone(),
                _ => container.join("0.log"),
            };
            fs::rename(&replace, &target).unwrap();
            symlink(&target, &replace).unwrap();
            match Root::open(&path, Limits::default()) {
                Ok(root) => assert!(root.scan().is_err()),
                Err(e) => assert!(matches!(e, Error::Unsafe)),
            }
        }
    }
    #[test]
    fn hardlinks_and_fifo_refuse_without_blocking() {
        let (temp, path, container) = fixture();
        let outside = temp.path().join("external");
        fs::write(&outside, b"private").unwrap();
        fs::remove_file(container.join("0.log")).unwrap();
        fs::hard_link(outside, container.join("0.log")).unwrap();
        let root = Root::open(&path, Limits::default()).unwrap();
        assert!(matches!(root.scan(), Err(Error::Unsafe)));
        fs::remove_file(container.join("0.log")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            container.join("0.log"),
            Mode::RUSR | Mode::WUSR,
        )
        .unwrap();
        assert!(matches!(root.scan(), Err(Error::Unsafe)));
    }
    #[test]
    fn incomplete_entry_active_or_archive_capacity_never_returns_prefix() {
        let (_temp, path, container) = fixture();
        for n in 0..8 {
            fs::write(path.join(format!("ignored-{n}")), b"x").unwrap();
        }
        let root = Root::open(
            &path,
            Limits {
                max_entries: 4,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(matches!(root.scan(), Err(Error::Capacity)));
        fs::write(container.join("1.log"), b"second\n").unwrap();
        let root = Root::open(
            &path,
            Limits {
                max_active: 1,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(matches!(root.scan(), Err(Error::Capacity)));
        fs::remove_file(container.join("1.log")).unwrap();
        fs::write(container.join("0.log.rotation"), b"old\n").unwrap();
        let root = Root::open(
            &path,
            Limits {
                max_rotated: 0,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(matches!(root.scan(), Err(Error::Capacity)));
    }
    #[test]
    fn changed_inode_truncation_and_parent_replacement_refuse_reopen() {
        let (temp, path, container) = fixture();
        let root = Root::open(&path, Limits::default()).unwrap();
        let candidate = root.scan().unwrap().active.remove(0);
        fs::rename(container.join("0.log"), temp.path().join("old-generation")).unwrap();
        fs::write(container.join("0.log"), b"replacement\n").unwrap();
        assert!(matches!(
            root.open_candidate(&candidate),
            Err(Error::Changed)
        ));
        let candidate = root.scan().unwrap().active.remove(0);
        fs::OpenOptions::new()
            .write(true)
            .open(container.join("0.log"))
            .unwrap()
            .set_len(1)
            .unwrap();
        assert!(matches!(
            root.open_candidate(&candidate),
            Err(Error::Changed)
        ));
        fs::rename(&container, temp.path().join("moved-container")).unwrap();
        symlink(temp.path().join("moved-container"), &container).unwrap();
        assert!(matches!(
            root.open_candidate(&candidate),
            Err(Error::Unsafe)
        ));
    }
    #[test]
    fn root_capability_survives_path_replacement_without_following_new_tree() {
        let (temp, path, _container) = fixture();
        let root = Root::open(&path, Limits::default()).unwrap();
        let original = root.scan().unwrap().active.remove(0);
        let identity = root.identity();
        fs::rename(&path, temp.path().join("retained-root")).unwrap();
        fs::create_dir_all(path.join(POD).join("main")).unwrap();
        fs::write(path.join(POD).join("main/0.log"), b"new-tree\n").unwrap();
        let current = root.scan().unwrap().active.remove(0);
        assert_eq!(current.inode, original.inode);
        assert_eq!(root.identity(), identity);
        let mut data = String::new();
        root.open_candidate(&current)
            .unwrap()
            .read_to_string(&mut data)
            .unwrap();
        assert_eq!(data, "original\n");
    }
    #[test]
    fn forged_candidate_cannot_escape_or_open_compressed_source() {
        let (_temp, path, _container) = fixture();
        let root = Root::open(&path, Limits::default()).unwrap();
        let original = root.scan().unwrap().active.remove(0);
        for name in [
            "../escape",
            "0.log/escape",
            "0.log.gz",
            "0.log..\\escape",
            "00.log",
        ] {
            let mut forged = original.clone();
            forged.file_name = name.into();
            assert!(root.open_candidate(&forged).is_err());
        }
        let mut forged = original;
        forged.source.container = "../escape".into();
        assert!(root.open_candidate(&forged).is_err());
        assert!(Root::open(Path::new("relative"), Limits::default()).is_err());
        assert!(Root::open(Path::new("/tmp/../tmp"), Limits::default()).is_err());
    }
    #[test]
    fn disappearance_after_complete_scan_requires_rescan_instead_of_silent_replacement() {
        let (_temp, path, container) = fixture();
        let root = Root::open(&path, Limits::default()).unwrap();
        let candidate = root.scan().unwrap().active.remove(0);
        fs::remove_file(container.join("0.log")).unwrap();
        assert!(root.open_candidate(&candidate).is_err());
        let empty = root.scan().unwrap();
        assert!(empty.active.is_empty());
        assert!(empty.rotated.is_empty());
    }
    #[test]
    fn namespace_selector_is_exact_and_still_charges_unselected_root_entries() {
        let (temp, path, _container) = fixture();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, path.join("other_workload_runtime-other")).unwrap();
        let root = Root::open(&path, Limits::default()).unwrap();
        let selected = root.scan_namespace(Some("team")).unwrap();
        assert_eq!(selected.active.len(), 1);
        assert_eq!(selected.active[0].source.namespace, "team");
        assert!(selected.metrics.examined >= 4);
        assert!(root.scan().is_err());
        assert!(root.scan_namespace(Some("team_other")).is_err());
    }
}
