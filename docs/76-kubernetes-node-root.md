# Rooted node-log filesystem access

This slice adds `signal_agent::node_root`, a synchronous filesystem capability
for the later node producer. It does not activate node mode or close K8S-CONTEXT.
The host must call it in one retained physical worker with original operation
cancellation/deadline handling; caller timeout cannot release live filesystem
work or admit an unbounded replacement worker.

## Root and file capabilities

`Root::open` accepts an absolute path up to4096bytes/128components, rejects parent
traversal and opens each component using an already owned parent descriptor.
Every component uses safe Rustix1.1.5 `openat` with DIRECTORY,NOFOLLOW,CLOEXEC,
NONBLOCK and read-only access. The repository's unsafe-code prohibition remains.
Root device/inode identify the retained physical directory. A subsequent rename
or replacement of its configured pathname cannot redirect the existing capability.
The future node profile binding must include the configured root and its physical
identity; opening another root does not silently rebind retained cursors.

Discovery opens Pod directories, container directories and files relative to
owned descriptors; native strings never supply an absolute path. Each descendant
open refuses symlinks, including during reopening after rotation. Files must be
regular, have one link and remain on the root device; descendant directories also
must remain on that device. A descriptor-relative nofollow metadata precheck refuses ordinary special files
before opening them; descriptor checks repeat afterward and detect changed
device/inode. Opens retain NONBLOCK. This
is a configured trusted filesystem root, not protection against a privileged host
administrator replacing mounts or modifying files through another capability.

`open_candidate` revalidates source components, generation basename, regular file,
link count, device/inode and nondecreasing length. It returns a read-only owned
File. The producer must additionally compare its durable offset anchor and size:
inode identity alone cannot rule out reuse, same-size rewrite or copy-truncation.
Missing/changed/unsafe sources return an error rather than opening a replacement
silently. The caller may retain an already admitted physical FD while draining
an old generation; opening a different generation needs its own cursor decision.

## Bounded complete discovery

Default limits are4096examined entries,16active files and128rotated files;
configuration permits at most16384entries,16active files and256rotated files.
Every returned directory entry, including nonmatching names and dot entries,
charges the shared scan budget. Entry names are at most255bytes; directory-depth
is exactly Pod/container/file. Returned candidate arrays and temporary name
vectors are bounded by these limits. Rustix `Dir::read_from` uses an independently
opened directory stream, so repeated scans do not share an exhausted offset.

Only versioned SDK source identities matching
`namespace_pod-name_runtime-uid/container/<canonical-u32>.log` are active sources.
Safe bounded `.log.<rotation-suffix>` basenames are retained as recovery candidates;
compressed `.gz` candidates are marked and cannot be opened for raw CRI reading.
A missing or compressed unread generation cannot silently reset its cursor.
Nonmatching names are counted; invalid UTF8 names are not lossy-converted into
source identities. Metrics report examined/rejected names and active/rotated
occupancy for a completed scan. A capacity or I/O failure returns no prefix
snapshot; the later worker must count its refused scan and retain existing state.

Sorting is for presentation only, never durable slot allocation. A completed
iteration is not an atomic filesystem snapshot or proof of source coverage.
Concurrent changes may require rescan. The producer must restore durable source
slots first, inspect all bounded candidates before concluding a generation is
unavailable, refuse ambiguity and retain offset-anchor checks. Plain rotated
files are recovery candidates for existing cursors, not automatically new streams
whose old contents can be reingested repeatedly.

## Required following work

Rooted filesystem tests do not prove a production collector. Node-specific
cursor/profile/state quotas, prospective-state preflight, original event pins,
bounded retained physical worker, agent configuration/metrics/shutdown, spool and
sender integration remain. Follow [75](75-kubernetes-node-cri.md) and the saved
node design. Actual acceptance still requires read-only hostPath collection from
a running owned kind workload, permission denial, churn/rotation/deletion and
SIGKILL/uncertain-ACK/exact-replay recovery. AWS/EKS, native ARM64/current CI and
release decisions remain separate.

Rustix documentation was fetched with Context7 for `/bytecodealliance/rustix/v1.1.5`;
its version-matching published [openat](https://docs.rs/rustix/1.1.5/rustix/fs/fn.openat.html)
contract and local1.1.5 source confirm safe OwnedFd/AsFd ownership and
`Dir::read_from` independent stream behavior. The agent adds a direct dependency
on the version already in Cargo.lock; no dependency version changes.
