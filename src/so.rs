//! Native `.so` dumping from a running process's memory.
//!
//! Unlike the DEX path this does not use eBPF/uprobes at all: it reads
//! `/proc/<pid>/maps`, merges each library's separately mapped segments
//! (r--/r-x/rw-) back into one contiguous span, and reads it out with
//! `process_vm_readv`. It optionally also scans anonymous, path-less ELF
//! images to catch libraries a packer mapped/decrypted itself instead of
//! going through the dynamic linker. `--watch` keeps polling so a runtime-
//! decrypted library is captured the moment it appears (or changes).

// The shared parsing/grouping helpers below are only referenced by the
// Linux/Android implementation; on other hosts they exist solely for the
// unit tests, so don't warn about them being unused there.
#![cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]

use std::path::PathBuf;
use std::time::Duration;

/// Safety cap: refuse to allocate/dump a single module larger than this.
const MAX_SO_DUMP_SIZE: u64 = 512 * 1024 * 1024; // 512MB

/// Used to retry a failed whole-range read page by page, so a single
/// unreadable guard page doesn't sacrifice an entire dump.
const SO_READ_CHUNK: usize = 4096;

/// Caps how many times a single (pid, base, end) region is re-dumped when its
/// contents change, so an app that keeps writing can't drive an unbounded loop.
const WATCH_MAX_REDUMPS: u32 = 3;

/// Read-only firmware/partition mounts whose libraries can be pulled straight
/// off the device image, so dumping them from memory is just noise. Anonymous
/// (self-mapped) images are never matched here.
const SYSTEM_LIB_PREFIXES: [&str; 6] = [
    "/system/",
    "/apex/",
    "/vendor/",
    "/system_ext/",
    "/product/",
    "/odm/",
];

#[derive(Clone, Debug)]
pub struct DumpSoConfig {
    pub uid: u32,
    /// Only dump libraries whose path contains this substring (None = all).
    pub lib_filter: Option<String>,
    pub out: PathBuf,
    pub include_anon: bool,
    pub include_system: bool,
    pub auto_fix: bool,
    pub watch: bool,
    pub watch_interval: Duration,
    /// None = watch until interrupted.
    pub watch_timeout: Option<Duration>,
}

/// One candidate native image to dump: either a file-backed shared library
/// (spanning all of its mapped segments) or an anonymous, self-mapped ELF
/// image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SoModule {
    /// Library file name, or "anon_<base>" for self-mapped images.
    pub(crate) name: String,
    /// Full path from /proc/<pid>/maps, empty for anonymous modules.
    pub(crate) path: String,
    pub(crate) base: u64,
    pub(crate) end: u64, // exclusive
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MapEntry {
    start: u64,
    end: u64,
    perms: String,
    path: String,
}

/// Matches bionic-style "libfoo.so" as well as glibc-style versioned sonames
/// like "libfoo.so.6" or "libfoo.so.1.2" (upstream regex `\.so(\.[0-9]+)*$`).
fn has_so_suffix(path: &str) -> bool {
    let mut s = path;
    // Strip any trailing ".<digits>" groups, then check for a ".so" tail.
    while let Some(idx) = s.rfind('.') {
        let digits = &s[idx + 1..];
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            s = &s[..idx];
        } else {
            break;
        }
    }
    s.ends_with(".so")
}

/// Whether path lives on one of the firmware partitions.
fn is_system_lib_path(path: &str) -> bool {
    SYSTEM_LIB_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn base_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

pub(crate) fn sanitize_so_name(name: &str) -> String {
    let trimmed = name.strip_suffix(".so").unwrap_or(name);
    trimmed
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect()
}

pub(crate) fn parse_map_entries(content: &str) -> Vec<MapEntry> {
    content.lines().filter_map(parse_map_line).collect()
}

fn parse_map_line(line: &str) -> Option<MapEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let _offset = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    // Anything left is the path; anonymous mappings have none.
    let path = parts.collect::<Vec<_>>().join(" ");
    let (start, end) = range.split_once('-')?;
    Some(MapEntry {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        perms: perms.to_string(),
        path,
    })
}

/// Turns raw /proc/<pid>/maps entries into dumpable modules:
///   - file-backed ".so" mappings are merged by path into one [minStart,maxEnd)
///     span (the loader maps each PT_LOAD segment separately but reserves the
///     whole span contiguously)
///   - when `include_anon` is set, runs of path-less VMAs whose first mapped
///     page starts with the ELF magic are merged the same way
///
/// A non-empty `lib_filter` narrows file-backed modules to matching paths and,
/// since it can't match an anonymous region by name, implicitly disables
/// anonymous scanning. Unless `include_system` is set, file-backed libraries on
/// the firmware partitions are skipped (a `lib_filter` overrides this).
pub(crate) fn group_so_modules(
    entries: &[MapEntry],
    lib_filter: Option<&str>,
    mut include_anon: bool,
    include_system: bool,
    elf_magic_at: &dyn Fn(u64) -> bool,
) -> Vec<SoModule> {
    if lib_filter.is_some() {
        include_anon = false;
    }

    let mut mods: Vec<SoModule> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for e in entries {
        if e.path.is_empty() || !has_so_suffix(&e.path) {
            continue;
        }
        if let Some(filter) = lib_filter {
            if !e.path.contains(filter) {
                continue;
            }
        }
        if lib_filter.is_none() && !include_system && is_system_lib_path(&e.path) {
            continue;
        }
        match index.get(&e.path) {
            None => {
                index.insert(e.path.clone(), mods.len());
                mods.push(SoModule {
                    name: base_name(&e.path),
                    path: e.path.clone(),
                    base: e.start,
                    end: e.end,
                });
            }
            Some(&i) => {
                if e.start < mods[i].base {
                    mods[i].base = e.start;
                }
                if e.end > mods[i].end {
                    mods[i].end = e.end;
                }
            }
        }
    }

    if include_anon {
        let mut i = 0;
        while i < entries.len() {
            let e = &entries[i];
            if !e.path.is_empty() || !e.perms.contains('r') || !elf_magic_at(e.start) {
                i += 1;
                continue;
            }
            let start = e.start;
            let mut end = e.end;
            let mut j = i + 1;
            while j < entries.len() && entries[j].path.is_empty() && entries[j].start == end {
                end = entries[j].end;
                j += 1;
            }
            mods.push(SoModule {
                name: format!("anon_{start:x}"),
                path: String::new(),
                base: start,
                end,
            });
            i = j;
        }
    }

    mods
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod imp {
    use super::*;
    use crate::shutdown::keep_running;
    use anyhow::{Context, Result};
    use std::collections::HashMap;
    use std::fs;
    use std::hash::Hasher;
    use std::path::Path;
    use std::time::Instant;

    /// One `process_vm_readv` call. Returns the raw syscall result (bytes read,
    /// or negative on error).
    fn pvr(pid: u32, addr: u64, buf: &mut [u8]) -> isize {
        if buf.is_empty() {
            return 0;
        }
        let mut local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut remote = libc::iovec {
            iov_base: addr as usize as *mut libc::c_void,
            iov_len: buf.len(),
        };
        unsafe {
            libc::syscall(
                libc::SYS_process_vm_readv,
                pid as libc::pid_t,
                &mut local,
                1usize,
                &mut remote,
                1usize,
                0usize,
            ) as isize
        }
    }

    /// Reads `buf.len()` bytes at `base`. If the whole-range read fails (a
    /// common symptom of a guard/unmapped page inside an otherwise-contiguous
    /// span), it falls back to page-sized reads so an unreadable page only
    /// costs that page. Returns the number of bytes actually populated.
    fn read_remote_range(pid: u32, base: u64, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let n = pvr(pid, base, buf);
        if n >= 0 && n as usize == buf.len() {
            return buf.len();
        }

        let len = buf.len();
        let mut total = 0;
        let mut off = 0;
        while off < len {
            let end = (off + SO_READ_CHUNK).min(len);
            let cn = pvr(pid, base + off as u64, &mut buf[off..end]);
            if cn >= 0 && cn as usize == end - off {
                total += end - off;
            }
            off += SO_READ_CHUNK;
        }
        total
    }

    fn peek_is_elf(pid: u32, addr: u64) -> bool {
        let mut buf = [0u8; 4];
        pvr(pid, addr, &mut buf) == 4 && buf == [0x7f, b'E', b'L', b'F']
    }

    /// Scans /proc for running processes owned by `uid`.
    fn find_pids_for_uid(uid: u32) -> Result<Vec<u32>> {
        let mut pids = Vec::new();
        for entry in fs::read_dir("/proc").context("read /proc")? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            for line in status.lines() {
                let Some(rest) = line.strip_prefix("Uid:") else {
                    continue;
                };
                if rest
                    .split_whitespace()
                    .next()
                    .and_then(|f| f.parse::<u32>().ok())
                    == Some(uid)
                {
                    pids.push(pid);
                }
                break;
            }
        }
        if pids.is_empty() {
            anyhow::bail!("no running process found for uid {uid}");
        }
        Ok(pids)
    }

    fn scan_so_modules(
        pid: u32,
        lib_filter: Option<&str>,
        include_anon: bool,
        include_system: bool,
    ) -> Result<Vec<SoModule>> {
        let content = fs::read_to_string(format!("/proc/{pid}/maps"))
            .with_context(|| format!("read /proc/{pid}/maps"))?;
        let entries = parse_map_entries(&content);
        let elf = |addr: u64| peek_is_elf(pid, addr);
        Ok(group_so_modules(
            &entries,
            lib_filter,
            include_anon,
            include_system,
            &elf,
        ))
    }

    /// Reads each module's full mapped span and writes it as a raw file under
    /// `out_dir`. Returns the paths written.
    fn dump_so_modules(pid: u32, mods: &[SoModule], out_dir: &Path) -> Vec<PathBuf> {
        let mut written = Vec::new();
        for m in mods {
            let size = m.end - m.base;
            if size == 0 {
                continue;
            }
            if size > MAX_SO_DUMP_SIZE {
                eprintln!(
                    "[so-dump] skip {}: size {size} exceeds safety cap {MAX_SO_DUMP_SIZE}",
                    m.name
                );
                continue;
            }

            let mut buf = vec![0u8; size as usize];
            let got = read_remote_range(pid, m.base, &mut buf);
            if got == 0 {
                eprintln!(
                    "[so-dump] failed to read {} (pid={pid}, 0x{:x}-0x{:x})",
                    m.name, m.base, m.end
                );
                continue;
            }
            if (got as u64) < size {
                eprintln!(
                    "[so-dump] partial read for {}: {got}/{size} bytes captured",
                    m.name
                );
            }

            let fname = out_dir.join(format!(
                "so_{pid}_{:x}_{:x}_{}.so",
                m.base,
                size,
                sanitize_so_name(&m.name)
            ));
            match fs::write(&fname, &buf) {
                Ok(()) => {
                    println!("[so-dump] saved {} (size={size})", fname.display());
                    written.push(fname);
                }
                Err(err) => eprintln!("[so-dump] write failed for {}: {err}", fname.display()),
            }
        }
        written
    }

    /// Tracks a region across scans: `fp` is a cheap fingerprint of a few
    /// sampled windows, `dumps` is how many times it's been captured so far.
    #[derive(Clone, Copy)]
    struct ModWatchState {
        fp: u64,
        dumps: u32,
    }

    /// Samples a few small windows across a module's span and hashes them.
    /// Cheap enough to run every scan; changes when a packer rewrites code in
    /// place (e.g. decrypts .text), which is what tells the watcher to re-dump.
    fn module_fingerprint(pid: u32, m: &SoModule) -> u64 {
        let span = m.end - m.base;
        if span == 0 {
            return 0;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let mut win = [0u8; 256];
        for frac in [0, span / 4, span / 2, (span * 3) / 4] {
            let n = pvr(pid, m.base + frac, &mut win);
            if n > 0 {
                h.write(&win[..n as usize]);
            }
        }
        h.finish()
    }

    fn sleep_interruptible(dur: Duration) {
        let step = Duration::from_millis(100);
        let mut slept = Duration::ZERO;
        while slept < dur && keep_running() {
            let chunk = step.min(dur - slept);
            std::thread::sleep(chunk);
            slept += chunk;
        }
    }

    /// Polls the target uid's processes and dumps each newly appearing (or
    /// changed) module until the deadline or an interrupt. Captures runtime-
    /// decrypted / self-mapped images without knowing the decrypt routine.
    fn watch_and_dump(config: &DumpSoConfig, out_dir: &Path) -> Vec<PathBuf> {
        let mut written = Vec::new();
        let mut seen: HashMap<String, ModWatchState> = HashMap::new();
        let deadline = config.watch_timeout.map(|t| Instant::now() + t);
        let lib_filter = config.lib_filter.as_deref();

        loop {
            let pids = find_pids_for_uid(config.uid).unwrap_or_default();
            for pid in pids {
                let Ok(mods) =
                    scan_so_modules(pid, lib_filter, config.include_anon, config.include_system)
                else {
                    continue;
                };
                let mut fresh = Vec::new();
                for m in mods {
                    let key = format!("{pid}_{:x}_{:x}", m.base, m.end);
                    let prev = seen.get(&key).copied();
                    if let Some(st) = prev {
                        if st.dumps >= WATCH_MAX_REDUMPS {
                            continue; // settled: stop re-reading it
                        }
                    }
                    let fp = module_fingerprint(pid, &m);
                    if let Some(st) = prev {
                        if st.fp == fp {
                            continue; // unchanged since the last capture
                        }
                    }
                    seen.insert(
                        key,
                        ModWatchState {
                            fp,
                            dumps: prev.map_or(0, |st| st.dumps) + 1,
                        },
                    );
                    fresh.push(m);
                }
                if !fresh.is_empty() {
                    println!(
                        "[so-watch] pid {pid}: {} new/changed module(s)",
                        fresh.len()
                    );
                    written.extend(dump_so_modules(pid, &fresh, out_dir));
                }
            }

            if !keep_running() {
                break;
            }
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    break;
                }
            }
            sleep_interruptible(config.watch_interval);
            if !keep_running() {
                break;
            }
        }
        written
    }

    extern "C" fn signal_handler(_: libc::c_int) {
        crate::shutdown::request_stop();
    }

    fn install_signal_handlers() {
        unsafe {
            libc::signal(libc::SIGINT, signal_handler as *const () as usize);
            libc::signal(libc::SIGTERM, signal_handler as *const () as usize);
            libc::signal(libc::SIGHUP, signal_handler as *const () as usize);
            libc::signal(libc::SIGQUIT, signal_handler as *const () as usize);
        }
    }

    pub fn run(config: DumpSoConfig) -> Result<()> {
        fs::create_dir_all(&config.out)
            .with_context(|| format!("create output dir {}", config.out.display()))?;

        let lib_filter = config.lib_filter.as_deref();
        let written = if config.watch {
            install_signal_handlers();
            println!(
                "[so-dump] watching uid {} (interval {}s, timeout {})",
                config.uid,
                config.watch_interval.as_secs(),
                config
                    .watch_timeout
                    .map(|t| format!("{}s", t.as_secs()))
                    .unwrap_or_else(|| "until interrupted".to_string()),
            );
            watch_and_dump(&config, &config.out)
        } else {
            let pids = find_pids_for_uid(config.uid)?;
            let mut written = Vec::new();
            for pid in pids {
                let mods =
                    scan_so_modules(pid, lib_filter, config.include_anon, config.include_system)?;
                println!("[so-dump] pid {pid}: {} module(s) to dump", mods.len());
                written.extend(dump_so_modules(pid, &mods, &config.out));
            }
            written
        };

        println!("[so-dump] {} file(s) written", written.len());

        if config.auto_fix && !written.is_empty() {
            println!("[so-dump] auto-fixing dumped .so files...");
            if let Err(err) = crate::so_fix::fix_so_directory(&config.out, &[], "") {
                eprintln!("[so-fix] auto-fix failed: {err:#}");
            }
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod imp {
    use super::DumpSoConfig;
    use anyhow::Result;

    pub fn run(_config: DumpSoConfig) -> Result<()> {
        anyhow::bail!("dumpso is only supported on Linux/Android targets")
    }
}

pub use imp::run;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(start: u64, end: u64, perms: &str, path: &str) -> MapEntry {
        MapEntry {
            start,
            end,
            perms: perms.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn so_suffix_matches_bionic_and_versioned_sonames() {
        assert!(has_so_suffix("/data/app/libfoo.so"));
        assert!(has_so_suffix("libc.so.6"));
        assert!(has_so_suffix("libfoo.so.1.2"));
        assert!(!has_so_suffix("/system/bin/app_process"));
        assert!(!has_so_suffix("libfoo.sox"));
        assert!(!has_so_suffix("foo.so.bar"));
    }

    #[test]
    fn system_lib_paths_are_recognized() {
        assert!(is_system_lib_path("/apex/com.android.art/lib64/libart.so"));
        assert!(is_system_lib_path("/vendor/lib64/libfoo.so"));
        assert!(!is_system_lib_path("/data/app/~~abc/libnative.so"));
    }

    #[test]
    fn sanitize_strips_suffix_and_illegal_chars() {
        assert_eq!(sanitize_so_name("libfoo.so"), "libfoo");
        assert_eq!(sanitize_so_name("lib bar!.so"), "lib_bar_");
        assert_eq!(sanitize_so_name("anon_7f00"), "anon_7f00");
    }

    #[test]
    fn group_merges_file_backed_segments_by_path() {
        let entries = vec![
            entry(0x1000, 0x2000, "r--p", "/data/app/libx.so"),
            entry(0x2000, 0x4000, "r-xp", "/data/app/libx.so"),
            entry(0x4000, 0x5000, "rw-p", "/data/app/libx.so"),
        ];
        let mods = group_so_modules(&entries, None, false, false, &|_| false);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "libx.so");
        assert_eq!(mods[0].base, 0x1000);
        assert_eq!(mods[0].end, 0x5000);
    }

    #[test]
    fn group_skips_system_libs_unless_included() {
        let entries = vec![entry(0x1000, 0x2000, "r-xp", "/apex/foo/libart.so")];
        assert_eq!(
            group_so_modules(&entries, None, false, false, &|_| false).len(),
            0
        );
        assert_eq!(
            group_so_modules(&entries, None, false, true, &|_| false).len(),
            1
        );
    }

    #[test]
    fn lib_filter_narrows_and_overrides_system_skip() {
        let entries = vec![
            entry(0x1000, 0x2000, "r-xp", "/apex/foo/libart.so"),
            entry(0x3000, 0x4000, "r-xp", "/data/app/libtarget.so"),
        ];
        let mods = group_so_modules(&entries, Some("libtarget"), true, false, &|_| true);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "libtarget.so");
    }

    #[test]
    fn group_merges_anonymous_elf_runs_when_enabled() {
        let entries = vec![
            entry(0x10000, 0x11000, "r--p", ""), // ELF magic here
            entry(0x11000, 0x13000, "r-xp", ""), // contiguous, merged
            entry(0x20000, 0x21000, "rw-p", ""), // no ELF magic, ignored
        ];
        let elf_at = |addr: u64| addr == 0x10000;
        let mods = group_so_modules(&entries, None, true, false, &elf_at);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].name, "anon_10000");
        assert_eq!(mods[0].base, 0x10000);
        assert_eq!(mods[0].end, 0x13000);
    }

    #[test]
    fn anonymous_scan_disabled_when_lib_filter_set() {
        let entries = vec![entry(0x10000, 0x11000, "r--p", "")];
        let mods = group_so_modules(&entries, Some("libx"), true, false, &|_| true);
        assert_eq!(mods.len(), 0);
    }
}
