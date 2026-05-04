use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct DumpConfig {
    pub uid: u32,
    pub pid: Option<u32>,
    pub package_name: Option<String>,
    pub libart: PathBuf,
    pub out: PathBuf,
    pub trace: bool,
    pub auto_fix: bool,
    pub execute_offset: Option<u64>,
    pub nterp_offset: Option<u64>,
    pub runtime_layout: Option<crate::art::ArtRuntimeLayout>,
    pub debug_layout: bool,
    pub code_item_fallback: bool,
    pub maps_scan: bool,
    pub native_buffer_scan: bool,
    pub libc: Option<PathBuf>,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod imp {
    use super::DumpConfig;
    use crate::{art, dex::DexParser, fix};
    use anyhow::{Context, Result};
    use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
    use aya::programs::{ProgramError, UProbe};
    use aya::{include_bytes_aligned, Btf, EbpfLoader, Pod};
    use object::Endianness;
    use serde::Serialize;
    use sha1::{Digest, Sha1};
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, RwLock};
    use std::thread;
    use std::time::Duration;

    const BPF_OBJECT: &[u8] =
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bpf_arm64_bpfel.o"));
    const DEX_CHUNK_HEADER_SIZE: usize = 24;
    const METHOD_EVENT_HEADER_SIZE: usize = 40;
    const READ_FAILURE_HEADER_SIZE: usize = 24;
    const LAYOUT_DEBUG_EVENT_SIZE: usize = 40;
    const NATIVE_BUFFER_EVENT_SIZE: usize = 32;
    const DEX_HEADER_FILE_SIZE_OFFSET: usize = 0x20;
    const DEX_HEADER_SIZE_OFFSET: usize = 0x24;
    const DEX_HEADER_ENDIAN_TAG_OFFSET: usize = 0x28;
    const DEX_HEADER_MAP_OFF_OFFSET: usize = 0x34;
    const DEX_HEADER_SIZE: u32 = 0x70;
    const DEX_ENDIAN_CONSTANT: u32 = 0x1234_5678;
    const MAX_DEX_FILE_SIZE: u32 = 0x4000_0000;
    const CODE_ITEM_BACKSCAN_LIMIT: u64 = 64 * 1024 * 1024;
    const CODE_ITEM_BACKSCAN_STEP: u64 = 0x1000;
    const MAPS_SCAN_MAX_REGION: u64 = 512 * 1024 * 1024;
    const NATIVE_BUFFER_SCAN_LIMIT: u64 = 64 * 1024 * 1024;
    const NATIVE_BUFFER_SCAN_STEP: u64 = 0x1000;
    static RUNNING: AtomicBool = AtomicBool::new(false);

    fn keep_running() -> bool {
        RUNNING.load(Ordering::Relaxed)
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct BpfConfig {
        uid: u32,
        pid: i32,
        code_item_fallback: u32,
        debug_layout: u32,
        native_buffer_scan: u32,
        reserved: u32,
    }

    unsafe impl Pod for BpfConfig {}

    unsafe impl Pod for art::ArtRuntimeLayout {}

    #[derive(Clone, Debug, Serialize)]
    struct MethodCodeRecord {
        name: String,
        method_idx: u32,
        code: String,
    }

    #[derive(Default)]
    struct DumpState {
        output_dir: PathBuf,
        trace: bool,
        dex_cache: RwLock<HashMap<u64, Vec<u8>>>,
        dex_hashes: RwLock<HashSet<[u8; 20]>>,
        dex_sizes: RwLock<HashMap<u64, u32>>,
        pending_dex: RwLock<HashMap<u64, DexRecvState>>,
        method_records: RwLock<HashMap<u64, Vec<MethodCodeRecord>>>,
        method_sig_cache: RwLock<HashMap<(u64, u32), String>>,
    }

    #[derive(Clone, Debug)]
    struct DexRecvState {
        total: u32,
        recv: u32,
        buf: Vec<u8>,
    }

    impl DumpState {
        fn new(output_dir: PathBuf, trace: bool) -> Self {
            Self {
                output_dir,
                trace,
                dex_cache: RwLock::new(HashMap::new()),
                dex_hashes: RwLock::new(HashSet::new()),
                dex_sizes: RwLock::new(HashMap::new()),
                pending_dex: RwLock::new(HashMap::new()),
                method_records: RwLock::new(HashMap::new()),
                method_sig_cache: RwLock::new(HashMap::new()),
            }
        }

        fn handle_dex_event(&self, data: &[u8]) {
            let Some(evt) = DexEvent::parse(data) else {
                eprintln!("Dex event too short: {} bytes", data.len());
                return;
            };
            self.dex_sizes.write().unwrap().insert(evt.begin, evt.size);
        }

        fn handle_dex_chunk(&self, data: &[u8]) {
            let Some(hdr) = DexChunkEvent::parse(data) else {
                eprintln!("Dex chunk event too short: {} bytes", data.len());
                return;
            };
            let payload_start = DEX_CHUNK_HEADER_SIZE;
            let payload_end = payload_start.saturating_add(hdr.data_len as usize);
            let Some(payload) = data.get(payload_start..payload_end) else {
                eprintln!("Dex chunk payload out of bounds: {} bytes", data.len());
                return;
            };

            let maybe_complete = {
                let mut pending = self.pending_dex.write().unwrap();
                let state = pending.entry(hdr.begin).or_insert_with(|| {
                    self.dex_sizes.write().unwrap().insert(hdr.begin, hdr.size);
                    DexRecvState {
                        total: hdr.size,
                        recv: 0,
                        buf: vec![0; hdr.size as usize],
                    }
                });

                let end = hdr.offset.saturating_add(hdr.data_len);
                if end as usize <= state.buf.len() {
                    state.buf[hdr.offset as usize..end as usize].copy_from_slice(payload);
                    if state.recv < end {
                        state.recv = end;
                    }
                }

                if state.recv >= state.total {
                    pending
                        .remove(&hdr.begin)
                        .map(|state| (hdr.begin, hdr.size, state.buf))
                } else {
                    None
                }
            };

            if let Some((begin, size, bytes)) = maybe_complete {
                self.save_dex(begin, size, bytes);
            }
        }

        fn handle_method_event(&self, data: &[u8]) {
            let Some(hdr) = MethodEvent::parse(data) else {
                return;
            };
            let bytecode = if hdr.codeitem_size > 0 {
                data.get(
                    METHOD_EVENT_HEADER_SIZE..METHOD_EVENT_HEADER_SIZE + hdr.codeitem_size as usize,
                )
                .unwrap_or_default()
            } else {
                &[]
            };

            let method_name = self.method_name(hdr.begin, hdr.method_index);

            if self.trace {
                if hdr.codeitem_size > 0 {
                    println!(
                        "{} (pid={}, dex=0x{:x}, method_idx={}, art_method=0x{:x}, bytecode_size={})",
                        method_name,
                        hdr.pid,
                        hdr.begin,
                        hdr.method_index,
                        hdr.art_method_ptr,
                        hdr.codeitem_size
                    );
                } else {
                    println!(
                        "{} (pid={}, dex=0x{:x}, method_idx={}, art_method=0x{:x})",
                        method_name, hdr.pid, hdr.begin, hdr.method_index, hdr.art_method_ptr
                    );
                }
            }

            if !bytecode.is_empty() {
                let record = MethodCodeRecord {
                    name: method_name,
                    method_idx: hdr.method_index,
                    code: hex::encode(bytecode),
                };
                self.method_records
                    .write()
                    .unwrap()
                    .entry(hdr.begin)
                    .or_default()
                    .push(record);
            }
        }

        fn handle_read_failure(&self, data: &[u8]) {
            let Some(evt) = ReadFailureEvent::parse(data) else {
                eprintln!("Read failure event too short: {} bytes", data.len());
                return;
            };
            eprintln!(
                "eBPF read failed at offset {} for dex 0x{:x} (pid={}); using process_vm_readv fallback",
                evt.failed_offset, evt.begin, evt.pid
            );
            match read_remote_mem(evt.pid, evt.begin, evt.size) {
                Ok(bytes) => {
                    self.pending_dex.write().unwrap().remove(&evt.begin);
                    self.save_dex(evt.begin, evt.size, bytes);
                }
                Err(err) => eprintln!("process_vm_readv failed for dex 0x{:x}: {err:#}", evt.begin),
            }
        }

        fn handle_layout_debug_event(&self, data: &[u8]) {
            let Some(evt) = LayoutDebugEvent::parse(data) else {
                eprintln!("Layout debug event too short: {} bytes", data.len());
                return;
            };
            if self.trace {
                println!(
                    "layout event pid={} art_method=0x{:x} code_item=0x{:x} begin=0x{:x} size={} reason={} source={}",
                    evt.pid,
                    evt.art_method_ptr,
                    evt.code_item_ptr,
                    evt.begin,
                    evt.size,
                    evt.reason,
                    evt.source
                );
            }
            if evt.code_item_ptr == 0 {
                return;
            }
            match dump_dex_from_code_item(evt.pid, evt.code_item_ptr) {
                Ok(Some((begin, size, bytes))) => self.save_dex(begin, size, bytes),
                Ok(None) => {
                    if self.trace {
                        eprintln!(
                            "code item fallback did not find dex header for pid={} code_item=0x{:x}",
                            evt.pid, evt.code_item_ptr
                        );
                    }
                }
                Err(err) => eprintln!(
                    "code item fallback failed for pid={} code_item=0x{:x}: {err:#}",
                    evt.pid, evt.code_item_ptr
                ),
            }
        }

        fn handle_native_buffer_event(&self, data: &[u8]) {
            let Some(evt) = NativeBufferEvent::parse(data) else {
                eprintln!("Native buffer event too short: {} bytes", data.len());
                return;
            };
            if self.trace {
                println!(
                    "native buffer event pid={} addr=0x{:x} size=0x{:x} source={} prot=0x{:x} flags=0x{:x}",
                    evt.pid, evt.addr, evt.size, evt.source, evt.prot, evt.flags
                );
            }
            match dump_dex_from_native_buffer(evt.pid, evt.addr, evt.size) {
                Ok(found) => {
                    for (begin, size, bytes) in found {
                        self.save_dex(begin, size, bytes);
                    }
                }
                Err(err) => {
                    if self.trace {
                        eprintln!(
                            "native buffer scan failed for pid={} addr=0x{:x} size=0x{:x}: {err:#}",
                            evt.pid, evt.addr, evt.size
                        );
                    }
                }
            }
        }

        fn save_dex(&self, begin: u64, size: u32, bytes: Vec<u8>) {
            {
                let mut cache = self.dex_cache.write().unwrap();
                if cache.contains_key(&begin) {
                    return;
                }
                if let Err(err) = DexParser::new(&bytes) {
                    // Skip writing malformed dex so the fix stage stays clean
                    // and we don't leave half-truncated files on disk.
                    eprintln!(
                        "Skip malformed dex 0x{begin:x} ({} bytes): {err}",
                        bytes.len()
                    );
                    return;
                }
                let hash = Self::dex_content_hash(&bytes);
                if !self.dex_hashes.write().unwrap().insert(hash) {
                    if self.trace {
                        eprintln!(
                            "Skip duplicate dex 0x{begin:x} ({} bytes, sha1={})",
                            bytes.len(),
                            hex::encode(hash)
                        );
                    }
                    return;
                }
                // Drop any half-assembled chunks for this dex; another path
                // just landed a complete, valid copy.
                self.pending_dex.write().unwrap().remove(&begin);
                cache.insert(begin, bytes.clone());
            }
            self.dex_sizes.write().unwrap().insert(begin, size);

            let file_name = self.output_dir.join(format!("dex_{begin:x}_{size:x}.dex"));
            match fs::write(&file_name, &bytes) {
                Ok(()) => println!(
                    "Dex file saved to {}, size {}",
                    file_name.display(),
                    bytes.len()
                ),
                Err(err) => eprintln!("Write dexData failed for {}: {err}", file_name.display()),
            }
        }

        fn dex_content_hash(bytes: &[u8]) -> [u8; 20] {
            let mut sha1 = Sha1::new();
            sha1.update(bytes);
            sha1.finalize().into()
        }

        fn method_name(&self, begin: u64, method_idx: u32) -> String {
            if let Some(cached) = self
                .method_sig_cache
                .read()
                .unwrap()
                .get(&(begin, method_idx))
                .cloned()
            {
                return cached;
            }

            let name = self
                .dex_cache
                .read()
                .unwrap()
                .get(&begin)
                .and_then(|dex| DexParser::new(dex).ok())
                .and_then(|parser| parser.get_method_info(method_idx).ok())
                .map(|method| method.pretty_method())
                .unwrap_or_else(|| format!("method_idx_{method_idx}"));

            self.method_sig_cache
                .write()
                .unwrap()
                .insert((begin, method_idx), name.clone());
            name
        }

        fn flush_json(&self) -> Result<()> {
            let mut records_by_dex = self.method_records.write().unwrap();
            let records_by_dex = std::mem::take(&mut *records_by_dex);

            let sizes = self.dex_sizes.read().unwrap().clone();
            for (begin, records) in records_by_dex {
                if records.is_empty() {
                    continue;
                }
                let size =
                    sizes
                        .get(&begin)
                        .copied()
                        .or_else(|| {
                            self.dex_cache.read().unwrap().get(&begin).and_then(|dex| {
                                DexParser::new(dex).ok().map(|p| p.header().file_size)
                            })
                        })
                        .unwrap_or(0);
                let file_name = self
                    .output_dir
                    .join(format!("dex_{begin:x}_{size:x}_code.json"));
                let file = fs::File::create(&file_name)
                    .with_context(|| format!("failed to create {}", file_name.display()))?;
                serde_json::to_writer_pretty(file, &records)
                    .with_context(|| format!("failed to write {}", file_name.display()))?;
                println!(
                    "Saved code records to {} ({} entries)",
                    file_name.display(),
                    records.len()
                );
            }
            Ok(())
        }

        fn scan_uid_maps_once(&self, uid: u32) {
            match scan_uid_maps(uid) {
                Ok(found) => self.save_scanned_dexes(found),
                Err(err) => {
                    if self.trace {
                        eprintln!("maps scan skipped: {err:#}");
                    }
                }
            }
        }

        fn save_scanned_dexes(&self, dexes: Vec<(u64, u32, Vec<u8>)>) {
            for (begin, size, bytes) in dexes {
                self.save_dex(begin, size, bytes);
            }
        }

        fn spawn_maps_scan(self: &Arc<Self>, uid: u32, pid: Option<u32>) -> thread::JoinHandle<()> {
            let state = Arc::clone(self);
            thread::spawn(move || match pid {
                Some(pid) => match scan_process_maps(pid) {
                    Ok(dexes) => state.save_scanned_dexes(dexes),
                    Err(err) => eprintln!("maps scan failed for pid {pid}: {err:#}"),
                },
                None => state.scan_uid_maps_once(uid),
            })
        }
    }

    pub fn run(config: DumpConfig) -> Result<()> {
        fs::create_dir_all(&config.out).with_context(|| {
            format!("failed to create output directory {}", config.out.display())
        })?;

        let targets =
            art::find_art_offsets(&config.libart, config.execute_offset, config.nterp_offset)
                .with_context(|| {
                    format!(
                        "failed to locate ART hook targets in {}",
                        config.libart.display()
                    )
                })?;
        print_target("Execute", targets.execute);
        print_target("ExecuteNterpImpl", targets.execute_nterp);
        print_target(
            "ExecuteNterpWithClinitImpl",
            targets.execute_nterp_with_clinit,
        );
        print_target("VerifyClass", targets.verify_class);
        print_target("DexFile::DexFile", targets.dex_file_ctor);
        print_target("ClassLinker::RegisterDexFile", targets.register_dex_file);
        println!(
            "[+] nterp_op_invoke_* pattern targets: {}",
            targets.nterp_invoke_addrs.len()
        );
        let runtime_layout = match config.runtime_layout {
            Some(layout) => layout,
            None => art::resolve_runtime_layout(&config.libart).with_context(|| {
                format!(
                    "failed to resolve ART layout for {}",
                    config.libart.display()
                )
            })?,
        };
        println!("[+] ART runtime layout: {}", runtime_layout.summary());
        println!(
            "[+] CodeItem fallback: {}",
            if config.code_item_fallback {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "[+] Native buffer scan: {}",
            if config.native_buffer_scan {
                "enabled"
            } else {
                "disabled"
            }
        );

        let asset_btf = load_asset_btf();
        let mut loader = EbpfLoader::new();
        if let Some(btf) = asset_btf.as_ref() {
            loader.btf(Some(btf));
        }
        bump_memlock_rlimit();
        let mut ebpf = loader
            .load(BPF_OBJECT)
            .context("failed to load eBPF object")?;

        let mut config_map: AyaHashMap<&mut MapData, u32, BpfConfig> =
            AyaHashMap::try_from(ebpf.map_mut("config_map").context("config_map not found")?)?;
        config_map.insert(
            0,
            BpfConfig {
                uid: config.uid,
                pid: config.pid.map(|p| p as i32).unwrap_or(-1),
                code_item_fallback: u32::from(config.code_item_fallback),
                debug_layout: u32::from(config.debug_layout),
                native_buffer_scan: u32::from(config.native_buffer_scan),
                reserved: 0,
            },
            0,
        )?;
        let mut layout_map: AyaHashMap<&mut MapData, u32, art::ArtRuntimeLayout> =
            AyaHashMap::try_from(
                ebpf.map_mut("art_layout_map")
                    .context("art_layout_map not found")?,
            )?;
        layout_map.insert(0, runtime_layout, 0)?;
        println!("[+] Filtering on uid {}", config.uid);

        let mut attached_main = 0usize;
        if let Some(target) = targets.execute {
            attach_probe(
                &mut ebpf,
                "uprobe_libart_execute",
                &config.libart,
                target.addr,
            )
            .context("failed to attach Execute uprobe")?;
            attached_main += 1;
        }
        if let Some(target) = targets.execute_nterp {
            attach_probe(
                &mut ebpf,
                "uprobe_libart_executeNterpImpl",
                &config.libart,
                target.addr,
            )
            .context("failed to attach ExecuteNterpImpl uprobe")?;
            attached_main += 1;
        }
        if let Some(target) = targets.execute_nterp_with_clinit {
            attach_probe(
                &mut ebpf,
                "uprobe_libart_executeNterpImpl",
                &config.libart,
                target.addr,
            )
            .context("failed to attach ExecuteNterpWithClinitImpl uprobe")?;
            attached_main += 1;
        }
        if attached_main == 0 {
            anyhow::bail!("no ART main entry uprobe was attached");
        }

        for target in targets.nterp_invoke_addrs {
            if let Err(err) = attach_probe(
                &mut ebpf,
                "uprobe_libart_nterpOpInvoke",
                &config.libart,
                target.addr,
            ) {
                eprintln!(
                    "[-] failed to attach nterp_op_invoke_* at 0x{:x}: {err:#}",
                    target.addr
                );
            }
        }
        if let Some(target) = targets.dex_file_ctor {
            if let Err(err) = attach_probe(
                &mut ebpf,
                "uprobe_libart_dexFileCtor",
                &config.libart,
                target.addr,
            ) {
                eprintln!(
                    "[-] failed to attach DexFile::DexFile at 0x{:x}: {err:#}",
                    target.addr
                );
            }
        }
        if let Some(target) = targets.register_dex_file {
            if let Err(err) = attach_probe(
                &mut ebpf,
                "uprobe_libart_registerDexFile",
                &config.libart,
                target.addr,
            ) {
                eprintln!(
                    "[-] failed to attach RegisterDexFile at 0x{:x}: {err:#}",
                    target.addr
                );
            }
        }
        if config.native_buffer_scan {
            if let Some(libc_path) = resolve_libc_path(config.libc.as_deref()) {
                attach_native_buffer_probes(&mut ebpf, &libc_path);
            } else {
                eprintln!("[-] libc not found; native buffer scan disabled");
            }
        }

        RUNNING.store(true, Ordering::SeqCst);
        install_signal_handlers();

        let state = Arc::new(DumpState::new(config.out.clone(), config.trace));
        let maps_scan_thread = if config.maps_scan {
            Some(state.spawn_maps_scan(config.uid, config.pid))
        } else {
            None
        };

        let mut events =
            RingBuf::try_from(ebpf.take_map("events").context("events map not found")?)?;
        let mut method_events = RingBuf::try_from(
            ebpf.take_map("method_events")
                .context("method_events map not found")?,
        )?;
        let mut dex_chunks = RingBuf::try_from(
            ebpf.take_map("dex_chunks")
                .context("dex_chunks map not found")?,
        )?;
        let mut read_failures = RingBuf::try_from(
            ebpf.take_map("read_failures")
                .context("read_failures map not found")?,
        )?;
        let mut layout_debug_events = RingBuf::try_from(
            ebpf.take_map("layout_debug_events")
                .context("layout_debug_events map not found")?,
        )?;
        let mut native_buffer_events = RingBuf::try_from(
            ebpf.take_map("native_buffer_events")
                .context("native_buffer_events map not found")?,
        )?;

        println!("eBPF DexDumper started successfully");
        while RUNNING.load(Ordering::SeqCst) {
            drain_ring(&mut events, |data| state.handle_dex_event(data));
            drain_ring(&mut method_events, |data| state.handle_method_event(data));
            drain_ring(&mut dex_chunks, |data| state.handle_dex_chunk(data));
            drain_ring(&mut read_failures, |data| state.handle_read_failure(data));
            drain_ring(&mut layout_debug_events, |data| {
                state.handle_layout_debug_event(data)
            });
            drain_ring(&mut native_buffer_events, |data| {
                state.handle_native_buffer_event(data)
            });
            thread::sleep(Duration::from_millis(50));
        }
        if let Some(handle) = maps_scan_thread {
            if handle.join().is_err() {
                eprintln!("[!] maps scan thread panicked");
            }
        }

        println!("Stopping eBPF DexDumper");
        drain_ring(&mut events, |data| state.handle_dex_event(data));
        drain_ring(&mut method_events, |data| state.handle_method_event(data));
        drain_ring(&mut dex_chunks, |data| state.handle_dex_chunk(data));
        drain_ring(&mut read_failures, |data| state.handle_read_failure(data));
        drain_ring(&mut layout_debug_events, |data| {
            state.handle_layout_debug_event(data)
        });
        drain_ring(&mut native_buffer_events, |data| {
            state.handle_native_buffer_event(data)
        });
        state.flush_json()?;
        if config.auto_fix {
            println!("[+] Auto-fixing DEX files...");
            if let Err(err) = fix::fix_dex_directory(&config.out) {
                eprintln!("[!] Auto-fix failed: {err:#}");
            }
        }
        println!("DexDumper stopped");
        Ok(())
    }

    fn attach_probe(
        ebpf: &mut aya::Ebpf,
        program_name: &str,
        target: &std::path::Path,
        offset: u64,
    ) -> Result<()> {
        let program: &mut UProbe = ebpf
            .program_mut(program_name)
            .with_context(|| format!("{program_name} not found"))?
            .try_into()?;
        match program.load() {
            Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
            Err(err) => return Err(err.into()),
        }
        program.attach(None, offset, target, None)?;
        Ok(())
    }

    fn attach_native_buffer_probes(ebpf: &mut aya::Ebpf, libc_path: &std::path::Path) {
        let probes = [
            (
                "memcpy",
                "uprobe_libc_memcpy",
                Some("uretprobe_libc_memcpy"),
            ),
            (
                "memmove",
                "uprobe_libc_memmove",
                Some("uretprobe_libc_memmove"),
            ),
            ("mmap", "uprobe_libc_mmap", Some("uretprobe_libc_mmap")),
            ("mmap64", "uprobe_libc_mmap", Some("uretprobe_libc_mmap")),
            ("mprotect", "uprobe_libc_mprotect", None),
        ];
        let mut attached = 0usize;
        for (symbol, entry_program, ret_program) in probes {
            let Some(offset) = find_elf_symbol(libc_path, symbol) else {
                continue;
            };
            let entry_result = attach_probe(ebpf, entry_program, libc_path, offset);
            match entry_result {
                Ok(()) => attached += 1,
                Err(err) => {
                    eprintln!(
                        "[-] failed to attach native probe {entry_program}:{symbol} at 0x{offset:x}: {err:#}"
                    );
                    continue;
                }
            }
            if let Some(ret_program) = ret_program {
                if let Err(err) = attach_probe(ebpf, ret_program, libc_path, offset) {
                    eprintln!(
                        "[-] failed to attach native retprobe {ret_program}:{symbol} at 0x{offset:x}: {err:#}"
                    );
                }
            }
        }
        println!(
            "[+] Native libc probes attached: {} ({})",
            attached,
            libc_path.display()
        );
    }

    fn resolve_libc_path(explicit: Option<&std::path::Path>) -> Option<PathBuf> {
        if let Some(path) = explicit {
            if path.exists() {
                return Some(path.to_path_buf());
            }
            eprintln!("[-] requested libc path does not exist: {}", path.display());
            return None;
        }
        [
            "/apex/com.android.runtime/lib64/bionic/libc.so",
            "/system/lib64/libc.so",
            "/apex/com.android.runtime/lib/bionic/libc.so",
            "/system/lib/libc.so",
        ]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
    }

    fn find_elf_symbol(path: &std::path::Path, name: &str) -> Option<u64> {
        use object::{Object, ObjectSymbol};
        let bytes = fs::read(path).ok()?;
        let file = object::File::parse(bytes.as_slice()).ok()?;
        for symbol in file.dynamic_symbols().chain(file.symbols()) {
            if symbol.is_definition() && symbol.name().ok() == Some(name) {
                return Some(symbol.address());
            }
        }
        None
    }

    fn drain_ring<T: std::borrow::Borrow<MapData>, F: FnMut(&[u8])>(
        ring: &mut RingBuf<T>,
        mut handler: F,
    ) {
        while let Some(item) = ring.next() {
            handler(&item);
        }
    }

    fn print_target(name: &str, target: Option<art::ResolvedTarget>) {
        match target {
            Some(target) => println!("[+] {name}: 0x{:x} ({})", target.addr, target.source),
            None => println!("[-] {name}: not found"),
        }
    }

    fn load_asset_btf() -> Option<Btf> {
        if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return None;
        }

        let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let asset = if release.contains("rockchip") {
            include_bytes!("../assets/rock5b-5.10-arm64_min.btf").as_slice()
        } else {
            include_bytes!("../assets/a12-5.10-arm64_min.btf").as_slice()
        };

        match Btf::parse(asset, Endianness::Little) {
            Ok(btf) => {
                if release.contains("rockchip") {
                    println!("[+] Loaded BTF spec from rock5b-5.10-arm64_min.btf");
                } else {
                    println!("[+] Loaded BTF spec from a12-5.10-arm64_min.btf");
                }
                Some(btf)
            }
            Err(err) => {
                eprintln!("[!] Failed to parse embedded BTF spec: {err}");
                None
            }
        }
    }

    fn bump_memlock_rlimit() {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            eprintln!(
                "[!] Failed to raise RLIMIT_MEMLOCK: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    fn install_signal_handlers() {
        unsafe {
            libc::signal(libc::SIGINT, signal_handler as *const () as usize);
            libc::signal(libc::SIGTERM, signal_handler as *const () as usize);
            libc::signal(libc::SIGHUP, signal_handler as *const () as usize);
            libc::signal(libc::SIGQUIT, signal_handler as *const () as usize);
        }
    }

    extern "C" fn signal_handler(_: libc::c_int) {
        RUNNING.store(false, Ordering::SeqCst);
    }

    #[derive(Clone, Copy, Debug)]
    struct DexEvent {
        begin: u64,
        size: u32,
    }

    impl DexEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            Some(Self {
                begin: le64(data, 0)?,
                size: le32(data, 12)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct DexChunkEvent {
        begin: u64,
        size: u32,
        offset: u32,
        data_len: u32,
    }

    impl DexChunkEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < DEX_CHUNK_HEADER_SIZE {
                return None;
            }
            Some(Self {
                begin: le64(data, 0)?,
                size: le32(data, 12)?,
                offset: le32(data, 16)?,
                data_len: le32(data, 20)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct MethodEvent {
        begin: u64,
        pid: u32,
        art_method_ptr: u64,
        method_index: u32,
        codeitem_size: u32,
    }

    impl MethodEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < METHOD_EVENT_HEADER_SIZE {
                return None;
            }
            Some(Self {
                begin: le64(data, 0)?,
                pid: le32(data, 8)?,
                art_method_ptr: le64(data, 24)?,
                method_index: le32(data, 32)?,
                codeitem_size: le32(data, 36)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct ReadFailureEvent {
        begin: u64,
        pid: u32,
        size: u32,
        failed_offset: u32,
    }

    impl ReadFailureEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < READ_FAILURE_HEADER_SIZE {
                return None;
            }
            Some(Self {
                begin: le64(data, 0)?,
                pid: le32(data, 8)?,
                size: le32(data, 12)?,
                failed_offset: le32(data, 16)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct LayoutDebugEvent {
        art_method_ptr: u64,
        code_item_ptr: u64,
        begin: u64,
        pid: u32,
        size: u32,
        reason: u32,
        source: u32,
    }

    impl LayoutDebugEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < LAYOUT_DEBUG_EVENT_SIZE {
                return None;
            }
            Some(Self {
                art_method_ptr: le64(data, 0)?,
                code_item_ptr: le64(data, 8)?,
                begin: le64(data, 16)?,
                pid: le32(data, 24)?,
                size: le32(data, 28)?,
                reason: le32(data, 32)?,
                source: le32(data, 36)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct NativeBufferEvent {
        addr: u64,
        size: u64,
        pid: u32,
        source: u32,
        prot: u32,
        flags: u32,
    }

    impl NativeBufferEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < NATIVE_BUFFER_EVENT_SIZE {
                return None;
            }
            Some(Self {
                addr: le64(data, 0)?,
                size: le64(data, 8)?,
                pid: le32(data, 16)?,
                source: le32(data, 20)?,
                prot: le32(data, 24)?,
                flags: le32(data, 28)?,
            })
        }
    }

    fn dump_dex_from_code_item(
        pid: u32,
        code_item_ptr: u64,
    ) -> Result<Option<(u64, u32, Vec<u8>)>> {
        if code_item_ptr == 0 {
            return Ok(None);
        }
        let mut scan = code_item_ptr & !(CODE_ITEM_BACKSCAN_STEP - 1);
        let scan_floor = code_item_ptr.saturating_sub(CODE_ITEM_BACKSCAN_LIMIT);
        while scan >= scan_floor {
            let Ok(page) = read_remote_mem(pid, scan, CODE_ITEM_BACKSCAN_STEP as u32) else {
                if scan < CODE_ITEM_BACKSCAN_STEP {
                    break;
                }
                scan -= CODE_ITEM_BACKSCAN_STEP;
                continue;
            };
            let mut off = 0usize;
            while let Some(idx) = find_subslice(&page[off..], b"dex\n") {
                let begin = scan + (off + idx) as u64;
                if begin > code_item_ptr {
                    off += idx + 4;
                    if off >= page.len() {
                        break;
                    }
                    continue;
                }
                let page_off = off + idx;
                let header_in_page = page.get(page_off..page_off + DEX_HEADER_SIZE as usize);
                let validated = match header_in_page {
                    Some(header) => validate_dex_header_contains(header, begin, code_item_ptr),
                    None => read_remote_mem(pid, begin, DEX_HEADER_SIZE)
                        .ok()
                        .and_then(|h| validate_dex_header_contains(&h, begin, code_item_ptr)),
                };
                if let Some(size) = validated {
                    let bytes = read_remote_mem(pid, begin, size)
                        .with_context(|| format!("read dex from 0x{begin:x}, size 0x{size:x}"))?;
                    if DexParser::new(&bytes).is_ok() {
                        return Ok(Some((begin, size, bytes)));
                    }
                }
                off += idx + 4;
                if off >= page.len() {
                    break;
                }
            }
            if scan < CODE_ITEM_BACKSCAN_STEP {
                break;
            }
            scan -= CODE_ITEM_BACKSCAN_STEP;
        }
        Ok(None)
    }

    fn dump_dex_from_native_buffer(
        pid: u32,
        addr: u64,
        size: u64,
    ) -> Result<Vec<(u64, u32, Vec<u8>)>> {
        if addr == 0 || size == 0 {
            return Ok(Vec::new());
        }
        let end = addr
            .checked_add(size.min(NATIVE_BUFFER_SCAN_LIMIT))
            .context("native buffer address overflow")?;
        let mut found = Vec::new();

        if let Ok(header) = read_remote_mem(pid, addr, DEX_HEADER_SIZE) {
            if let Some(file_size) = validate_dex_header(&header) {
                if addr + file_size as u64 <= end {
                    let bytes = read_remote_mem(pid, addr, file_size)
                        .with_context(|| format!("read native dex from 0x{addr:x}"))?;
                    if DexParser::new(&bytes).is_ok() {
                        found.push((addr, file_size, bytes));
                        return Ok(found);
                    }
                }
            }
        }

        scan_native_range_for_dex(pid, addr, end, &mut found);
        Ok(found)
    }

    fn scan_native_range_for_dex(
        pid: u32,
        start: u64,
        end: u64,
        found: &mut Vec<(u64, u32, Vec<u8>)>,
    ) {
        let mut pos = start;
        while pos + DEX_HEADER_SIZE as u64 <= end {
            let remaining = end.saturating_sub(pos);
            let read_len = remaining.min(NATIVE_BUFFER_SCAN_STEP) as u32;
            let Ok(page) = read_remote_mem(pid, pos, read_len) else {
                pos = pos.saturating_add(NATIVE_BUFFER_SCAN_STEP);
                continue;
            };
            let mut off = 0usize;
            while let Some(idx) = find_subslice(&page[off..], b"dex\n") {
                let begin = pos + (off + idx) as u64;
                if begin + DEX_HEADER_SIZE as u64 > end {
                    break;
                }
                if let Ok(header) = read_remote_mem(pid, begin, DEX_HEADER_SIZE) {
                    if let Some(size) = validate_dex_header(&header) {
                        if begin + size as u64 <= end {
                            if let Ok(bytes) = read_remote_mem(pid, begin, size) {
                                if DexParser::new(&bytes).is_ok() {
                                    found.push((begin, size, bytes));
                                }
                            }
                        }
                    }
                }
                off += idx + 4;
                if off >= page.len() {
                    break;
                }
            }
            pos = pos.saturating_add(NATIVE_BUFFER_SCAN_STEP);
        }
    }

    fn validate_dex_header(header: &[u8]) -> Option<u32> {
        if header.len() < DEX_HEADER_SIZE as usize {
            return None;
        }
        if !header.starts_with(b"dex\n") {
            return None;
        }
        let file_size = le32(header, DEX_HEADER_FILE_SIZE_OFFSET)?;
        if !(DEX_HEADER_SIZE..=MAX_DEX_FILE_SIZE).contains(&file_size) {
            return None;
        }
        let header_size = le32(header, DEX_HEADER_SIZE_OFFSET)?;
        if header_size != DEX_HEADER_SIZE {
            return None;
        }
        let endian_tag = le32(header, DEX_HEADER_ENDIAN_TAG_OFFSET)?;
        if endian_tag != DEX_ENDIAN_CONSTANT {
            return None;
        }
        let map_off = le32(header, DEX_HEADER_MAP_OFF_OFFSET)?;
        if map_off != 0 && map_off >= file_size {
            return None;
        }
        Some(file_size)
    }

    fn validate_dex_header_contains(header: &[u8], begin: u64, addr: u64) -> Option<u32> {
        let file_size = validate_dex_header(header)?;
        let dex_end = begin.checked_add(file_size as u64)?;
        if addr < begin || addr >= dex_end {
            return None;
        }
        Some(file_size)
    }

    fn scan_uid_maps(uid: u32) -> Result<Vec<(u64, u32, Vec<u8>)>> {
        let mut found = Vec::new();
        for pid in pids_for_uid(uid)? {
            if !keep_running() {
                break;
            }
            match scan_process_maps(pid) {
                Ok(mut dexes) => found.append(&mut dexes),
                Err(err) => eprintln!("maps scan failed for pid {pid}: {err:#}"),
            }
        }
        Ok(found)
    }

    fn pids_for_uid(uid: u32) -> Result<Vec<u32>> {
        let mut pids = Vec::new();
        for entry in fs::read_dir("/proc").context("read /proc")? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            if status.lines().any(|line| uid_line_matches(line, uid)) {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    fn uid_line_matches(line: &str, uid: u32) -> bool {
        let Some(rest) = line.strip_prefix("Uid:") else {
            return false;
        };
        rest.split_whitespace()
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            == Some(uid)
    }

    fn scan_process_maps(pid: u32) -> Result<Vec<(u64, u32, Vec<u8>)>> {
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
            .with_context(|| format!("read /proc/{pid}/maps"))?;
        let mut found = Vec::new();
        for line in maps.lines() {
            if !keep_running() {
                break;
            }
            let Some(region) = parse_readable_map_region(line) else {
                continue;
            };
            if region.end <= region.start || region.end - region.start > MAPS_SCAN_MAX_REGION {
                continue;
            }
            scan_region_for_dex(pid, region.start, region.end, &mut found);
        }
        Ok(found)
    }

    #[derive(Clone, Copy, Debug)]
    struct MapRegion {
        start: u64,
        end: u64,
    }

    fn parse_readable_map_region(line: &str) -> Option<MapRegion> {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next()?;
        if !perms.starts_with('r') {
            return None;
        }
        let (start, end) = range.split_once('-')?;
        Some(MapRegion {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
        })
    }

    fn scan_region_for_dex(pid: u32, start: u64, end: u64, found: &mut Vec<(u64, u32, Vec<u8>)>) {
        let mut pos = start;
        while pos + DEX_HEADER_SIZE as u64 <= end {
            if !keep_running() {
                return;
            }
            let Ok(page) = read_remote_mem(pid, pos, CODE_ITEM_BACKSCAN_STEP as u32) else {
                pos = pos.saturating_add(CODE_ITEM_BACKSCAN_STEP);
                continue;
            };
            let mut off = 0usize;
            while let Some(idx) = find_subslice(&page[off..], b"dex\n") {
                let begin = pos + (off + idx) as u64;
                if begin + DEX_HEADER_SIZE as u64 > end {
                    break;
                }
                if let Ok(header) = read_remote_mem(pid, begin, DEX_HEADER_SIZE) {
                    if let Some(size) = validate_dex_header(&header) {
                        if begin + size as u64 <= end {
                            if let Ok(bytes) = read_remote_mem(pid, begin, size) {
                                if DexParser::new(&bytes).is_ok() {
                                    found.push((begin, size, bytes));
                                }
                            }
                        }
                    }
                }
                off += idx + 4;
                if off >= page.len() {
                    break;
                }
            }
            pos = pos.saturating_add(CODE_ITEM_BACKSCAN_STEP);
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn read_remote_mem(pid: u32, remote_addr: u64, len: u32) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        let mut local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut remote = libc::iovec {
            iov_base: remote_addr as usize as *mut libc::c_void,
            iov_len: len as usize,
        };

        let read = unsafe {
            libc::syscall(
                libc::SYS_process_vm_readv,
                pid as libc::pid_t,
                &mut local,
                1usize,
                &mut remote,
                1usize,
                0usize,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("process_vm_readv");
        }
        let read = read as usize;
        if read < buf.len() {
            eprintln!(
                "process_vm_readv partial read: expected {}, got {read}",
                buf.len()
            );
            buf.truncate(read);
        }
        Ok(buf)
    }

    fn le32(data: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            data.get(offset..offset + 4)?.try_into().ok()?,
        ))
    }

    fn le64(data: &[u8], offset: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            data.get(offset..offset + 8)?.try_into().ok()?,
        ))
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod imp {
    use super::DumpConfig;
    use crate::art;
    use anyhow::{Context, Result};
    use std::fs;

    pub fn run(config: DumpConfig) -> Result<()> {
        fs::create_dir_all(&config.out).with_context(|| {
            format!("failed to create output directory {}", config.out.display())
        })?;
        let targets =
            art::find_art_offsets(&config.libart, config.execute_offset, config.nterp_offset)
                .with_context(|| {
                    format!(
                        "failed to locate ART hook targets in {}",
                        config.libart.display()
                    )
                })?;
        print_target("Execute", targets.execute);
        print_target("ExecuteNterpImpl", targets.execute_nterp);
        print_target(
            "ExecuteNterpWithClinitImpl",
            targets.execute_nterp_with_clinit,
        );
        print_target("VerifyClass", targets.verify_class);
        print_target("DexFile::DexFile", targets.dex_file_ctor);
        print_target("ClassLinker::RegisterDexFile", targets.register_dex_file);
        println!(
            "[+] nterp_op_invoke_* pattern targets: {}",
            targets.nterp_invoke_addrs.len()
        );
        let runtime_layout = match config.runtime_layout {
            Some(layout) => layout,
            None => art::resolve_runtime_layout(&config.libart).with_context(|| {
                format!(
                    "failed to resolve ART layout for {}",
                    config.libart.display()
                )
            })?,
        };
        println!("[+] ART runtime layout: {}", runtime_layout.summary());
        println!("[+] Filtering on uid {}", config.uid);
        let _ = (
            config.pid,
            config.package_name,
            config.trace,
            config.auto_fix,
            config.debug_layout,
            config.code_item_fallback,
            config.maps_scan,
            config.native_buffer_scan,
            config.libc,
        );
        anyhow::bail!("live dump is available only when built for Linux/Android")
    }

    fn print_target(name: &str, target: Option<art::ResolvedTarget>) {
        match target {
            Some(target) => println!("[+] {name}: 0x{:x} ({})", target.addr, target.source),
            None => println!("[-] {name}: not found"),
        }
    }
}

pub use imp::run;
