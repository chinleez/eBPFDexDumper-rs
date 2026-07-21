use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use ebpf_dex_dumper_rs::{art, dump, fix, platform, so, so_fix};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "eBPFDexDumper",
    about = "Android eBPF DEX dumper",
    after_help = "Project GitHub: https://github.com/chinleez/eBPFDexDumper-rs",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start eBPF-based DEX dumper.
    Dump(DumpArgs),
    /// Fix dumped DEX files in a directory.
    Fix(FixArgs),
    /// Dump native .so libraries from a running process's memory.
    DumpSo(DumpSoArgs),
    /// Fix dumped .so files in a directory for static-analysis tools.
    FixSo(FixSoArgs),
    /// Locate ART interpreter hook targets in a libart.so ELF.
    Offsets(OffsetsArgs),
}

#[derive(Debug, Parser)]
struct DumpArgs {
    /// Filter by Android UID. Use either --uid or --name.
    #[arg(short, long)]
    uid: Option<u32>,

    /// Optional pid filter applied in addition to --uid.
    #[arg(short = 'p', long)]
    pid: Option<u32>,

    /// Android package name used to derive UID.
    #[arg(short, long)]
    name: Option<String>,

    /// Path to libart.so on target device.
    #[arg(short, long, default_value = "/apex/com.android.art/lib64/libart.so")]
    libart: PathBuf,

    /// Output directory on target device.
    #[arg(
        short,
        long,
        alias = "output",
        default_value = "/data/local/tmp/dex_out"
    )]
    out: PathBuf,

    /// Print executed methods while dumping.
    #[arg(short, long)]
    trace: bool,

    /// Remove /data/app/.../oat folders of target app(s) before dumping.
    #[arg(short = 'c', long, default_value_t = true)]
    clean_oat: bool,

    /// Automatically fix DEX files after dumping.
    #[arg(short = 'f', long, default_value_t = true)]
    auto_fix: bool,

    /// Disable automatic oat cleaning.
    #[arg(long)]
    no_clean_oat: bool,

    /// Disable automatic DEX fixing.
    #[arg(long)]
    no_auto_fix: bool,

    /// Debug fallback for art::interpreter::Execute, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    execute_offset: Option<u64>,

    /// Debug fallback for ExecuteNterpImpl, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    nterp_offset: Option<u64>,

    /// Manual offset for art::JNI<>::RegisterNatives (hex); auto-detected via
    /// symbol or string xref when omitted.
    #[arg(long, value_parser = parse_u64)]
    register_natives_offset: Option<u64>,

    /// Override ART runtime layout offsets as ten comma-separated integers.
    #[arg(long, value_parser = parse_art_layout)]
    art_layout: Option<art::ArtRuntimeLayout>,

    /// Enable CodeItem fallback events and ART layout diagnostics.
    #[arg(long)]
    debug_layout: bool,

    /// Disable user-space DEX header backscan from CodeItem events.
    #[arg(long)]
    no_code_item_fallback: bool,

    /// Disable one-shot /proc/<pid>/maps DEX scan for the target UID.
    #[arg(long)]
    no_maps_scan: bool,

    /// Disable libc native buffer probes for mmap/mprotect/memcpy/memmove.
    #[arg(long)]
    no_native_buffer_scan: bool,

    /// Experimental: dump anonymous executable ARM64 ELF candidates from native loader behavior.
    #[arg(long)]
    native_elf_scan: bool,

    /// Probe set to attach: full, lifecycle, or maps-only.
    #[arg(long, value_enum, default_value_t = ProbeModeArg::Full)]
    probe_mode: ProbeModeArg,

    /// Path to libc.so used for native buffer probes.
    #[arg(long)]
    libc: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProbeModeArg {
    /// Attach ART interpreter, DexFile lifecycle, nterp invoke, and libc native buffer probes.
    Full,
    /// Attach only DexFile lifecycle probes; keeps maps scan but reduces uprobe footprint.
    Lifecycle,
    /// Do not attach uprobes; only scan target process maps.
    MapsOnly,
}

impl From<ProbeModeArg> for dump::ProbeMode {
    fn from(value: ProbeModeArg) -> Self {
        match value {
            ProbeModeArg::Full => Self::Full,
            ProbeModeArg::Lifecycle => Self::Lifecycle,
            ProbeModeArg::MapsOnly => Self::MapsOnly,
        }
    }
}

#[derive(Debug, Parser)]
struct FixArgs {
    /// Directory containing dumped DEX files.
    #[arg(short, long)]
    dir: PathBuf,

    /// Apply method bytecode even when its length does not match the DEX
    /// header's `insns_size` (truncating or zero-padding to fit). Off by
    /// default — mismatches usually indicate stale headers and writing back
    /// can corrupt the bytecode stream.
    #[arg(long)]
    force_mismatch: bool,
}

#[derive(Debug, Parser)]
struct DumpSoArgs {
    /// Filter by Android UID. Use either --uid or --name.
    #[arg(short, long)]
    uid: Option<u32>,

    /// Android package name used to derive UID.
    #[arg(short, long)]
    name: Option<String>,

    /// Only dump libraries whose path contains this substring (default: all).
    #[arg(short, long)]
    lib: Option<String>,

    /// Output directory on target device.
    #[arg(short, long, alias = "output", default_value = "/data/local/tmp/so_out")]
    out: PathBuf,

    /// Also scan anonymous memory regions for self-mapped ELF images.
    #[arg(short, long, default_value_t = true)]
    anon: bool,

    /// Automatically fix dumped .so files after dumping.
    #[arg(short = 'f', long, default_value_t = true)]
    auto_fix: bool,

    /// Disable anonymous ELF region scanning.
    #[arg(long)]
    no_anon: bool,

    /// Disable automatic .so fixing.
    #[arg(long)]
    no_auto_fix: bool,

    /// Also dump system libraries under /system, /apex, /vendor (default: skip).
    #[arg(long)]
    include_system: bool,

    /// Keep watching the process and dump modules as they appear.
    #[arg(short, long)]
    watch: bool,

    /// Seconds between map re-scans in --watch mode.
    #[arg(long, default_value_t = 1)]
    watch_interval: u64,

    /// Stop --watch after N seconds (0 = until interrupted).
    #[arg(long, default_value_t = 60)]
    watch_timeout: u64,
}

#[derive(Debug, Parser)]
struct FixSoArgs {
    /// Directory containing dumped .so files.
    #[arg(short, long)]
    dir: PathBuf,

    /// File of "offset name" lines to inject as .symtab symbols (e.g. recovered
    /// JNI functions).
    #[arg(short, long)]
    symbols: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct OffsetsArgs {
    /// Path to libart.so.
    #[arg(short, long)]
    libart: PathBuf,

    /// Debug fallback for art::interpreter::Execute, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    execute_offset: Option<u64>,

    /// Debug fallback for ExecuteNterpImpl, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    nterp_offset: Option<u64>,

    /// Override ART runtime layout offsets as ten comma-separated integers.
    #[arg(long, value_parser = parse_art_layout)]
    art_layout: Option<art::ArtRuntimeLayout>,

    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct OffsetsJson {
    execute: Option<art::ResolvedTarget>,
    execute_nterp_impl: Option<art::ResolvedTarget>,
    execute_nterp_with_clinit_impl: Option<art::ResolvedTarget>,
    verify_class: Option<art::ResolvedTarget>,
    dex_file_ctor: Option<art::ResolvedTarget>,
    register_dex_file: Option<art::ResolvedTarget>,
    nterp_op_invoke: Vec<art::ResolvedTarget>,
    runtime_layout: art::ArtRuntimeLayout,
    android_16_notes: &'static str,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
        Some(Command::Fix(args)) => fix::fix_dex_directory_with(
            &args.dir,
            fix::FixOptions {
                force_mismatch: args.force_mismatch,
            },
        ),
        Some(Command::DumpSo(args)) => {
            let uid = match (args.uid, args.name.as_deref()) {
                (Some(uid), _) if uid != 0 => uid,
                (_, Some(pkg)) => {
                    let uid = platform::lookup_uid_by_package_name(pkg)?;
                    println!("[+] Resolved UID {uid} from package {pkg:?}");
                    uid
                }
                _ => anyhow::bail!("either --uid or --name must be provided"),
            };
            let watch_timeout = (args.watch_timeout != 0)
                .then(|| std::time::Duration::from_secs(args.watch_timeout));
            let config = so::DumpSoConfig {
                uid,
                lib_filter: args.lib,
                out: args.out,
                include_anon: args.anon && !args.no_anon,
                include_system: args.include_system,
                auto_fix: args.auto_fix && !args.no_auto_fix,
                watch: args.watch,
                watch_interval: std::time::Duration::from_secs(args.watch_interval),
                watch_timeout,
            };
            so::run(config)
        }
        Some(Command::FixSo(args)) => {
            let (injected, target) = match args.symbols.as_deref() {
                Some(sf) => {
                    let syms = so_fix::parse_symbol_file(sf)?;
                    let target = so_fix::module_stem_from_symbols_file(sf);
                    if target.is_empty() {
                        println!(
                            "[+] Loaded {} symbol(s) from {}; couldn't infer target module, will inject into every .so",
                            syms.len(),
                            sf.display()
                        );
                    } else {
                        println!(
                            "[+] Loaded {} symbol(s) from {} (target module {target:?})",
                            syms.len(),
                            sf.display()
                        );
                    }
                    (syms, target)
                }
                None => (Vec::new(), String::new()),
            };
            so_fix::fix_so_directory(&args.dir, &injected, &target)
        }
        Some(Command::Offsets(args)) => {
            let targets = if args.json {
                art::find_art_offsets_quiet(&args.libart, args.execute_offset, args.nterp_offset)
            } else {
                art::find_art_offsets(&args.libart, args.execute_offset, args.nterp_offset)
            }
            .with_context(|| format!("failed to parse {}", args.libart.display()))?;
            let runtime_layout = match args.art_layout {
                Some(layout) => layout,
                None => art::resolve_runtime_layout(&args.libart).with_context(|| {
                    format!("failed to resolve ART layout for {}", args.libart.display())
                })?,
            };
            if args.json {
                serde_json::to_writer_pretty(
                    std::io::stdout(),
                    &OffsetsJson {
                        execute: targets.execute,
                        execute_nterp_impl: targets.execute_nterp,
                        execute_nterp_with_clinit_impl: targets.execute_nterp_with_clinit,
                        verify_class: targets.verify_class,
                        dex_file_ctor: targets.dex_file_ctor,
                        register_dex_file: targets.register_dex_file,
                        nterp_op_invoke: targets.nterp_invoke_addrs,
                        runtime_layout,
                        android_16_notes: "android16-release keeps arm64 ExecuteNterpWithClinitImpl branching into ExecuteNterpImpl and ArtMethod::data_ as runtime CodeItem*",
                    },
                )?;
                println!();
            } else {
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
                    "nterp_op_invoke_*: {} target(s)",
                    targets.nterp_invoke_addrs.len()
                );
                println!("ART runtime layout: {}", runtime_layout.summary());
            }
            Ok(())
        }
        Some(Command::Dump(args)) => {
            let clean_oat = args.clean_oat && !args.no_clean_oat;
            let auto_fix = args.auto_fix && !args.no_auto_fix;
            let uid = match (args.uid, args.name.as_deref()) {
                (Some(uid), _) if uid != 0 => uid,
                (_, Some(pkg)) => {
                    let uid = platform::lookup_uid_by_package_name(pkg)?;
                    println!("[+] Resolved UID {uid} from package {pkg:?}");
                    uid
                }
                _ => anyhow::bail!("either --uid or --name must be provided"),
            };

            if clean_oat {
                if let Some(pkg) = args.name.as_deref() {
                    platform::remove_oat_dirs_for_package(pkg);
                } else {
                    platform::remove_oat_dirs_by_uid(uid);
                }
            }

            let subdir = if let Some(pkg) = args.name.as_deref() {
                platform::sanitize_path_component(pkg)
            } else if let Some(pid) = args.pid {
                platform::package_name_from_pid(pid)
                    .map(|n| platform::sanitize_path_component(&n))
                    .unwrap_or_else(|| format!("pid_{pid}"))
            } else {
                format!("uid_{uid}")
            };
            let out_dir = args.out.join(&subdir);
            println!("[+] Output directory: {}", out_dir.display());

            let config = dump::DumpConfig {
                uid,
                pid: args.pid,
                package_name: args.name,
                libart: args.libart,
                out: out_dir,
                trace: args.trace,
                auto_fix,
                execute_offset: args.execute_offset,
                nterp_offset: args.nterp_offset,
                register_natives_offset: args.register_natives_offset,
                runtime_layout: args.art_layout,
                debug_layout: args.debug_layout,
                code_item_fallback: !args.no_code_item_fallback,
                maps_scan: !args.no_maps_scan,
                native_buffer_scan: !args.no_native_buffer_scan,
                native_elf_scan: args.native_elf_scan,
                probe_mode: args.probe_mode.into(),
                libc: args.libc,
            };
            dump::run(config)
        }
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        s.parse::<u64>().map_err(|err| err.to_string())
    }
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let value = parse_u64(s)?;
    u32::try_from(value).map_err(|_| format!("{s} is larger than u32"))
}

fn parse_art_layout(s: &str) -> Result<art::ArtRuntimeLayout, String> {
    let parts = s
        .split(',')
        .map(str::trim)
        .map(parse_u32)
        .collect::<Result<Vec<_>, _>>()?;
    let [
        shadow_frame_method_offset,
        art_method_declaring_class_offset,
        art_method_dex_method_index_offset,
        art_method_data_offset,
        class_dex_cache_offset,
        dex_cache_dex_file_offset,
        dex_file_begin_offset,
        dex_header_file_size_offset,
        code_item_insns_size_offset,
        code_item_insns_offset,
    ]: [u32; 10] = parts.try_into().map_err(|parts: Vec<u32>| {
        format!(
            "expected 10 comma-separated offsets, got {}",
            parts.len()
        )
    })?;

    Ok(art::ArtRuntimeLayout {
        shadow_frame_method_offset,
        art_method_declaring_class_offset,
        art_method_dex_method_index_offset,
        art_method_data_offset,
        class_dex_cache_offset,
        dex_cache_dex_file_offset,
        dex_file_begin_offset,
        dex_header_file_size_offset,
        code_item_insns_size_offset,
        code_item_insns_offset,
    })
}

fn print_target(name: &str, target: Option<art::ResolvedTarget>) {
    match target {
        Some(target) => println!("{name}: 0x{:x} ({})", target.addr, target.source),
        None => println!("{name}: not found"),
    }
}
