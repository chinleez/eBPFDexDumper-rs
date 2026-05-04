use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ebpf_dex_dumper_rs::{art, dump, fix, platform};
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

    /// Path to libc.so used for native buffer probes.
    #[arg(long)]
    libc: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct FixArgs {
    /// Directory containing dumped DEX files.
    #[arg(short, long)]
    dir: PathBuf,
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
        Some(Command::Fix(args)) => fix::fix_dex_directory(&args.dir),
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

            let config = dump::DumpConfig {
                uid,
                pid: args.pid,
                package_name: args.name,
                libart: args.libart,
                out: args.out,
                trace: args.trace,
                auto_fix,
                execute_offset: args.execute_offset,
                nterp_offset: args.nterp_offset,
                runtime_layout: args.art_layout,
                debug_layout: args.debug_layout,
                code_item_fallback: !args.no_code_item_fallback,
                maps_scan: !args.no_maps_scan,
                native_buffer_scan: !args.no_native_buffer_scan,
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
