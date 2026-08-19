#!/usr/bin/env python3
"""Run the Android DEX dump workflow from a Windows, macOS, or Linux host."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence


class CommandError(RuntimeError):
    """A required external command failed."""


def run_command(
    command: Sequence[str],
    *,
    capture: bool = False,
    quiet: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            text=True,
            capture_output=capture,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
        )
    except OSError as exc:
        raise CommandError(f"failed to run {' '.join(command)}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise CommandError(f"command failed ({' '.join(command)}){suffix}")
    return result


def output_text(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stdout or "").replace("\r", "").strip()


def env_command(name: str, env_name: str | None = None) -> str | None:
    value = os.environ.get(env_name or name.upper())
    return value or shutil.which(name)


def find_aapt() -> str | None:
    explicit = os.environ.get("AAPT")
    if explicit:
        return explicit
    sdk_root_value = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get(
        "ANDROID_HOME"
    )
    if sdk_root_value:
        sdk_root = Path(sdk_root_value)
    elif os.name == "nt":
        sdk_root = (
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
            / "Android"
            / "Sdk"
        )
    elif sys.platform == "darwin":
        sdk_root = Path.home() / "Library" / "Android" / "sdk"
    else:
        sdk_root = Path.home() / "Android" / "Sdk"
    build_tools = sdk_root / "build-tools"
    if not build_tools.is_dir():
        return None
    candidates = [
        path
        for path in build_tools.rglob("aapt*")
        if path.is_file() and path.name.lower() in {"aapt", "aapt.exe"}
    ]
    if not candidates:
        return None

    def version_key(path: Path) -> tuple[tuple[int, ...], str]:
        numbers = tuple(int(part) for part in re.findall(r"\d+", path.parent.name))
        return numbers, str(path)

    return str(max(candidates, key=version_key))


def resolve_package(apk: Path) -> str:
    analyzer = env_command("apkanalyzer", "APK_ANALYZER")
    if analyzer:
        result = run_command(
            [analyzer, "manifest", "application-id", str(apk)],
            capture=True,
            check=False,
        )
        package = output_text(result)
        if result.returncode == 0 and package:
            return package.splitlines()[0]

    aapt = find_aapt()
    if aapt:
        result = run_command(
            [aapt, "dump", "badging", str(apk)], capture=True, check=False
        )
        match = re.search(
            r"^package:\s+name='([^']+)'", result.stdout or "", re.MULTILINE
        )
        if result.returncode == 0 and match:
            return match.group(1)
    raise CommandError(
        "cannot read package id: install apkanalyzer or set AAPT/APK_ANALYZER"
    )


def adb_command(
    adb: str, *args: str, **kwargs: object
) -> subprocess.CompletedProcess[str]:
    return run_command([adb, *args], **kwargs)


def count_remote_dex(adb: str, remote_dir: str) -> int:
    result = adb_command(
        adb,
        "shell",
        f"find '{remote_dir}' -type f -name 'dex_*.dex' 2>/dev/null | wc -l",
        capture=True,
        check=False,
    )
    try:
        return int(output_text(result) or "0")
    except ValueError:
        return 0


def run_mode(adb: str, package: str, activity: str, remote: str, mode: str) -> int:
    adb_command(adb, "shell", "am", "force-stop", package, quiet=True)
    adb_command(adb, "shell", "am", "start", "-n", activity, quiet=True)
    command = (
        f"/data/local/tmp/eBPFDexDumper dump -n '{package}' "
        f"-o '{remote}/{mode}' --no-clean-oat --probe-mode '{mode}'"
    )
    result = adb_command(adb, "shell", "su", "-c", command, check=False)
    return result.returncode


def report_files(result_dir: Path) -> tuple[list[Path], int]:
    files = sorted(result_dir.rglob("dex_*.dex")) if result_dir.exists() else []
    return files, sum(path.stat().st_size for path in files)


def write_report(
    report: Path,
    *,
    package: str,
    api: str,
    abi: str,
    activity: str,
    output: Path,
    result_dir: Path,
) -> tuple[int, int]:
    files, total_bytes = report_files(result_dir)
    lines = [
        f"package={package}",
        f"api={api}",
        f"abi={abi}",
        f"launcher={activity}",
        "requested_mode=full",
        "fallback_order=full,lifecycle,maps-only",
        f"output={output}",
        f"dex_files={len(files)}",
        f"total_bytes={total_bytes}",
        "",
    ]
    for path in files:
        data = path.read_bytes()[:8]
        magic = (
            data.decode("ascii", errors="replace")
            .replace("\x00", "\\0")
            .replace("\n", "\\n")
        )
        lines.append(f"{path.stat().st_size} {magic} {path}")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(files), total_bytes


def main(argv: Sequence[str]) -> int:
    if not argv or len(argv) > 2:
        print(f"usage: {Path(sys.argv[0]).name} <apk> [output-dir]", file=sys.stderr)
        return 2

    apk = Path(argv[0]).expanduser()
    if not apk.is_file():
        print(f"APK not found: {apk}", file=sys.stderr)
        return 1

    output = (
        Path(argv[1]).expanduser()
        if len(argv) == 2
        else Path.home() / "Downloads" / f"android-dex-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    binary = Path(
        os.environ.get(
            "DUMPER_BIN",
            str(
                Path.cwd()
                / "target"
                / "aarch64-linux-android"
                / "release"
                / "eBPFDexDumper"
            ),
        )
    ).expanduser()
    adb = env_command("adb", "ADB")
    if not binary.is_file():
        print(f"Dumper binary not found: {binary}", file=sys.stderr)
        return 1
    if not adb:
        print(
            "ADB not found: install Android platform-tools or set ADB=/path/to/adb",
            file=sys.stderr,
        )
        return 1

    try:
        output.mkdir(parents=True, exist_ok=True)
        package = resolve_package(apk)
        state = output_text(adb_command(adb, "get-state", capture=True, check=False))
        if state != "device":
            raise CommandError(
                "no usable ADB device; connect a local ARM64 target and retry"
            )

        api = output_text(
            adb_command(adb, "shell", "getprop", "ro.build.version.sdk", capture=True)
        )
        abi = output_text(
            adb_command(adb, "shell", "getprop", "ro.product.cpu.abi", capture=True)
        )
        adb_command(adb, "install", "-r", str(apk), quiet=True)
        activity_lines = output_text(
            adb_command(
                adb,
                "shell",
                "cmd",
                "package",
                "resolve-activity",
                "--brief",
                package,
                capture=True,
            )
        ).splitlines()
        activity = activity_lines[-1] if activity_lines else ""
        if "/" not in activity:
            raise CommandError(f"launcher activity not found for {package}")
        adb_command(
            adb, "push", str(binary), "/data/local/tmp/eBPFDexDumper", quiet=True
        )
        adb_command(
            adb, "shell", "chmod", "755", "/data/local/tmp/eBPFDexDumper", quiet=True
        )

        remote = f"/data/local/tmp/android_dex_run_{int(time.time())}"
        adb_command(adb, "shell", "mkdir", "-p", remote, quiet=True)
        run_mode(adb, package, activity, remote, "full")
        count = count_remote_dex(adb, f"{remote}/full")
        if count == 0:
            run_mode(adb, package, activity, remote, "lifecycle")
            count = count_remote_dex(adb, f"{remote}/lifecycle")
        if count == 0:
            run_mode(adb, package, activity, remote, "maps-only")

        result_dir = output / "result"
        result_dir.mkdir(parents=True, exist_ok=True)
        for mode in ("full", "lifecycle", "maps-only"):
            local_mode = result_dir / mode
            local_mode.mkdir(parents=True, exist_ok=True)
            adb_command(
                adb,
                "pull",
                f"{remote}/{mode}",
                str(local_mode),
                quiet=True,
                check=False,
            )

        report = output / "report.txt"
        dex_count, _ = write_report(
            report,
            package=package,
            api=api,
            abi=abi,
            activity=activity,
            output=output,
            result_dir=result_dir,
        )
        print(f"package: {package}")
        print(f"output: {output}")
        print(f"report: {report}")
        print(f"DEX files: {dex_count}")
        return 0
    except CommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
