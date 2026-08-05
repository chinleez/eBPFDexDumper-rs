#!/bin/sh
set -eu

if [ -n "${CARGO:-}" ]; then
  cargo_bin="${CARGO}"
elif [ -x "${HOME}/.cargo/bin/cargo" ]; then
  cargo_bin="${HOME}/.cargo/bin/cargo"
else
  cargo_bin="cargo"
fi

if [ -z "${CLANG:-}" ]; then
  if [ -x /opt/homebrew/opt/llvm/bin/clang ]; then
    export CLANG=/opt/homebrew/opt/llvm/bin/clang
  elif [ -x /usr/local/opt/llvm/bin/clang ]; then
    export CLANG=/usr/local/opt/llvm/bin/clang
  fi
fi

if "${cargo_bin}" ndk --version >/dev/null 2>&1; then
  "${cargo_bin}" ndk -t arm64-v8a build --release
else
  : "${ANDROID_NDK_HOME:=${NDK_HOME:-}}"
  if [ -n "${ANDROID_NDK_HOME}" ]; then
    host_tags="linux-x86_64"
    case "$(uname -s)-$(uname -m)" in
      Darwin-arm64) host_tags="darwin-arm64 darwin-x86_64" ;;
      Darwin-x86_64) host_tags="darwin-x86_64 darwin-arm64" ;;
      Linux-x86_64) host_tags="linux-x86_64" ;;
    esac
    api="${ANDROID_API:-23}"
    for host_tag in ${host_tags}; do
      linker="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/${host_tag}/bin/aarch64-linux-android${api}-clang"
      if [ -x "${linker}" ]; then
        export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${linker}"
        break
      fi
    done
  fi
  if [ -z "${CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER:-}" ]; then
    echo "error: Android NDK not found; install an NDK and set ANDROID_NDK_HOME" >&2
    echo "       (or NDK_HOME), or set CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER" >&2
    exit 1
  fi
  "${cargo_bin}" build --target aarch64-linux-android --release
fi
