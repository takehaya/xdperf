#!/bin/bash
# Build a test kernel with CONFIG_SCHED_CLASS_EXT=y for the pkg/scx tests.
#
# The upstream vimto images (ghcr.io/cilium/ci-kernels) do not enable
# sched_ext, so the scx load tests boot this kernel instead:
#
#   ./scripts/scx_kernel/build.sh
#   vimto -kernel out/scx-kernel/bzImage -- go test ./pkg/scx/ -run TestScx
#
# The config is the ci-kernels 6.18 config (extracted from /proc/config.gz)
# plus sched_ext, so everything vimto needs (9p, virtio, BTF) stays enabled.
# Requires Docker. The build is CPU-bound (~10 min on many cores) and the
# result is cached: an existing out/scx-kernel/bzImage is reused unless
# FORCE=1.
set -euo pipefail

KERNEL_VERSION="${KERNEL_VERSION:-6.18.36}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BASE_CONFIG="scripts/scx_kernel/config-base-6.18"
OUT_DIR="out/scx-kernel"
DOCKER="${DOCKER:-docker}"

cd "${REPO_ROOT}"

if [ -f "${OUT_DIR}/bzImage" ] && [ "${FORCE:-0}" != "1" ]; then
    echo "reusing existing ${OUT_DIR}/bzImage (FORCE=1 to rebuild)"
    exit 0
fi

mkdir -p "${OUT_DIR}"

${DOCKER} run --rm \
    -v "${REPO_ROOT}:/work" \
    -e KERNEL_VERSION="${KERNEL_VERSION}" \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    debian:trixie bash -euc '
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            build-essential flex bison bc libelf-dev libssl-dev dwarves \
            xz-utils curl ca-certificates cpio kmod python3 rsync >/dev/null
        cd /tmp
        curl -fsSLO "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
        tar xf "linux-${KERNEL_VERSION}.tar.xz"
        cd "linux-${KERNEL_VERSION}"
        cp /work/scripts/scx_kernel/config-base-6.18 .config
        ./scripts/config -e SCHED_CLASS_EXT
        # veth for the in-VM end-to-end scenarios (examples/)
        ./scripts/config -e VETH
        make olddefconfig
        grep -q "^CONFIG_SCHED_CLASS_EXT=y" .config || {
            echo "CONFIG_SCHED_CLASS_EXT did not resolve to =y" >&2
            grep "SCHED_CLASS_EXT\|BPF_JIT=\|DEBUG_INFO_BTF=" .config >&2
            exit 1
        }
        make -j"$(nproc)" bzImage
        cp arch/x86/boot/bzImage /work/out/scx-kernel/bzImage
        cp .config /work/out/scx-kernel/config
        chown -R "${HOST_UID}:${HOST_GID}" /work/out/scx-kernel
    '

echo "built ${OUT_DIR}/bzImage (linux ${KERNEL_VERSION} + CONFIG_SCHED_CLASS_EXT=y)"
