#!/bin/bash
set -e

# Configuration
PROJECT_ROOT="/home/user/Workspace/zeta-sdk/attestation-service"
LIBS_DIR="${PROJECT_ROOT}/src/linuxMain/libs/tpm2-tss"
BUILD_DIR="/tmp/tpm2-tss-build"
TPM2_TSS_VERSION="4.1.3"

echo "Building tpm2-tss static libraries"
echo "Target directory: ${LIBS_DIR}"

# Create lib directories
mkdir -p "${LIBS_DIR}/x86_64"
mkdir -p "${LIBS_DIR}/include"

# Clean and create build directory
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Clone and checkout
git clone https://github.com/tpm2-software/tpm2-tss.git
cd tpm2-tss
git checkout "${TPM2_TSS_VERSION}"

# Bootstrap and configure
./bootstrap
./configure \
    --enable-static \
    --disable-shared \
    --disable-doxygen-doc \
    --prefix="${BUILD_DIR}/install" \
    CFLAGS="-fPIC -O2"

# Build and install
make -j$(nproc)
make install

# Copy static libraries
cp "${BUILD_DIR}/install/lib/libtss2-esys.a" "${LIBS_DIR}/x86_64/"
cp "${BUILD_DIR}/install/lib/libtss2-mu.a" "${LIBS_DIR}/x86_64/"
cp "${BUILD_DIR}/install/lib/libtss2-sys.a" "${LIBS_DIR}/x86_64/"
cp "${BUILD_DIR}/install/lib/libtss2-tctildr.a" "${LIBS_DIR}/x86_64/"
cp "${BUILD_DIR}/install/lib/libtss2-tcti-device.a" "${LIBS_DIR}/x86_64/"
cp "${BUILD_DIR}/install/lib/libtss2-tcti-mssim.a" "${LIBS_DIR}/x86_64/"
cp "${BUILD_DIR}/install/lib/libtss2-rc.a" "${LIBS_DIR}/x86_64/"

# Copy headers
cp -r "${BUILD_DIR}/install/include/tss2" "${LIBS_DIR}/include/"

# Generate checksums
cd "${LIBS_DIR}/x86_64"
sha256sum *.a > SHA256SUMS

# Cleanup
rm -rf "${BUILD_DIR}"

echo "Build complete"
ls -lh "${LIBS_DIR}/x86_64/"
