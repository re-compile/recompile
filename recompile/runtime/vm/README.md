VM assets
---------

This directory contains the aarch64 Linux kernel with BTF and a glibc-based Ubuntu rootfs image.

Steps (macOS Apple Silicon):
1) brew install qemu curl
2) scripts/build-vm.sh  # downloads Ubuntu jammy ARM64 cloud image
3) Provide a kernel with BTF (we will automate in a later step).

Optional: If you have edk2 firmware, its path is recorded in firmware.path.

llvm-symbolizer will be included inside the VM image in a later step.
