#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-normal}
profile=debug
release_flag=""
case "$mode" in normal) features="" ;; release) features=""; profile=release; release_flag=--release ;; nx) features="--features nx-test" ;; fault) features="--features fault-test" ;; protection) features="--features protection-test" ;; unmap) features="--features unmap-test" ;; *) echo 'usage: sh kernel/build.sh [normal|release|fault|protection|unmap|nx]' >&2; exit 2 ;; esac
out="$root/target/kernel-$mode"
grub_dir=${HYBER_GRUB_BIOS_DIR:-/usr/lib/grub/i386-pc}
if [ ! -f "$grub_dir/modinfo.sh" ]; then grub_dir="$root/target/kernel-tools/usr/lib/grub/i386-pc"; fi
if [ ! -f "$grub_dir/modinfo.sh" ]; then echo 'Missing GRUB BIOS modules; see docs/kernel/phase21.md' >&2; exit 1; fi
mkdir -p "$out/iso/boot/grub"
cargo build --locked --manifest-path "$root/kernel/native/Cargo.toml" --target-dir "$out/cargo" --target x86_64-unknown-none $features $release_flag
cp "$out/cargo/x86_64-unknown-none/$profile/hyber-kernel" "$out/iso/boot/hyber-kernel"
cp "$root/kernel/grub.cfg" "$out/iso/boot/grub/grub.cfg"
grub-file --is-x86-multiboot2 "$out/iso/boot/hyber-kernel"
grub-mkrescue -d "$grub_dir" -o "$out/hyber.iso" "$out/iso"
