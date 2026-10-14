#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1:-}" in "") ninja -C "$root" kernel-images ;; --no-build) ;; *) echo 'usage: sh kernel/smoke.sh [--no-build]' >&2; exit 2 ;; esac
for mode in normal release fault protection unmap nx; do
    for ram in 32 64 128; do
        log="$root/target/kernel-$mode/qemu-$ram.log"
        status=0
        timeout 20s qemu-system-x86_64 -accel tcg -m "$ram" -smp 1 -cdrom "$root/target/kernel-$mode/hyber.iso" -display none -serial stdio -monitor none -nic none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$log" 2>&1 || status=$?
        case "$mode" in
            normal|release) expected=33; marker='PHASE21 PASS' ;;
            fault) expected=35; marker='EXCEPTION vector=0000000000000006 error=0000000000000000' ;;
            protection) expected=35; marker='EXCEPTION vector=000000000000000e error=0000000000000003' ;;
            unmap) expected=35; marker='EXCEPTION vector=000000000000000e error=0000000000000000' ;;
            nx) expected=35; marker='EXCEPTION vector=000000000000000e error=0000000000000011' ;;
        esac
        if [ "$status" -ne "$expected" ] || ! rg -q "$marker" "$log"; then
            echo "FAIL $mode ${ram}MiB status=$status" >&2
            sed -n '1,100p' "$log"
            exit 1
        fi
        echo "PASS $mode ${ram}MiB"
    done
done
