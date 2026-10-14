# Phase 21: native kernel mechanism prototype

This is the native mechanism foundation for the **same Hyber provider model**.
It is not a second object system or a native port of the current hosted shell.
Rust implements memory and scheduling policy; NASM implements x86 entry,
interrupt register frames and context switching. No C/C++/Java runtime is
required at this stage; their future use is not removed from VISION.

## Boundaries and source ownership

| Source | Responsibility |
| --- | --- |
| `kernel/foundation` | no_std frame/block accounting, validated boot-map parser, bounded round robin; host unit tests |
| `kernel/native/entry.asm` | Multiboot2 header, 32→64-bit transition, GDT, identity paging, ISR stubs, ABI context switch |
| `kernel/native/src/main.rs` | serial, kernel allocator, IDT/PIC/PIT, boot checks and two-context scheduling |
| `kernel/native/src/paging.rs` | bounded supervisor mapping window, zero-filled map, protection, unmap and frame reclamation |
| `kernel/native/link.ld` | explicit ELF layout at 1 MiB and kernel-end reservation |
| `kernel/build.sh`, `kernel/smoke.sh` | BIOS ISO and bounded TCG acceptance tests |
| `build.ninja` | incremental image builds, host tests, lint and QEMU acceptance entry points |

The boot binary is an independent workspace targeting
`x86_64-unknown-none`. Its foundation library also participates in root
`cargo test`. Bare-metal tests are deliberately not represented as ordinary
host unit tests: they must actually boot QEMU.

## Build and run

Required tools: Rust with `x86_64-unknown-none`, NASM, GRUB rescue/file tools,
GRUB **i386-pc BIOS modules**, xorriso, QEMU x86_64, Ninja, timeout and ripgrep.
The target uses Rust's bundled linker. No bootloader is installed on the host.

```sh
rustup target add x86_64-unknown-none
ninja kernel-check
```

Ninja builds normal, optimized release, invalid-opcode, write-protection, unmap
and NX images. The smoke script boots each with 32, 64 and 128 MiB RAM
(18 cases). It requires a specific serial
marker **and** QEMU's debug-exit code (33 success, 35 expected exception).
An unexpected panic, triple fault or 20-second timeout fails the run. Logs and
ISOs are under `target/kernel-{normal,release,fault,protection,unmap,nx}/`. The test image
exits after its self-tests; it is not an interactive distribution.

Build just the normal ISO with `ninja`, all images with `ninja kernel-images`,
or run the VM matrix with `ninja kernel-qemu`. Tests always run when requested;
unchanged images are reused. Shell scripts are implementation helpers, not a
Makefile-based build. A matching manual
test invocation is:

```sh
qemu-system-x86_64 -accel tcg -smp 1 -m 128 \
  -cdrom target/kernel-normal/hyber.iso \
  -display none -serial stdio -monitor none -nic none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

### Missing BIOS modules

Having `grub-mkrescue` alone is insufficient when only EFI modules are installed.
The build first checks `HYBER_GRUB_BIOS_DIR`, defaulting to
`/usr/lib/grub/i386-pc`, then `target/kernel-tools/usr/lib/grub/i386-pc`.
Install the appropriate distribution build dependency, or extract a matching
distribution package locally. On the development Debian host, validation used
`apt-get download grub-pc-bin` inside `target/kernel-tools` followed by
`dpkg-deb -x <downloaded-package.deb> .`. This does not install or configure GRUB.
The build script never downloads packages automatically. Use modules matching
the installed GRUB tools.

## Boot and memory invariants

- Loader magic must match Multiboot2. Boot-info is aligned, lies inside the
  identity window, and has a bounded total length and structurally valid tags.
  The complete map is validated before callbacks mutate frame accounting.
  Modules are rejected until module ownership/reservation is designed.
- Only available memory-map ranges enter the allocator. A second pass reserves
  all non-available entries; then low memory, kernel, stacks, tables, heap and
  boot information are reserved. Reservations remain reserved even if a later
  available range overlaps them. Live allocations cannot be reclassified.
  The kernel refuses range arithmetic overflow.
- Managed physical RAM is capped at 128 MiB. The initial supervisor identity
  window spans 1 GiB, but an address being mapped does not mean it is allocatable.
- The paging window is 2 MiB at virtual address `0x40000000`, using 4 KiB pages.
  Map rejects duplicates/out-of-window pages; exhaustion rolls back table setup.
  New data frames are zeroed, mappings are supervisor-only and NX. Protect and
  unmap invalidate the local TLB before frames are released. Drop reclaims all
  remaining mappings and flushes paging-structure caches before recycling tables.
  Hardware-shared entries use volatile accesses; window recreation is tested.
  A native user AddressSpace is Phase 22, not this window.
- Heap policy is 64 reclaimable 4 KiB-aligned blocks, each allocation at most
  4 KiB. Exhaustion returns null to the allocation runtime. This intentionally
  bounded allocator is not general-purpose userspace malloc.
- CR0.WP and EFER.NXE are enabled. Initial huge identity pages are writable and
  executable; final kernel W^X/guard-page hardening is not claimed.

## Interrupts and scheduling

All 256 IDT vectors have assembly entry stubs. Architectural exception error
codes are normalized; GPRs and FXSAVE state are preserved around the Rust
handler. The initial PIC masks everything except PIT IRQ0, which increments an
atomic tick counter and acknowledges the master PIC. Unexpected vectors log
vector/error/RIP and fail-stop. Serial waits are bounded. Exception diagnostics
require a usable stack: TSS/IST double-fault and stack-overflow recovery are not
implemented yet and must precede untrusted/native process execution.

The scheduler switches between two separate kernel stacks at explicit safe
points after timer ticks. The assembly routine preserves SysV callee-saved GPRs
and per-context x87/SSE FXSAVE state. Distinct MXCSR rounding modes are checked
after switches to detect cross-context state leaks.
The idle wait uses the `sti; hlt` pattern with an interrupt-disabled recheck.
No IRQ handler allocates, locks the heap, calls VFS or executes applications.
This is single-CPU, timer-driven **cooperative** scheduling, not preemption.
AVX/XSAVE support and arbitrary instruction preemption belong to
the later process/context work. No assertion of SMP safety is made.

## Migration contract

| Hosted implementation today | Native mechanism / later integration |
| --- | --- |
| std allocation / collections | kernel allocator + alloc; port only modules that need native ownership |
| SystemTime / host waiting | kernel clock/ticks and later wait queues |
| std Mutex / host threads | kernel synchronization and Phase 22 contexts |
| Linux process provider | Phase 22 native processes using these CPU/memory mechanisms |
| hosted Object/Handle/Namespace | Phase 23 preserves Hyber identities and reference/rights contracts |
| HostFS / VFS | Phase 24 VFS and Phase 25 HyberFS/block providers |
| hosted networking | native device/network providers in later phases |

No hosted provider has been replaced prematurely. Phase 21 does not boot Lua,
services, shell, filesystem or networking. Those consumers retain their Hyber
API/provider concepts as the native implementations become available.

## Verification

```sh
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo clippy --manifest-path kernel/native/Cargo.toml --target x86_64-unknown-none -- -D warnings
cargo fmt --manifest-path kernel/native/Cargo.toml -- --check
ninja kernel-qemu
```

Expected normal serial transcript:

```text
HyberKOS native x86_64
CPU GDT IDT OK
MEMORY frames OK
MEMORY heap OK
MEMORY map protect unmap OK
SCHEDULER two contexts and FP isolation OK
PHASE21 PASS
```

Protection tests cause actual #PF faults: write to a present read-only page
must produce error 3; read after unmap must produce error 0; executing an NX
page must produce error 17 (hexadecimal 0x11). The invalid-opcode
test exercises a no-error-code exception (#UD). These checks supplement the
host tests for exhaustion, reuse, malformed/truncated maps and scheduling
order. They do not certify physical hardware or production security.
