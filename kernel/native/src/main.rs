#![no_std]
#![no_main]

extern crate alloc;
mod paging;
use core::{
    alloc::{GlobalAlloc, Layout},
    arch::asm,
    cell::UnsafeCell,
    ptr::{addr_of, addr_of_mut},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use hyber_kernel_foundation::{Blocks, Frames, RoundRobin, PAGE};

unsafe extern "C" {
    static kernel_end: u8;
    static isr_table: [u64; 256];
    static mut pdpt: [u64; 512];
    fn switch_context(old: *mut usize, new: usize, old_fx: *mut FxState, new_fx: *const FxState);
}
unsafe fn out(port: u16, value: u8) {
    asm!("out dx, al",in("dx")port,in("al")value,options(nomem,nostack,preserves_flags));
}
unsafe fn input(port: u16) -> u8 {
    let v;
    asm!("in al, dx",in("dx")port,out("al")v,options(nomem,nostack,preserves_flags));
    v
}
fn serial_byte(byte: u8) {
    unsafe {
        // Bounded even when UART hardware is absent.
        for _ in 0..100_000 {
            if input(0x3fd) & 0x20 != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        out(0x3f8, byte);
    }
}
fn serial(text: &str) {
    for byte in text.bytes() {
        serial_byte(byte);
    }
}
fn hex(value: u64) {
    for shift in (0..16).rev() {
        let digit = ((value >> (shift * 4)) & 15) as u8;
        serial_byte(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
    }
}
fn exit(code: u32) -> ! {
    unsafe {
        asm!("cli", "out dx, eax",in("dx")0xf4u16,in("eax")code,options(nomem,nostack));
    }
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    serial("KERNEL PANIC\n");
    exit(0x11)
}

#[repr(C, align(4096))]
struct HeapBytes([u8; 64 * PAGE]);
static mut HEAP: HeapBytes = HeapBytes([0; 64 * PAGE]);
struct Heap {
    locked: AtomicBool,
    blocks: UnsafeCell<Blocks>,
}
unsafe impl Sync for Heap {}
impl Heap {
    fn with<T>(&self, f: impl FnOnce(&mut Blocks) -> T) -> T {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = f(unsafe { &mut *self.blocks.get() });
        self.locked.store(false, Ordering::Release);
        result
    }
}
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with(|b| b.allocate(layout.size(), layout.align()))
            .map_or(core::ptr::null_mut(), |slot| {
                (addr_of_mut!(HEAP) as *mut u8).add(slot * PAGE)
            })
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        let offset = (ptr as usize)
            .checked_sub(addr_of!(HEAP) as usize)
            .expect("invalid heap pointer");
        assert!(offset.is_multiple_of(PAGE));
        self.with(|b| b.release(offset / PAGE))
            .expect("heap release");
    }
}
#[global_allocator]
static ALLOCATOR: Heap = Heap {
    locked: AtomicBool::new(false),
    blocks: UnsafeCell::new(Blocks::new()),
};
static mut FRAMES: Frames = Frames::new();

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Gate {
    low: u16,
    selector: u16,
    ist: u8,
    flags: u8,
    middle: u16,
    high: u32,
    zero: u32,
}
const EMPTY: Gate = Gate {
    low: 0,
    selector: 0,
    ist: 0,
    flags: 0,
    middle: 0,
    high: 0,
    zero: 0,
};
static mut IDT: [Gate; 256] = [EMPTY; 256];
#[repr(C, packed)]
struct Descriptor {
    limit: u16,
    base: u64,
}
static TICKS: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
extern "C" fn interrupt_dispatch(vector: u64, error: u64, ip: u64) {
    if vector == 32 {
        TICKS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            out(0x20, 0x20);
        }
    } else {
        serial("EXCEPTION vector=");
        hex(vector);
        serial(" error=");
        hex(error);
        serial(" rip=");
        hex(ip);
        serial("\n");
        exit(0x11);
    }
}
unsafe fn interrupts() {
    for (i, &address) in isr_table.iter().enumerate() {
        addr_of_mut!(IDT).cast::<Gate>().add(i).write(Gate {
            low: address as u16,
            selector: 8,
            ist: 0,
            flags: 0x8e,
            middle: (address >> 16) as u16,
            high: (address >> 32) as u32,
            zero: 0,
        });
    }
    let descriptor = Descriptor {
        limit: (core::mem::size_of::<[Gate; 256]>() - 1) as u16,
        base: addr_of!(IDT) as u64,
    };
    asm!("lidt [{}]",in(reg)&descriptor,options(readonly,nostack));
    // PIC initialization; port 0x80 provides the legacy I/O delay.
    for (port, value) in [
        (0x20, 0x11),
        (0xa0, 0x11),
        (0x21, 32),
        (0xa1, 40),
        (0x21, 4),
        (0xa1, 2),
        (0x21, 1),
        (0xa1, 1),
        (0x21, 0xfe),
        (0xa1, 0xff),
    ] {
        out(port, value);
        out(0x80, 0);
    }
    let divisor = 11932u16;
    out(0x43, 0x36);
    out(0x40, divisor as u8);
    out(0x40, (divisor >> 8) as u8);
}

unsafe fn memory(info: usize) {
    assert!(info.is_multiple_of(8) && (0x1000..(1 << 30) - 8).contains(&info));
    let size = (info as *const u32).read() as usize;
    assert!((16..=1024 * 1024).contains(&size) && info.checked_add(size).unwrap() < 1 << 30);
    let bytes = core::slice::from_raw_parts(info as *const u8, size);
    let frames = &mut *addr_of_mut!(FRAMES);
    hyber_kernel_foundation::memory_map(bytes, |base, len, kind| {
        if kind == 1 {
            frames.available(base, len).unwrap();
        }
    })
    .unwrap();
    hyber_kernel_foundation::memory_map(bytes, |base, len, kind| {
        if kind != 1 {
            frames.reserve(base, len).unwrap();
        }
    })
    .unwrap();
    frames.reserve(0, addr_of!(kernel_end) as u64).unwrap();
    frames.reserve(info as u64, size as u64).unwrap();
    let frame = frames.allocate().expect("usable RAM");
    frames.release(frame).unwrap();
    assert_eq!(frames.allocate(), Some(frame));
    frames.release(frame).unwrap();
    serial("MEMORY frames OK\n");
    let a = alloc::boxed::Box::new(42u64);
    let pointer = &*a as *const u64 as usize;
    assert_eq!(*a, 42);
    drop(a);
    let b = alloc::boxed::Box::new(43u64);
    assert_eq!(&*b as *const u64 as usize, pointer);
    drop(b);
    serial("MEMORY heap OK\n");
    mapping_test(frames);
}

unsafe fn mapping_test(frames: &mut Frames) {
    let mut window = paging::Window::new(frames).unwrap();
    let virtual_address = window.map(0).unwrap();
    assert!(window.map(0).is_err());
    assert!(window.map(512).is_err());
    (virtual_address as *mut u64).write_volatile(0x4859424552);
    window.protect(0, false).unwrap();
    assert_eq!(
        (virtual_address as *const u64).read_volatile(),
        0x4859424552
    );
    if cfg!(feature = "protection-test") {
        (virtual_address as *mut u64).write_volatile(1);
        panic!("write protection failed");
    }
    if cfg!(feature = "nx-test") {
        asm!("call {}", in(reg) virtual_address, clobber_abi("C"));
        panic!("NX protection failed");
    }
    window.unmap(0).unwrap();
    assert!(window.unmap(0).is_err());
    assert!(window.protect(0, true).is_err());
    if cfg!(feature = "unmap-test") {
        let _ = (virtual_address as *const u64).read_volatile();
        panic!("unmap failed");
    }
    let remapped = window.map(0).unwrap();
    assert_eq!((remapped as *const u64).read_volatile(), 0);
    drop(window);
    let mut recreated = paging::Window::new(frames).unwrap();
    let address = recreated.map(0).unwrap();
    assert_eq!((address as *const u64).read_volatile(), 0);
    (address as *mut u64).write_volatile(42);
    assert_eq!((address as *const u64).read_volatile(), 42);
    drop(recreated);
    serial("MEMORY map protect unmap OK\n");
}

#[repr(C, align(16))]
struct Stack([u8; 65536]);
static mut TASK_STACK: Stack = Stack([0; 65536]);
static mut CONTEXT: [usize; 2] = [0; 2];
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct FxState([u8; 512]);
static mut FX: [FxState; 2] = [FxState([0; 512]); 2];
static mut QUEUE: Option<RoundRobin> = None;
static WORK: AtomicU64 = AtomicU64::new(0);
fn yield_now() {
    unsafe {
        // No timer handler accesses this queue; switching occurs only at safe points.
        let (old, new) = (&mut *addr_of_mut!(QUEUE)).as_mut().unwrap().advance();
        let context = addr_of_mut!(CONTEXT).cast::<usize>();
        let fx = addr_of_mut!(FX).cast::<FxState>();
        switch_context(
            context.add(old),
            context.add(new).read(),
            fx.add(old),
            fx.add(new),
        );
    }
}
fn next_tick() {
    let previous = TICKS.load(Ordering::Relaxed);
    loop {
        unsafe {
            asm!("cli", options(nomem, nostack));
            if TICKS.load(Ordering::Relaxed) != previous {
                asm!("sti", options(nomem, nostack));
                break;
            }
            asm!("sti", "hlt", options(nomem, nostack));
        }
    }
}
extern "C" fn worker() -> ! {
    let control = 0x3f80u32;
    unsafe {
        asm!("ldmxcsr [{}]",in(reg)&control,options(nostack));
    }
    loop {
        next_tick();
        WORK.fetch_add(1, Ordering::Relaxed);
        yield_now();
        assert_eq!(mxcsr(), control);
    }
}
fn mxcsr() -> u32 {
    let mut value = 0u32;
    unsafe {
        asm!("stmxcsr [{}]",in(reg)&mut value,options(nostack));
    }
    value
}
unsafe fn scheduler() -> ! {
    for i in 0..2 {
        asm!("fxsave64 [{}]",in(reg)addr_of_mut!(FX).cast::<FxState>().add(i),options(nostack));
    }
    // Return-address frame plus the six ABI callee-saved registers.
    let top = addr_of_mut!(TASK_STACK) as usize + 65536;
    let saved = (top - 64) as *mut usize;
    for i in 0..6 {
        saved.add(i).write(0);
    }
    saved.add(6).write(worker as *const () as usize);
    addr_of_mut!(CONTEXT)
        .cast::<usize>()
        .add(1)
        .write(saved as usize);
    addr_of_mut!(QUEUE).write(RoundRobin::new(2));
    asm!("sti", options(nomem, nostack));
    for _ in 0..10 {
        next_tick();
        yield_now();
        assert_eq!(mxcsr(), 0x1f80);
    }
    assert!(WORK.load(Ordering::Relaxed) >= 10 && TICKS.load(Ordering::Relaxed) >= 20);
    serial("SCHEDULER two contexts and FP isolation OK\nPHASE21 PASS\n");
    exit(0x10);
}

#[no_mangle]
extern "C" fn kernel_main(magic: u32, info: u32) -> ! {
    unsafe {
        out(0x3f9, 0);
        out(0x3fb, 0x80);
        out(0x3f8, 3);
        out(0x3f9, 0);
        out(0x3fb, 3);
        out(0x3fa, 0xc7);
        out(0x3fc, 0x0b);
        serial("HyberKOS native x86_64\n");
        assert_eq!(magic, 0x36d76289);
        interrupts();
        serial("CPU GDT IDT OK\n");
        memory(info as usize);
        if cfg!(feature = "fault-test") {
            asm!("ud2", options(noreturn));
        }
        scheduler();
    }
}
