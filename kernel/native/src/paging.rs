//! One supervisor-only 2 MiB window for bring-up. Not a user address space.
use core::{arch::asm, ptr::addr_of_mut};
use hyber_kernel_foundation::{Frames, PAGE};
const BASE: usize = 0x40000000;
const NX: u64 = 1 << 63;
pub struct Window<'a> {
    frames: &'a mut Frames,
    directory: usize,
    table: usize,
}
impl<'a> Window<'a> {
    /// Caller runs on the bootstrap CPU with the bootstrap CR3/identity map.
    /// No other CPU or mapping manager may mutate PDPT entry 1.
    pub unsafe fn new(frames: &'a mut Frames) -> Result<Self, &'static str> {
        let root = addr_of_mut!(super::pdpt).cast::<u64>().add(1);
        if root.read_volatile() != 0 {
            return Err("window already mapped");
        }
        let directory = frames.allocate().ok_or("no directory frame")?;
        let Some(table) = frames.allocate() else {
            frames.release(directory)?;
            return Err("no table frame");
        };
        core::ptr::write_bytes(directory as *mut u8, 0, PAGE);
        core::ptr::write_bytes(table as *mut u8, 0, PAGE);
        (directory as *mut u64).write_volatile(table as u64 | 3);
        root.write_volatile(directory as u64 | 3);
        Ok(Self {
            frames,
            directory,
            table,
        })
    }
    fn entry(&self, page: usize) -> Result<*mut u64, &'static str> {
        if page >= 512 {
            return Err("page outside window");
        }
        Ok(unsafe { (self.table as *mut u64).add(page) })
    }
    fn invalidate(page: usize) {
        unsafe {
            asm!("invlpg [{}]", in(reg) (BASE + page*PAGE), options(nostack));
        }
    }
    pub fn map(&mut self, page: usize) -> Result<usize, &'static str> {
        let entry = self.entry(page)?;
        if unsafe { entry.read_volatile() } != 0 {
            return Err("page already mapped");
        }
        let frame = self.frames.allocate().ok_or("no data frame")?;
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE);
            entry.write_volatile(frame as u64 | 3 | NX);
        }
        Self::invalidate(page);
        Ok(BASE + page * PAGE)
    }
    pub fn protect(&mut self, page: usize, writable: bool) -> Result<(), &'static str> {
        let entry = self.entry(page)?;
        let old = unsafe { entry.read_volatile() };
        if old & 1 == 0 {
            return Err("unmapped page");
        }
        unsafe {
            entry.write_volatile((old & !2) | if writable { 2 } else { 0 });
        }
        Self::invalidate(page);
        Ok(())
    }
    pub fn unmap(&mut self, page: usize) -> Result<(), &'static str> {
        let entry = self.entry(page)?;
        let old = unsafe { entry.read_volatile() };
        if old & 1 == 0 {
            return Err("unmapped page");
        }
        unsafe {
            entry.write_volatile(0);
        }
        Self::invalidate(page);
        self.frames.release((old & 0x000f_ffff_ffff_f000) as usize)
    }
}
impl Drop for Window<'_> {
    fn drop(&mut self) {
        for page in 0..512 {
            if unsafe { self.entry(page).unwrap().read_volatile() } & 1 != 0 {
                self.unmap(page).unwrap();
            }
        }
        unsafe {
            addr_of_mut!(super::pdpt)
                .cast::<u64>()
                .add(1)
                .write_volatile(0);
            // Flush paging-structure caches before recycling their frames.
            // Bootstrap uses neither PCID nor global mappings, on one CPU.
            let cr3: usize;
            asm!("mov {}, cr3", out(reg) cr3, options(nostack));
            asm!("mov cr3, {}", in(reg) cr3, options(nostack));
        }
        // All leaf translations were invalidated before freeing page tables.
        self.frames.release(self.table).unwrap();
        self.frames.release(self.directory).unwrap();
    }
}
