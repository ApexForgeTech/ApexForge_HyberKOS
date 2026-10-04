//! Read-only consistency checker. Recovery selects valid snapshots and never repairs in place.
use hyber_fs::{BlockDevice, FsError, Volume};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
struct ReadOnly(File, u64);
impl BlockDevice for ReadOnly {
    fn len(&self) -> u64 {
        self.1
    }
    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), FsError> {
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.read_exact(out)?;
        Ok(())
    }
    fn write_at(&mut self, _: u64, _: &[u8]) -> Result<(), FsError> {
        Err(FsError::PermissionDenied)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        Ok(())
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("usage: hyberfsck <image>".into());
    }
    let file = File::open(&args[1])?;
    file.try_lock_shared()?;
    let length = file.metadata()?.len();
    let volume = Volume::mount(ReadOnly(file, length))?;
    volume.check()?;
    if !volume.recovery_warnings().is_empty() {
        return Err(format!(
            "recovered generation {}; damaged slots: {}",
            volume.format_generation(),
            volume.recovery_warnings().join("; ")
        )
        .into());
    }
    println!("valid HyberFS generation {}", volume.format_generation());
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("hyberfsck: {error}");
        std::process::exit(1);
    }
}
