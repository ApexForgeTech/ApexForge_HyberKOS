use hyber_fs::{BlockDevice, FileDevice, FsError, Volume, BLOCK_SIZE};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Image(PathBuf);
impl Image {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "hyber-fs-test-{}-{}.img",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn image_open_never_creates_or_resizes_and_locks_writers() {
    let image = Image::new();
    assert!(FileDevice::open(&image.0, 16).is_err());
    assert!(!image.0.exists());
    let mut volume = Volume::format(FileDevice::create(&image.0, 16, false).unwrap()).unwrap();
    volume.create_file("/a", 0o600).unwrap();
    volume.write_file("/a", 0, b"data").unwrap();
    volume.sync().unwrap();
    assert!(matches!(FileDevice::open(&image.0, 16), Err(FsError::Busy)));
    assert!(matches!(
        FileDevice::create(&image.0, 8, true),
        Err(FsError::Busy)
    ));
    drop(volume.unmount().unwrap());
    let before = std::fs::read(&image.0).unwrap();
    assert!(FileDevice::open(&image.0, 8).is_err());
    assert!(FileDevice::create(&image.0, 16, false).is_err());
    assert!(FileDevice::create(&image.0, 1, true).is_err());
    assert_eq!(std::fs::read(&image.0).unwrap(), before);
    let mut device = FileDevice::open(&image.0, 16).unwrap();
    assert!(device.write_at(16 * BLOCK_SIZE as u64, b"x").is_err());
    assert!(device.write_at(u64::MAX, b"x").is_err());
    assert_eq!(
        std::fs::metadata(&image.0).unwrap().len(),
        16 * BLOCK_SIZE as u64
    );
    drop(device);
    let mut read_only = FileDevice::open_read_only(&image.0, 16).unwrap();
    assert!(read_only.write_at(0, b"x").is_err());
    assert!(FileDevice::open_read_only(&image.0, 16).is_ok());
}
