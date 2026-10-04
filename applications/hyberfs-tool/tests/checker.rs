use hyber_fs::{FileDevice, Volume};
use std::process::Command;

#[test]
fn checker_is_read_only_and_errors_are_nonzero() {
    let path = std::env::temp_dir().join(format!("hyberfsck-test-{}.img", std::process::id()));
    let volume = Volume::format(FileDevice::create(&path, 16, false).unwrap()).unwrap();
    drop(volume.unmount().unwrap());
    let before = std::fs::read(&path).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hyberfsck"))
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let output = Command::new(env!("CARGO_BIN_EXE_hyberfs-tool"))
        .args(["check", path.to_str().unwrap(), "8"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut corrupt = before;
    corrupt[24] ^= 1;
    std::fs::write(&path, &corrupt).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hyberfsck"))
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    assert!(!Command::new(env!("CARGO_BIN_EXE_hyberfsck"))
        .output()
        .unwrap()
        .status
        .success());
    assert!(!Command::new(env!("CARGO_BIN_EXE_hyberfs-tool"))
        .arg("invalid-command")
        .output()
        .unwrap()
        .status
        .success());
    std::fs::remove_file(path).unwrap();
}
