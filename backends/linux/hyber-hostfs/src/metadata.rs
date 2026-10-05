//! Linux-private, atomic per-object metadata. No host identity is imported.
use hyber_core::{GroupId, MetadataValue, UserId};
use hyber_object::Object;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

const NAME: &[u8] = b"user.hyber.metadata.v1\0";
const LIMIT: usize = 60 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u32,
    owner: u32,
    group: u32,
    mode: u32,
    created: u64,
    modified: u64,
    flags: u32,
    extended: BTreeMap<String, MetadataValue>,
}
impl Record {
    pub fn apply(self, object: &mut Object) {
        object.owner = UserId(self.owner);
        object.group = GroupId(self.group);
        object.permissions = self.mode;
        object.created_at = self.created;
        object.modified_at = self.modified;
        object.flags = self.flags;
        object.extended_metadata = self.extended.into_iter().collect();
    }
}
pub(super) fn open(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())
}
fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}
pub(super) fn encode(object: &Object) -> Result<Vec<u8>, String> {
    let record = Record {
        version: 1,
        owner: object.owner.0,
        group: object.group.0,
        mode: object.permissions,
        created: object.created_at,
        modified: object.modified_at,
        flags: object.flags,
        extended: object.extended_metadata.clone().into_iter().collect(),
    };
    let payload = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    if payload.len() > LIMIT - 8 {
        return Err("HostFS metadata exceeds storage limit".into());
    }
    let mut bytes = hash(&payload).to_le_bytes().to_vec();
    bytes.extend(payload);
    Ok(bytes)
}
pub(super) fn load(file: &File) -> Result<Option<Record>, String> {
    let mut bytes = vec![0u8; LIMIT];
    // SAFETY: live fd, NUL-terminated static name and writable bounded buffer.
    let n = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            NAME.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if n < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(format!("HostFS metadata unavailable: {error}"));
    }
    bytes.truncate(n as usize);
    if bytes.len() < 8 || hash(&bytes[8..]) != u64::from_le_bytes(bytes[..8].try_into().unwrap()) {
        return Err("HostFS metadata checksum mismatch".into());
    }
    let record: Record =
        serde_json::from_slice(&bytes[8..]).map_err(|e| format!("invalid HostFS metadata: {e}"))?;
    if record.version != 1 || record.mode & !0o777 != 0 {
        return Err("unsupported HostFS metadata".into());
    }
    for (key, value) in &record.extended {
        hyber_object::ObjectManager::validate_metadata_entry(key, value)?;
    }
    Ok(Some(record))
}
pub(super) fn store(file: &File, bytes: &[u8]) -> Result<(), String> {
    // SAFETY: live fd; name and byte buffers remain valid throughout the call.
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            NAME.as_ptr().cast(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
        )
    };
    if result != 0 {
        return Err(format!(
            "HostFS metadata write failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    file.sync_all().map_err(|e| e.to_string())
}
