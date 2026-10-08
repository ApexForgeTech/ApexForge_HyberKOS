//! Authenticated hosted control transport. Passwords are prompted per request,
//! never persisted, placed in command arguments, or retained by the provider.
use hyber_core::{ObjectId, ObjectType};
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::Provider;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};

#[derive(Clone)]
pub struct ServiceClient {
    pub socket: PathBuf,
    pub session: hyber_auth::SessionGuard,
}
impl ServiceClient {
    pub fn request(&self, command: &str, id: Option<&str>) -> Result<String, String> {
        let context = self
            .session
            .context()
            .map_err(|_| "shell session invalid")?;
        hyber_core::SecurityManager::check_capability(&context, "CAP_SYS_ADMIN")?;
        let username = self
            .session
            .username()
            .map_err(|_| "shell session invalid")?;
        let password = hyber_auth::prompt_password("Service authority password: ")
            .map_err(|_| "password input failed")?;
        request(&self.socket, &username, &password, command, id)
    }
}
pub fn request(
    socket: &std::path::Path,
    username: &str,
    password: &str,
    command: &str,
    id: Option<&str>,
) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket).map_err(|_| "service daemon unavailable")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "control socket failed")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "control socket failed")?;
    let message =
        serde_json::json!({"username":username,"password":password,"command":command,"id":id});
    let mut bytes = serde_json::to_vec(&message).map_err(|_| "invalid request")?;
    if bytes.len() >= 8192 {
        return Err("request too large".into());
    }
    bytes.push(b'\n');
    let write = stream.write_all(&bytes);
    bytes.fill(0);
    write.map_err(|_| "control request failed")?;
    let mut bytes = Vec::new();
    stream
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "control response failed")?;
    if bytes.len() > 65536 {
        return Err("control response too large".into());
    }
    let response: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid control response")?;
    if response["ok"] != true {
        return Err(response["result"]
            .as_str()
            .unwrap_or("service request denied")
            .into());
    }
    response["result"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "invalid response".into())
}
pub struct RemoteServiceProvider {
    pub client: ServiceClient,
    pub root: ObjectId,
    pub objects: BTreeMap<String, ObjectId>,
}
impl Provider for RemoteServiceProvider {
    fn check_open(&self, object: ObjectId, rights: hyber_core::Rights) -> Result<(), String> {
        let context = self
            .client
            .session
            .context()
            .map_err(|_| "shell session invalid")?;
        hyber_core::SecurityManager::check_capability(&context, "CAP_SYS_ADMIN")?;
        hyber_service::projection::check_projection_rights(rights)?;
        if object == self.root {
            if rights.read {
                return Err("cannot read service directory as a file".into());
            }
        } else if !self.objects.values().any(|id| *id == object) || rights.enumerate {
            return Err("invalid service projection object or operation".into());
        }
        Ok(())
    }
    fn persist_metadata(&mut self, _: &hyber_object::Object) -> Result<(), String> {
        Err("service projection metadata is authority-owned".into())
    }
    fn create(
        &mut self,
        _: &mut ObjectManager,
        _: &mut NamespaceManager,
        _: ObjectId,
        _: &str,
        _: ObjectType,
    ) -> Result<ObjectId, String> {
        Err("services are read-only".into())
    }
    fn remove(
        &mut self,
        _: &mut ObjectManager,
        _: &mut NamespaceManager,
        _: ObjectId,
        _: &str,
    ) -> Result<(), String> {
        Err("services are read-only".into())
    }
    fn rename(
        &mut self,
        _: &mut ObjectManager,
        _: &mut NamespaceManager,
        _: ObjectId,
        _: &str,
        _: ObjectId,
        _: &str,
    ) -> Result<(), String> {
        Err("services are read-only".into())
    }
    fn write(&mut self, _: ObjectId, _: u64, _: &[u8]) -> Result<usize, String> {
        Err("services are read-only".into())
    }
    fn read(&self, object: ObjectId, offset: u64, output: &mut [u8]) -> Result<usize, String> {
        let (id, _) = self
            .objects
            .iter()
            .find(|(_, value)| **value == object)
            .ok_or("unknown service object")?;
        let response = self.client.request("status", Some(id))?;
        let offset = usize::try_from(offset).map_err(|_| "offset overflow")?;
        let bytes = response.as_bytes().get(offset..).unwrap_or_default();
        let length = bytes.len().min(output.len());
        output[..length].copy_from_slice(&bytes[..length]);
        Ok(length)
    }
    fn enumerate(&self, root: ObjectId) -> Result<Option<Vec<(String, ObjectId)>>, String> {
        self.check_open(
            root,
            hyber_core::Rights {
                enumerate: true,
                ..hyber_core::Rights::empty()
            },
        )?;
        if root != self.root {
            return Err("not a service directory".into());
        }
        Ok(Some(
            self.objects
                .iter()
                .map(|(name, id)| (name.clone(), *id))
                .collect(),
        ))
    }
}
