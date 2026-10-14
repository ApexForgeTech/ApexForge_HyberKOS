//! One bounded RPC in flight per service. Socket I/O never blocks supervisor
//! polling. The child has no transport socket; the broker owns Hyber handles.
use hyber_auth::SessionGuard;
use hyber_core::{HandleId, ProcessId, SecurityContext};
use hyber_handle::HandleManager;
use hyber_manifest::ApplicationGrant;
use hyber_network::{authorize_service_outbound, NetworkAccess, NetworkManager, Protocol};
use hyber_network_host::HostedNetworkProvider;
use hyber_object::ObjectManager;
use hyber_service_contract::ServiceDefinition;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

static BROKERS: AtomicUsize = AtomicUsize::new(0);
struct Permit;
impl Drop for Permit {
    fn drop(&mut self) {
        BROKERS.fetch_sub(1, Ordering::SeqCst);
    }
}
pub(crate) struct Broker {
    request: mpsc::SyncSender<Value>,
    response: mpsc::Receiver<Value>,
    cancelled: Arc<AtomicBool>,
    pub pending: bool,
}
impl Broker {
    pub fn new(
        definition: ServiceDefinition,
        grant: ApplicationGrant,
        session: SessionGuard,
        context: SecurityContext,
        process: ProcessId,
    ) -> Result<Self, String> {
        BROKERS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < 64).then_some(n + 1)
            })
            .map_err(|_| "network broker capacity")?;
        let permit = Permit;
        let (tx, rx) = mpsc::sync_channel(1);
        let (reply, response) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopping = cancelled.clone();
        std::thread::Builder::new().name("hyber-service-network".into()).spawn(move || {
            let _permit = permit;
            let mut network = NetworkManager::new(HostedNetworkProvider::with_timeout(Duration::from_secs(2)));
            let mut objects = ObjectManager::new();
            let mut handles = HandleManager::new();
            while !stopping.load(Ordering::Acquire) {
                let value: Value = match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(v) => v, Err(mpsc::RecvTimeoutError::Timeout) => continue, Err(_) => break,
                };
                let id = value["id"].as_u64().unwrap_or(0);
                let result = (|| -> Result<Value, String> {
                    if stopping.load(Ordering::Acquire) { return Err("network operation cancelled".into()); }
                    let current = session.context().map_err(|_| "network session revoked")?;
                    if current.user_id != context.user_id || (current.group_id != context.group_id && !current.supplementary_groups.contains(&context.group_id)) { return Err("network identity mismatch".into()); }
                    definition.validate_against(&grant).map_err(|_| "network policy mismatch")?;
                    let handle = HandleId(value["handle"].as_u64().unwrap_or(0));
                    match value["action"].as_str() {
                        Some("connect") => {
                            let host = value["host"].as_str().ok_or("invalid host")?;
                            let port = value["port"].as_u64().and_then(|p| u16::try_from(p).ok()).ok_or("invalid port")?;
                            authorize_service_outbound(&context, &grant, &definition, host).map_err(|e| e.to_string())?;
                            let protocol = match value["protocol"].as_str() { Some("tcp") => Protocol::Tcp, Some("udp") => Protocol::Udp, _ => return Err("invalid protocol".into()) };
                            let handle = network.connect(&mut objects, &mut handles, process, &context, &grant, protocol, host, port).map_err(|e| e.to_string())?;
                            Ok(json!({"handle":handle.0}))
                        },
                        Some("write") => {
                            let bytes = value["data"].as_array().filter(|a| a.len() <= 512).ok_or("payload exceeds 512 bytes")?;
                            let bytes = bytes.iter().map(|v| v.as_u64().and_then(|b| u8::try_from(b).ok()).ok_or("invalid byte")).collect::<Result<Vec<_>, _>>()?;
                            let access = NetworkAccess { objects: &objects, handles: &handles, process, context: &context, grant: &grant };
                            let n = network.send(&access, handle, &bytes).map_err(|e| e.to_string())?;
                            Ok(json!({"written":n}))
                        },
                        Some("read") => {
                            let limit = value["limit"].as_u64().filter(|n| *n > 0 && *n <= 512).ok_or("read exceeds 512 bytes")?;
                            let access = NetworkAccess { objects: &objects, handles: &handles, process, context: &context, grant: &grant };
                            let protocol = network.inspect(&access, handle).map_err(|e| e.to_string())?.protocol;
                            let data = network.receive(&access, handle, limit as usize).map_err(|e| e.to_string())?;
                            Ok(json!({"eof":protocol == Protocol::Tcp && data.is_empty(), "data":data}))
                        },
                        Some("close") => {
                            network.close(&mut objects, &mut handles, process, handle).map_err(|e| e.to_string())?;
                            Ok(json!({}))
                        },
                        _ => Err("unsupported network operation".into()),
                    }
                })();
                if stopping.load(Ordering::Acquire) || session.context().is_err() { break; }
                let value = match result { Ok(data) => json!({"op":"network-result","id":id,"ok":true,"result":data}), Err(error) => json!({"op":"network-result","id":id,"ok":false,"error":error}) };
                if reply.try_send(value).is_err() { break; }
            }
            let _ = network.shutdown(&mut objects, &mut handles);
        }).map_err(|_| "cannot start network broker")?;
        Ok(Self {
            request: tx,
            response,
            cancelled,
            pending: false,
        })
    }
    pub fn submit(&mut self, value: Value) -> Result<(), ()> {
        if self.pending || value["id"].as_u64().is_none_or(|id| id == 0) {
            return Err(());
        }
        self.request.try_send(value).map_err(|_| ())?;
        self.pending = true;
        Ok(())
    }
    pub fn poll(&mut self) -> Option<Value> {
        self.response.try_recv().ok()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.cancel();
    }
}
