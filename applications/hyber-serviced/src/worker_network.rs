//! Worker-side language binding to the Rust broker. No host sockets here.
use mlua::{Lua, Table, UserData, UserDataMethods, Value};
use serde_json::{json, Value as Json};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

struct Client {
    responses: mpsc::Receiver<Json>,
    stop: Arc<AtomicBool>,
    next: u64,
}
impl Client {
    fn call(&mut self, mut request: Json) -> mlua::Result<Json> {
        if self.stop.load(Ordering::Acquire) {
            return Err(mlua::Error::external("service stopped"));
        }
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| mlua::Error::external("request identifiers exhausted"))?;
        request["op"] = json!("network");
        request["id"] = json!(id);
        crate::worker::emit(request)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(mlua::Error::external(
                    "network request cancelled or timed out",
                ));
            }
            match self.responses.recv_timeout(Duration::from_millis(20)) {
                Ok(reply) => {
                    if reply["id"].as_u64() != Some(id) {
                        return Err(mlua::Error::external("network response correlation failed"));
                    }
                    return if reply["ok"] == true {
                        Ok(reply["result"].clone())
                    } else {
                        Err(mlua::Error::external(
                            reply["error"]
                                .as_str()
                                .unwrap_or("network request failed")
                                .to_owned(),
                        ))
                    };
                }
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(_) => return Err(mlua::Error::external("network broker closed")),
            }
        }
    }
}
struct Socket {
    client: Rc<RefCell<Client>>,
    handle: u64,
    closed: bool,
}
impl UserData for Socket {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("cancel", |_, this, ()| {
            if this.closed {
                return Err(mlua::Error::external("closed socket"));
            }
            this.client
                .borrow_mut()
                .call(json!({"action":"cancel","handle":this.handle}))?;
            Ok(())
        });
        methods.add_method("wait", |_, this, (interest, timeout_ms): (String, u32)| {
            if this.closed || timeout_ms > 2000 || !matches!(interest.as_str(), "readable" | "writable") {
                return Err(mlua::Error::external("closed socket or invalid wait request"));
            }
            let result = this.client.borrow_mut().call(json!({"action":"wait","handle":this.handle,"interest":interest,"timeout_ms":timeout_ms}))?;
            result["ready"].as_bool().ok_or_else(|| mlua::Error::external("invalid wait response"))
        });
        methods.add_method("inspect", |lua, this, ()| {
            if this.closed {
                return Err(mlua::Error::external("closed socket"));
            }
            let result = this
                .client
                .borrow_mut()
                .call(json!({"action":"inspect","handle":this.handle}))?;
            let info = lua.create_table()?;
            for key in ["protocol", "state", "host", "provider"] {
                info.set(
                    key,
                    result[key]
                        .as_str()
                        .ok_or_else(|| mlua::Error::external("invalid inspection response"))?,
                )?;
            }
            for key in ["object_id", "owner", "port", "bytes_sent", "bytes_received"] {
                info.set(
                    key,
                    result[key]
                        .as_u64()
                        .ok_or_else(|| mlua::Error::external("invalid inspection response"))?,
                )?;
            }
            Ok(info)
        });
        methods.add_method("write", |_, this, data: mlua::String| {
            if this.closed || data.as_bytes().len() > 512 {
                return Err(mlua::Error::external(
                    "closed socket or write exceeds 512 bytes",
                ));
            }
            let value = this
                .client
                .borrow_mut()
                .call(json!({"action":"write","handle":this.handle,"data":data.as_bytes()}))?;
            value["written"]
                .as_u64()
                .ok_or_else(|| mlua::Error::external("invalid write response"))
        });
        methods.add_method("read", |lua, this, limit: Option<usize>| {
            let limit = limit.unwrap_or(512);
            if this.closed || limit == 0 || limit > 512 {
                return Err(mlua::Error::external("closed socket or invalid read limit"));
            }
            let value = this
                .client
                .borrow_mut()
                .call(json!({"action":"read","handle":this.handle,"limit":limit}))?;
            if value["eof"] == true {
                return Ok(Value::Nil);
            }
            let bytes = value["data"]
                .as_array()
                .ok_or_else(|| mlua::Error::external("invalid data response"))?;
            let bytes = bytes
                .iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|b| u8::try_from(b).ok())
                        .ok_or_else(|| mlua::Error::external("invalid byte"))
                })
                .collect::<mlua::Result<Vec<_>>>()?;
            Ok(Value::String(lua.create_string(&bytes)?))
        });
        methods.add_method_mut("close", |_, this, ()| {
            if !this.closed {
                this.client
                    .borrow_mut()
                    .call(json!({"action":"close","handle":this.handle}))?;
                this.closed = true;
            }
            Ok(())
        });
    }
}
pub fn table(
    lua: &Lua,
    stop: Arc<AtomicBool>,
    responses: mpsc::Receiver<Json>,
) -> mlua::Result<Table<'_>> {
    let client = Rc::new(RefCell::new(Client {
        responses,
        stop,
        next: 1,
    }));
    let table = lua.create_table()?;
    let resolver = client.clone();
    table.set(
        "resolve",
        lua.create_function(move |lua, host: String| {
            if host.len() > 253 {
                return Err(mlua::Error::external("hostname too long"));
            }
            let result = resolver
                .borrow_mut()
                .call(json!({"action":"resolve","host":host}))?;
            let info = lua.create_table()?;
            info.set(
                "host",
                result["host"]
                    .as_str()
                    .ok_or_else(|| mlua::Error::external("invalid resolver response"))?,
            )?;
            info.set(
                "answers",
                result["answers"]
                    .as_u64()
                    .ok_or_else(|| mlua::Error::external("invalid resolver response"))?,
            )?;
            info.set(
                "cached",
                result["cached"]
                    .as_bool()
                    .ok_or_else(|| mlua::Error::external("invalid resolver response"))?,
            )?;
            info.set(
                "cache_seconds",
                result["cache_seconds"]
                    .as_u64()
                    .ok_or_else(|| mlua::Error::external("invalid resolver response"))?,
            )?;
            Ok(info)
        })?,
    )?;
    table.set(
        "connect",
        lua.create_function(
            move |lua, (host, port, protocol): (String, u16, Option<String>)| {
                if host.len() > 253 {
                    return Err(mlua::Error::external("hostname too long"));
                }
                let protocol = protocol.unwrap_or_else(|| "tcp".into());
                if protocol != "tcp" && protocol != "udp" {
                    return Err(mlua::Error::external("invalid protocol"));
                }
                let result = client.borrow_mut().call(
                    json!({"action":"connect","host":host,"port":port,"protocol":protocol}),
                )?;
                let handle = result["handle"]
                    .as_u64()
                    .ok_or_else(|| mlua::Error::external("invalid connect response"))?;
                lua.create_userdata(Socket {
                    client: client.clone(),
                    handle,
                    closed: false,
                })
            },
        )?,
    )?;
    Ok(table)
}
