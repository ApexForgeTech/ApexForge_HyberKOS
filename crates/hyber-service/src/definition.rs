//! Bounded, data-only Lua declaration loader. Identity and grants are supplied
//! by trusted Rust policy, never by the declaration itself.
use hyber_identity::AccountRegistry;
use hyber_manifest::ApplicationGrant;
use hyber_service_contract::{LuaServiceTable, ServiceDefinition, ServiceIdentity};
use mlua::{ChunkMode, HookTriggers, Lua, LuaOptions, StdLib, Table, Value};
use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub fn load_lua_definition(
    source: &str,
    identity: ServiceIdentity,
    accounts: &AccountRegistry,
    grant: &ApplicationGrant,
) -> Result<ServiceDefinition, String> {
    if source.len() > 64 * 1024 {
        return Err("service definition exceeds 64 KiB".into());
    }
    load_inner(source, identity, accounts, grant)
        // Lua errors may contain arbitrary declaration strings. Do not publish
        // them as operational diagnostics or terminal escape sequences.
        .map_err(|_| "invalid or unauthorized service definition".into())
}

fn load_inner(
    source: &str,
    identity: ServiceIdentity,
    accounts: &AccountRegistry,
    grant: &ApplicationGrant,
) -> Result<ServiceDefinition, String> {
    let lua = Lua::new_with(StdLib::NONE, LuaOptions::default()).map_err(|e| e.to_string())?;
    lua.set_memory_limit(2 * 1024 * 1024)
        .map_err(|e| e.to_string())?;
    // A fresh empty environment has no catchable protected calls, coroutines,
    // host I/O, module loading, dynamic compilation, or supervisor access.
    let environment = lua.create_table().map_err(|e| e.to_string())?;
    let counter = Arc::new(AtomicUsize::new(0));
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(1000),
        move |_, _| {
            if counter.fetch_add(1000, Ordering::Relaxed) >= 100_000 {
                Err(mlua::Error::RuntimeError(
                    "service declaration instruction limit".into(),
                ))
            } else {
                Ok(())
            }
        },
    );
    let table: Table = lua
        .load(source)
        .set_mode(ChunkMode::Text)
        .set_environment(environment)
        .eval()
        .map_err(|e| e.to_string())?;
    let fields = [
        "format_version",
        "service_id",
        "application_id",
        "startup",
        "restart",
        "health_check",
        "dependencies",
        "entrypoint",
        "requested_capabilities",
        "socket_outbound",
        "socket_inbound",
        "socket_domains",
        "ipc_endpoints",
        "max_message_bytes",
        "max_concurrency",
        "arguments",
    ];
    for pair in table.clone().pairs::<Value, Value>() {
        let (key, _) = pair.map_err(|e| e.to_string())?;
        let Value::String(key) = key else {
            return Err("invalid field key".into());
        };
        if !fields.contains(&key.to_str().map_err(|e| e.to_string())?) {
            return Err("unknown service field".into());
        }
    }
    let raw = LuaServiceTable {
        format_version: number(&table, "format_version")?,
        service_id: string(&table, "service_id")?,
        application_id: string(&table, "application_id")?,
        startup: string(&table, "startup")?,
        restart: string(&table, "restart")?,
        health_check: string(&table, "health_check")?,
        dependencies: strings(&table, "dependencies")?,
        entrypoint: string(&table, "entrypoint")?,
        requested_capabilities: strings(&table, "requested_capabilities")?,
        socket_outbound: boolean(&table, "socket_outbound")?,
        socket_inbound: boolean(&table, "socket_inbound")?,
        socket_domains: strings(&table, "socket_domains")?,
        ipc_endpoints: strings(&table, "ipc_endpoints")?,
        max_message_bytes: number(&table, "max_message_bytes")?,
    };
    let entrypoint = raw.entrypoint.clone();
    let mut definition =
        ServiceDefinition::from_lua_table(raw, identity).map_err(|e| e.to_string())?;
    if grant.manifest.runtime == hyber_manifest::Runtime::Go {
        let arguments = match table
            .raw_get::<_, Value>("arguments")
            .map_err(|e| e.to_string())?
        {
            Value::Nil => Vec::new(),
            Value::Table(args) => {
                let count = args.clone().pairs::<Value, Value>().count();
                if count > 64 {
                    return Err("too many arguments".into());
                }
                let mut values = Vec::new();
                for index in 1..=count {
                    match args.raw_get::<_, Value>(index).map_err(|e| e.to_string())? {
                        Value::String(value) => {
                            values.push(value.to_str().map_err(|e| e.to_string())?.to_owned())
                        }
                        _ => return Err("invalid argument list".into()),
                    }
                }
                values
            }
            _ => return Err("invalid arguments".into()),
        };
        definition.payload =
            hyber_service_contract::ServicePayload::Go(hyber_service_contract::GoPayloadContract {
                module: entrypoint,
                arguments,
                max_concurrency: number(&table, "max_concurrency")?
                    .try_into()
                    .map_err(|_| "invalid concurrency")?,
                cooperative_cancellation: true,
            });
    } else if !matches!(
        table
            .raw_get::<_, Value>("arguments")
            .map_err(|e| e.to_string())?,
        Value::Nil
    ) || !matches!(
        table
            .raw_get::<_, Value>("max_concurrency")
            .map_err(|e| e.to_string())?,
        Value::Nil
    ) {
        return Err("Go-only declaration fields on non-Go payload".into());
    }
    definition
        .validate_against(grant)
        .map_err(|e| e.to_string())?;
    definition
        .validate_identity(accounts)
        .map_err(|e| e.to_string())?;
    Ok(definition)
}
fn string(table: &Table, key: &str) -> Result<String, String> {
    match table.raw_get::<_, Value>(key).map_err(|e| e.to_string())? {
        Value::String(value) => {
            let text = value.to_str().map_err(|e| e.to_string())?;
            if text.len() > 1024 {
                return Err("field too long".into());
            }
            Ok(text.to_owned())
        }
        _ => Err("expected string".into()),
    }
}
fn number(table: &Table, key: &str) -> Result<u32, String> {
    match table.raw_get::<_, Value>(key).map_err(|e| e.to_string())? {
        Value::Integer(value) => value.try_into().map_err(|_| "invalid integer".into()),
        _ => Err("expected integer".into()),
    }
}
fn boolean(table: &Table, key: &str) -> Result<bool, String> {
    match table.raw_get::<_, Value>(key).map_err(|e| e.to_string())? {
        Value::Boolean(value) => Ok(value),
        Value::Nil => Ok(false),
        _ => Err("expected boolean".into()),
    }
}
fn strings(table: &Table, key: &str) -> Result<BTreeSet<String>, String> {
    let value = table.raw_get::<_, Value>(key).map_err(|e| e.to_string())?;
    if matches!(value, Value::Nil) {
        return Ok(BTreeSet::new());
    }
    let Value::Table(values) = value else {
        return Err("expected list".into());
    };
    let mut indices = BTreeSet::new();
    let mut result = BTreeSet::new();
    for pair in values.pairs::<Value, Value>() {
        let (key, value) = pair.map_err(|e| e.to_string())?;
        let Value::Integer(index) = key else {
            return Err("non-array list".into());
        };
        let Value::String(value) = value else {
            return Err("expected string element".into());
        };
        let value = value.to_str().map_err(|e| e.to_string())?;
        if !(1..=64).contains(&index) || value.len() > 1024 || !result.insert(value.to_owned()) {
            return Err("invalid or duplicate list item".into());
        }
        indices.insert(index);
    }
    if indices.iter().copied().ne(1..=indices.len() as i64) {
        return Err("sparse list".into());
    }
    Ok(result)
}
