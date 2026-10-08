use mlua::{HookTriggers, Lua, LuaOptions, StdLib, Value};
use std::{
    io::{BufRead, Write},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

fn emit(value: serde_json::Value) -> mlua::Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{value}")
        .and_then(|_| stdout.flush())
        .map_err(mlua::Error::external)
}
pub fn run(path: &str, memory: usize, shares: usize) -> Result<(), String> {
    let source = std::fs::read_to_string(path).map_err(|_| "payload unavailable")?;
    if source.len() > 16 * 1024 * 1024 {
        return Err("payload too large".into());
    }
    let stop = Arc::new(AtomicBool::new(false));
    let input_stop = stop.clone();
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            let mut frame = Vec::new();
            use std::io::Read;
            match input.by_ref().take(8193).read_until(b'\n', &mut frame) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if frame.len() > 8192
                        || serde_json::from_slice::<serde_json::Value>(&frame)
                            .map(|v| v["op"] == "stop")
                            .unwrap_or(true)
                    {
                        break;
                    }
                }
            }
        }
        input_stop.store(true, Ordering::Release);
    });
    let lua = Lua::new_with(
        StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8,
        LuaOptions::default(),
    )
    .map_err(|e| e.to_string())?;
    lua.set_memory_limit(memory / 2)
        .map_err(|e| e.to_string())?;
    for name in [
        "pcall",
        "xpcall",
        "load",
        "loadfile",
        "dofile",
        "require",
        "print",
        "collectgarbage",
    ] {
        lua.globals()
            .set(name, Value::Nil)
            .map_err(|e| e.to_string())?;
    }
    let hook_stop = stop.clone();
    let counter = AtomicUsize::new(0);
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(1000),
        move |_, _| {
            if hook_stop.load(Ordering::Acquire) {
                return Err(mlua::Error::RuntimeError("service stopped".into()));
            }
            if counter.fetch_add(1000, Ordering::Relaxed) >= shares.clamp(1, 1024) * 1000 {
                counter.store(0, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        },
    );
    let hyber = lua.create_table().map_err(|e| e.to_string())?;
    let service = lua.create_table().map_err(|e| e.to_string())?;
    service
        .set(
            "ready",
            lua.create_function(|_, ()| emit(serde_json::json!({"op":"ready"})))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let check = stop.clone();
    service
        .set(
            "stopping",
            lua.create_function(move |_, ()| Ok(check.load(Ordering::Acquire)))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let wait_stop = stop.clone();
    service
        .set(
            "wait",
            lua.create_function(move |_, ms: u64| {
                if ms > 60_000 {
                    return Err(mlua::Error::RuntimeError("wait exceeds 60 seconds".into()));
                }
                let deadline = std::time::Instant::now() + Duration::from_millis(ms);
                while !wait_stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(!wait_stop.load(Ordering::Acquire))
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let log = lua.create_table().map_err(|e| e.to_string())?;
    log.set(
        "info",
        lua.create_function(|_, message: String| {
            if message.len() > 1024 {
                return Err(mlua::Error::RuntimeError("log too large".into()));
            }
            emit(serde_json::json!({"op":"log", "message": message}))
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    hyber.set("service", service).map_err(|e| e.to_string())?;
    hyber.set("log", log).map_err(|e| e.to_string())?;
    lua.globals()
        .set("hyber", hyber)
        .map_err(|e| e.to_string())?;
    let result = lua.load(&source).set_mode(mlua::ChunkMode::Text).exec();
    if stop.load(Ordering::Acquire) {
        Ok(())
    } else {
        result.map_err(|_| "service payload failed".into())
    }
}
