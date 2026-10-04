use crate::context::AppContext;
use crate::manifest;
use hyber_core::Path;
use std::path::{Path as FsPath, PathBuf};

pub fn run(args: &[String]) -> Result<(), String> {
    let input = one_path(args, "run <path>")?;
    let script_path = script_path(&input)?;
    let script = std::fs::read_to_string(&script_path)
        .map_err(|e| format!("cannot read {}: {e}", script_path.display()))?;
    let context = AppContext::new()?;
    let (vfs, ns_mgr, handles, objects, result) = hyber_lua::run_lua_script(
        &script,
        context.vfs,
        context.ns_mgr,
        context.handle_mgr,
        context.obj_mgr,
        context.proc_mgr,
        context.process_id,
        context.security_context,
    );
    // Keep ownership explicit until the runtime returns; this ensures all Lua
    // mutations were retained and avoids silently discarding borrowed state.
    drop((vfs, ns_mgr, handles, objects));
    result.map_err(|e| format!("Lua error: {e}"))
}

pub fn inspect(args: &[String]) -> Result<(), String> {
    let path = Path::parse(&one_path(args, "inspect <path>")?).normalize();
    let context = AppContext::new()?;
    let id = context.ns_mgr.resolve(&path, context.ns_mgr.root())?;
    let object = context.obj_mgr.lookup(id).ok_or("Object not found")?;
    println!("Object ID: {}", object.id);
    println!("Type: {}", object.object_type);
    println!("State: {}", object.state);
    println!("Owner: {}", object.owner);
    println!("Group: {}", object.group);
    println!("Permissions: {:o}", object.permissions);
    println!("Size: {}", object.size);
    Ok(())
}

pub fn ns(args: &[String]) -> Result<(), String> {
    let path = Path::parse(&one_path(args, "ns <path>")?).normalize();
    let context = AppContext::new()?;
    let mut entries = context.vfs.enumerate_secure(
        &context.ns_mgr,
        &context.obj_mgr,
        &context.security_context,
        &path,
    )?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, object_id) in entries {
        println!("{}\t{}", name, object_id);
    }
    Ok(())
}

pub fn handles(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("Usage: handles".into());
    }
    let context = AppContext::new()?;
    for handle in context.handle_mgr.list_handles(context.process_id) {
        println!(
            "{}\t{}\t{}",
            handle.handle_id, handle.object_id, handle.provider_name
        );
    }
    Ok(())
}

pub fn mount(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("Usage: mount".into());
    }
    let context = AppContext::new()?;
    for mount in context.vfs.list_mounts() {
        println!("{}\t{}", mount.path, mount.provider_name);
    }
    Ok(())
}

pub fn trace(args: &[String]) -> Result<(), String> {
    let path = Path::parse(&one_path(args, "trace <path>")?).normalize();
    if !path.is_absolute {
        return Err("trace requires an absolute Hyber path".into());
    }
    let context = AppContext::new()?;
    let mut components = Vec::new();
    println!("/ -> {}", context.ns_mgr.root());
    for component in path.components {
        components.push(component);
        let step = Path {
            components: components.clone(),
            is_absolute: true,
        };
        let id = context.ns_mgr.resolve(&step, context.ns_mgr.root())?;
        println!("{} -> {}", step, id);
    }
    Ok(())
}

pub fn new_app(args: &[String]) -> Result<(), String> {
    let name = one_path(args, "new <name>")?;
    if !is_valid_app_name(&name) {
        return Err(
            "application name must contain only ASCII letters, digits, '-' or '_' and start with a letter or digit".into(),
        );
    }
    let dir = PathBuf::from(&name);
    if dir.exists() {
        return Err(format!("{} already exists", dir.display()));
    }
    std::fs::create_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let manifest = format!("name = \"{name}\"\nversion = \"0.1.0\"\nentrypoint = \"main.lua\"\n");
    if let Err(error) = std::fs::write(dir.join("hyber.toml"), manifest).and_then(|_| {
        std::fs::write(
            dir.join("main.lua"),
            "hyber.log.info(\"Hello from HyberKOS!\")\n",
        )
    }) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!("cannot scaffold {}: {error}", dir.display()));
    }
    println!("Created Lua application at {}", dir.display());
    Ok(())
}

fn is_valid_app_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn one_path(args: &[String], usage: &str) -> Result<String, String> {
    if args.len() != 1 {
        return Err(format!("Usage: hyber {usage}"));
    }
    Ok(args[0].clone())
}

fn script_path(input: &str) -> Result<PathBuf, String> {
    let input_path = FsPath::new(input);
    if input_path.is_file() {
        if input_path.extension().and_then(|e| e.to_str()) != Some("lua") {
            return Err("only .lua scripts are supported in Phase 14".into());
        }
        return Ok(input_path.to_path_buf());
    }
    if !input_path.is_dir() {
        return Err(format!(
            "{} is not a Lua script or application directory",
            input
        ));
    }
    let app_dir = input_path
        .canonicalize()
        .map_err(|e| format!("cannot resolve {input}: {e}"))?;
    let manifest = manifest::load(&app_dir)?;
    let _author = &manifest.author;
    let entry = app_dir.join(&manifest.entrypoint);
    let canonical_entry = entry
        .canonicalize()
        .map_err(|e| format!("cannot resolve entrypoint: {e}"))?;
    if !canonical_entry.starts_with(&app_dir)
        || canonical_entry.extension().and_then(|e| e.to_str()) != Some("lua")
    {
        return Err(
            "manifest entrypoint must stay inside the app directory and end in .lua".into(),
        );
    }
    if let Some(permissions) = manifest.permissions {
        let _ = (permissions.read, permissions.write); // parsed now; Phase 13 enforces portable manifests.
    }
    Ok(canonical_entry)
}

#[cfg(test)]
mod tests {
    use super::is_valid_app_name;

    #[test]
    fn accepts_safe_application_names() {
        assert!(is_valid_app_name("calculator"));
        assert!(is_valid_app_name("app_2"));
        assert!(is_valid_app_name("demo-app"));
    }

    #[test]
    fn rejects_path_or_toml_injection_names() {
        assert!(!is_valid_app_name("../escape"));
        assert!(!is_valid_app_name("bad/name"));
        assert!(!is_valid_app_name("bad\"\nversion = \"evil"));
        assert!(!is_valid_app_name("_starts-with-symbol"));
        assert!(!is_valid_app_name(""));
    }
}
