use crate::context::AppContext;
use crate::manifest;
use hyber_core::Path;
use std::path::{Path as FsPath, PathBuf};

pub fn run(args: &[String]) -> Result<(), String> {
    let (args, session) = if args.len() == 5 && args[0] == "--auth" {
        let blocks = args[2].parse().map_err(|_| "invalid block count")?;
        let session = hyber_auth::hosted_login(
            &args[1],
            blocks,
            &args[3],
            hyber_auth::SessionKind::NonInteractive,
        )
        .map_err(|e| e.to_string())?;
        (&args[4..], Some(session))
    } else {
        (args, None)
    };
    let input = one_path(args, "run [--auth <image> <blocks> <username>] <path>")?;
    let (script_path, manifest) = script_path(&input)?;
    let script = std::fs::read_to_string(&script_path)
        .map_err(|e| format!("cannot read {}: {e}", script_path.display()))?;
    let grant = manifest
        .map(|manifest| hyber_manifest::GrantPolicy::deny_all().approve(manifest))
        .transpose()
        .map_err(|e| e.to_string())?;
    let context = match (session, grant) {
        (Some(session), Some(grant)) => AppContext::authenticated_for_grant(session, grant)?,
        (None, Some(grant)) => AppContext::developer_for_grant(grant)?,
        (Some(session), None) => AppContext::authenticated_for_app(session, "script")?,
        (None, None) => AppContext::new_for_app("script")?,
    };
    let guard = context.session.clone();
    let sandbox = context.sandbox.clone();
    let (vfs, ns_mgr, handles, objects, result) = if let Some(sandbox) = sandbox {
        hyber_lua::run_lua_script_with_application_sandbox(
            &script,
            context.vfs,
            context.ns_mgr,
            context.handle_mgr,
            context.obj_mgr,
            context.proc_mgr,
            context.process_id,
            context.security_context,
            context.session,
            context.app_layout,
            sandbox,
        )
    } else {
        hyber_lua::run_lua_script_with_session_and_layout(
            &script,
            context.vfs,
            context.ns_mgr,
            context.handle_mgr,
            context.obj_mgr,
            context.proc_mgr,
            context.process_id,
            context.security_context,
            context.session,
            Some(context.app_layout),
        )
    };
    // Keep ownership explicit until the runtime returns; this ensures all Lua
    // mutations were retained and avoids silently discarding borrowed state.
    drop((vfs, ns_mgr, handles, objects));
    if let Some(session) = guard {
        let _ = session.logout();
    }
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
    let manifest = format!("format_version = 1\napp_id = \"{name}\"\nversion = \"0.1.0\"\npublisher = \"local\"\ndisplay_name = \"{name}\"\nentrypoint = \"main.lua\"\nruntime = \"lua\"\nexecution = \"background\"\n\n[storage]\nconfig = \"read-write\"\ndata = \"read-write\"\nstate = \"read-write\"\ncache = \"read-write\"\ntemporary = \"read-write\"\nruntime = \"read-write\"\n\n[resources]\nmemory_bytes = 67108864\ncpu_shares = 100\nhandles = 64\nstorage_bytes = 67108864\n");
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

fn script_path(input: &str) -> Result<(PathBuf, Option<manifest::Manifest>), String> {
    let input_path = FsPath::new(input);
    if input_path.is_file() {
        if input_path.extension().and_then(|e| e.to_str()) != Some("lua") {
            return Err("only .lua scripts are supported in Phase 14".into());
        }
        return Ok((input_path.to_path_buf(), None));
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
    if manifest.runtime != hyber_manifest::Runtime::Lua {
        return Err("this launcher can run only Lua application manifests".into());
    }
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
    Ok((canonical_entry, Some(manifest)))
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
