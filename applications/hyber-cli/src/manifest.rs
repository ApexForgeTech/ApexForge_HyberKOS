use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    pub author: Option<String>,
    pub permissions: Option<Permissions>,
}

#[derive(Debug, Deserialize)]
pub struct Permissions {
    pub read: Option<Vec<String>>,
    pub write: Option<Vec<String>>,
}

pub fn load(app_dir: &Path) -> Result<Manifest, String> {
    let path = app_dir.join("hyber.toml");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let manifest: Manifest =
        toml::from_str(&text).map_err(|e| format!("invalid {}: {e}", path.display()))?;
    if manifest.name.trim().is_empty() || manifest.version.trim().is_empty() {
        return Err("manifest name and version must not be empty".into());
    }
    if manifest.entrypoint.is_empty() || Path::new(&manifest.entrypoint).is_absolute() {
        return Err("manifest entrypoint must be a non-empty relative Lua path".into());
    }
    Ok(manifest)
}
