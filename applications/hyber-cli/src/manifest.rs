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
    if !is_valid_manifest_name(&manifest.name) {
        return Err("manifest name must contain only ASCII letters, digits, '-' or '_' and start with a letter or digit".into());
    }
    if manifest.version.trim().is_empty() {
        return Err("manifest version must not be empty".into());
    }
    if manifest.entrypoint.is_empty() || Path::new(&manifest.entrypoint).is_absolute() {
        return Err("manifest entrypoint must be a non-empty relative Lua path".into());
    }
    Ok(manifest)
}

fn is_valid_manifest_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::is_valid_manifest_name;

    #[test]
    fn accepts_safe_names() {
        assert!(is_valid_manifest_name("editor"));
        assert!(is_valid_manifest_name("editor-2"));
    }

    #[test]
    fn rejects_path_and_injection_names() {
        assert!(!is_valid_manifest_name("../editor"));
        assert!(!is_valid_manifest_name("editor/name"));
        assert!(!is_valid_manifest_name("editor\"\nversion = \"evil"));
        assert!(!is_valid_manifest_name(""));
    }
}
