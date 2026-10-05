//! Hosted manifest loader. Policy approval remains in the trusted launcher.
pub use hyber_manifest::Manifest;
use std::path::Path;

pub fn load(app_dir: &Path) -> Result<Manifest, String> {
    let path = app_dir.join("hyber.toml");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Manifest::parse_toml(&text).map_err(|e| format!("invalid {}: {e}", path.display()))
}
