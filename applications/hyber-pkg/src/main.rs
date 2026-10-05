//! Narrow local Phase 17 artifact tool.
//!
//! Private signing material is accepted only as an exact 32-byte file, never a
//! command-line argument. Installation/activation commands deliberately wait
//! for a Special_2 authenticated registry adapter.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hyber_core::SecurityContext;
use hyber_package::{build_from_staging, LocalRepository, TrustStore, TrustedKey};
use hyber_package_format::SignedPackage;
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") if args.len() == 5 => build(&args[1], &args[2], &args[3], &args[4]),
        Some("verify") if args.len() == 3 => verify(&args[1], &args[2]),
        Some("repo-import") if args.len() == 6 => {
            repo_import(&args[1], &args[2], &args[3], &args[4], &args[5])
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            help();
            Ok(())
        }
        _ => Err("invalid command; run hyber-pkg help".into()),
    };
    if let Err(error) = result {
        eprintln!("hyber-pkg: {error}");
        std::process::exit(1);
    }
}

fn build(staging: &str, output: &str, key_id: &str, private_key: &str) -> Result<(), String> {
    let key = SigningKey::from_bytes(&read_key(private_key)?);
    let package =
        build_from_staging(Path::new(staging), key_id, &key).map_err(|error| error.to_string())?;
    hyber_package::write_artifact(&package, Path::new(output), false)
        .map_err(|error| error.to_string())?;
    println!("built {}", output);
    Ok(())
}

fn verify(artifact: &str, public_key: &str) -> Result<(), String> {
    let package =
        SignedPackage::decode(&std::fs::read(artifact).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let key = VerifyingKey::from_bytes(&read_key(public_key)?)
        .map_err(|_| "invalid Ed25519 public key")?;
    package.verify(&key).map_err(|error| error.to_string())?;
    println!(
        "verified {} {}",
        package.input.metadata.key.id.0, package.input.metadata.key.version
    );
    Ok(())
}

fn repo_import(
    root: &str,
    artifact: &str,
    key_id: &str,
    publisher: &str,
    public_key: &str,
) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(&read_key(public_key)?)
        .map_err(|_| "invalid Ed25519 public key")?;
    let mut trust = TrustStore::default();
    trust
        .add(
            &SecurityContext::root(),
            TrustedKey {
                key_id: key_id.into(),
                publisher: publisher.into(),
                package_prefix: None,
                state: hyber_package::KeyState::Trusted,
                verifying_key: key,
            },
        )
        .map_err(|error| error.to_string())?;
    let local = LocalRepository::open(root).map_err(|error| error.to_string())?;
    let mut repository = local.load(&trust).map_err(|error| error.to_string())?;
    let record = local
        .import(
            &mut repository,
            &trust,
            &std::fs::read(artifact).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    println!("imported {} {}", record.key.id.0, record.key.version);
    Ok(())
}

fn read_key(path: &str) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|error| format!("cannot read key file: {error}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| "key file must contain exactly 32 raw bytes".into())
}

fn help() {
    println!("Phase 17 local package artifact tool");
    println!("  hyber-pkg build <staging-dir> <artifact.hybp> <key-id> <private-key-file>");
    println!("  hyber-pkg verify <artifact.hybp> <public-key-file>");
    println!(
        "  hyber-pkg repo-import <repo-dir> <artifact.hybp> <key-id> <publisher> <public-key-file>"
    );
    println!("Private/public key files contain exactly 32 raw bytes.");
}
