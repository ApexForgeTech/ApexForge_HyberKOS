//! Authenticated local Phase 17 package operator tool.
//!
//! Private signing material is accepted only as an exact 32-byte file, never a
//! command-line argument.  State-changing commands authenticate through the
//! Special_2 hosted session boundary before opening the HyberFS image.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hyber_auth::{hosted_login, SessionKind};
use hyber_core::{SecurityContext, SecurityManager};
use hyber_fs::{FileDevice, FsError, Volume};
use hyber_manifest::GrantPolicy;
use hyber_package::{
    build_from_staging, HyberFsPackageStore, LocalRepository, PackageManager, TrustStore,
    TrustedKey, PACKAGE_TRUST_PATH,
};
use hyber_package_format::{
    Dependency, PackageId, PackageVersion, SignedPackage, VersionRequirement,
};
use std::path::Path;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") if args.len() == 5 => build(&args[1], &args[2], &args[3], &args[4]),
        Some("verify") if args.len() == 3 => verify(&args[1], &args[2]),
        Some("repo-import") if args.len() == 6 => {
            repo_import(&args[1], &args[2], &args[3], &args[4], &args[5])
        }
        Some("init") if args.len() == 4 => state_init(&args[1], &args[2], &args[3]),
        Some("trust-add") if (args.len() == 7 || args.len() == 8) => trust_add(
            &args[1],
            &args[2],
            &args[3],
            &args[4],
            &args[5],
            &args[6],
            args.get(7).map(String::as_str),
        ),
        Some("import") if args.len() == 5 => state_import(&args[1], &args[2], &args[3], &args[4]),
        Some("resolve") if args.len() == 5 => resolve(&args[1], &args[2], &args[3], &args[4]),
        Some("install") if args.len() == 5 => {
            install(&args[1], &args[2], &args[3], &args[4], false)
        }
        Some("install-service") if args.len() == 5 => {
            install(&args[1], &args[2], &args[3], &args[4], true)
        }
        Some("update") if args.len() == 5 => update(&args[1], &args[2], &args[3], &args[4], false),
        Some("update-service") if args.len() == 5 => {
            update(&args[1], &args[2], &args[3], &args[4], true)
        }
        Some("rollback") if args.len() == 5 => rollback(&args[1], &args[2], &args[3], &args[4]),
        Some("remove") if args.len() == 5 => remove(&args[1], &args[2], &args[3], &args[4]),
        Some("list") if args.len() == 4 => list(&args[1], &args[2], &args[3]),
        Some("check") if args.len() == 4 => check(&args[1], &args[2], &args[3]),
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

fn with_state<F>(image: &str, blocks: &str, username: &str, operation: F) -> Result<(), String>
where
    F: FnOnce(
        &SecurityContext,
        &mut Volume<FileDevice>,
        &mut PackageManager,
        &mut TrustStore,
        &HyberFsPackageStore,
    ) -> Result<(), String>,
{
    let blocks = parse_blocks(blocks)?;
    let guard = hosted_login(image, blocks, username, SessionKind::Interactive)
        .map_err(|error| format!("authentication failed: {error}"))?;
    let context = guard
        .context()
        .map_err(|error| format!("session invalid: {error}"))?;
    SecurityManager::check_capability(&context, "CAP_SYS_ADMIN")
        .map_err(|_| "package administration requires CAP_SYS_ADMIN".to_string())?;
    let device = FileDevice::open(image, blocks).map_err(|error| error.to_string())?;
    let mut volume = Volume::mount(device).map_err(|error| error.to_string())?;
    let store = HyberFsPackageStore;
    let (mut manager, mut trust) = match volume.stat(PACKAGE_TRUST_PATH) {
        Ok(_) => store.load(&volume).map_err(|error| error.to_string())?,
        Err(FsError::NotFound) => (PackageManager::default(), TrustStore::default()),
        Err(error) => return Err(error.to_string()),
    };
    let result = operation(&context, &mut volume, &mut manager, &mut trust, &store);
    let logout = guard
        .logout()
        .map_err(|error| format!("logout failed: {error}"));
    result.and(logout)
}

fn parse_blocks(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|blocks| *blocks >= 8)
        .ok_or_else(|| "blocks must be an integer of at least 8".into())
}

fn state_init(image: &str, blocks: &str, username: &str) -> Result<(), String> {
    with_state(
        image,
        blocks,
        username,
        |_, volume, manager, trust, store| {
            store
                .save(volume, manager, trust)
                .map_err(|error| error.to_string())?;
            println!("initialized Phase 17 package state");
            Ok(())
        },
    )
}

fn trust_add(
    image: &str,
    blocks: &str,
    username: &str,
    key_id: &str,
    publisher: &str,
    public_key: &str,
    prefix: Option<&str>,
) -> Result<(), String> {
    let verifying_key = VerifyingKey::from_bytes(&read_key(public_key)?)
        .map_err(|_| "invalid Ed25519 public key")?;
    with_state(
        image,
        blocks,
        username,
        move |context, volume, manager, trust, store| {
            let mut next = trust.clone();
            next.add(
                context,
                TrustedKey {
                    key_id: key_id.into(),
                    publisher: publisher.into(),
                    package_prefix: prefix.map(str::to_owned),
                    state: hyber_package::KeyState::Trusted,
                    verifying_key,
                },
            )
            .map_err(|error| error.to_string())?;
            store
                .save(volume, manager, &next)
                .map_err(|error| error.to_string())?;
            *trust = next;
            println!("trusted key {key_id}");
            Ok(())
        },
    )
}

fn state_import(image: &str, blocks: &str, username: &str, artifact: &str) -> Result<(), String> {
    let artifact = std::fs::read(artifact).map_err(|error| error.to_string())?;
    with_state(
        image,
        blocks,
        username,
        move |_, volume, manager, trust, store| {
            let mut next = manager.clone();
            let record = next
                .repository
                .import(trust, &artifact)
                .map_err(|error| error.to_string())?;
            store
                .save(volume, &next, trust)
                .map_err(|error| error.to_string())?;
            *manager = next;
            println!("imported {} {}", record.key.id.0, record.key.version);
            Ok(())
        },
    )
}

fn dependency(value: &str, newest: bool) -> Result<Dependency, String> {
    let (id, version) = value
        .split_once('@')
        .ok_or_else(|| "package must be package-id@major.minor.patch".to_string())?;
    let version = PackageVersion::parse(version).map_err(|error| error.to_string())?;
    Ok(Dependency {
        package: PackageId(id.into()),
        requirement: if newest {
            VersionRequirement::AtLeast(version)
        } else {
            VersionRequirement::Exact(version)
        },
    })
}

fn resolve(image: &str, blocks: &str, username: &str, request: &str) -> Result<(), String> {
    let request = dependency(request, false)?;
    with_state(image, blocks, username, move |_, _, manager, _, _| {
        for record in manager
            .resolve(&[request])
            .map_err(|error| error.to_string())?
            .ordered
        {
            println!(
                "{} {} {}",
                record.key.id.0,
                record.key.version,
                hex(&record.digest)
            );
        }
        Ok(())
    })
}

fn service_policy(enabled: bool) -> GrantPolicy {
    let mut policy = GrantPolicy::deny_all();
    if enabled {
        policy.allow_service = true;
        policy
            .capabilities
            .insert(hyber_manifest::CapabilityName("service.background".into()));
        policy.max_resources.memory_bytes = 2 * 1024 * 1024 * 1024;
    }
    policy
}
fn install(
    image: &str,
    blocks: &str,
    username: &str,
    request: &str,
    service: bool,
) -> Result<(), String> {
    let request = dependency(request, false)?;
    with_state(
        image,
        blocks,
        username,
        move |context, volume, manager, trust, store| {
            let plan = manager
                .install_and_save(
                    volume,
                    store,
                    context,
                    trust,
                    &service_policy(service),
                    &[request],
                )
                .map_err(|error| error.to_string())?;
            println!(
                "installed {} package(s); service.background allowed: {}",
                plan.ordered.len(),
                service
            );
            Ok(())
        },
    )
}

fn update(
    image: &str,
    blocks: &str,
    username: &str,
    id: &str,
    service: bool,
) -> Result<(), String> {
    let package = PackageId(id.into());
    with_state(
        image,
        blocks,
        username,
        move |context, volume, manager, trust, store| {
            let active = manager
                .registry
                .active(&package)
                .ok_or_else(|| "package is not installed".to_string())?;
            let request = Dependency {
                package: package.clone(),
                requirement: VersionRequirement::AtLeast(active.record.key.version),
            };
            manager
                .install_and_save(
                    volume,
                    store,
                    context,
                    trust,
                    &service_policy(service),
                    &[request],
                )
                .map_err(|error| error.to_string())?;
            println!("updated {id}");
            Ok(())
        },
    )
}

fn rollback(image: &str, blocks: &str, username: &str, id: &str) -> Result<(), String> {
    let id = PackageId(id.into());
    with_state(
        image,
        blocks,
        username,
        move |context, volume, manager, trust, store| {
            manager
                .rollback_and_save(volume, store, context, trust, &id)
                .map_err(|error| error.to_string())?;
            println!("rolled back {}", id.0);
            Ok(())
        },
    )
}

fn remove(image: &str, blocks: &str, username: &str, id: &str) -> Result<(), String> {
    let id = PackageId(id.into());
    with_state(
        image,
        blocks,
        username,
        move |context, volume, manager, trust, store| {
            manager
                .remove_and_save(volume, store, context, trust, &id)
                .map_err(|error| error.to_string())?;
            println!("removed {}", id.0);
            Ok(())
        },
    )
}

fn list(image: &str, blocks: &str, username: &str) -> Result<(), String> {
    with_state(image, blocks, username, |_, _, manager, _, _| {
        for (id, package) in manager.registry.installed() {
            println!(
                "{} {} app={} digest={}",
                id.0,
                package.record.key.version,
                package.record.application_id,
                hex(&package.record.digest)
            );
        }
        Ok(())
    })
}

fn check(image: &str, blocks: &str, username: &str) -> Result<(), String> {
    with_state(
        image,
        blocks,
        username,
        |_, volume, _manager, _trust, _store| {
            volume.check().map_err(|error| error.to_string())?;
            println!("package state is valid");
            Ok(())
        },
    )
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_key(path: &str) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|error| format!("cannot read key file: {error}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| "key file must contain exactly 32 raw bytes".into())
}

fn help() {
    println!("Phase 17 authenticated local package operator");
    println!("  hyber-pkg build <staging-dir> <artifact.hybp> <key-id> <private-key-file>");
    println!("  hyber-pkg verify <artifact.hybp> <public-key-file>");
    println!(
        "  hyber-pkg repo-import <repo-dir> <artifact.hybp> <key-id> <publisher> <public-key-file>"
    );
    println!("  hyber-pkg init <image> <blocks> <admin-user>");
    println!("  hyber-pkg trust-add <image> <blocks> <admin-user> <key-id> <publisher> <public-key-file> [package-prefix]");
    println!("  hyber-pkg import <image> <blocks> <admin-user> <artifact.hybp>");
    println!("  hyber-pkg resolve|install <image> <blocks> <admin-user> <package-id@version>");
    println!("  hyber-pkg install-service <image> <blocks> <admin-user> <package-id@version>");
    println!("  hyber-pkg update-service <image> <blocks> <admin-user> <package-id>");
    println!("  hyber-pkg update|rollback|remove <image> <blocks> <admin-user> <package-id>");
    println!("  hyber-pkg list|check <image> <blocks> <admin-user>");
    println!("State-changing commands prompt through the Special_2 authentication boundary.");
    println!("The initial operator policy is explicit deny-all for requested capabilities;");
    println!("install-service/update-service explicitly approve only service.background (2 GiB memory ceiling), never network/device capabilities.");
    println!(
        "a package requesting capabilities is rejected until a reviewed grant policy is supplied."
    );
    println!("Private/public key files contain exactly 32 raw bytes.");
}
