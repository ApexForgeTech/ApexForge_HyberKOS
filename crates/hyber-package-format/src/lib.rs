//! Deterministic, signed Phase 17 `.hybp` package artifacts.
//!
//! This crate deliberately has no filesystem, repository, process, or VFS
//! dependency. It validates untrusted bytes and defines the exact bytes signed
//! by a publisher. The trusted package manager decides which public keys and
//! grants are acceptable.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hyber_manifest::Manifest;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const FORMAT_VERSION: u32 = 1;
pub const MAGIC: [u8; 8] = *b"HYBPKG1\0";
pub const MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_FILES: usize = 4_096;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_PATH_BYTES: usize = 512;
pub const MAX_DEPENDENCIES: usize = 256;
pub const MAX_KEY_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PackageVersion {
    pub fn parse(value: &str) -> Result<Self, PackageFormatError> {
        let mut parts = value.split('.');
        let parse = |part: Option<&str>| -> Result<u64, PackageFormatError> {
            let part = part.ok_or(PackageFormatError::Invalid("invalid package version"))?;
            if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
                return Err(PackageFormatError::Invalid("invalid package version"));
            }
            part.parse()
                .map_err(|_| PackageFormatError::Invalid("invalid package version"))
        };
        let version = Self {
            major: parse(parts.next())?,
            minor: parse(parts.next())?,
            patch: parse(parts.next())?,
        };
        if parts.next().is_some() {
            return Err(PackageFormatError::Invalid("invalid package version"));
        }
        Ok(version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageKey {
    pub id: PackageId,
    pub version: PackageVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRequirement {
    Exact(PackageVersion),
    AtLeast(PackageVersion),
}

impl VersionRequirement {
    pub fn matches(&self, version: PackageVersion) -> bool {
        match self {
            Self::Exact(expected) => version == *expected,
            Self::AtLeast(minimum) => version >= *minimum,
        }
    }

    pub fn parse(value: &str) -> Result<Self, PackageFormatError> {
        if let Some(value) = value.strip_prefix(">=") {
            return Ok(Self::AtLeast(PackageVersion::parse(value)?));
        }
        Ok(Self::Exact(PackageVersion::parse(value)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub package: PackageId,
    pub requirement: VersionRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMetadata {
    pub key: PackageKey,
    pub application_id: String,
    pub publisher: String,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInput {
    pub metadata: PackageMetadata,
    /// Exact `hyber.toml` bytes whose Special_6 semantics are validated.
    pub application_manifest: String,
    pub files: Vec<PackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPackage {
    pub input: PackageInput,
    pub key_id: String,
    pub payload_digest: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageFormatError {
    Invalid(&'static str),
    InvalidOwned(String),
    UnsupportedVersion,
    DigestMismatch,
    BadSignature,
    Truncated,
    TrailingBytes,
}

impl fmt::Display for PackageFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::InvalidOwned(reason) => f.write_str(reason),
            Self::UnsupportedVersion => f.write_str("unsupported package format version"),
            Self::DigestMismatch => f.write_str("package payload digest mismatch"),
            Self::BadSignature => f.write_str("package signature verification failed"),
            Self::Truncated => f.write_str("truncated package artifact"),
            Self::TrailingBytes => f.write_str("unexpected trailing package bytes"),
        }
    }
}
impl std::error::Error for PackageFormatError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageToml {
    format_version: u32,
    package_id: String,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
}

impl PackageMetadata {
    /// Parse the package-side manifest while preserving the application manifest
    /// as the authoritative source of runtime/capability semantics.
    pub fn from_toml(
        package_toml: &str,
        application_manifest: &str,
    ) -> Result<Self, PackageFormatError> {
        if package_toml.len() > MAX_MANIFEST_BYTES {
            return Err(PackageFormatError::Invalid(
                "package manifest exceeds limit",
            ));
        }
        let package: PackageToml = toml::from_str(package_toml)
            .map_err(|_| PackageFormatError::Invalid("invalid package manifest TOML"))?;
        if package.format_version != FORMAT_VERSION {
            return Err(PackageFormatError::UnsupportedVersion);
        }
        let application = parse_application_manifest(application_manifest)?;
        let dependencies = package
            .dependencies
            .into_iter()
            .map(|(package, requirement)| {
                Ok(Dependency {
                    package: PackageId(package),
                    requirement: VersionRequirement::parse(&requirement)?,
                })
            })
            .collect::<Result<Vec<_>, PackageFormatError>>()?;
        let metadata = Self {
            key: PackageKey {
                id: PackageId(package.package_id),
                version: PackageVersion::parse(&application.version)?,
            },
            application_id: application.app_id.0.clone(),
            publisher: application.publisher.clone(),
            dependencies,
        };
        metadata.validate(&application)?;
        Ok(metadata)
    }

    pub fn validate(&self, application: &Manifest) -> Result<(), PackageFormatError> {
        validate_id(&self.key.id.0, "invalid package id")?;
        validate_id(&self.application_id, "invalid application id")?;
        validate_id(&self.publisher, "invalid publisher")?;
        if self.application_id != application.app_id.0
            || self.publisher != application.publisher
            || self.key.version != PackageVersion::parse(&application.version)?
        {
            return Err(PackageFormatError::Invalid(
                "package metadata does not match application manifest",
            ));
        }
        if self.dependencies.len() > MAX_DEPENDENCIES {
            return Err(PackageFormatError::Invalid("too many dependencies"));
        }
        let mut seen = BTreeSet::new();
        for dependency in &self.dependencies {
            validate_id(&dependency.package.0, "invalid dependency package id")?;
            if dependency.package == self.key.id || !seen.insert(dependency.package.clone()) {
                return Err(PackageFormatError::Invalid(
                    "self or duplicate dependency is not allowed",
                ));
            }
        }
        Ok(())
    }
}

impl PackageInput {
    pub fn validate(&self) -> Result<(), PackageFormatError> {
        let application = parse_application_manifest(&self.application_manifest)?;
        self.metadata.validate(&application)?;
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            return Err(PackageFormatError::Invalid("invalid package file count"));
        }
        let mut paths = BTreeSet::new();
        let mut total = 0usize;
        let mut packaged_manifest = None;
        for file in &self.files {
            validate_relative_path(&file.path)?;
            if file.path == "package.toml" {
                return Err(PackageFormatError::Invalid(
                    "package control manifest is not installable content",
                ));
            }
            if file.path == "hyber.toml" {
                packaged_manifest = Some(&file.bytes);
            }
            if file.bytes.len() > MAX_FILE_BYTES || !paths.insert(file.path.clone()) {
                return Err(PackageFormatError::Invalid(
                    "invalid, duplicate, or oversized package file",
                ));
            }
            total = total
                .checked_add(file.bytes.len())
                .ok_or(PackageFormatError::Invalid("package size overflow"))?;
            if total > MAX_PACKAGE_BYTES {
                return Err(PackageFormatError::Invalid("package exceeds size limit"));
            }
        }
        if !paths.contains(&application.entrypoint) {
            return Err(PackageFormatError::Invalid("package entrypoint is missing"));
        }
        if packaged_manifest
            .map(Vec::as_slice)
            .is_none_or(|contents| contents != self.application_manifest.as_bytes())
        {
            return Err(PackageFormatError::Invalid(
                "packaged hyber.toml does not match application manifest",
            ));
        }
        Ok(())
    }

    /// Canonical body used for the payload digest and signature. Files and
    /// dependencies are sorted, so callers cannot obtain different artifacts
    /// by changing host-directory enumeration order.
    pub fn canonical_body(&self) -> Result<Vec<u8>, PackageFormatError> {
        self.validate()?;
        let mut out = Vec::new();
        put_string(&mut out, &self.metadata.key.id.0)?;
        put_version(&mut out, self.metadata.key.version);
        put_string(&mut out, &self.metadata.application_id)?;
        put_string(&mut out, &self.metadata.publisher)?;
        let mut dependencies = self.metadata.dependencies.clone();
        dependencies.sort_by(|left, right| left.package.cmp(&right.package));
        put_u32(
            &mut out,
            u32::try_from(dependencies.len())
                .map_err(|_| PackageFormatError::Invalid("too many dependencies"))?,
        );
        for dependency in dependencies {
            put_string(&mut out, &dependency.package.0)?;
            match dependency.requirement {
                VersionRequirement::Exact(version) => {
                    out.push(0);
                    put_version(&mut out, version);
                }
                VersionRequirement::AtLeast(version) => {
                    out.push(1);
                    put_version(&mut out, version);
                }
            }
        }
        put_bytes(
            &mut out,
            self.application_manifest.as_bytes(),
            MAX_MANIFEST_BYTES,
        )?;
        let mut files = self.files.clone();
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        put_u32(
            &mut out,
            u32::try_from(files.len())
                .map_err(|_| PackageFormatError::Invalid("too many package files"))?,
        );
        for file in files {
            put_string(&mut out, &file.path)?;
            put_bytes(&mut out, &file.bytes, MAX_FILE_BYTES)?;
        }
        Ok(out)
    }
}

impl SignedPackage {
    pub fn sign(
        input: PackageInput,
        key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Result<Self, PackageFormatError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let body = input.canonical_body()?;
        let payload_digest = Sha256::digest(&body).into();
        let signed = signed_bytes(&key_id, payload_digest, &body)?;
        let signature = signing_key.sign(&signed).to_bytes();
        Ok(Self {
            input,
            key_id,
            payload_digest,
            signature,
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), PackageFormatError> {
        self.input.validate()?;
        validate_key_id(&self.key_id)?;
        let body = self.input.canonical_body()?;
        if Sha256::digest(&body).as_slice() != self.payload_digest {
            return Err(PackageFormatError::DigestMismatch);
        }
        let signed = signed_bytes(&self.key_id, self.payload_digest, &body)?;
        key.verify(&signed, &Signature::from_bytes(&self.signature))
            .map_err(|_| PackageFormatError::BadSignature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PackageFormatError> {
        let body = self.input.canonical_body()?;
        if Sha256::digest(&body).as_slice() != self.payload_digest {
            return Err(PackageFormatError::DigestMismatch);
        }
        let mut out = signed_bytes(&self.key_id, self.payload_digest, &body)?;
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_PACKAGE_BYTES {
            return Err(PackageFormatError::Invalid("package exceeds size limit"));
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PackageFormatError> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(PackageFormatError::Invalid("package exceeds size limit"));
        }
        let mut reader = Reader::new(bytes);
        if reader.take_exact(8)? != MAGIC {
            return Err(PackageFormatError::Invalid("invalid package magic"));
        }
        if reader.u32()? != FORMAT_VERSION {
            return Err(PackageFormatError::UnsupportedVersion);
        }
        let body_len = reader.usize_from_u64()?;
        let mut payload_digest = [0; 32];
        payload_digest.copy_from_slice(reader.take_exact(32)?);
        let key_id = reader.string(MAX_KEY_ID_BYTES)?;
        validate_key_id(&key_id)?;
        let body = reader.take_exact(body_len)?;
        let mut signature = [0; 64];
        signature.copy_from_slice(reader.take_exact(64)?);
        if !reader.finished() {
            return Err(PackageFormatError::TrailingBytes);
        }
        if Sha256::digest(body).as_slice() != payload_digest {
            return Err(PackageFormatError::DigestMismatch);
        }
        let input = decode_body(body)?;
        Ok(Self {
            input,
            key_id,
            payload_digest,
            signature,
        })
    }
}

pub fn artifact_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn signed_bytes(
    key_id: &str,
    payload_digest: [u8; 32],
    body: &[u8],
) -> Result<Vec<u8>, PackageFormatError> {
    validate_key_id(key_id)?;
    let mut out = Vec::with_capacity(8 + 4 + 8 + 32 + 2 + key_id.len() + body.len());
    out.extend_from_slice(&MAGIC);
    put_u32(&mut out, FORMAT_VERSION);
    put_u64(
        &mut out,
        u64::try_from(body.len())
            .map_err(|_| PackageFormatError::Invalid("package body too large"))?,
    );
    out.extend_from_slice(&payload_digest);
    put_string(&mut out, key_id)?;
    out.extend_from_slice(body);
    Ok(out)
}

fn decode_body(bytes: &[u8]) -> Result<PackageInput, PackageFormatError> {
    let mut reader = Reader::new(bytes);
    let package_id = PackageId(reader.string(128)?);
    let version = reader.version()?;
    let application_id = reader.string(128)?;
    let publisher = reader.string(128)?;
    let dependency_count = reader.count(MAX_DEPENDENCIES)?;
    let mut dependencies = Vec::with_capacity(dependency_count);
    for _ in 0..dependency_count {
        let package = PackageId(reader.string(128)?);
        let requirement = match reader.byte()? {
            0 => VersionRequirement::Exact(reader.version()?),
            1 => VersionRequirement::AtLeast(reader.version()?),
            _ => {
                return Err(PackageFormatError::Invalid(
                    "invalid dependency requirement",
                ))
            }
        };
        dependencies.push(Dependency {
            package,
            requirement,
        });
    }
    let application_manifest = String::from_utf8(reader.bytes(MAX_MANIFEST_BYTES)?)
        .map_err(|_| PackageFormatError::Invalid("application manifest is not UTF-8"))?;
    let file_count = reader.count(MAX_FILES)?;
    let mut files = Vec::with_capacity(file_count);
    for _ in 0..file_count {
        files.push(PackageFile {
            path: reader.string(MAX_PATH_BYTES)?,
            bytes: reader.bytes(MAX_FILE_BYTES)?,
        });
    }
    if !reader.finished() {
        return Err(PackageFormatError::TrailingBytes);
    }
    let input = PackageInput {
        metadata: PackageMetadata {
            key: PackageKey {
                id: package_id,
                version,
            },
            application_id,
            publisher,
            dependencies,
        },
        application_manifest,
        files,
    };
    input.validate()?;
    Ok(input)
}

fn parse_application_manifest(value: &str) -> Result<Manifest, PackageFormatError> {
    if value.len() > MAX_MANIFEST_BYTES {
        return Err(PackageFormatError::Invalid(
            "application manifest exceeds limit",
        ));
    }
    Manifest::parse_toml(value).map_err(|error| {
        PackageFormatError::InvalidOwned(format!("invalid application manifest: {error}"))
    })
}

fn validate_id(value: &str, reason: &'static str) -> Result<(), PackageFormatError> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(PackageFormatError::Invalid(reason))
    } else {
        Ok(())
    }
}

fn validate_key_id(value: &str) -> Result<(), PackageFormatError> {
    if value.is_empty()
        || value.len() > MAX_KEY_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        Err(PackageFormatError::Invalid("invalid signing key id"))
    } else {
        Ok(())
    }
}

fn validate_relative_path(value: &str) -> Result<(), PackageFormatError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.starts_with('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        Err(PackageFormatError::Invalid("invalid package file path"))
    } else {
        Ok(())
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_version(out: &mut Vec<u8>, value: PackageVersion) {
    put_u64(out, value.major);
    put_u64(out, value.minor);
    put_u64(out, value.patch);
}
fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), PackageFormatError> {
    put_bytes(out, value.as_bytes(), MAX_MANIFEST_BYTES)
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8], limit: usize) -> Result<(), PackageFormatError> {
    if value.len() > limit {
        return Err(PackageFormatError::Invalid("encoded field exceeds limit"));
    }
    put_u32(
        out,
        u32::try_from(value.len())
            .map_err(|_| PackageFormatError::Invalid("encoded field too large"))?,
    );
    out.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take_exact(&mut self, count: usize) -> Result<&'a [u8], PackageFormatError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PackageFormatError::Truncated)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(PackageFormatError::Truncated)?;
        self.offset = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, PackageFormatError> {
        Ok(self.take_exact(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, PackageFormatError> {
        Ok(u32::from_le_bytes(
            self.take_exact(4)?.try_into().expect("fixed length"),
        ))
    }
    fn u64(&mut self) -> Result<u64, PackageFormatError> {
        Ok(u64::from_le_bytes(
            self.take_exact(8)?.try_into().expect("fixed length"),
        ))
    }
    fn usize_from_u64(&mut self) -> Result<usize, PackageFormatError> {
        usize::try_from(self.u64()?).map_err(|_| PackageFormatError::Invalid("length overflow"))
    }
    fn count(&mut self, maximum: usize) -> Result<usize, PackageFormatError> {
        let count = usize::try_from(self.u32()?)
            .map_err(|_| PackageFormatError::Invalid("count overflow"))?;
        if count > maximum {
            return Err(PackageFormatError::Invalid("count exceeds limit"));
        }
        Ok(count)
    }
    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, PackageFormatError> {
        let count = self.count(maximum)?;
        Ok(self.take_exact(count)?.to_vec())
    }
    fn string(&mut self, maximum: usize) -> Result<String, PackageFormatError> {
        String::from_utf8(self.bytes(maximum)?)
            .map_err(|_| PackageFormatError::Invalid("string field is not UTF-8"))
    }
    fn version(&mut self) -> Result<PackageVersion, PackageFormatError> {
        Ok(PackageVersion {
            major: self.u64()?,
            minor: self.u64()?,
            patch: self.u64()?,
        })
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application_manifest() -> String {
        "format_version = 1\napp_id = \"demo\"\nversion = \"1.0.0\"\npublisher = \"example\"\ndisplay_name = \"Demo\"\nentrypoint = \"main.lua\"\nruntime = \"lua\"\nexecution = \"background\"\n\n[storage]\ndata = \"read-write\"\n\n[resources]\nmemory_bytes = 1024\ncpu_shares = 1\nhandles = 1\nstorage_bytes = 1024\n".into()
    }
    fn input() -> PackageInput {
        PackageInput {
            metadata: PackageMetadata {
                key: PackageKey {
                    id: PackageId("demo".into()),
                    version: PackageVersion::parse("1.0.0").unwrap(),
                },
                application_id: "demo".into(),
                publisher: "example".into(),
                dependencies: vec![],
            },
            application_manifest: application_manifest(),
            files: vec![
                PackageFile {
                    path: "hyber.toml".into(),
                    bytes: application_manifest().into_bytes(),
                },
                PackageFile {
                    path: "main.lua".into(),
                    bytes: b"return true\n".to_vec(),
                },
            ],
        }
    }
    #[test]
    fn deterministic_signed_round_trip_and_signature_verification() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let first = SignedPackage::sign(input(), "example.dev", &key)
            .unwrap()
            .encode()
            .unwrap();
        let second = SignedPackage::sign(input(), "example.dev", &key)
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(first, second);
        let decoded = SignedPackage::decode(&first).unwrap();
        decoded.verify(&key.verifying_key()).unwrap();
        assert_eq!(decoded.input.metadata.key.id.0, "demo");
    }
    #[test]
    fn rejects_tampering_paths_duplicates_and_manifest_mismatch() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let mut bytes = SignedPackage::sign(input(), "example.dev", &key)
            .unwrap()
            .encode()
            .unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(SignedPackage::decode(&bytes)
            .and_then(|package| package.verify(&key.verifying_key()))
            .is_err());
        let mut invalid = input();
        invalid.files.push(PackageFile {
            path: "main.lua".into(),
            bytes: vec![],
        });
        assert!(invalid.validate().is_err());
        let mut invalid = input();
        invalid.files[0].path = "../main.lua".into();
        assert!(invalid.validate().is_err());
    }
    #[test]
    fn package_toml_reuses_special_six_manifest_meaning() {
        let metadata = PackageMetadata::from_toml(
            "format_version = 1\npackage_id = \"demo\"\n[dependencies]\nbase = \">=1.0.0\"\n",
            &application_manifest(),
        )
        .unwrap();
        assert!(matches!(
            metadata.dependencies[0].requirement,
            VersionRequirement::AtLeast(_)
        ));
    }
}
