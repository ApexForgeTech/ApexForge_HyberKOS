//! Trusted administrative diagnostics, not ambient application authority.
use hyber_core::{SecurityContext, SecurityManager};
use hyber_manifest::*;
use hyber_network::HostName;
use std::collections::BTreeSet;

pub fn diagnostic_grant(context: &SecurityContext, host: &str) -> Result<ApplicationGrant, String> {
    SecurityManager::check_capability(context, "CAP_SYS_ADMIN")
        .map_err(|_| "network diagnostics require administrative authority".to_string())?;
    let host = HostName::parse(host).map_err(|e| e.to_string())?;
    let capabilities = BTreeSet::from([CapabilityName("network.outbound".into())]);
    let manifest = Manifest {
        format_version: 1,
        app_id: ApplicationId("hyber.network-diagnostics".into()),
        version: "1.0.0".into(),
        publisher: "hyber".into(),
        display_name: "Network diagnostics".into(),
        entrypoint: "main.lua".into(),
        runtime: Runtime::Lua,
        requested_capabilities: capabilities.clone(),
        storage: StorageScopes::default(),
        execution: ExecutionMode::Background,
        network: NetworkPolicy {
            outbound: true,
            inbound: false,
            domains: BTreeSet::from([host.as_str().into()]),
        },
        resources: ResourceQuotas {
            memory_bytes: 65536,
            cpu_shares: 1,
            handles: 4096,
            storage_bytes: 1,
        },
    };
    GrantPolicy {
        capabilities,
        allow_gui: false,
        allow_background: true,
        allow_service: false,
        max_resources: manifest.resources,
    }
    .approve(manifest)
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostics_require_authority_and_valid_names() {
        let mut user = SecurityContext::root();
        user.user_id = hyber_core::UserId(10);
        user.capabilities.clear();
        assert!(diagnostic_grant(&user, "localhost").is_err());
        assert!(diagnostic_grant(&SecurityContext::root(), "127.0.0.1").is_err());
        let grant = diagnostic_grant(&SecurityContext::root(), "LOCALHOST").unwrap();
        assert!(grant.capability_granted("network.outbound"));
        assert_eq!(
            grant.manifest.network.domains,
            BTreeSet::from(["localhost".into()])
        );
    }
}
