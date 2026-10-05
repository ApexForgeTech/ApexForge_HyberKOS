//! Special_8 integration gate and migration decision validator.
//!
//! This crate records the boundary that later package/install work must honor.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AffectedLayer {
    Storage,
    Identity,
    Session,
    Shell,
    Manifest,
    Capability,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationDecision {
    pub id: String,
    pub from_version: u32,
    pub to_version: u32,
    pub affected_layers: BTreeSet<AffectedLayer>,
    pub incompatible: bool,
    pub migration_steps: Vec<String>,
    pub rollback_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    InvalidDecision(&'static str),
    MissingEvidence(&'static str),
}
impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDecision(reason) => write!(f, "invalid migration decision: {reason}"),
            Self::MissingEvidence(reason) => {
                write!(f, "integration gate evidence missing: {reason}")
            }
        }
    }
}
impl std::error::Error for GateError {}

impl MigrationDecision {
    pub fn validate(&self) -> Result<(), GateError> {
        if self.id.is_empty()
            || self.id.len() > 96
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(GateError::InvalidDecision("invalid decision id"));
        }
        if self.to_version < self.from_version || self.affected_layers.is_empty() {
            return Err(GateError::InvalidDecision(
                "invalid version or affected layers",
            ));
        }
        if self.incompatible
            && (self.to_version == self.from_version
                || self.migration_steps.is_empty()
                || self.rollback_steps.is_empty())
        {
            return Err(GateError::InvalidDecision(
                "incompatible changes require migration and rollback steps",
            ));
        }
        if self
            .migration_steps
            .iter()
            .chain(&self.rollback_steps)
            .any(|step| step.is_empty() || step.len() > 1024)
        {
            return Err(GateError::InvalidDecision("invalid migration step"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GateEvidence {
    pub account_session_layout: bool,
    pub shell_profile_history: bool,
    pub application_isolation: bool,
    pub storage_remount: bool,
    pub service_contract: bool,
    pub neutral_input: bool,
}
impl GateEvidence {
    pub fn validate(self) -> Result<(), GateError> {
        for (present, label) in [
            (self.account_session_layout, "account/session/layout"),
            (self.shell_profile_history, "shell profile/history"),
            (self.application_isolation, "application isolation"),
            (self.storage_remount, "storage remount"),
            (self.service_contract, "service contract"),
            (self.neutral_input, "neutral input"),
        ] {
            if !present {
                return Err(GateError::MissingEvidence(label));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyber_auth::{AuthService, SessionKind, SystemClock};
    use hyber_fs::{MemDevice, Volume};
    use hyber_identity::AccountState;
    use hyber_shell::{
        input::{Aliases, Controller, Event, Outcome},
        profiles::Profiles,
    };
    use std::sync::Arc;

    #[test]
    fn migration_decisions_and_evidence_fail_closed() {
        let decision = MigrationDecision {
            id: "hyberfs-v1-to-v2".into(),
            from_version: 1,
            to_version: 2,
            affected_layers: BTreeSet::from([AffectedLayer::Storage, AffectedLayer::Identity]),
            incompatible: true,
            migration_steps: vec!["write a v2 snapshot".into()],
            rollback_steps: vec!["retain v1 snapshot until verification".into()],
        };
        assert!(decision.validate().is_ok());
        assert!(MigrationDecision {
            rollback_steps: vec![],
            ..decision
        }
        .validate()
        .is_err());
        assert!(GateEvidence {
            account_session_layout: true,
            shell_profile_history: true,
            application_isolation: true,
            storage_remount: true,
            service_contract: true,
            neutral_input: true
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn auth_and_application_data_survive_hyberfs_remount() {
        let clock = Arc::new(SystemClock);
        let mut volume = Volume::format(MemDevice::new(64).unwrap()).unwrap();
        let password = b"gate root password";
        let mut auth = AuthService::provision(password, clock.clone()).unwrap();
        let admin = auth
            .login("root", password, SessionKind::Interactive, 600)
            .unwrap();
        let group = auth
            .edit_accounts(&admin, |accounts| accounts.create_group("users"))
            .unwrap();
        let alice = auth
            .edit_accounts(&admin, |accounts| {
                accounts.create_user("alice", group, AccountState::Active)
            })
            .unwrap();
        auth.set_password(&admin, alice, b"gate alice password")
            .unwrap();
        auth.save(&mut volume, "/auth.store").unwrap();
        volume.create_dir("/data", 0o700).unwrap();
        volume.create_file("/data/app-state", 0o600).unwrap();
        volume
            .write_file("/data/app-state", 0, b"persistent")
            .unwrap();
        let device = volume.unmount().unwrap();
        let remounted = Volume::mount(device).unwrap();
        let mut loaded = AuthService::load(&remounted, "/auth.store", clock).unwrap();
        assert!(loaded
            .login(
                "alice",
                b"gate alice password",
                SessionKind::NonInteractive,
                600
            )
            .is_ok());
        let mut bytes = [0; 10];
        assert_eq!(
            remounted
                .read_file("/data/app-state", 0, &mut bytes)
                .unwrap(),
            10
        );
        assert_eq!(&bytes, b"persistent");
    }

    #[test]
    fn profile_history_and_alias_use_one_controller() {
        let mut profiles = Profiles::default();
        profiles.load("gate-profile", "return {history=true, aliases={ll='ls -l'}, prompt=function(c) return c.user .. '> ' end}").unwrap();
        let mut controller = Controller::default();
        controller.remember("pwd");
        controller.remember("ls");
        assert_eq!(
            controller.dispatch(Event::Previous).unwrap(),
            Outcome::Changed
        );
        assert_eq!(controller.buffer(), "ls");
        assert_eq!(controller.dispatch(Event::Next).unwrap(), Outcome::Changed);
        assert_eq!(controller.buffer(), "");
        let aliases: Aliases = profiles.aliases.clone();
        assert_eq!(
            aliases.expand(vec!["ll".into(), "/".into()]).unwrap(),
            ["ls", "-l", "/"]
        );
        assert_eq!(profiles.prompt("/", "alice").unwrap(), "alice> ");
    }
}
