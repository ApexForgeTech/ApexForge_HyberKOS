//! Hosted bootstrap/admin tool. No credential is accepted in command arguments.
use hyber_auth::{prompt_password, AuthService, SessionKind, SystemClock, STORE_PATH};
use hyber_fs::{FileDevice, Volume};
use hyber_identity::{AccountState, IdentityError};
use std::sync::Arc;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        return Err("usage: hyber-auth-tool <command> <image> <blocks> [arguments]; commands: init, check, users, groups, user-add, user-delete, passwd, passwd-self, lock, unlock, disable, group-add, group-delete, group-join, group-leave, primary-group, capability-grant, capability-revoke".into());
    }
    let blocks: u64 = args[3].parse()?;
    let command = args[1].as_str();
    match command {
        "init" | "check" | "users" | "groups" if args.len() == 4 => (),
        "user-add"
            if args.len() == 5
                || (args.len() == 6 && matches!(args[5].as_str(), "service" | "guest")) => {}
        "passwd" | "passwd-self" | "lock" | "disable" | "group-add" | "group-delete"
        | "user-delete"
            if args.len() == 5 => {}
        "group-join" | "group-leave" | "primary-group" | "capability-grant"
        | "capability-revoke"
            if args.len() == 6 => {}
        "unlock"
            if args.len() == 6 && matches!(args[5].as_str(), "active" | "service" | "guest") => {}
        _ => return Err("invalid command or arguments".into()),
    }
    let clock = Arc::new(SystemClock);
    if command == "init" {
        let password = prompt_password("New root password (12+ bytes): ")?;
        let confirmation = prompt_password("Repeat password: ")?;
        if *password != *confirmation {
            return Err("passwords do not match".into());
        }
        let auth = AuthService::provision(password.as_bytes(), clock)?;
        let mut volume = Volume::format(FileDevice::create(&args[2], blocks, false)?)?;
        auth.save(&mut volume, STORE_PATH)?;
        volume.unmount()?;
        println!("Authentication store initialized.");
        return Ok(());
    }
    if command == "check" {
        let volume = Volume::mount(FileDevice::open_read_only(&args[2], blocks)?)?;
        AuthService::load(&volume, STORE_PATH, clock)?;
        println!("Authentication store valid.");
        return Ok(());
    }
    let mut volume = Volume::mount(FileDevice::open(&args[2], blocks)?)?;
    let mut auth = AuthService::load(&volume, STORE_PATH, clock)?;
    if command == "passwd-self" {
        let old = prompt_password("Current password: ")?;
        let token = auth.login(&args[4], old.as_bytes(), SessionKind::Interactive, 600)?;
        let password = confirmed_password()?;
        auth.change_password(&token, old.as_bytes(), password.as_bytes())?;
        auth.save(&mut volume, STORE_PATH)?;
        volume.unmount()?;
        println!("Password change committed. Log in again.");
        return Ok(());
    }
    let password = prompt_password("Root password: ")?;
    let admin = auth.login("root", password.as_bytes(), SessionKind::Interactive, 600)?;
    if command == "users" || command == "groups" {
        if command == "users" {
            for user in auth.accounts().users() {
                println!(
                    "{} uid={} primary_group={} state={:?} supplementary={:?} capabilities={:?}",
                    user.username,
                    user.id.0,
                    user.primary_group.0,
                    user.state,
                    user.supplementary_groups,
                    user.capabilities
                );
            }
        } else {
            for group in auth.accounts().groups() {
                println!(
                    "{} gid={} members={:?}",
                    group.name, group.id.0, group.members
                );
            }
        }
        // Inspection must not rewrite the store or invalidate hosted sessions.
        return Ok(());
    }
    let name = &args[4];
    match command {
        "user-add" => {
            let state = match args.get(5).map(String::as_str) {
                Some("service") => AccountState::Service,
                Some("guest") => AccountState::Guest,
                _ => AccountState::Active,
            };
            let new_password = confirmed_password()?;
            let user = auth.edit_accounts(&admin, |accounts| {
                let group = accounts.create_group(name)?;
                accounts.create_user(name, group, state)
            })?;
            auth.set_password(&admin, user, new_password.as_bytes())?;
        }
        "passwd" => {
            let user = auth
                .accounts()
                .user_by_name(name)
                .ok_or("account not found")?
                .id;
            let password = confirmed_password()?;
            auth.set_password(&admin, user, password.as_bytes())?;
        }
        "group-add" | "group-delete" | "group-join" | "group-leave" | "primary-group"
        | "capability-grant" | "capability-revoke" | "user-delete" => {
            auth.edit_accounts(&admin, |accounts| {
                if command == "group-add" {
                    accounts.create_group(name)?;
                    return Ok(());
                }
                if command == "group-delete" {
                    let group = accounts
                        .group_by_name(name)
                        .ok_or(IdentityError::NotFound)?
                        .id;
                    return accounts.delete_group(group);
                }
                let user = accounts
                    .user_by_name(name)
                    .ok_or(IdentityError::NotFound)?
                    .id;
                match command {
                    "user-delete" => accounts.delete_user(user),
                    "capability-grant" => accounts.grant_capability(user, &args[5]),
                    "capability-revoke" => accounts.revoke_capability(user, &args[5]),
                    _ => {
                        let group = accounts
                            .group_by_name(&args[5])
                            .ok_or(IdentityError::NotFound)?
                            .id;
                        match command {
                            "group-join" => accounts.add_to_group(user, group),
                            "group-leave" => accounts.remove_from_group(user, group),
                            _ => accounts.set_primary_group(user, group),
                        }
                    }
                }
            })?;
        }
        _ => {
            let user = auth
                .accounts()
                .user_by_name(name)
                .ok_or("account not found")?
                .id;
            let state = match command {
                "lock" => AccountState::Locked,
                "disable" => AccountState::Disabled,
                _ => match args[5].as_str() {
                    "service" => AccountState::Service,
                    "guest" => AccountState::Guest,
                    _ => AccountState::Active,
                },
            };
            auth.edit_accounts(&admin, |accounts| accounts.set_state(user, state))?;
        }
    }
    // Root password replacement invalidates this token too.
    let _ = auth.logout(&admin);
    auth.save(&mut volume, STORE_PATH)?;
    volume.unmount()?;
    println!("Account update committed.");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("hyber-auth-tool: {error}");
        std::process::exit(1);
    }
}

fn confirmed_password() -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    let password = prompt_password("New password (12+ bytes): ")?;
    let confirmation = prompt_password("Repeat password: ")?;
    if *password != *confirmation {
        return Err("passwords do not match".into());
    }
    Ok(password)
}
