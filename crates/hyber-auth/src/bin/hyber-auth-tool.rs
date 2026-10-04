//! Hosted bootstrap/admin tool. No credential is accepted in command arguments.
use hyber_auth::{prompt_password, AuthService, SessionKind, SystemClock, STORE_PATH};
use hyber_fs::{FileDevice, Volume};
use hyber_identity::AccountState;
use std::sync::Arc;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        return Err("usage: hyber-auth-tool <init|check|user-add|passwd|lock|unlock|disable> <image> <blocks> [username [state]]; unlock requires active|service|guest".into());
    }
    let blocks: u64 = args[3].parse()?;
    let command = args[1].as_str();
    match command {
        "init" | "check" if args.len() == 4 => (),
        "user-add"
            if args.len() == 5
                || (args.len() == 6 && matches!(args[5].as_str(), "service" | "guest")) => {}
        "passwd" | "lock" | "disable" if args.len() == 5 => (),
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
    let password = prompt_password("Root password: ")?;
    let admin = auth.login("root", password.as_bytes(), SessionKind::Interactive, 600)?;
    let name = &args[4];
    match command {
        "user-add" => {
            let state = match args.get(5).map(String::as_str) {
                Some("service") => AccountState::Service,
                Some("guest") => AccountState::Guest,
                _ => AccountState::Active,
            };
            let new_password = prompt_password("New account password (12+ bytes): ")?;
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
            let password = prompt_password("New password (12+ bytes): ")?;
            auth.set_password(&admin, user, password.as_bytes())?;
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
