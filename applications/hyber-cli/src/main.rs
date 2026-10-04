//! HyberKOS Developer Toolchain — `hyber` CLI
//! Phase 14A — Lua Foundation Developer Toolchain
//!
//! ## Commands
//!
//! | Command                      | Description                                          |
//! |------------------------------|------------------------------------------------------|
//! | `hyber run <path>`           | Run a `.lua` script or a dir with `hyber.toml`       |
//! | `hyber inspect <path>`       | Inspect a namespace path (object info)               |
//! | `hyber ns <path>`            | List namespace entries at a path                     |
//! | `hyber handles`              | List open handles in the current session             |
//! | `hyber mount`                | Show active VFS mount points                         |
//! | `hyber trace <path>`         | Trace the full resolution path of a namespace entry  |
//! | `hyber new <name>`           | Scaffold a new HyberKOS Lua application              |
//!
//! ## Application Manifest (`hyber.toml`)
//!
//! ```toml
//! name       = "my-app"
//! version    = "0.1.0"
//! entrypoint = "main.lua"
//! author     = "neo"
//!
//! [permissions]
//! read  = ["/runtime", "/data"]
//! write = ["/runtime"]
//! ```

mod commands;
mod context;
mod manifest;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    let subcommand = args[1].as_str();
    let rest = &args[2..];

    let result = match subcommand {
        "run" => commands::run(rest),
        "inspect" => commands::inspect(rest),
        "ns" => commands::ns(rest),
        "handles" => commands::handles(rest),
        "mount" => commands::mount(rest),
        "trace" => commands::trace(rest),
        "new" => commands::new_app(rest),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "version" | "--version" | "-v" => {
            println!("hyber {}", env!("CARGO_PKG_VERSION"));
            println!("HyberKOS Developer Toolchain — Phase 14A");
            Ok(())
        }
        other => {
            eprintln!("hyber: unknown subcommand '{}'", other);
            eprintln!("Run 'hyber help' for usage.");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("hyber: error: {}", e);
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "HyberKOS Developer Toolchain v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("Phase 14A — Lua Application Runner & Inspector");
    println!();
    println!("USAGE:");
    println!("  hyber <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("  run <path>       Run a .lua script or a directory with hyber.toml");
    println!("  inspect <path>   Show object metadata for a HyberKOS namespace path");
    println!("  ns <path>        List namespace entries at a path");
    println!("  handles          Show all open handles");
    println!("  mount            Show active VFS mount points");
    println!("  trace <path>     Trace namespace resolution steps for a path");
    println!("  new <name>       Scaffold a new HyberKOS Lua application");
    println!("  version          Print version information");
    println!("  help             Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("  hyber run /apps/calc.lua");
    println!("  hyber run ./my-app/");
    println!("  hyber inspect /runtime");
    println!("  hyber ns /");
    println!("  hyber trace /users/neo/test.txt");
    println!("  hyber new calculator");
}
