//! HyberKOS Shell — First User-Space Environment
//! Phase 7 — REPL with Standard & Native Commands

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use hyber_core::{HandleId, ObjectType, Path, ProcessId, Rights};
use hyber_handle::HandleManager;
use hyber_hostfs::HostFSProvider;
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_vfs::VFS;

/// HyberKOS Shell state
struct HyberShell {
    obj_mgr: ObjectManager,
    ns_mgr: NamespaceManager,
    handle_mgr: HandleManager,
    vfs: VFS<HostFSProvider>,
    current_dir: Path,
    process_id: ProcessId,
    running: bool,
}

impl HyberShell {
    /// Initialize the shell with all managers and mount HostFS at /
    fn new(host_root: PathBuf) -> Result<Self, String> {
        let mut obj_mgr = ObjectManager::new();
        let ns_mgr = NamespaceManager::new(&mut obj_mgr);
        let handle_mgr = HandleManager::new();

        let provider = HostFSProvider::new(&host_root)
            .map_err(|e| format!("Failed to initialize HostFS at {:?}: {}", host_root, e))?;
        let mut vfs = VFS::new(provider);

        // Mount HostFS at root
        vfs.mount(Path::from_str("/"), "HostFSProvider".to_string());

        let current_dir = Path::from_str("/");
        let process_id = ProcessId(1); // Shell is process #1

        Ok(Self {
            obj_mgr,
            ns_mgr,
            handle_mgr,
            vfs,
            current_dir,
            process_id,
            running: true,
        })
    }

    /// Main REPL loop
    fn run(&mut self) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        println!("HyberKOS Shell v0.1.0");
        println!("Type 'exit' to quit.\n");

        while self.running {
            // Print prompt with current directory
            print!("hyber:{}$ ", self.current_dir);
            stdout.flush().unwrap();

            // Read user input
            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    self.execute(line);
                }
                Err(e) => {
                    eprintln!("Error reading input: {}", e);
                    break;
                }
            }
        }

        // Cleanup: release all open handles
        self.cleanup();
        println!("Goodbye from HyberKOS!");
    }

    /// Parse and execute a command
    fn execute(&mut self, input: &str) {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        let command = parts[0];
        let args = &parts[1..];

        let result = match command {
            // Standard Base Commands
            "pwd" => self.cmd_pwd(args),
            "cd" => self.cmd_cd(args),
            "ls" => self.cmd_ls(args),
            "mkdir" => self.cmd_mkdir(args),
            "touch" => self.cmd_touch(args),
            "rm" => self.cmd_rm(args),
            "mv" => self.cmd_mv(args),
            "cp" => self.cmd_cp(args),
            "cat" => self.cmd_cat(args),

            // HyberKOS Native Commands
            "list" => self.cmd_list(args),
            "look" => self.cmd_look(args),
            "acquire" => self.cmd_acquire(args),
            "release" => self.cmd_release(args),
            "handles" => self.cmd_handles(args),
            "mnts" => self.cmd_mnts(args),
            "rights" => self.cmd_rights(args),
            "exit" => self.cmd_exit(args),
            "help" => self.cmd_help(args),

            _ => {
                eprintln!("Unknown command: '{}'. Type 'help' for available commands.", command);
                Ok(())
            }
        };

        if let Err(e) = result {
            eprintln!("Error: {}", e);
        }
    }

    /// Helper: Parse flags from arguments (e.g., "-l", "-a")
    fn parse_flags<'a>(args: &'a [&'a str]) -> (Vec<String>, Vec<&'a str>) {
        let mut flags = Vec::new();
        let mut positional = Vec::new();
        for arg in args {
            if arg.starts_with('-') {
                flags.push(arg[1..].to_string()); // Remove leading '-'
            } else {
                positional.push(*arg);
            }
        }
        (flags, positional)
    }

    /// Helper: Resolve a path relative to current_dir
    fn resolve_path(&self, path_str: &str) -> Path {
        if path_str.starts_with('/') {
            Path::from_str(path_str)
        } else if path_str == "." {
            self.current_dir.clone()
        } else {
            // Relative path: combine with current_dir
            let mut combined = self.current_dir.to_string();
            if !combined.ends_with('/') {
                combined.push('/');
            }
            combined.push_str(path_str);
            Path::from_str(&combined).normalize()
        }
    }

    // ==========================================
    // Standard Base Commands
    // ==========================================

    fn cmd_pwd(&self, _args: &[&str]) -> Result<(), String> {
        println!("{}", self.current_dir);
        Ok(())
    }

    fn cmd_cd(&mut self, args: &[&str]) -> Result<(), String> {
        if args.is_empty() {
            self.current_dir = Path::from_str("/");
            return Ok(());
        }

        let target = args[0];
        let path = if target == ".." {
            // Go to parent
            let mut components = self.current_dir.components.clone();
            if !components.is_empty() {
                components.pop();
            }
            Path {
                components,
                is_absolute: self.current_dir.is_absolute,
            }
        } else if target == "." {
            self.current_dir.clone()
        } else {
            self.resolve_path(target)
        };

        // Verify it's a directory
        let obj_id = self.ns_mgr.resolve(&path, self.ns_mgr.root())?;
        let obj = self.obj_mgr.lookup(obj_id)
            .ok_or("Object not found")?;
        if obj.object_type != ObjectType::Directory {
            return Err(format!("{:?} is not a directory", obj_id));
        }

        self.current_dir = path;
        Ok(())
    }

    fn cmd_ls(&mut self, args: &[&str]) -> Result<(), String> {
        let (flags, positional) = Self::parse_flags(args);
        let path_str = positional.first().copied().unwrap_or(".");
        let path = self.resolve_path(path_str);
        let dir_id = self.ns_mgr.resolve(&path, self.ns_mgr.root())?;

        let nodes = self.ns_mgr.list_directory(dir_id)
            .ok_or("Failed to list directory")?;

        let long_format = flags.contains(&"l".to_string());
        let show_all = flags.contains(&"a".to_string());

        for node in nodes {
            if !show_all && node.name.starts_with('.') {
                continue;
            }
            if long_format {
                let obj = self.obj_mgr.lookup(node.object_id);
                let obj_type = obj.map(|o| o.object_type.to_string()).unwrap_or("?".to_string());
                println!("{} [{}]", node.name, obj_type);
            } else {
                println!("{}", node.name);
            }
        }
        Ok(())
    }

    fn cmd_mkdir(&mut self, args: &[&str]) -> Result<(), String> {
        let (flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: mkdir [-p] <path>".to_string());
        }

        let recursive = flags.contains(&"p".to_string());
        let path = self.resolve_path(positional[0]);
        let components = path.components.clone();
        if components.is_empty() {
            return Err("Cannot create root directory".to_string());
        }

        if recursive {
            // Create parent directories as needed
            for i in 0..components.len() {
                let partial_name = components[i].0.clone();
                let partial_parent = Path {
                    components: components[..i].to_vec(),
                    is_absolute: path.is_absolute,
                };
                // Check if it already exists
                if self.ns_mgr.resolve(
                    &Path {
                        components: components[..=i].to_vec(),
                        is_absolute: path.is_absolute,
                    },
                    self.ns_mgr.root(),
                ).is_ok() {
                    continue; // Already exists
                }
                self.vfs.create(&mut self.ns_mgr, &mut self.obj_mgr, &partial_parent, &partial_name, ObjectType::Directory)?;
            }
            Ok(())
        } else {
            let name = components.last().unwrap().0.clone();
            let parent_path = Path {
                components: components[..components.len() - 1].to_vec(),
                is_absolute: path.is_absolute,
            };

            self.vfs.create(&mut self.ns_mgr, &mut self.obj_mgr, &parent_path, &name, ObjectType::Directory)?;
            Ok(())
        }
    }

    fn cmd_touch(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: touch <path>".to_string());
        }
        let path = self.resolve_path(positional[0]);
        let components = path.components.clone();
        if components.is_empty() {
            return Err("Cannot create root file".to_string());
        }

        // Check if file already exists (update modified_at)
        if let Ok(obj_id) = self.ns_mgr.resolve(&path, self.ns_mgr.root()) {
            if let Some(obj) = self.obj_mgr.lookup_mut(obj_id) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                obj.modified_at = now;
                return Ok(());
            }
        }

        let name = components.last().unwrap().0.clone();
        let parent_path = Path {
            components: components[..components.len() - 1].to_vec(),
            is_absolute: path.is_absolute,
        };

        self.vfs.create(&mut self.ns_mgr, &mut self.obj_mgr, &parent_path, &name, ObjectType::File)?;
        Ok(())
    }

    fn cmd_rm(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: rm [-r] <path>".to_string());
        }
        let path = self.resolve_path(positional[0]);
        let components = path.components.clone();
        if components.is_empty() {
            return Err("Cannot remove root".to_string());
        }

        let name = components.last().unwrap().0.clone();
        let parent_path = Path {
            components: components[..components.len() - 1].to_vec(),
            is_absolute: path.is_absolute,
        };

        self.vfs.remove(&mut self.ns_mgr, &mut self.obj_mgr, &parent_path, &name)?;
        Ok(())
    }

    fn cmd_mv(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.len() < 2 {
            return Err("Usage: mv <source> <dest>".to_string());
        }
        let src_path = self.resolve_path(positional[0]);
        let dest_path = self.resolve_path(positional[1]);

        let src_components = src_path.components.clone();
        let dest_components = dest_path.components.clone();

        if src_components.is_empty() || dest_components.is_empty() {
            return Err("Invalid paths".to_string());
        }

        let src_name = src_components.last().unwrap().0.clone();
        let dest_name = dest_components.last().unwrap().0.clone();

        let src_parent = Path {
            components: src_components[..src_components.len() - 1].to_vec(),
            is_absolute: src_path.is_absolute,
        };
        let dest_parent = Path {
            components: dest_components[..dest_components.len() - 1].to_vec(),
            is_absolute: dest_path.is_absolute,
        };

        self.vfs.rename(&mut self.ns_mgr, &mut self.obj_mgr, &src_parent, &src_name, &dest_parent, &dest_name)?;
        Ok(())
    }

    fn cmd_cp(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.len() < 2 {
            return Err("Usage: cp <source> <dest>".to_string());
        }
        let src_path = self.resolve_path(positional[0]);
        let dest_path = self.resolve_path(positional[1]);

        // Open source for reading
        let src_handle = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &src_path,
            Rights::read_only(),
        )?;

        // Read all data
        let mut data = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let bytes = self.vfs.read(&mut self.handle_mgr, self.process_id, src_handle, &mut buffer)?;
            if bytes == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..bytes]);
        }
        self.vfs.close(&mut self.handle_mgr, &mut self.obj_mgr, self.process_id, src_handle)?;

        // Create dest file
        let dest_components = dest_path.components.clone();
        if dest_components.is_empty() {
            return Err("Invalid destination path".to_string());
        }
        let dest_name = dest_components.last().unwrap().0.clone();
        let dest_parent = Path {
            components: dest_components[..dest_components.len() - 1].to_vec(),
            is_absolute: dest_path.is_absolute,
        };
        self.vfs.create(&mut self.ns_mgr, &mut self.obj_mgr, &dest_parent, &dest_name, ObjectType::File)?;

        // Open dest for writing
        let dest_handle = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &dest_path,
            Rights::read_write(),
        )?;

        self.vfs.write(&mut self.handle_mgr, self.process_id, dest_handle, &data)?;
        self.vfs.close(&mut self.handle_mgr, &mut self.obj_mgr, self.process_id, dest_handle)?;

        Ok(())
    }

    fn cmd_cat(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: cat <path>".to_string());
        }
        let path = self.resolve_path(positional[0]);

        let handle = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &path,
            Rights::read_only(),
        )?;

        let mut buffer = [0u8; 4096];
        loop {
            let bytes = self.vfs.read(&mut self.handle_mgr, self.process_id, handle, &mut buffer)?;
            if bytes == 0 {
                break;
            }
            print!("{}", String::from_utf8_lossy(&buffer[..bytes]));
        }
        println!();

        self.vfs.close(&mut self.handle_mgr, &mut self.obj_mgr, self.process_id, handle)?;
        Ok(())
    }

    // ==========================================
    // HyberKOS Native Commands
    // ==========================================

    fn cmd_list(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        let path_str = positional.first().copied().unwrap_or(".");
        let path = self.resolve_path(path_str);
        let dir_id = self.ns_mgr.resolve(&path, self.ns_mgr.root())?;

        let nodes = self.ns_mgr.list_directory(dir_id)
            .ok_or("Failed to list directory")?;

        println!("{:<20} | {:<12} | {:<10} | {:<5} | {}", "Name", "ObjectId", "Type", "Refs", "Size");
        println!("{}", "-".repeat(65));
        for node in nodes {
            let obj = self.obj_mgr.lookup(node.object_id);
            let obj_type = obj.map(|o| o.object_type.to_string()).unwrap_or("?".to_string());
            let refs = obj.map(|o| o.references).unwrap_or(0);
            // Size is not tracked yet in Object, show "-"
            println!("{:<20} | {:<12} | {:<10} | {:<5} | {}", node.name, node.object_id, obj_type, refs, "-");
        }
        Ok(())
    }

    fn cmd_look(&self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: look <path>".to_string());
        }
        let path = self.resolve_path(positional[0]);
        let obj_id = self.ns_mgr.resolve(&path, self.ns_mgr.root())?;

        let obj = self.obj_mgr.lookup(obj_id)
            .ok_or("Object not found")?;

        println!("Object ID:   {}", obj.id);
        println!("Type:        {}", obj.object_type);
        println!("State:       {}", obj.state);
        println!("References:  {}", obj.references);
        println!("Created:     {}", obj.created_at);
        println!("Modified:    {}", obj.modified_at);
        println!("Flags:       {}", obj.flags);
        println!("Provider:    HostFSProvider");
        Ok(())
    }

    fn cmd_acquire(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: acquire <path> [r|w|rw]".to_string());
        }
        let path = self.resolve_path(positional[0]);
        let mode = positional.get(1).copied().unwrap_or("r");

        let rights = match mode {
            "r" => Rights::read_only(),
            "w" => Rights { write: true, ..Rights::empty() },
            "rw" => Rights::read_write(),
            _ => return Err("Invalid mode. Use: r, w, or rw".to_string()),
        };

        let handle_id = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &path,
            rights,
        )?;

        let obj_id = self.ns_mgr.resolve(&path, self.ns_mgr.root())?;
        println!("Acquired Handle #{} for Object #{}", handle_id.0, obj_id.0);
        Ok(())
    }

    fn cmd_release(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: release <handle_id>".to_string());
        }
        let handle_id_num: u64 = positional[0].parse()
            .map_err(|_| "Invalid handle ID".to_string())?;
        let handle_id = HandleId(handle_id_num);

        self.vfs.close(&mut self.handle_mgr, &mut self.obj_mgr, self.process_id, handle_id)?;
        println!("Released Handle #{}", handle_id.0);
        Ok(())
    }

    fn cmd_handles(&self, _args: &[&str]) -> Result<(), String> {
        println!("{:<10} | {:<12} | {:<10} | {}", "HandleId", "ObjectId", "Rights", "Offset");
        println!("{}", "-".repeat(50));
        let handles = self.handle_mgr.list_handles(self.process_id);
        for handle in handles {
            let rights_str = format!(
                "{}{}{}",
                if handle.rights.read { "R" } else { "-" },
                if handle.rights.write { "W" } else { "-" },
                if handle.rights.execute { "X" } else { "-" }
            );
            println!("{:<10} | {:<12} | {:<10} | {}", handle.handle_id, handle.object_id, rights_str, handle.offset);
        }
        Ok(())
    }

    fn cmd_mnts(&self, _args: &[&str]) -> Result<(), String> {
        println!("{:<20} | {:<20} | {}", "Namespace Path", "Provider Name", "Status");
        println!("{}", "-".repeat(55));
        for mount in self.vfs.list_mounts() {
            println!("{:<20} | {:<20} | Active", mount.path, mount.provider_name);
        }
        Ok(())
    }

    fn cmd_rights(&self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: rights <path>".to_string());
        }
        let path = self.resolve_path(positional[0]);
        let obj_id = self.ns_mgr.resolve(&path, self.ns_mgr.root())?;
        let obj = self.obj_mgr.lookup(obj_id)
            .ok_or("Object not found")?;

        // For now, show basic rights based on object type
        let can_read = obj.object_type == ObjectType::File || obj.object_type == ObjectType::Directory;
        let can_write = obj.object_type == ObjectType::File;
        let can_execute = false; // No execution model yet

        println!("READ:    {}", if can_read { "Yes" } else { "No" });
        println!("WRITE:   {}", if can_write { "Yes" } else { "No" });
        println!("EXECUTE: {}", if can_execute { "Yes" } else { "No" });
        Ok(())
    }

    fn cmd_exit(&mut self, _args: &[&str]) -> Result<(), String> {
        self.running = false;
        Ok(())
    }

    fn cmd_help(&self, _args: &[&str]) -> Result<(), String> {
        println!("=== HyberKOS Shell Commands ===\n");
        println!("Standard Commands:");
        println!("  pwd                     Print working directory");
        println!("  cd <path>               Change directory");
        println!("  ls [-l] [-a] [path]     List directory contents");
        println!("  mkdir [-p] <path>       Create directory");
        println!("  touch <path>            Create file / update timestamp");
        println!("  rm [-r] <path>          Remove file/directory");
        println!("  mv <src> <dest>         Move/rename");
        println!("  cp <src> <dest>         Copy file");
        println!("  cat <path>              Print file contents");
        println!();
        println!("HyberKOS Native Commands:");
        println!("  list [path]             List with Object details");
        println!("  look <path>             Deep Object inspection");
        println!("  acquire <path> [mode]   Get Handle (r/w/rw)");
        println!("  release <handle_id>     Release Handle");
        println!("  handles                 Show Handle Table");
        println!("  mnts                    Show mount points");
        println!("  rights <path>           Show access rights");
        println!("  exit                    Exit shell");
        println!("  help                    Show this help");
        Ok(())
    }

    /// Cleanup: release all open handles
    fn cleanup(&mut self) {
        let handle_ids = self.handle_mgr.list_handle_ids(self.process_id);
        for hid in handle_ids {
            let _ = self.vfs.close(&mut self.handle_mgr, &mut self.obj_mgr, self.process_id, hid);
        }
    }
}

fn main() {
    // Default host root: ~/hyber-host
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let host_root = PathBuf::from(home).join("hyber-host");

    match HyberShell::new(host_root.clone()) {
        Ok(mut shell) => {
            println!("HostFS mounted at: {:?}\n", host_root);
            shell.run();
        }
        Err(e) => {
            eprintln!("Failed to start HyberKOS Shell: {}", e);
            std::process::exit(1);
        }
    }
}