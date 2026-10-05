//! HyberKOS Shell — First User-Space Environment
//! Phase 7–12 — REPL with Standard, Native, Virtual Namespace & Lua Commands

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hyber_core::{
    GroupId, HandleId, MetadataValue, ObjectType, Path, ProcessId, Rights, SecurityContext, UserId,
};
use hyber_device::{DeviceClass, DeviceManager, DeviceProvider};
use hyber_handle::HandleManager;
use hyber_hostfs::HostFSProvider;
use hyber_memfs::MemFSProvider;
use hyber_namespace::NamespaceManager;
use hyber_object::ObjectManager;
use hyber_process::{ProcessManager, ProcessProvider};
use hyber_service::{ServiceManager, ServiceProvider};
use hyber_vfs::{Provider, VFS};

/// HyberKOS Shell state
struct HyberShell {
    session: Option<hyber_auth::SessionGuard>,
    obj_mgr: ObjectManager,
    ns_mgr: NamespaceManager,
    handle_mgr: HandleManager,
    vfs: VFS,
    current_dir: Path,
    process_id: ProcessId,
    proc_mgr: Arc<Mutex<ProcessManager>>,
    dev_mgr: Arc<Mutex<DeviceManager>>,
    svc_mgr: Arc<Mutex<ServiceManager>>,
    running: bool,
}

impl HyberShell {
    /// Initialize the shell with all managers and mount the full virtual namespace tree.
    /// Phase 11 Exit Criteria namespace:
    ///   /
    ///   ├── system/       (HostFS — OS internals)
    ///   ├── users/        (HostFS — user data)
    ///   ├── apps/         (HostFS — installed applications)
    ///   ├── data/         (HostFS — persistent data)
    ///   ├── config/       (HostFS — configuration files)
    ///   ├── packages/     (HostFS — package artifacts)
    ///   ├── services/     (ServiceProvider — virtual service registry)
    ///   ├── devices/      (DeviceProvider — virtual device registry)
    ///   ├── processes/    (ProcessProvider — live process tree)
    ///   ├── runtime/      (MemFS — volatile runtime data)
    ///   ├── temporary/    (MemFS — ephemeral scratch space)
    ///   ├── volumes/      (HostFS — mountable storage volumes)
    ///   └── developer/    (HostFS — developer tooling & debug data)
    fn new(host_root: PathBuf) -> Result<Self, String> {
        let mut obj_mgr = ObjectManager::new();
        let mut ns_mgr = NamespaceManager::new(&mut obj_mgr);
        let handle_mgr = HandleManager::new();

        // ── Process Manager (Phase 10) ────────────────────────────────────────────
        let mut proc_mgr = ProcessManager::new();
        let root_security = SecurityContext::root();
        let shell_pid = proc_mgr
            .create_process(&mut obj_mgr, None, root_security, Some(std::process::id()))
            .map_err(|e| format!("Failed to create shell process: {e}"))?;
        proc_mgr
            .start_process(shell_pid)
            .map_err(|e| format!("Failed to start shell process: {e}"))?;
        let proc_mgr_arc = Arc::new(Mutex::new(proc_mgr));

        // ── Device Manager (Phase 11) — pre-register standard virtual devices ─────
        let mut dev_mgr_inner = DeviceManager::new();
        dev_mgr_inner.register_device(
            &mut obj_mgr,
            "null",
            DeviceClass::Virtual,
            "Discard all writes, return zeros on read",
        );
        dev_mgr_inner.register_device(
            &mut obj_mgr,
            "zero",
            DeviceClass::Virtual,
            "Always returns zero bytes",
        );
        dev_mgr_inner.register_device(
            &mut obj_mgr,
            "random",
            DeviceClass::Virtual,
            "Pseudo-random byte generator",
        );
        let dev_mgr = Arc::new(Mutex::new(dev_mgr_inner));

        // ── Service Manager (Phase 11) — pre-register placeholder services ────────
        let mut svc_mgr_inner = ServiceManager::new();
        svc_mgr_inner.register_service(&mut obj_mgr, "logger", "HyberKOS system event logger");
        svc_mgr_inner.register_service(
            &mut obj_mgr,
            "scheduler",
            "HyberKOS cooperative task scheduler",
        );
        svc_mgr_inner.register_service(
            &mut obj_mgr,
            "netstack",
            "HyberKOS network stack (not yet active)",
        );
        let svc_mgr = Arc::new(Mutex::new(svc_mgr_inner));

        // Create the persistent namespace roots before importing the host tree.
        // Importing them is essential: it establishes HostFS's private
        // ObjectId -> relative-path mapping for every parent directory.
        for name in [
            "system",
            "users",
            "apps",
            "data",
            "config",
            "packages",
            "volumes",
            "developer",
        ] {
            std::fs::create_dir_all(host_root.join(name))
                .map_err(|e| format!("Failed to create host subdir '{name}': {e}"))?;
        }

        // ── HostFS — sync existing files from the host root ───────────────────────
        let mut hostfs = HostFSProvider::new(&host_root)
            .map_err(|e| format!("Failed to initialize HostFS at {:?}: {}", host_root, e))?;
        let root_id = ns_mgr.root();
        hostfs.bind_root(root_id);
        Self::sync_host_directory(&host_root, &mut obj_mgr, &mut ns_mgr, &mut hostfs, root_id)
            .map_err(|e| format!("Failed to sync host directory: {}", e))?;

        // ── VFS setup ─────────────────────────────────────────────────────────────
        let mut vfs = VFS::new();

        // Mount HostFS at namespace root (covers all non-virtual paths)
        vfs.register_provider("hostfs".to_string(), Box::new(hostfs));
        vfs.mount(Path::parse("/"), "hostfs".to_string());

        // Helper: create a namespace directory node and mount a provider at it
        // We define a closure-like pattern inline for each virtual mount point.

        // ── /processes  (ProcessProvider) ────────────────────────────────────────
        let proc_dir_id = obj_mgr.create_object(ObjectType::Directory);
        ns_mgr
            .create_node(&obj_mgr, ns_mgr.root(), "processes", proc_dir_id)
            .unwrap();
        ns_mgr.initialize_directory(proc_dir_id).ok(); // idempotent
        let shell_process_object = proc_mgr_arc
            .lock()
            .unwrap()
            .get_process(shell_pid)
            .ok_or("Shell process was not registered")?
            .object_id;
        ns_mgr.create_node(
            &obj_mgr,
            proc_dir_id,
            &shell_pid.0.to_string(),
            shell_process_object,
        )?;
        vfs.register_provider(
            "procfs".to_string(),
            Box::new(ProcessProvider::new(proc_mgr_arc.clone())),
        );
        vfs.mount(Path::parse("/processes"), "procfs".to_string());

        // ── /devices  (DeviceProvider) ────────────────────────────────────────────
        let dev_dir_id = obj_mgr.create_object(ObjectType::Directory);
        ns_mgr
            .create_node(&obj_mgr, ns_mgr.root(), "devices", dev_dir_id)
            .unwrap();
        ns_mgr.initialize_directory(dev_dir_id).ok();
        for device in dev_mgr
            .lock()
            .map_err(|_| "DeviceManager lock poisoned")?
            .list_devices()
        {
            ns_mgr.create_node(&obj_mgr, dev_dir_id, &device.name, device.object_id)?;
        }
        vfs.register_provider(
            "devfs".to_string(),
            Box::new(DeviceProvider::new(dev_mgr.clone())),
        );
        vfs.mount(Path::parse("/devices"), "devfs".to_string());

        // ── /services  (ServiceProvider) ─────────────────────────────────────────
        let svc_dir_id = obj_mgr.create_object(ObjectType::Directory);
        ns_mgr
            .create_node(&obj_mgr, ns_mgr.root(), "services", svc_dir_id)
            .unwrap();
        ns_mgr.initialize_directory(svc_dir_id).ok();
        for service in svc_mgr
            .lock()
            .map_err(|_| "ServiceManager lock poisoned")?
            .list_services()
        {
            ns_mgr.create_node(&obj_mgr, svc_dir_id, &service.name, service.object_id)?;
        }
        vfs.register_provider(
            "svcfs".to_string(),
            Box::new(ServiceProvider::new(svc_mgr.clone())),
        );
        vfs.mount(Path::parse("/services"), "svcfs".to_string());

        // ── /runtime  (MemFS — volatile runtime data) ─────────────────────────────
        let runtime_dir_id = obj_mgr.create_object(ObjectType::Directory);
        ns_mgr
            .create_node(&obj_mgr, ns_mgr.root(), "runtime", runtime_dir_id)
            .unwrap();
        ns_mgr.initialize_directory(runtime_dir_id).ok();
        let mut runtime_memfs = MemFSProvider::new();
        runtime_memfs
            .create(
                &mut obj_mgr,
                &mut ns_mgr,
                runtime_dir_id,
                ".keep",
                ObjectType::File,
            )
            .ok();
        vfs.register_provider("runtime-memfs".to_string(), Box::new(runtime_memfs));
        vfs.mount(Path::parse("/runtime"), "runtime-memfs".to_string());

        // ── /temporary  (MemFS — ephemeral scratch space) ─────────────────────────
        let tmp_dir_id = obj_mgr.create_object(ObjectType::Directory);
        ns_mgr
            .create_node(&obj_mgr, ns_mgr.root(), "temporary", tmp_dir_id)
            .unwrap();
        ns_mgr.initialize_directory(tmp_dir_id).ok();
        vfs.register_provider("tmp-memfs".to_string(), Box::new(MemFSProvider::new()));
        vfs.mount(Path::parse("/temporary"), "tmp-memfs".to_string());

        let current_dir = Path::parse("/");

        Ok(Self {
            session: None,
            obj_mgr,
            ns_mgr,
            handle_mgr,
            vfs,
            current_dir,
            process_id: shell_pid,
            proc_mgr: proc_mgr_arc,
            dev_mgr,
            svc_mgr,
            running: true,
        })
    }

    fn sync_host_directory(
        host_path: &std::path::Path,
        obj_mgr: &mut ObjectManager,
        ns_mgr: &mut NamespaceManager,
        hostfs: &mut HostFSProvider,
        parent_id: hyber_core::ObjectId,
    ) -> Result<(), String> {
        let entries =
            std::fs::read_dir(host_path).map_err(|e| format!("Failed to read dir: {}", e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("IO Error: {}", e))?;
            let path = entry.path();
            let name = entry.file_name().into_string().map_err(|_| {
                format!("HostFS cannot import non-Unicode name: {}", path.display())
            })?;
            let entry_type = entry
                .file_type()
                .map_err(|e| format!("Failed to inspect {}: {e}", path.display()))?;

            // Links and special files have no safe HostFS object model yet.
            // Refuse them instead of following a host-controlled redirection.
            if entry_type.is_symlink() {
                return Err(format!("HostFS refuses symbolic link: {}", path.display()));
            }

            if entry_type.is_dir() {
                let obj_id = hostfs.register_existing(
                    obj_mgr,
                    ns_mgr,
                    parent_id,
                    &name,
                    ObjectType::Directory,
                )?;
                Self::sync_host_directory(&path, obj_mgr, ns_mgr, hostfs, obj_id)?;
            } else if entry_type.is_file() {
                let obj_id = hostfs.register_existing(
                    obj_mgr,
                    ns_mgr,
                    parent_id,
                    &name,
                    ObjectType::File,
                )?;
                // Update size metadata for existing files
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Some(obj) = obj_mgr.lookup_mut(obj_id) {
                        obj.size = metadata.len();
                    }
                }
            } else {
                return Err(format!(
                    "HostFS supports only regular files and directories: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    /// Materialize the authenticated identity's validated `/users/<name>`
    /// directory before accepting commands.  Identity owns the path policy;
    /// this shell only creates the missing namespace object with a privileged
    /// bootstrap context, then assigns it to the session identity.
    fn ensure_session_home(&mut self) -> Result<(), String> {
        let session = self.session.as_ref().ok_or("no authenticated session")?;
        let context = session.context().map_err(|e| e.to_string())?;
        let home = session.home().map_err(|e| e.to_string())?;
        let path = Path::parse(&home).normalize();
        if !path.is_absolute || path.components.len() != 2 || path.components[0].0 != "users" {
            return Err("identity supplied an invalid home path".into());
        }

        match self.ns_mgr.resolve(&path, self.ns_mgr.root()) {
            Ok(id) => {
                let object = self.obj_mgr.lookup(id).ok_or("home object missing")?;
                if object.object_type != ObjectType::Directory
                    || object.owner != context.user_id
                    || object.group != context.group_id
                {
                    return Err("existing home directory belongs to another identity".into());
                }
                Ok(())
            }
            Err(_) => {
                let (parent, name) = path.parent_and_name().ok_or("invalid home path")?;
                let bootstrap = SecurityContext {
                    user_id: UserId(0),
                    group_id: GroupId(0),
                    supplementary_groups: Vec::new(),
                    capabilities: Vec::new(),
                };
                let id = self.vfs.create(
                    &mut self.ns_mgr,
                    &mut self.obj_mgr,
                    &bootstrap,
                    &parent,
                    &name,
                    ObjectType::Directory,
                )?;
                let object = self.obj_mgr.lookup_mut(id).ok_or("home object missing")?;
                object.owner = context.user_id;
                object.group = context.group_id;
                object.permissions = 0o700;
                Ok(())
            }
        }
    }

    /// Main REPL loop
    fn run(&mut self) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        println!("HyberKOS Shell v0.12.5  (Phase 12.5 — Advanced Lua Orchestration)");
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

    /// Parse and execute a command line (can contain multiple commands separated by ';')
    fn execute(&mut self, input: &str) {
        let mut commands = Vec::new();
        let mut current_cmd = String::new();
        let mut in_quotes = false;
        let mut quote_char = ' ';

        for c in input.chars() {
            if in_quotes {
                if c == quote_char {
                    in_quotes = false;
                }
                current_cmd.push(c);
            } else {
                if c == '"' || c == '\'' {
                    in_quotes = true;
                    quote_char = c;
                    current_cmd.push(c);
                } else if c == ';' {
                    if !current_cmd.trim().is_empty() {
                        commands.push(current_cmd.trim().to_string());
                    }
                    current_cmd.clear();
                } else {
                    current_cmd.push(c);
                }
            }
        }
        if !current_cmd.trim().is_empty() {
            commands.push(current_cmd.trim().to_string());
        }

        for cmd in commands {
            self.execute_single(&cmd);
            if !self.running {
                break;
            }
        }
    }

    /// Execute a single command
    fn execute_single(&mut self, input: &str) {
        if let Some(session) = &self.session {
            match session.context() {
                Ok(context) => {
                    if let Some(process) = self
                        .proc_mgr
                        .lock()
                        .unwrap()
                        .get_process_mut(self.process_id)
                    {
                        process.security_context = context;
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    self.running = false;
                    return;
                }
            }
        }
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        let command = parts[0];
        let args = &parts[1..];

        let result = match command {
            // Standard Base Commands
            "pwd" => self.cmd_pwd(args),
            "whoami" => self.cmd_whoami(args),
            "chmod" => self.cmd_chmod(args),
            "chgrp" => self.cmd_chgrp(args),
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
            "meta" => self.cmd_meta(args),
            "su" => self.cmd_su(args),
            "ps" => self.cmd_ps(args),
            "lsdev" => self.cmd_lsdev(args),
            "lssvc" => self.cmd_lssvc(args),
            "tree" => self.cmd_tree(args),
            "exit" => self.cmd_exit(args),
            "help" => self.cmd_help(args),
            "cls" | "clear" => self.cmd_cls(args),

            // Phase 12 — Lua Runtime
            "lua" => self.cmd_lua(args),
            "luafile" => self.cmd_luafile(args),

            _ => {
                eprintln!(
                    "Unknown command: '{}'. Type 'help' for available commands.",
                    command
                );
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
            if let Some(flag) = arg.strip_prefix('-') {
                flags.push(flag.to_string());
            } else {
                positional.push(*arg);
            }
        }
        (flags, positional)
    }

    /// Helper: Resolve a path relative to current_dir
    fn resolve_path(&self, path_str: &str) -> Path {
        if path_str.starts_with('/') {
            Path::parse(path_str)
        } else if path_str == "." {
            self.current_dir.clone()
        } else {
            // Relative path: combine with current_dir
            let mut combined = self.current_dir.to_string();
            if !combined.ends_with('/') {
                combined.push('/');
            }
            combined.push_str(path_str);
            Path::parse(&combined).normalize()
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
            self.current_dir = Path::parse("/");
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
        let obj = self.obj_mgr.lookup(obj_id).ok_or("Object not found")?;
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
        let security_context = self
            .proc_mgr
            .lock()
            .map_err(|_| "Process manager lock poisoned")?
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();

        let nodes =
            self.vfs
                .enumerate_secure(&self.ns_mgr, &self.obj_mgr, &security_context, &path)?;

        let long_format = flags.contains(&"l".to_string());
        let show_all = flags.contains(&"a".to_string());

        for (name, object_id) in nodes {
            if !show_all && name.starts_with('.') {
                continue;
            }
            if long_format {
                let obj = self.obj_mgr.lookup(object_id);
                let obj_type = obj
                    .map(|o| o.object_type.to_string())
                    .unwrap_or("?".to_string());
                println!("{} [{}]", name, obj_type);
            } else {
                println!("{}", name);
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
                if self
                    .ns_mgr
                    .resolve(
                        &Path {
                            components: components[..=i].to_vec(),
                            is_absolute: path.is_absolute,
                        },
                        self.ns_mgr.root(),
                    )
                    .is_ok()
                {
                    continue; // Already exists
                }
                let sec_ctx = self
                    .proc_mgr
                    .lock()
                    .unwrap()
                    .get_process(self.process_id)
                    .unwrap()
                    .security_context
                    .clone();
                self.vfs.create(
                    &mut self.ns_mgr,
                    &mut self.obj_mgr,
                    &sec_ctx,
                    &partial_parent,
                    &partial_name,
                    ObjectType::Directory,
                )?;
            }
            Ok(())
        } else {
            let name = components.last().unwrap().0.clone();
            let parent_path = Path {
                components: components[..components.len() - 1].to_vec(),
                is_absolute: path.is_absolute,
            };

            let sec_ctx = self
                .proc_mgr
                .lock()
                .unwrap()
                .get_process(self.process_id)
                .unwrap()
                .security_context
                .clone();
            self.vfs.create(
                &mut self.ns_mgr,
                &mut self.obj_mgr,
                &sec_ctx,
                &parent_path,
                &name,
                ObjectType::Directory,
            )?;
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
            let context = self
                .proc_mgr
                .lock()
                .map_err(|_| "Process manager lock poisoned")?
                .get_process(self.process_id)
                .ok_or("Shell process not found")?
                .security_context
                .clone();
            if let Some(obj) = self.obj_mgr.lookup_mut(obj_id) {
                hyber_core::SecurityManager::check_access(
                    &context,
                    obj.owner,
                    obj.group,
                    obj.permissions,
                    Rights {
                        write: true,
                        ..Rights::empty()
                    },
                )?;
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

        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .unwrap()
            .security_context
            .clone();
        self.vfs.create(
            &mut self.ns_mgr,
            &mut self.obj_mgr,
            &sec_ctx,
            &parent_path,
            &name,
            ObjectType::File,
        )?;
        Ok(())
    }

    fn cmd_rm(&mut self, args: &[&str]) -> Result<(), String> {
        let (flags, positional) = Self::parse_flags(args);
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

        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();
        let recursive = flags.iter().any(|flag| flag.contains('r'));
        if recursive {
            self.remove_tree(&path, &sec_ctx)?;
        } else {
            self.vfs.remove(
                &mut self.ns_mgr,
                &mut self.obj_mgr,
                &sec_ctx,
                &parent_path,
                &name,
            )?;
        }
        Ok(())
    }

    /// Post-order recursive removal for providers whose normal remove operation
    /// intentionally refuses non-empty directories.
    fn remove_tree(&mut self, path: &Path, context: &SecurityContext) -> Result<(), String> {
        let object_id = self.ns_mgr.resolve(path, self.ns_mgr.root())?;
        if self
            .obj_mgr
            .lookup(object_id)
            .map(|o| o.object_type == ObjectType::Directory)
            .unwrap_or(false)
        {
            let entries = self
                .vfs
                .enumerate_secure(&self.ns_mgr, &self.obj_mgr, context, path)?;
            for (name, _) in entries {
                let child = Path::parse(&format!("{}/{}", path, name)).normalize();
                self.remove_tree(&child, context)?;
            }
        }
        let components = &path.components;
        let name = components.last().ok_or("Cannot remove root")?.0.clone();
        let parent = Path {
            components: components[..components.len() - 1].to_vec(),
            is_absolute: true,
        };
        self.vfs
            .remove(&mut self.ns_mgr, &mut self.obj_mgr, context, &parent, &name)
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

        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();
        self.vfs.rename(
            &mut self.ns_mgr,
            &mut self.obj_mgr,
            &sec_ctx,
            &src_parent,
            &src_name,
            &dest_parent,
            &dest_name,
        )?;
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
        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .unwrap()
            .security_context
            .clone();

        let src_handle = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &sec_ctx,
            &src_path,
            Rights::read_only(),
        )?;

        // Read all data
        let mut data = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let bytes = self.vfs.read_secure(
                &mut self.handle_mgr,
                &self.obj_mgr,
                self.process_id,
                &sec_ctx,
                src_handle,
                &mut buffer,
            )?;
            if bytes == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..bytes]);
        }
        self.vfs.close(
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            src_handle,
        )?;

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
        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .unwrap()
            .security_context
            .clone();
        self.vfs.create(
            &mut self.ns_mgr,
            &mut self.obj_mgr,
            &sec_ctx,
            &dest_parent,
            &dest_name,
            ObjectType::File,
        )?;

        // Open dest for writing
        let dest_handle = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &sec_ctx,
            &dest_path,
            Rights::read_write(),
        )?;

        self.vfs.write_secure(
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &sec_ctx,
            dest_handle,
            &data,
        )?;
        self.vfs.close(
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            dest_handle,
        )?;

        Ok(())
    }

    fn cmd_cat(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: cat <path>".to_string());
        }
        let path = self.resolve_path(positional[0]);

        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .unwrap()
            .security_context
            .clone();
        let handle = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &sec_ctx,
            &path,
            Rights::read_only(),
        )?;

        let handle_obj_id = self
            .handle_mgr
            .get_handle(self.process_id, handle)
            .ok_or("Handle disappeared")?
            .object_id;
        let is_device = self
            .obj_mgr
            .lookup(handle_obj_id)
            .map(|o| o.object_type == ObjectType::Device)
            .unwrap_or(false);

        let mut buffer = [0u8; 4096];
        loop {
            let bytes = self.vfs.read_secure(
                &mut self.handle_mgr,
                &self.obj_mgr,
                self.process_id,
                &sec_ctx,
                handle,
                &mut buffer,
            )?;
            if bytes == 0 {
                break;
            }
            print!("{}", String::from_utf8_lossy(&buffer[..bytes]));
            // Stream-aware break for devices (avoid infinite shell lockup)
            if is_device {
                println!("\n[Device output truncated]");
                break;
            }
        }
        println!();

        self.vfs.close(
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            handle,
        )?;
        Ok(())
    }

    // ==========================================
    // HyberKOS Native Commands
    // ==========================================

    fn cmd_list(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        let path_str = positional.first().copied().unwrap_or(".");
        let path = self.resolve_path(path_str);
        let context = self
            .proc_mgr
            .lock()
            .map_err(|_| "Process manager lock poisoned")?
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();
        let nodes = self
            .vfs
            .enumerate_secure(&self.ns_mgr, &self.obj_mgr, &context, &path)?;

        println!(
            "{:<20} | {:<12} | {:<10} | {:<5} | Size",
            "Name", "ObjectId", "Type", "Refs"
        );
        println!("{}", "-".repeat(65));
        for (name, object_id) in nodes {
            let obj = self.obj_mgr.lookup(object_id);
            let obj_type = obj
                .map(|o| o.object_type.to_string())
                .unwrap_or("?".to_string());
            let refs = obj.map(|o| o.references).unwrap_or(0);
            let size = obj.map(|o| o.size).unwrap_or(0);
            println!(
                "{:<20} | {:<12} | {:<10} | {:<5} | {}",
                name, object_id, obj_type, refs, size
            );
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

        let obj = self.obj_mgr.lookup(obj_id).ok_or("Object not found")?;
        let context = self
            .proc_mgr
            .lock()
            .map_err(|_| "Process manager lock poisoned")?
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();
        hyber_core::SecurityManager::check_access(
            &context,
            obj.owner,
            obj.group,
            obj.permissions,
            Rights::read_only(),
        )?;

        println!("Object ID:   {}", obj.id);
        println!("Type:        {}", obj.object_type);
        println!("State:       {}", obj.state);
        println!("References:  {}", obj.references);
        println!("Owner:       {}", obj.owner);
        println!("Group:       {}", obj.group);
        println!("Permissions: {:o}", obj.permissions);
        println!("Size:        {}", obj.size);
        println!("Created:     {}", obj.created_at);
        println!("Modified:    {}", obj.modified_at);
        println!("Flags:       {}", obj.flags);
        let provider = self
            .vfs
            .list_mounts()
            .iter()
            .filter(|mount| {
                path.to_string() == mount.path.to_string()
                    || path
                        .to_string()
                        .starts_with(&(mount.path.to_string() + "/"))
            })
            .max_by_key(|mount| mount.path.to_string().len())
            .map(|mount| mount.provider_name.as_str())
            .unwrap_or("unknown");
        println!("Provider:    {}", provider);
        if !obj.extended_metadata.is_empty() {
            println!("Extended Metadata:");
            for (k, v) in &obj.extended_metadata {
                println!("  {} = {}", k, v);
            }
        }
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
            "w" => Rights {
                write: true,
                ..Rights::empty()
            },
            "rw" => Rights::read_write(),
            _ => return Err("Invalid mode. Use: r, w, or rw".to_string()),
        };

        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .unwrap()
            .security_context
            .clone();
        let handle_id = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &sec_ctx,
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
        let handle_id_num: u64 = positional[0]
            .parse()
            .map_err(|_| "Invalid handle ID".to_string())?;
        let handle_id = HandleId(handle_id_num);

        self.vfs.close(
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            handle_id,
        )?;
        println!("Released Handle #{}", handle_id.0);
        Ok(())
    }

    fn cmd_handles(&self, _args: &[&str]) -> Result<(), String> {
        println!(
            "{:<10} | {:<12} | {:<10} | Offset",
            "HandleId", "ObjectId", "Rights"
        );
        println!("{}", "-".repeat(50));
        let handles = self.handle_mgr.list_handles(self.process_id);
        for handle in handles {
            let rights_str = format!(
                "{}{}{}",
                if handle.rights.read { "R" } else { "-" },
                if handle.rights.write { "W" } else { "-" },
                if handle.rights.execute { "X" } else { "-" }
            );
            println!(
                "{:<10} | {:<12} | {:<10} | {}",
                handle.handle_id, handle.object_id, rights_str, handle.offset
            );
        }
        Ok(())
    }

    fn cmd_mnts(&self, _args: &[&str]) -> Result<(), String> {
        println!(
            "{:<20} | {:<20} | Status",
            "Namespace Path", "Provider Name"
        );
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
        let obj = self.obj_mgr.lookup(obj_id).ok_or("Object not found")?;

        let context = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();
        let can_read = hyber_core::SecurityManager::check_access(
            &context,
            obj.owner,
            obj.group,
            obj.permissions,
            Rights::read_only(),
        )
        .is_ok();
        let can_write = hyber_core::SecurityManager::check_access(
            &context,
            obj.owner,
            obj.group,
            obj.permissions,
            Rights {
                write: true,
                ..Rights::empty()
            },
        )
        .is_ok();
        let can_execute = hyber_core::SecurityManager::check_access(
            &context,
            obj.owner,
            obj.group,
            obj.permissions,
            Rights {
                execute: true,
                ..Rights::empty()
            },
        )
        .is_ok();

        println!("READ:    {}", if can_read { "Yes" } else { "No" });
        println!("WRITE:   {}", if can_write { "Yes" } else { "No" });
        println!("EXECUTE: {}", if can_execute { "Yes" } else { "No" });
        Ok(())
    }

    fn cmd_meta(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: meta <ls|get|set|rm> <path> [key] [type] [value]".to_string());
        }

        let action = positional[0];
        if positional.len() < 2 {
            return Err("Missing path argument".to_string());
        }

        let path = self.resolve_path(positional[1]);
        let obj_id = self.ns_mgr.resolve(&path, self.ns_mgr.root())?;
        let context = self
            .proc_mgr
            .lock()
            .map_err(|_| "Process manager lock poisoned")?
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();
        let object = self.obj_mgr.lookup(obj_id).ok_or("Object not found")?;
        let metadata_rights = if matches!(action, "set" | "rm") {
            Rights {
                write: true,
                ..Rights::empty()
            }
        } else {
            Rights::read_only()
        };
        hyber_core::SecurityManager::check_access(
            &context,
            object.owner,
            object.group,
            object.permissions,
            metadata_rights,
        )?;

        match action {
            "ls" => {
                if let Some(meta_list) = self.obj_mgr.list_metadata(obj_id) {
                    if meta_list.is_empty() {
                        println!("No extended metadata.");
                    } else {
                        for (k, v) in meta_list {
                            println!("{} = {}", k, v);
                        }
                    }
                }
            }
            "get" => {
                if positional.len() < 3 {
                    return Err("Missing key argument".to_string());
                }
                let key = positional[2];
                if let Some(val) = self.obj_mgr.get_metadata(obj_id, key) {
                    println!("{}", val);
                } else {
                    println!("Key not found.");
                }
            }
            "rm" => {
                if positional.len() < 3 {
                    return Err("Missing key argument".to_string());
                }
                let key = positional[2];
                if self.obj_mgr.remove_metadata(obj_id, key)? {
                    println!("Metadata removed.");
                } else {
                    println!("Key not found.");
                }
            }
            "set" => {
                if positional.len() < 5 {
                    return Err(
                        "Usage: meta set <path> <key> <type> <value>\nTypes: string, int, bool"
                            .to_string(),
                    );
                }
                let key = positional[2];
                let val_type = positional[3];
                // The value might have spaces, so join the remaining positional args
                let val_str = positional[4..].join(" ");

                let meta_val = match val_type {
                    "string" => MetadataValue::String(val_str),
                    "int" => {
                        let i = val_str.parse::<i64>().map_err(|_| "Invalid integer")?;
                        MetadataValue::Integer(i)
                    }
                    "bool" => {
                        let b = val_str
                            .parse::<bool>()
                            .map_err(|_| "Invalid boolean (true/false)")?;
                        MetadataValue::Boolean(b)
                    }
                    _ => return Err("Unsupported type. Use: string, int, bool".to_string()),
                };

                self.obj_mgr.set_metadata(obj_id, key, meta_val)?;
                println!("Metadata set.");
            }
            _ => return Err("Unknown meta action. Use: ls, get, set, rm".to_string()),
        }
        Ok(())
    }

    fn whoami_name(&self) -> Result<String, String> {
        if let Some(session) = &self.session {
            return session.username().map_err(|error| error.to_string());
        }
        let processes = self
            .proc_mgr
            .lock()
            .map_err(|_| "process manager unavailable")?;
        let uid = processes
            .get_process(self.process_id)
            .ok_or("shell process missing")?
            .security_context
            .user_id;
        // Bootstrap mode has no account registry. Only the reserved root
        // identity has a known name; numeric su must not fabricate a username.
        if uid == UserId(0) {
            Ok("root".into())
        } else {
            Err(format!(
                "No Hyber account name available for UID {} in bootstrap mode",
                uid.0
            ))
        }
    }

    fn cmd_whoami(&self, args: &[&str]) -> Result<(), String> {
        if !args.is_empty() {
            return Err("Usage: whoami".into());
        }
        println!("{}", self.whoami_name()?);
        Ok(())
    }

    fn current_security_context(&self) -> Result<SecurityContext, String> {
        if let Some(session) = &self.session {
            return session.context().map_err(|error| error.to_string());
        }
        self.proc_mgr
            .lock()
            .map_err(|_| "process manager unavailable")?
            .get_process(self.process_id)
            .map(|process| process.security_context.clone())
            .ok_or_else(|| "shell process missing".into())
    }

    fn cmd_chmod(&mut self, args: &[&str]) -> Result<(), String> {
        if args.len() != 2
            || args[0].is_empty()
            || args[0].len() > 4
            || !args[0].bytes().all(|b| matches!(b, b'0'..=b'7'))
        {
            return Err("Usage: chmod <octal-mode: 000..777> <path>".into());
        }
        let mode = u32::from_str_radix(args[0], 8).map_err(|_| "invalid mode")?;
        let context = self.current_security_context()?;
        let path = self.resolve_path(args[1]);
        VFS::check_traversal(&self.ns_mgr, &self.obj_mgr, &context, &path, false)?;
        let id = self.vfs.lookup(&self.ns_mgr, &path)?;
        self.obj_mgr.chmod(id, &context, mode)
    }

    fn cmd_chgrp(&mut self, args: &[&str]) -> Result<(), String> {
        if args.len() != 2 {
            return Err("Usage: chgrp <group-name> <path>".into());
        }
        let context = self.current_security_context()?;
        let group = match &self.session {
            Some(session) => session
                .group_id(args[0])
                .map_err(|error| error.to_string())?,
            None if args[0] == "root" => GroupId(0),
            None => return Err("Named groups require an authenticated account registry".into()),
        };
        let path = self.resolve_path(args[1]);
        VFS::check_traversal(&self.ns_mgr, &self.obj_mgr, &context, &path, false)?;
        let id = self.vfs.lookup(&self.ns_mgr, &path)?;
        self.obj_mgr.chgrp(id, &context, group)
    }

    fn cmd_su(&mut self, args: &[&str]) -> Result<(), String> {
        if self.session.is_some() {
            return Err(
                "Authenticated sessions cannot use numeric su; log in as the target account."
                    .into(),
            );
        }
        let context = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .ok_or("process missing")?
            .security_context
            .clone();
        hyber_core::SecurityManager::check_capability(&context, "CAP_SYS_ADMIN")?;
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: su <uid> [gid]".to_string());
        }

        let uid: u32 = positional[0].parse().map_err(|_| "Invalid UID")?;
        let gid: u32 = if positional.len() > 1 {
            positional[1].parse().map_err(|_| "Invalid GID")?
        } else {
            uid // Default gid to uid
        };

        if let Some(proc) = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process_mut(self.process_id)
        {
            proc.security_context.user_id = UserId(uid);
            proc.security_context.group_id = GroupId(gid);
            proc.security_context.supplementary_groups.clear();
            // If changing to non-root, clear capabilities
            if uid != 0 {
                proc.security_context.capabilities.clear();
            }
            println!("Switched to UID: {}, GID: {}", uid, gid);
        }
        Ok(())
    }

    fn cmd_ps(&self, _args: &[&str]) -> Result<(), String> {
        let proc_mgr = self.proc_mgr.lock().unwrap();
        let processes = proc_mgr.list_processes();
        println!(
            "{:<5} | {:<5} | {:<10} | {:<5} | GID",
            "PID", "PPID", "State", "UID"
        );
        println!("{}", "-".repeat(55));
        for p in processes {
            let ppid_str = p
                .parent_id
                .map(|id| id.0.to_string())
                .unwrap_or("-".to_string());
            println!(
                "{:<5} | {:<5} | {:<10?} | {:<5} | {:<5}",
                p.id.0,
                ppid_str,
                p.state,
                p.security_context.user_id.0,
                p.security_context.group_id.0
            );
        }
        Ok(())
    }

    fn cmd_lsdev(&self, _args: &[&str]) -> Result<(), String> {
        let mgr = self
            .dev_mgr
            .lock()
            .map_err(|_| "DeviceManager lock poisoned")?;
        let devices = mgr.list_devices();
        if devices.is_empty() {
            println!("No devices registered.");
            return Ok(());
        }
        println!(
            "{:<12} | {:<10} | {:<8} | Description",
            "Name", "Class", "Online"
        );
        println!("{}", "-".repeat(60));
        for d in devices {
            println!(
                "{:<12} | {:<10?} | {:<8} | {}",
                d.name, d.class, d.online, d.description
            );
        }
        Ok(())
    }

    fn cmd_lssvc(&self, _args: &[&str]) -> Result<(), String> {
        let mgr = self
            .svc_mgr
            .lock()
            .map_err(|_| "ServiceManager lock poisoned")?;
        let services = mgr.list_services();
        if services.is_empty() {
            println!("No services registered.");
            return Ok(());
        }
        println!(
            "{:<14} | {:<10} | {:<6} | Description",
            "Name", "State", "PID"
        );
        println!("{}", "-".repeat(62));
        for s in services {
            let pid_str = s
                .process_id
                .map(|p| p.0.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{:<14} | {:<10} | {:<6} | {}",
                s.name, s.state, pid_str, s.description
            );
        }
        Ok(())
    }

    fn cmd_tree(&self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        let path_str = positional.first().copied().unwrap_or("/");
        let path = self.resolve_path(path_str);
        println!("{}", path);
        self.tree_recursive(&path, "", 0, 4)?;
        Ok(())
    }

    fn tree_recursive(
        &self,
        path: &Path,
        prefix: &str,
        depth: usize,
        max_depth: usize,
    ) -> Result<(), String> {
        if depth >= max_depth {
            return Ok(());
        }
        let security_context = self
            .proc_mgr
            .lock()
            .map_err(|_| "Process manager lock poisoned")?
            .get_process(self.process_id)
            .ok_or("Shell process not found")?
            .security_context
            .clone();
        let entries =
            self.vfs
                .enumerate_secure(&self.ns_mgr, &self.obj_mgr, &security_context, path)?;
        let mut sorted = entries;
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let count = sorted.len();
        for (i, (name, obj_id)) in sorted.into_iter().enumerate() {
            let is_last = i == count - 1;
            let connector = if is_last { "└── " } else { "├── " };
            let obj_type = self
                .obj_mgr
                .lookup(obj_id)
                .map(|o| format!(" [{}]", o.object_type))
                .unwrap_or_default();
            println!("{}{}{}{}", prefix, connector, name, obj_type);
            // Recurse into directories
            if self
                .obj_mgr
                .lookup(obj_id)
                .map(|o| o.object_type == ObjectType::Directory)
                .unwrap_or(false)
            {
                let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
                let child_path_str = format!("{}/{}", path, name);
                let child_path = Path::parse(&child_path_str).normalize();
                let _ = self.tree_recursive(&child_path, &child_prefix, depth + 1, max_depth);
            }
        }
        Ok(())
    }

    fn cmd_exit(&mut self, _args: &[&str]) -> Result<(), String> {
        self.running = false;
        Ok(())
    }

    fn cmd_cls(&mut self, _args: &[&str]) -> Result<(), String> {
        print!("\x1B[2J\x1B[1;1H");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        Ok(())
    }

    fn cmd_help(&self, _args: &[&str]) -> Result<(), String> {
        println!("=== HyberKOS Shell Commands (Phase 12.5) ===\n");
        println!("Standard Commands:");
        println!("  pwd                     Print working directory");
        println!("  whoami                  Print current Hyber account name");
        println!("  chmod <mode> <path>      Set runtime Hyber rwx permissions (octal)");
        println!("  chgrp <group> <path>     Set runtime Hyber object group");
        println!("  cd <path>               Change directory");
        println!("  ls [-l] [-a] [path]     List directory contents");
        println!("  mkdir [-p] <path>       Create directory");
        println!("  touch <path>            Create file / update timestamp");
        println!("  rm [-r] <path>          Remove file/directory");
        println!("  mv <src> <dest>         Move/rename");
        println!("  cp <src> <dest>         Copy file");
        println!("  cat <path>              Print file contents");
        println!("  cls | clear             Clear the terminal screen");
        println!();
        println!("HyberKOS Native Commands:");
        println!("  list [path]             List with Object details");
        println!("  look <path>             Deep Object inspection");
        println!("  tree [path]             Recursive namespace tree (max 4 levels)");
        println!("  acquire <path> [mode]   Get Handle (r/w/rw)");
        println!("  release <handle_id>     Release Handle");
        println!("  handles                 Show Handle Table");
        println!("  mnts                    Show mount points");
        println!("  rights <path>           Show access rights");
        println!("  meta <ls|get|set|rm>    Manage extended metadata");
        println!();
        println!("Phase 10/11 Commands:");
        println!("  su <uid> [gid]          Switch effective user ID");
        println!("  ps                      List processes");
        println!("  lsdev                   List registered devices (/devices)");
        println!("  lssvc                   List registered services (/services)");
        println!();
        println!("Phase 12/12.5 — Lua Runtime & Orchestration:");
        println!("  lua <script>            Execute inline Lua (quote the script)");
        println!("  luafile <path>          Execute a Lua script file from the namespace");
        println!("  Lua API:");
        println!("    hyber.fs.open(path, mode)      Open file (r/w/rw)");
        println!("    file:read() / file:write(s)    Read/write data");
        println!("    file:close()                   Close handle");
        println!("    hyber.ns.exists(path)          Check if path exists");
        println!("    hyber.ns.list(path)            List directory entries");
        println!("    hyber.obj.info(path)           Object metadata table");
        println!("    hyber.obj.meta_get/set(...)    Extended metadata");
        println!("    hyber.proc.pid() / .uid()      Process info");
        println!("    hyber.proc.spawn(path) / .wait(pid) Process control");
        println!("    hyber.sec.check_access(...)     Security check");
        println!("    hyber.log.info/warn/error(s)   Logging");
        println!("    hyber.cls()                    Clear terminal screen");
        println!();
        println!("Virtual Namespace (Phase 11):");
        println!("  /processes    -- live processes   (ProcessProvider)");
        println!("  /devices      -- virtual devices  (DeviceProvider)");
        println!("  /services     -- system services  (ServiceProvider)");
        println!("  /runtime      -- volatile data    (MemFS)");
        println!("  /temporary    -- scratch space    (MemFS)");
        println!("  /system, /users, /apps, /data, /config,");
        println!("  /packages, /volumes, /developer   (HostFS)");
        println!();
        println!("  exit                    Exit shell");
        println!("  help                    Show this help");
        Ok(())
    }

    // ── Phase 12 — Lua Commands ───────────────────────────────────────────────

    /// `lua <inline_script>`  — execute a Lua one-liner or short script.
    ///
    /// Example:
    ///   lua "hyber.log.info('Hello from Lua!')"  
    ///   lua "local f = hyber.fs.open('/temporary/.keep','r'); print(f:read()); f:close()"
    fn cmd_lua(&mut self, args: &[&str]) -> Result<(), String> {
        if args.is_empty() {
            return Err(
                "Usage: lua <script>\nExample: lua \"hyber.log.info('hi')\"\nFor files: luafile <path>"
                    .to_string(),
            );
        }
        let mut script = args.join(" ");
        // Strip outer quotes if the user quoted the script to protect ';'
        let len = script.len();
        if len >= 2 {
            let first = script.chars().next().unwrap();
            let last = script.chars().last().unwrap();
            if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
                script = script[1..len - 1].to_string();
            }
        }
        self.run_lua_script(&script)
    }

    /// `luafile <hyber-path>` — read a Lua script file from the HyberKOS
    /// namespace and execute it.
    ///
    /// Example:
    ///   luafile /apps/scripts/hello.lua
    fn cmd_luafile(&mut self, args: &[&str]) -> Result<(), String> {
        let (_flags, positional) = Self::parse_flags(args);
        if positional.is_empty() {
            return Err("Usage: luafile <path>".to_string());
        }
        let path = self.resolve_path(positional[0]);

        // Read the script via VFS (works for HostFS, MemFS, etc.)
        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .unwrap()
            .security_context
            .clone();
        let handle = self.vfs.open(
            &self.ns_mgr,
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            &sec_ctx,
            &path,
            Rights::read_only(),
        )?;

        let mut script_bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = self.vfs.read_secure(
                &mut self.handle_mgr,
                &self.obj_mgr,
                self.process_id,
                &sec_ctx,
                handle,
                &mut buf,
            )?;
            if n == 0 {
                break;
            }
            script_bytes.extend_from_slice(&buf[..n]);
        }
        self.vfs.close(
            &mut self.handle_mgr,
            &mut self.obj_mgr,
            self.process_id,
            handle,
        )?;

        let script = String::from_utf8(script_bytes)
            .map_err(|_| "Lua script file is not valid UTF-8".to_string())?;
        self.run_lua_script(&script)
    }

    /// Internal: hand state over to the Lua runtime, run the script, then
    /// swap the (potentially mutated) state back in.
    fn run_lua_script(&mut self, script: &str) -> Result<(), String> {
        // We need to *move* the managers into the Lua runtime and get them back.
        // Use std::mem::replace with placeholder values.
        let vfs = std::mem::replace(&mut self.vfs, VFS::new());
        let ns_mgr = std::mem::replace(&mut self.ns_mgr, NamespaceManager::new_placeholder());
        let handle_mgr = std::mem::replace(&mut self.handle_mgr, HandleManager::new());
        let obj_mgr = std::mem::replace(&mut self.obj_mgr, ObjectManager::new());

        let sec_ctx = self
            .proc_mgr
            .lock()
            .unwrap()
            .get_process(self.process_id)
            .unwrap()
            .security_context
            .clone();

        let (vfs, ns_mgr, handle_mgr, obj_mgr, exec_res) = hyber_lua::run_lua_script_with_session(
            script,
            vfs,
            ns_mgr,
            handle_mgr,
            obj_mgr,
            self.proc_mgr.clone(),
            self.process_id,
            sec_ctx,
            self.session.clone(),
        );

        // Always restore the state
        self.vfs = vfs;
        self.ns_mgr = ns_mgr;
        self.handle_mgr = handle_mgr;
        self.obj_mgr = obj_mgr;

        match exec_res {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("[lua] {}", e);
                Err(format!("Lua error: {}", e))
            }
        }
    }

    /// Cleanup: release all open handles
    fn cleanup(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = session.logout();
        }
        let handle_ids = self.handle_mgr.list_handle_ids(self.process_id);
        for hid in handle_ids {
            let _ = self.vfs.close(
                &mut self.handle_mgr,
                &mut self.obj_mgr,
                self.process_id,
                hid,
            );
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let session = if args.len() == 5 && args[1] == "--auth" {
        let result = args[3]
            .parse::<u64>()
            .map_err(|_| "invalid block count".to_string())
            .and_then(|blocks| {
                hyber_auth::hosted_login(
                    &args[2],
                    blocks,
                    &args[4],
                    hyber_auth::SessionKind::Interactive,
                )
                .map_err(|e| e.to_string())
            });
        match result {
            Ok(session) => Some(session),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    } else if args.len() == 1 {
        None
    } else {
        eprintln!("usage: hyber-shell [--auth <image> <blocks> <username>]");
        std::process::exit(1);
    };
    // Default host root: ~/hyber-host
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let host_root = PathBuf::from(home).join("hyber-host");

    match HyberShell::new(host_root.clone()) {
        Ok(mut shell) => {
            shell.session = session;
            if shell.session.is_some() {
                if let Err(error) = shell.ensure_session_home() {
                    eprintln!("Failed to prepare authenticated home: {error}");
                    shell.cleanup();
                    std::process::exit(1);
                }
            }
            println!("HostFS mounted at: {:?}\n", host_root);
            shell.run();
        }
        Err(e) => {
            eprintln!("Failed to start HyberKOS Shell: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use hyber_auth::{AuthService, SessionGuard, SessionKind, SystemClock};

    #[test]
    fn numeric_su_cannot_regain_root_and_authenticated_logout_stops_dispatch() {
        let root = std::env::temp_dir().join(format!("hyber-shell-session-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let mut shell = HyberShell::new(root.clone()).unwrap();
        assert_eq!(shell.whoami_name().unwrap(), "root");
        assert!(shell.cmd_whoami(&["extra"]).is_err());
        shell.cmd_touch(&["/temporary/permission-test"]).unwrap();
        shell
            .cmd_chmod(&["640", "/temporary/permission-test"])
            .unwrap();
        shell
            .cmd_chgrp(&["root", "/temporary/permission-test"])
            .unwrap();
        assert!(shell
            .cmd_chmod(&["4755", "/temporary/permission-test"])
            .is_err());
        shell.cmd_su(&["1000", "1000"]).unwrap();
        assert!(shell
            .cmd_chmod(&["777", "/temporary/permission-test"])
            .is_err());
        assert!(shell
            .cmd_chgrp(&["root", "/temporary/permission-test"])
            .is_err());
        assert!(shell.whoami_name().is_err());
        assert!(shell.cmd_su(&["0"]).is_err());
        let password = b"temporary shell test password";
        let mut auth = AuthService::provision(password, Arc::new(SystemClock)).unwrap();
        let token = auth
            .login("root", password, SessionKind::Interactive, 600)
            .unwrap();
        let session = SessionGuard::new(Arc::new(Mutex::new(auth)), token).unwrap();
        shell.session = Some(session.clone());
        assert_eq!(shell.whoami_name().unwrap(), "root");
        shell.ensure_session_home().unwrap();
        let home = shell
            .ns_mgr
            .resolve(&Path::parse("/users/root"), shell.ns_mgr.root())
            .unwrap();
        let home_object = shell.obj_mgr.lookup(home).unwrap();
        assert_eq!(home_object.owner, UserId(0));
        assert_eq!(home_object.group, GroupId(0));
        assert_eq!(home_object.permissions, 0o700);
        assert!(shell.cmd_su(&["0"]).is_err());
        shell.execute_single("pwd");
        assert!(shell.running);
        session.logout().unwrap();
        assert!(shell.whoami_name().is_err());
        shell.execute_single("pwd");
        assert!(!shell.running);
        shell.cleanup();
        drop(shell);
        std::fs::remove_dir_all(root).unwrap();
    }
}
