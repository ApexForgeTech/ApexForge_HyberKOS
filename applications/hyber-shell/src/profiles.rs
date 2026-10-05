//! Profiles are configuration, never filesystem/process/security authority.
use crate::input::{valid_name, Aliases};
use mlua::{HookTriggers, Lua, LuaOptions, RegistryKey, StdLib, Table, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

pub fn profile_paths(home: &str, login: bool, interactive: bool, explicit: bool) -> Vec<String> {
    if !interactive && !explicit {
        return vec![];
    }
    let mut paths = vec![
        "/etc/hyber/profile.lua".into(),
        format!("{home}/.hyber_profile.lua"),
    ];
    if login {
        paths.push(format!("{home}/.hyber_login.lua"));
    }
    if interactive {
        paths.push(format!("{home}/.hyberrc.lua"));
    }
    paths
}

pub struct Profiles {
    lua: Lua,
    budget: Arc<AtomicUsize>,
    pub aliases: Aliases,
    pub environment: BTreeMap<String, String>,
    pub bindings: BTreeMap<String, String>,
    pub persistent_history: bool,
    prompt_text: String,
    functions: BTreeMap<String, RegistryKey>,
    pub safe_mode: bool,
}
impl Default for Profiles {
    fn default() -> Self {
        Self::new().expect("restricted profile runtime")
    }
}
impl Profiles {
    pub fn new() -> Result<Self, String> {
        let lua = Lua::new_with(
            StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8,
            LuaOptions::default(),
        )
        .map_err(|e| e.to_string())?;
        lua.set_memory_limit(2 * 1024 * 1024)
            .map_err(|e| e.to_string())?;
        // No catchable hook loop, dynamic code loading, host I/O or modules.
        for name in [
            "pcall",
            "xpcall",
            "load",
            "loadfile",
            "dofile",
            "require",
            "io",
            "os",
            "debug",
            "package",
            "coroutine",
            "print",
        ] {
            lua.globals()
                .set(name, Value::Nil)
                .map_err(|e| e.to_string())?;
        }
        let budget = Arc::new(AtomicUsize::new(0));
        let counter = budget.clone();
        lua.set_hook(
            HookTriggers::new().every_nth_instruction(1000),
            move |_, _| {
                if counter.fetch_add(1000, Ordering::Relaxed) >= 100_000 {
                    return Err(mlua::Error::RuntimeError(
                        "profile instruction limit".into(),
                    ));
                }
                Ok(())
            },
        );
        Ok(Self {
            lua,
            budget,
            aliases: Aliases::default(),
            environment: BTreeMap::new(),
            bindings: BTreeMap::new(),
            persistent_history: false,
            prompt_text: "hyber> ".into(),
            functions: BTreeMap::new(),
            safe_mode: false,
        })
    }
    pub fn fallback(&mut self) {
        *self = Self::default();
        self.safe_mode = true;
    }
    pub fn load(&mut self, name: &str, source: &str) -> Result<(), String> {
        let result = self.load_inner(name, source);
        if result.is_err() {
            self.fallback();
        }
        result
    }
    fn load_inner(&mut self, name: &str, source: &str) -> Result<(), String> {
        if source.len() > 64 * 1024 {
            return Err("profile too large".into());
        }
        self.budget.store(0, Ordering::Relaxed);
        let table: Table = self
            .lua
            .load(source)
            .set_mode(mlua::ChunkMode::Text)
            .set_name(name)
            .eval()
            .map_err(|e| e.to_string())?;
        for pair in table.clone().pairs::<String, Value>() {
            let (key, _) = pair.map_err(|e| e.to_string())?;
            if !matches!(
                key.as_str(),
                "aliases"
                    | "env"
                    | "prompt"
                    | "history"
                    | "bindings"
                    | "complete"
                    | "before_command"
                    | "after_command"
            ) {
                return Err(format!("unknown profile key: {key}"));
            }
        }
        if let Some(aliases) = table
            .get::<_, Option<Table>>("aliases")
            .map_err(|e| e.to_string())?
        {
            let mut values = BTreeMap::new();
            for pair in aliases.pairs::<String, String>() {
                let (k, v) = pair.map_err(|e| e.to_string())?;
                values.insert(k, v);
            }
            for (k, v) in values {
                self.aliases.set(&k, &v)?;
            }
        }
        if let Some(env) = table
            .get::<_, Option<Table>>("env")
            .map_err(|e| e.to_string())?
        {
            for pair in env.pairs::<String, String>() {
                let (k, v) = pair.map_err(|e| e.to_string())?;
                set_env(&mut self.environment, &k, &v)?;
            }
        }
        if let Some(enabled) = table
            .get::<_, Option<bool>>("history")
            .map_err(|e| e.to_string())?
        {
            self.persistent_history = enabled;
        }
        if let Some(bindings) = table
            .get::<_, Option<Table>>("bindings")
            .map_err(|e| e.to_string())?
        {
            for pair in bindings.pairs::<String, String>() {
                let (key, action) = pair.map_err(|e| e.to_string())?;
                if !matches!(
                    key.as_str(),
                    "Up" | "Down" | "CtrlP" | "CtrlN" | "CtrlR" | "CtrlA" | "CtrlE"
                ) || !matches!(
                    action.as_str(),
                    "previous" | "next" | "search" | "home" | "end" | "cancel"
                ) {
                    return Err("invalid input binding".into());
                }
                self.bindings.insert(key, action);
            }
        }
        for key in ["prompt", "complete", "before_command", "after_command"] {
            match table.get::<_, Value>(key).map_err(|e| e.to_string())? {
                Value::Nil => (),
                Value::String(s) if key == "prompt" => {
                    self.prompt_text = bounded_text(s.to_str().map_err(|e| e.to_string())?)?;
                    self.functions.remove(key);
                }
                Value::Function(function) => {
                    let registry = self
                        .lua
                        .create_registry_value(function)
                        .map_err(|e| e.to_string())?;
                    self.functions.insert(key.into(), registry);
                }
                _ => return Err(format!("invalid profile callback: {key}")),
            }
        }
        Ok(())
    }
    pub fn set_env(&mut self, name: &str, value: &str) -> Result<(), String> {
        set_env(&mut self.environment, name, value)
    }
    pub fn prompt(&mut self, cwd: &str, user: &str) -> Result<String, String> {
        if !self.functions.contains_key("prompt") {
            return Ok(self.prompt_text.clone());
        }
        self.callback("prompt", cwd, user, "")
    }
    pub fn callback(
        &mut self,
        key: &str,
        cwd: &str,
        user: &str,
        command: &str,
    ) -> Result<String, String> {
        let result = (|| {
            let Some(registry) = self.functions.get(key) else {
                return Ok(String::new());
            };
            self.budget.store(0, Ordering::Relaxed);
            let function: mlua::Function = self
                .lua
                .registry_value(registry)
                .map_err(|e| e.to_string())?;
            let context = self.lua.create_table().map_err(|e| e.to_string())?;
            context.set("cwd", cwd).map_err(|e| e.to_string())?;
            context.set("user", user).map_err(|e| e.to_string())?;
            context.set("command", command).map_err(|e| e.to_string())?;
            let env = self
                .lua
                .create_table_from(self.environment.clone())
                .map_err(|e| e.to_string())?;
            context.set("env", env).map_err(|e| e.to_string())?;
            let text: Option<String> = function.call(context).map_err(|e| e.to_string())?;
            bounded_text(text.as_deref().unwrap_or_default())
        })();
        if result.is_err() {
            self.fallback();
        }
        result
    }
    pub fn complete(&mut self, prefix: &str) -> Result<Vec<String>, String> {
        let result = (|| {
            let Some(registry) = self.functions.get("complete") else {
                return Ok(vec![]);
            };
            self.budget.store(0, Ordering::Relaxed);
            let function: mlua::Function = self
                .lua
                .registry_value(registry)
                .map_err(|e| e.to_string())?;
            let values: Vec<String> = function.call(prefix).map_err(|e| e.to_string())?;
            if values.len() > 128 {
                return Err("completion limit".into());
            }
            for value in &values {
                bounded_text(value)?;
            }
            Ok(values)
        })();
        if result.is_err() {
            self.fallback();
        }
        result
    }
}
fn set_env(
    environment: &mut BTreeMap<String, String>,
    name: &str,
    value: &str,
) -> Result<(), String> {
    if !valid_name(name)
        || value.len() > 1024
        || value.chars().any(char::is_control)
        || (environment.len() >= 128 && !environment.contains_key(name))
    {
        return Err("invalid session environment entry".into());
    }
    environment.insert(name.into(), value.into());
    Ok(())
}
fn bounded_text(text: &str) -> Result<String, String> {
    if text.len() > 1024 || text.chars().any(char::is_control) {
        return Err("invalid profile output".into());
    }
    Ok(text.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordering_and_noninteractive_policy() {
        assert!(profile_paths("/users/a", true, false, false).is_empty());
        assert_eq!(
            profile_paths("/users/a", true, true, false),
            vec![
                "/etc/hyber/profile.lua",
                "/users/a/.hyber_profile.lua",
                "/users/a/.hyber_login.lua",
                "/users/a/.hyberrc.lua"
            ]
        );
        assert_eq!(profile_paths("/users/a", false, true, false).len(), 3);
    }
    #[test]
    fn sandbox_and_safe_mode() {
        let mut p = Profiles::default();
        p.load("test", "assert(io == nil and os == nil and require == nil and pcall == nil); return {aliases={ll='ls -l'}, env={EDITOR='hyber'}, prompt=function(c) return c.user..'> ' end, history=true}").unwrap();
        assert_eq!(p.prompt("/", "alice").unwrap(), "alice> ");
        assert!(p.persistent_history);
        assert!(p.load("bad", "while true do end").is_err());
        assert!(p.safe_mode);
        assert!(p.aliases.entries().is_empty());
        assert!(p.environment.is_empty());
        p.load(
            "callback",
            "return {prompt=function() while true do end end}",
        )
        .unwrap();
        assert!(p.prompt("/", "a").is_err());
        assert!(p.safe_mode);
        assert!(p.load("host", "os.execute('true')").is_err());
    }

    #[test]
    fn callbacks_cannot_mutate_session_environment_or_submit_input() {
        let mut p = Profiles::default();
        p.load("callbacks", "return {env={EDITOR='hyber'}, bindings={Up='previous'}, complete=function(prefix) return {prefix..'file'} end, before_command=function(c) c.env.EDITOR='changed'; return c.command end}").unwrap();
        assert_eq!(p.complete("my").unwrap(), vec!["myfile"]);
        assert_eq!(
            p.callback("before_command", "/", "alice", "ls").unwrap(),
            "ls"
        );
        assert_eq!(p.environment["EDITOR"], "hyber");
        assert_eq!(p.bindings["Up"], "previous");
        assert!(p
            .load("unsafe-binding", "return {bindings={Up='submit'}}")
            .is_err());
        assert!(p.safe_mode);
    }
}
