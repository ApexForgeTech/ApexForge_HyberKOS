# Hosted shell input and profiles

The shell input controller is a reusable Rust API, not a terminal-specific
history engine. `Event::Previous` and `Event::Next` change the buffer only;
only `Submit` executes. Up/Down and Ctrl-P/Ctrl-N navigate, Left/Right and
Home/End edit, Ctrl-R searches using the current buffer, Ctrl-C cancels, and
Ctrl-D exits an empty buffer or deletes at the cursor. Tab requests completion.
Bracketed paste is bounded and never submits commands automatically.

The parser supports single/double quotes, escaping, empty quoted arguments,
and unquoted semicolon separators. It validates the whole line before any
command runs. It does not implement POSIX variable substitution, pipes,
redirection, command substitution, or host command execution.

## Profiles

Interactive shells load `/etc/hyber/profile.lua`, then the user's
`.hyber_profile.lua`, `.hyber_login.lua` for authenticated login shells, and
`.hyberrc.lua` for interactive shells. Non-interactive input skips profiles
unless `--profiles` is given (interactive-only profiles still do not run).
Files must be owned by the appropriate user (root for the system profile),
with no group/other write permission; ancestors must also be trusted.
Missing profiles are optional. Invalid/inaccessible profiles warn and restore
safe defaults instead of preventing recovery.

Example `/users/alice/.hyberrc.lua`:

```lua
return {
  aliases = { ll = "ls -l", md = "mkdir" },
  env = { EDITOR = "hyber-editor" },
  history = true,
  prompt = function(context)
    return context.user .. ":" .. context.cwd .. "> "
  end,
  bindings = { Up = "previous", Down = "next" },
  complete = function(prefix)
    if prefix == "l" then return { "ls", "list", "look" } end
    return {}
  end,
  before_command = function(context) return nil end,
  after_command = function(context) return nil end,
}
```

Callbacks receive a copy of `{cwd, user, command, env}`; completion receives
the input prefix. Hooks receive only the command name, not secret arguments.
They return optional display text, not commands. Prompt may also be a string.
Allowed binding keys: Up, Down, CtrlP, CtrlN, CtrlR, CtrlA, CtrlE. Actions:
previous, next, search, home, end, cancel. Submission cannot be rebound.
The environment is a session-local map (`env [name [value]]`), never the host
process environment or a permission grant. Supported fields are strictly
validated. No arbitrary shell command callback or filesystem API is exposed.

Each profile is limited to 64 KiB, Lua to 2 MiB, execution/callbacks to
100,000 instructions, and display strings to 1,024 bytes without control
characters. A failing callback resets profile state. Lua has no host I/O,
module loader, process API, or protected-call escape from instruction limits.

## Aliases

```text
alias ll='ls -l'
ll '/users/alice/Documents'
alias ll
alias
unalias ll
unalias --all
```

Definitions contain exactly one parsed command; call arguments are appended
as tokens without string re-parsing. Expansion allows at most 16 levels and
4,096 bytes; cycles fail. Up to 128 aliases are allowed. Control commands
`alias`, `unalias`, `history`, `env`, and `exit` cannot be shadowed. Alias
definitions are session-local; place them in a profile for persistence.

## History and privacy

History defaults to volatile memory. `history save on` enables persistence for
this session; `history=true` in a profile enables it across restarts. Storage
is atomic provider metadata `shell.history` on the private, user-owned mode
0700 `/users/<user>/.local/state/hyber-shell` directory. HostFS uses its xattr
record; there is no host history file. Limits are 100 entries, 1,024 bytes per
entry, and 24 KiB total; host xattr capacity can impose a smaller effective
limit, reported as a save warning. Consecutive duplicates are omitted.

`history clear` clears memory and, when saving is enabled, persisted history.
`history save off` stops further saves but does not erase an existing snapshot.
To erase it, clear while saving is on. `history search <text>` searches and
`history exclude <pattern>` excludes declared sensitive text. Lines beginning
with whitespace, alias/env/Lua/history commands, password-related commands,
and common secret markers are excluded; expanded aliases are checked too.
Unknown unlabeled secrets cannot be detected: prefix sensitive commands with a
space or explicitly exclude their marker. Password login prompts never enter
this controller. Identity changes clear history, aliases, and environment.

## Hosted launch and verification

```text
hyber-shell [--host-root <directory>] [--profiles] [--auth <image> <blocks> <user>]
cargo test -p hyber-shell
```

The order of options above is significant. `--host-root` selects the isolated
host backing directory, not a Hyber command path. The default is the existing
`hyber-host` directory under the host home. The no-auth mode is trusted
development bootstrap, not a deployed multi-user login authority. Terminal
I/O is currently Linux-hosted; future GUI frontends reuse the public controller.
