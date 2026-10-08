use std::collections::{BTreeMap, HashSet};

pub const MAX_LINE: usize = 4096;
const HISTORY_LIMIT: usize = 100;

/// Parse the whole submission before executing anything. Quotes protect
/// separators; backslash escapes outside single quotes. No substitution,
/// pipes, redirection or implicit host-shell execution is performed.
pub fn parse(line: &str) -> Result<Vec<Vec<String>>, String> {
    if line.len() > MAX_LINE || line.chars().any(|c| c.is_control() && c != '\t') {
        return Err("invalid or oversized command line".into());
    }
    let mut commands = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut escape = false;
    for c in line.chars() {
        if escape {
            word.push(c);
            started = true;
            escape = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            started = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            started = true;
        } else if c.is_whitespace() || c == ';' {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
            if c == ';' && !words.is_empty() {
                commands.push(std::mem::take(&mut words));
            }
        } else {
            word.push(c);
            started = true;
        }
    }
    if quote.is_some() || escape {
        return Err("unterminated quote or escape".into());
    }
    if started {
        words.push(word);
    }
    if !words.is_empty() {
        commands.push(words);
    }
    Ok(commands)
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[derive(Clone, Default, Debug)]
pub struct Aliases(BTreeMap<String, String>);
impl Aliases {
    pub fn set(&mut self, name: &str, replacement: &str) -> Result<(), String> {
        if !valid_name(name) || matches!(name, "alias" | "unalias" | "history" | "env" | "exit") {
            return Err("invalid or reserved alias name".into());
        }
        let parsed = parse(replacement)?;
        if parsed.len() != 1 || parsed[0][0].is_empty() {
            return Err("alias must expand to one command".into());
        }
        if self.0.len() >= 128 && !self.0.contains_key(name) {
            return Err("alias limit reached".into());
        }
        let old = self.0.insert(name.into(), replacement.into());
        if let Err(error) = self.expand(vec![name.into()]) {
            if let Some(old) = old {
                self.0.insert(name.into(), old);
            } else {
                self.0.remove(name);
            }
            return Err(error);
        }
        Ok(())
    }
    pub fn expand(&self, mut words: Vec<String>) -> Result<Vec<String>, String> {
        let mut seen = HashSet::new();
        for _ in 0..16 {
            let Some(first) = words.first() else {
                return Ok(words);
            };
            let Some(value) = self.0.get(first) else {
                return Ok(words);
            };
            if !seen.insert(first.clone()) {
                return Err("alias cycle".into());
            }
            let mut expanded = parse(value)?.remove(0);
            expanded.extend(words.into_iter().skip(1));
            if expanded.iter().map(String::len).sum::<usize>() > MAX_LINE {
                return Err("alias expansion too large".into());
            }
            words = expanded;
        }
        Err("alias expansion depth exceeded".into())
    }
    pub fn entries(&self) -> &BTreeMap<String, String> {
        &self.0
    }
    pub fn remove(&mut self, name: &str) -> bool {
        self.0.remove(name).is_some()
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Insert(String),
    Left,
    Right,
    Home,
    End,
    Backspace,
    Delete,
    Previous,
    Next,
    Search(String),
    ClearHistory,
    Cancel,
    Submit,
    Eof,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Changed,
    Submitted(String),
    Cancelled,
    Eof,
}

#[derive(Default, Debug)]
pub struct Controller {
    buffer: String,
    cursor: usize,
    history: Vec<String>,
    position: Option<usize>,
    draft: String,
    excluded: Vec<String>,
}
impl Controller {
    pub fn buffer(&self) -> &str {
        &self.buffer
    }
    pub fn cursor(&self) -> usize {
        self.cursor
    }
    pub fn history(&self) -> &[String] {
        &self.history
    }
    pub fn exclude(&mut self, value: &str) -> Result<(), String> {
        if value.is_empty() || value.len() > 128 || self.excluded.len() >= 64 {
            return Err("invalid history filter".into());
        }
        self.excluded.push(value.to_lowercase());
        let old = std::mem::take(&mut self.history);
        for line in old {
            self.remember(&line);
        }
        self.position = None;
        Ok(())
    }
    pub fn is_sensitive(&self, line: &str) -> bool {
        let lower = line.to_lowercase();
        line.starts_with(char::is_whitespace)
            || [
                "password",
                "passwd",
                "secret",
                "token",
                "bearer",
                "--auth",
                "private_key",
            ]
            .iter()
            .any(|s| lower.contains(s))
            || self.excluded.iter().any(|s| lower.contains(s))
            || parse(line).is_err_and(|_| true)
            || parse(line).is_ok_and(|commands| {
                commands
                    .iter()
                    // `history` itself is not secret input.  Keeping it here
                    // made `history` mysteriously absent from its own output
                    // and from persistent history.  Commands that can embed
                    // credentials or arbitrary source remain excluded.
                    .any(|cmd| matches!(cmd[0].as_str(), "alias" | "env" | "lua"))
            })
    }
    pub fn remember(&mut self, line: &str) {
        if line.is_empty() || line.len() > 1024 || self.is_sensitive(line) {
            return;
        }
        if self.history.last().is_none_or(|last| last != line) {
            self.history.push(line.into());
        }
        if self.history.len() > HISTORY_LIMIT {
            self.history.remove(0);
        }
        self.position = None;
    }
    pub fn encode(&self) -> Result<String, String> {
        let mut entries = self.history.as_slice();
        loop {
            let text = serde_json::to_string(entries).map_err(|e| e.to_string())?;
            if text.len() <= 24 * 1024 {
                return Ok(text);
            }
            entries = &entries[1..];
        }
    }
    pub fn load(&mut self, text: &str) -> Result<(), String> {
        if text.len() > 24 * 1024 {
            return Err("history too large".into());
        }
        let entries: Vec<String> = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if entries.len() > HISTORY_LIMIT {
            return Err("too many history entries".into());
        }
        for entry in entries {
            self.remember(&entry);
        }
        Ok(())
    }
    pub fn dispatch(&mut self, event: Event) -> Result<Outcome, String> {
        match event {
            Event::Insert(text) => {
                if text.chars().any(char::is_control) || self.buffer.len() + text.len() > MAX_LINE {
                    return Err("invalid input".into());
                }
                self.buffer.insert_str(self.cursor, &text);
                self.cursor += text.len();
                self.position = None;
            }
            Event::Left => {
                self.cursor = self.buffer[..self.cursor]
                    .char_indices()
                    .last()
                    .map_or(0, |(i, _)| i)
            }
            Event::Right => {
                self.cursor += self.buffer[self.cursor..]
                    .chars()
                    .next()
                    .map_or(0, char::len_utf8)
            }
            Event::Home => self.cursor = 0,
            Event::End => self.cursor = self.buffer.len(),
            Event::Backspace => {
                let left = self.buffer[..self.cursor]
                    .char_indices()
                    .last()
                    .map(|(i, _)| i);
                if let Some(left) = left {
                    self.buffer.drain(left..self.cursor);
                    self.cursor = left;
                }
                self.position = None;
            }
            Event::Delete => {
                if self.cursor < self.buffer.len() {
                    self.buffer.remove(self.cursor);
                }
                self.position = None;
            }
            Event::Previous => {
                if !self.history.is_empty() {
                    if self.position.is_none() {
                        self.draft = self.buffer.clone();
                    }
                    let p = self
                        .position
                        .unwrap_or(self.history.len())
                        .saturating_sub(1);
                    self.position = Some(p);
                    self.buffer = self.history[p].clone();
                    self.cursor = self.buffer.len();
                }
            }
            Event::Next => {
                if let Some(p) = self.position {
                    if p + 1 < self.history.len() {
                        self.position = Some(p + 1);
                        self.buffer = self.history[p + 1].clone();
                    } else {
                        self.position = None;
                        self.buffer = self.draft.clone();
                    }
                    self.cursor = self.buffer.len();
                }
            }
            Event::Search(query) => {
                let end = self.position.unwrap_or(self.history.len());
                if let Some(p) = self.history[..end]
                    .iter()
                    .rposition(|line| line.contains(&query))
                {
                    if self.position.is_none() {
                        self.draft = self.buffer.clone();
                    }
                    self.position = Some(p);
                    self.buffer = self.history[p].clone();
                    self.cursor = self.buffer.len();
                }
            }
            Event::ClearHistory => {
                self.history.clear();
                self.position = None;
                self.draft.clear();
            }
            Event::Cancel => {
                self.buffer.clear();
                self.cursor = 0;
                self.position = None;
                self.draft.clear();
                return Ok(Outcome::Cancelled);
            }
            Event::Submit => {
                self.cursor = 0;
                self.position = None;
                self.draft.clear();
                return Ok(Outcome::Submitted(std::mem::take(&mut self.buffer)));
            }
            Event::Eof => {
                if self.buffer.is_empty() {
                    return Ok(Outcome::Eof);
                }
            }
        }
        Ok(Outcome::Changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotes_aliases_and_cycles() {
        assert_eq!(
            parse("cat 'a b'; ls \"x;y\"").unwrap(),
            vec![vec!["cat", "a b"], vec!["ls", "x;y"]]
        );
        assert!(parse("pwd; cat 'bad").is_err());
        let mut aliases = Aliases::default();
        aliases.set("ll", "ls -l").unwrap();
        assert_eq!(
            aliases.expand(vec!["ll".into(), "a b".into()]).unwrap(),
            vec!["ls", "-l", "a b"]
        );
        aliases.set("a", "b").unwrap();
        assert!(aliases.set("b", "a").is_err());
        assert!(aliases.set("x", "pwd; exit").is_err());
    }
    #[test]
    fn history_never_executes_and_restores_draft() {
        let mut c = Controller::default();
        c.remember("pwd");
        c.remember("ls");
        c.dispatch(Event::Insert("draft".into())).unwrap();
        assert_eq!(c.dispatch(Event::Previous).unwrap(), Outcome::Changed);
        assert_eq!(c.buffer(), "ls");
        c.dispatch(Event::Next).unwrap();
        assert_eq!(c.buffer(), "draft");
        c.dispatch(Event::Search("pw".into())).unwrap();
        assert_eq!(c.buffer(), "pwd");
        c.dispatch(Event::Cancel).unwrap();
        assert_eq!(c.buffer(), "");
        c.dispatch(Event::Insert("ə🙂".into())).unwrap();
        c.dispatch(Event::Left).unwrap();
        c.dispatch(Event::Backspace).unwrap();
        assert_eq!(c.buffer(), "🙂");
        assert!(c.dispatch(Event::Insert("\x1b[2J".into())).is_err());
    }
    #[test]
    fn history_limits_secrets_and_reload() {
        let mut c = Controller::default();
        for n in 0..150 {
            c.remember(&format!("ls /{n}"));
        }
        c.remember("password hunter2");
        c.remember("alias x='secret'");
        c.remember(" hidden");
        assert_eq!(c.history().len(), 100);
        let text = c.encode().unwrap();
        let mut restored = Controller::default();
        restored.load(&text).unwrap();
        assert_eq!(restored.history(), c.history());
        restored.exclude("/149").unwrap();
        assert_eq!(restored.history().len(), 99);
        restored.dispatch(Event::ClearHistory).unwrap();
        assert_eq!(restored.encode().unwrap(), "[]");
    }

    #[test]
    fn history_commands_are_recorded_but_sensitive_input_is_not() {
        let mut controller = Controller::default();
        controller.remember("history");
        controller.remember("history search mkdir");
        controller.remember("lua print('safe-looking but arbitrary source')");
        controller.remember("env API_TOKEN secret-value");
        assert_eq!(controller.history(), ["history", "history search mkdir"]);
    }
}
