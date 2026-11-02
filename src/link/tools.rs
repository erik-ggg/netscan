//! Detection of the local tools the neural link relies on.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Tools {
    pub adb: Option<PathBuf>,
    pub ssh: Option<PathBuf>,
    pub git: Option<PathBuf>,
    pub python3: Option<PathBuf>,
    pub shell: PathBuf,
    /// `/usr/bin/git` and `/usr/bin/python3` are Command Line Tools stubs when
    /// `xcode-select -p` fails: present on disk but they only pop an installer.
    pub clt_stub: bool,
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Extra search directories beyond `$PATH`.
pub fn extra_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        home().join("Library/Android/sdk/platform-tools"),
    ]
}

fn is_exec(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// First executable called `name` in `dirs`.
pub fn find_in(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter().map(|d| d.join(name)).find(|p| is_exec(p))
}

fn search_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    v.extend(extra_dirs());
    v
}

fn clt_missing() -> bool {
    // 1 s cap: xcode-select -p is instant, but never block the UI on it.
    let Ok(mut c) = Command::new("xcode-select")
        .arg("-p")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let t0 = std::time::Instant::now();
    loop {
        match c.try_wait() {
            Ok(Some(s)) => return !s.success(),
            Ok(None) if t0.elapsed() < std::time::Duration::from_secs(1) => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            _ => {
                let _ = c.kill();
                return false;
            }
        }
    }
}

pub fn detect() -> Tools {
    let dirs = search_dirs();
    let git = find_in("git", &dirs);
    let python3 = find_in("python3", &dirs);
    let stub_in_use = [&git, &python3]
        .iter()
        .any(|p| p.as_deref().is_some_and(|p| p.starts_with("/usr/bin")));
    let shell = std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && is_exec(p))
        .unwrap_or_else(|| PathBuf::from("/bin/zsh"));
    Tools {
        adb: find_in("adb", &dirs),
        ssh: find_in("ssh", &dirs),
        git,
        python3,
        shell,
        clt_stub: stub_in_use && clt_missing(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_executables_only() {
        let sh = find_in(
            "sh",
            &[PathBuf::from("/nonexistent"), PathBuf::from("/bin")],
        );
        assert_eq!(sh, Some(PathBuf::from("/bin/sh")));
        assert!(find_in("definitely-not-a-tool", &[PathBuf::from("/bin")]).is_none());
        // a directory is not an executable file
        assert!(find_in("usr", &[PathBuf::from("/")]).is_none());
    }

    #[test]
    fn detect_has_shell() {
        let t = detect();
        assert!(t.shell.is_absolute());
    }
}
