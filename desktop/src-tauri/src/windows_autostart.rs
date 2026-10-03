//! Handle absent startup keys and quote only the app-owned Windows Run value.
//! auto-launch 0.5.0 assumes the key exists and leaves paths unquoted.
use crate::node::{Error, Result};
use std::io::ErrorKind;
use std::path::Path;
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE},
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

fn registered(root: &RegKey, path: &str, name: &str) -> Result<bool> {
    let key = match root.open_subkey_with_flags(path, KEY_READ) {
        Ok(key) => key,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error::AutostartUnavailable),
    };
    match key.get_value::<String, _>(name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Error::AutostartUnavailable),
    }
}

fn ensure_key(root: &RegKey, path: &str) -> Result<()> {
    root.create_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE)
        .map(|_| ())
        .map_err(|_| Error::AutostartUnavailable)
}

pub fn registration_present(name: &str) -> Result<bool> {
    registered(&RegKey::predef(HKEY_CURRENT_USER), RUN_KEY, name)
}

// Create the standard key only after the operator enables start at login.
pub fn prepare_registration() -> Result<()> {
    ensure_key(&RegKey::predef(HKEY_CURRENT_USER), RUN_KEY)
}

fn command(executable: &Path) -> Result<String> {
    let path = executable.to_str().ok_or(Error::AutostartUnavailable)?;
    if !executable.is_absolute() || path.contains(['"', '\r', '\n', '\0']) {
        return Err(Error::AutostartUnavailable);
    }
    Ok(format!("\"{path}\""))
}

pub fn quote_registered_command(name: &str, executable: &Path) -> Result<()> {
    let command = command(executable)?;
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_SET_VALUE)
        .map_err(|_| Error::AutostartUnavailable)?;
    let registered: String = key
        .get_value(name)
        .map_err(|_| Error::AutostartUnavailable)?;
    // Do not overwrite a different command, arguments, or another app's value.
    if registered.trim_end() != executable.to_str().ok_or(Error::AutostartUnavailable)? {
        return Err(Error::AutostartUnavailable);
    }
    key.set_value(name, &command)
        .map_err(|_| Error::AutostartUnavailable)?;
    if key
        .get_value::<String, _>(name)
        .map_err(|_| Error::AutostartUnavailable)?
        != command
    {
        return Err(Error::AutostartUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_is_one_quoted_executable_without_arguments() {
        assert_eq!(
            command(Path::new(
                r"C:\Program Files\Scarlett Node\scarlett-node-desktop.exe"
            ))
            .unwrap(),
            r#""C:\Program Files\Scarlett Node\scarlett-node-desktop.exe""#
        );
        for path in ["relative.exe", "C:\\bad\"path.exe", "C:\\bad\npath.exe"] {
            assert_eq!(command(Path::new(path)), Err(Error::AutostartUnavailable));
        }
    }

    #[test]
    fn fresh_profile_is_disabled_without_creating_a_run_key() {
        // Exercise native registry behavior below a disposable subtree, never
        // the operator's actual Windows startup registrations.
        let path = format!(
            r"Software\Scarlett Acceptance\Autostart\{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
            }
        }
        let _cleanup = Cleanup(path.clone());
        let (root, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&path)
            .unwrap();
        assert_eq!(registered(&root, "Run", "synthetic-scarlett"), Ok(false));
        assert!(root.open_subkey("Run").is_err());

        ensure_key(&root, "Run").unwrap();
        let key = root
            .open_subkey_with_flags("Run", KEY_READ | KEY_SET_VALUE)
            .unwrap();
        key.set_value("unrelated", &"preserve this value").unwrap();
        assert_eq!(registered(&root, "Run", "synthetic-scarlett"), Ok(false));
        key.set_value("synthetic-scarlett", &r#""C:\Scarlett\node.exe""#)
            .unwrap();
        assert_eq!(registered(&root, "Run", "synthetic-scarlett"), Ok(true));
        key.delete_value("synthetic-scarlett").unwrap();
        assert_eq!(registered(&root, "Run", "synthetic-scarlett"), Ok(false));
        assert_eq!(
            key.get_value::<String, _>("unrelated").unwrap(),
            "preserve this value"
        );
        key.set_value("synthetic-scarlett", &1u32).unwrap();
        assert_eq!(
            registered(&root, "Run", "synthetic-scarlett"),
            Err(Error::AutostartUnavailable)
        );
    }
}
