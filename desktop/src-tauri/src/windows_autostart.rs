//! Quote the app-owned Windows Run value after the official plugin registers it.
//! auto-launch 0.5.0 leaves executable paths unquoted, including paths with spaces.
use crate::node::{Error, Result};
use std::path::Path;
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE},
};

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
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            KEY_READ | KEY_SET_VALUE,
        )
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
}
