//! Non-secret preferences; the Go helper owns native private storage.
use crate::node::{Error, Result, private_helper};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Data {
    pub schema: u8,
    pub local_api_port: u16,
    pub background: bool,
    #[serde(default = "default_x_concurrency")]
    pub x_concurrency: u8,
    /// "notify" (default) or "automatic"; see updater.rs.
    #[serde(default = "default_updates")]
    pub updates: String,
    /// Start the node when the app opens; follows the last Start/Stop.
    #[serde(default)]
    pub resume_serving: bool,
    /// Serve web pages as well. On unless the operator turned it off; the
    /// node helper keeps it in its own file beside preferences.json.
    #[serde(default = "default_serve_web")]
    pub serve_web: bool,
    /// "Web pages at once": 0 is Auto (the node's default, 4 in this
    /// release), 1-16 a fixed number. The helper keeps it in its own file
    /// beside preferences.json; it applies to the next child process.
    #[serde(default)]
    pub web_concurrency: u8,
}
/// The desktop's ceiling for Web pages at once, below the node's own 32
/// until the coordinator shares the verifier's web sessions between nodes.
pub const MAX_WEB_CONCURRENCY: u8 = 16;
pub const fn default_x_concurrency() -> u8 {
    2
}
pub fn default_updates() -> String {
    "notify".into()
}
pub const fn default_serve_web() -> bool {
    true
}
impl Data {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.local_api_port < 1024
            || !(1..=8).contains(&self.x_concurrency)
            || !matches!(self.updates.as_str(), "notify" | "automatic")
            || self.web_concurrency > MAX_WEB_CONCURRENCY
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
pub struct Preferences {
    data: Mutex<Data>,
    background: AtomicBool,
}
impl Preferences {
    pub fn load(state: &Path, helper: &Path) -> Result<Self> {
        let data: Data = serde_json::from_value(private_helper(
            helper,
            "preferences-get",
            &state.join("preferences.json"),
        )?)
        .map_err(|_| Error::PrivateStorageUnavailable)?;
        data.validate()?;
        Ok(Self {
            background: AtomicBool::new(data.background),
            data: Mutex::new(data),
        })
    }
    pub fn snapshot(&self) -> Result<Data> {
        Ok(self
            .data
            .lock()
            .map_err(|_| Error::PrivateStorageUnavailable)?
            .clone())
    }
    pub fn updated(&self, data: Data) -> Result<()> {
        data.validate()?;
        let mut current = self
            .data
            .lock()
            .map_err(|_| Error::PrivateStorageUnavailable)?;
        self.background.store(data.background, Ordering::SeqCst);
        *current = data;
        Ok(())
    }
    pub fn background(&self) -> bool {
        self.background.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_settings_default_to_two_x_slots_and_require_bounded_values() {
        let legacy: Data =
            serde_json::from_str(r#"{"schema":1,"local_api_port":18088,"background":true}"#)
                .unwrap();
        assert_eq!(legacy.x_concurrency, 2);
        assert_eq!(legacy.updates, "notify");
        assert!(!legacy.resume_serving);
        assert!(legacy.serve_web);
        assert_eq!(legacy.web_concurrency, 0);
        assert!(legacy.validate().is_ok());
        for limit in [MAX_WEB_CONCURRENCY + 1, u8::MAX] {
            let mut invalid = legacy.clone();
            invalid.web_concurrency = limit;
            assert_eq!(invalid.validate(), Err(Error::InvalidInput));
        }
        let mut silent = legacy.clone();
        silent.updates = "silent".into();
        assert_eq!(silent.validate(), Err(Error::InvalidInput));
        for limit in [0, 9, u8::MAX] {
            let mut invalid = legacy.clone();
            invalid.x_concurrency = limit;
            assert_eq!(invalid.validate(), Err(Error::InvalidInput));
        }
    }
    #[test]
    fn settings_require_versioned_ports_and_exclude_credentials() {
        for raw in [
            r#"{"schema":2,"local_api_port":8088,"background":false}"#,
            r#"{"schema":1,"local_api_port":80,"background":false}"#,
        ] {
            let data: Data = serde_json::from_str(raw).unwrap();
            assert_eq!(data.validate(), Err(Error::InvalidInput));
        }
        assert!(
            serde_json::from_str::<Data>(
                r#"{"schema":1,"local_api_port":8088,"background":false,"token":"synthetic"}"#
            )
            .is_err()
        );
        let prefs = Preferences {
            data: Mutex::new(Data {
                schema: 1,
                local_api_port: 8088,
                background: false,
                x_concurrency: 2,
                updates: "notify".into(),
                resume_serving: false,
                serve_web: true,
                web_concurrency: 0,
            }),
            background: AtomicBool::new(false),
        };
        assert!(!prefs.background());
        prefs
            .updated(Data {
                schema: 1,
                local_api_port: 18088,
                background: true,
                x_concurrency: 3,
                updates: "automatic".into(),
                resume_serving: true,
                serve_web: false,
                web_concurrency: 8,
            })
            .unwrap();
        assert!(prefs.background());
        assert_eq!(prefs.snapshot().unwrap().local_api_port, 18088);
        assert!(!prefs.snapshot().unwrap().serve_web);
    }
    #[test]
    fn web_serving_defaults_on_and_round_trips_off() {
        // Every helper reply before this release, and a device that never
        // chose: web is on.
        let older: Data = serde_json::from_str(
            r#"{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"notify","resume_serving":true}"#,
        )
        .unwrap();
        assert!(older.serve_web);
        let mut off = older.clone();
        off.serve_web = false;
        let raw = serde_json::to_string(&off).unwrap();
        assert!(raw.contains(r#""serve_web":false"#), "{raw}");
        let back: Data = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, off);
        assert!(back.validate().is_ok());
        assert!(
            serde_json::from_str::<Data>(
                &raw.replace(r#""serve_web":false"#, r#""serve_web":"off""#)
            )
            .is_err()
        );
        // The helper's reply, every field at its widest, fits what the app
        // reads back from it (with the encoder's newline).
        let widest = Data {
            schema: 1,
            local_api_port: u16::MAX,
            background: false,
            x_concurrency: 8,
            updates: "automatic".into(),
            resume_serving: false,
            serve_web: false,
            web_concurrency: MAX_WEB_CONCURRENCY,
        };
        assert!(widest.validate().is_ok());
        let reply = serde_json::to_vec(&widest).unwrap().len() + 1;
        assert!(reply <= crate::node::PRIVATE_HELPER_REPLY_LIMIT, "{reply}");
    }
}
