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
    /// "Web pages at once": 0 is Auto (the node's adaptive limit), 1-16 a
    /// fixed number. The helper keeps it in its own file beside
    /// preferences.json; it applies to the next child process.
    #[serde(default)]
    pub web_concurrency: u8,
    /// "Browser pages at once": 0 is Auto (the node picks 1 below 16 GiB of
    /// memory, else 2), 1-4 a fixed number, passed on within Web pages at
    /// once. The helper keeps it in its own file beside preferences.json; it
    /// applies to the next child process.
    #[serde(default)]
    pub web_browser_concurrency: u8,
    /// "Send web pages through my proxy": the operator's own Webshare
    /// account, off by default. The username and password are in the OS
    /// keychain (web_proxy.rs), never here; these three settings are in the
    /// helper's own file beside preferences.json, and apply to the next child
    /// process. Only a passing test turns it on.
    #[serde(default)]
    pub web_proxy: bool,
    /// "Use it for": "limited_sites" (the default, sites that limit this
    /// network) or "all" (every web page).
    #[serde(default = "default_web_proxy_use")]
    pub web_proxy_use: String,
    /// The Webshare port: 80 (the default), 1080 or 3128.
    #[serde(default = "default_web_proxy_port")]
    pub web_proxy_port: u16,
}
/// The desktop's ceiling for Web pages at once, below the node's own 32
/// until the coordinator shares the verifier's web sessions between nodes.
pub const MAX_WEB_CONCURRENCY: u8 = 16;
/// The node's own ceiling for browser pages at once
/// (SCARLETT_WEB_BROWSER_CONCURRENCY, 1-4).
pub const MAX_WEB_BROWSER_CONCURRENCY: u8 = 4;
pub const fn default_x_concurrency() -> u8 {
    2
}
pub fn default_updates() -> String {
    "notify".into()
}
pub const fn default_serve_web() -> bool {
    true
}
pub fn default_web_proxy_use() -> String {
    "limited_sites".into()
}
pub const fn default_web_proxy_port() -> u16 {
    80
}
impl Data {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.local_api_port < 1024
            || !(1..=8).contains(&self.x_concurrency)
            || !matches!(self.updates.as_str(), "notify" | "automatic")
            || self.web_concurrency > MAX_WEB_CONCURRENCY
            || self.web_browser_concurrency > MAX_WEB_BROWSER_CONCURRENCY
            || crate::web_proxy::Route::new(&self.web_proxy_use, self.web_proxy_port).is_err()
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// The web proxy the next node uses with web, None when it is off.
    pub fn web_proxy_route(&self) -> Option<crate::web_proxy::Route> {
        crate::web_proxy::Route::new(&self.web_proxy_use, self.web_proxy_port)
            .ok()
            .filter(|_| self.web_proxy)
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
        assert_eq!(legacy.web_browser_concurrency, 0);
        assert!(!legacy.web_proxy);
        assert_eq!(legacy.web_proxy_use, "limited_sites");
        assert_eq!(legacy.web_proxy_port, 80);
        assert_eq!(legacy.web_proxy_route(), None);
        assert!(legacy.validate().is_ok());
        for limit in [MAX_WEB_CONCURRENCY + 1, u8::MAX] {
            let mut invalid = legacy.clone();
            invalid.web_concurrency = limit;
            assert_eq!(invalid.validate(), Err(Error::InvalidInput));
        }
        for limit in 0..=MAX_WEB_BROWSER_CONCURRENCY {
            let mut valid = legacy.clone();
            valid.web_browser_concurrency = limit;
            assert!(valid.validate().is_ok());
        }
        for limit in [MAX_WEB_BROWSER_CONCURRENCY + 1, u8::MAX] {
            let mut invalid = legacy.clone();
            invalid.web_browser_concurrency = limit;
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
        // Credentials never travel in preferences, the web proxy's included.
        for field in ["token", "username", "password"] {
            assert!(
                serde_json::from_str::<Data>(&format!(
                    r#"{{"schema":1,"local_api_port":8088,"background":false,"{field}":"synthetic"}}"#
                ))
                .is_err(),
                "{field}"
            );
        }
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
                web_browser_concurrency: 0,
                web_proxy: false,
                web_proxy_use: "limited_sites".into(),
                web_proxy_port: 80,
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
                web_browser_concurrency: 3,
                web_proxy: true,
                web_proxy_use: "all".into(),
                web_proxy_port: 1080,
            })
            .unwrap();
        assert!(prefs.background());
        assert_eq!(prefs.snapshot().unwrap().local_api_port, 18088);
        assert!(!prefs.snapshot().unwrap().serve_web);
        assert_eq!(prefs.snapshot().unwrap().web_browser_concurrency, 3);
        assert_eq!(
            prefs.snapshot().unwrap().web_proxy_route(),
            Some(crate::web_proxy::Route::new("all", 1080).unwrap())
        );
    }
    #[test]
    fn web_proxy_settings_are_bounded_and_on_only_when_chosen() {
        let saved: Data = serde_json::from_str(
            r#"{"schema":1,"local_api_port":8088,"background":false,"web_proxy":true,"web_proxy_use":"limited_sites","web_proxy_port":3128}"#,
        )
        .unwrap();
        assert!(saved.validate().is_ok());
        assert_eq!(
            saved.web_proxy_route(),
            Some(crate::web_proxy::Route::new("limited_sites", 3128).unwrap())
        );
        let mut off = saved.clone();
        off.web_proxy = false;
        assert_eq!(off.web_proxy_route(), None);
        for (pages, port) in [("every", 80), ("", 80), ("all", 8080), ("all", 0)] {
            let mut invalid = saved.clone();
            invalid.web_proxy_use = pages.into();
            invalid.web_proxy_port = port;
            assert_eq!(
                invalid.validate(),
                Err(Error::InvalidInput),
                "{pages} {port}"
            );
            // An off proxy is still validated, so a bad file never loads.
            invalid.web_proxy = false;
            assert_eq!(invalid.validate(), Err(Error::InvalidInput));
        }
        assert!(
            serde_json::from_str::<Data>(
                r#"{"schema":1,"local_api_port":8088,"background":false,"web_proxy":"on"}"#
            )
            .is_err()
        );
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
            web_browser_concurrency: MAX_WEB_BROWSER_CONCURRENCY,
            web_proxy: false,
            web_proxy_use: "limited_sites".into(),
            web_proxy_port: 3128,
        };
        assert!(widest.validate().is_ok());
        let reply = serde_json::to_vec(&widest).unwrap().len() + 1;
        assert_eq!(reply, 257);
        assert!(reply <= crate::node::PRIVATE_HELPER_REPLY_LIMIT, "{reply}");
    }
}
