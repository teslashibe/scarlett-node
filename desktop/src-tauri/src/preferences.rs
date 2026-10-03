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
}
impl Data {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.local_api_port < 1024 {
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
            }),
            background: AtomicBool::new(false),
        };
        assert!(!prefs.background());
        prefs
            .updated(Data {
                schema: 1,
                local_api_port: 18088,
                background: true,
            })
            .unwrap();
        assert!(prefs.background());
        assert_eq!(prefs.snapshot().unwrap().local_api_port, 18088);
    }
}
