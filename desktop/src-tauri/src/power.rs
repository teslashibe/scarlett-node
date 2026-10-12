//! Device sleep and wake, passed to the supervised node as `sleep` and `wake`
//! lines on its owner pipe. On sleep the node says goodbye to the coordinator
//! before the network goes, so offers it has not accepted move to other nodes
//! at once; on wake it reconnects and heartbeats at once instead of waiting
//! out a backoff.
//!
//! - macOS: `NSWorkspaceWillSleepNotification` and
//!   `NSWorkspaceDidWakeNotification`.
//! - Windows: `PBT_APMSUSPEND` and `PBT_APMRESUMEAUTOMATIC`, the
//!   `WM_POWERBROADCAST` events, through a power-notification callback. It
//!   needs no window, so it also works while the app runs in the tray only.
//! - Linux needs nothing: the node's own wall-clock jump check covers it, as
//!   it covers any event missed here.
use crate::node::{Node, OwnerCommand};
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

/// How long a sleep is held after its line reaches the node: the node's own
/// goodbye timeout. macOS lets an observer delay sleep for up to 30 s, and
/// Windows allows about 2 s for a suspend notification.
const GOODBYE: Duration = Duration::from_secs(1);
/// The most a sleep notification waits for its line to be written.
const LINE_WAIT: Duration = Duration::from_millis(500);

/// Watches the OS for sleep and wake for the rest of the app's life. False
/// when there is nothing to watch on this platform or registration failed.
#[cfg(target_os = "macos")]
pub fn watch(node: Arc<Node>) -> bool {
    macos::observe(move |command| forward(&node, command, GOODBYE))
}
#[cfg(windows)]
pub fn watch(node: Arc<Node>) -> bool {
    windows::observe(move |command| forward(&node, command, GOODBYE))
}
#[cfg(not(any(target_os = "macos", windows)))]
pub fn watch(_: Arc<Node>) -> bool {
    false
}

/// Passes one event on, from the OS notification's own thread. A sleep is
/// held until its line is written and the node has had `hold` to say
/// goodbye, since the network can be gone once this returns. A wake returns
/// at once.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
pub(crate) fn forward(node: &Arc<Node>, command: OwnerCommand, hold: Duration) {
    let (written, delivered) = mpsc::sync_channel(1);
    let node = node.clone();
    tauri::async_runtime::spawn(async move {
        let _ = written.send(node.owner_command(command).await);
    });
    if command == OwnerCommand::Sleep && delivered.recv_timeout(LINE_WAIT) == Ok(true) {
        std::thread::sleep(hold);
    }
}

/// The Windows power events used here (WinUser.h). Automatic resume comes on
/// every wake, whether or not someone is at the device; the resume that
/// follows when someone is (PBT_APMRESUMESUSPEND) would only repeat it.
#[cfg(any(windows, test))]
const PBT_APMSUSPEND: u32 = 0x4;
#[cfg(any(windows, test))]
const PBT_APMRESUMEAUTOMATIC: u32 = 0x12;
#[cfg(any(windows, test))]
fn pbt_command(event: u32) -> Option<OwnerCommand> {
    match event {
        PBT_APMSUSPEND => Some(OwnerCommand::Sleep),
        PBT_APMRESUMEAUTOMATIC => Some(OwnerCommand::Wake),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::OwnerCommand;
    use block2::RcBlock;
    use objc2_app_kit::{
        NSWorkspace, NSWorkspaceDidWakeNotification, NSWorkspaceWillSleepNotification,
    };
    use objc2_foundation::NSNotification;
    use std::{ptr::NonNull, sync::Arc};

    /// AppKit posts both on the main thread, on the workspace's own
    /// notification center. With no queue the block runs right there, so
    /// holding it holds the sleep.
    pub fn observe(handler: impl Fn(OwnerCommand) + Send + Sync + 'static) -> bool {
        let handler = Arc::new(handler);
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        // SAFETY: AppKit's own notification name constants.
        let names = unsafe {
            [
                (NSWorkspaceWillSleepNotification, OwnerCommand::Sleep),
                (NSWorkspaceDidWakeNotification, OwnerCommand::Wake),
            ]
        };
        for (name, command) in names {
            let handler = handler.clone();
            let block = RcBlock::new(move |_: NonNull<NSNotification>| handler(command));
            // SAFETY: no object filter, no queue (the posting thread) and a
            // Send + Sync block. The center keeps the registration and the
            // block for the life of the app; nothing removes it.
            let _ = unsafe {
                center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &block)
            };
        }
        true
    }
}

#[cfg(windows)]
mod windows {
    use super::{OwnerCommand, pbt_command};
    use std::ffi::c_void;
    use windows_sys::Win32::{
        System::Power::{
            DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification,
        },
        UI::WindowsAndMessaging::DEVICE_NOTIFY_CALLBACK,
    };

    type Handler = Box<dyn Fn(OwnerCommand) + Send + Sync>;

    /// Windows calls this on a thread of its own for each power event and
    /// waits for it during a suspend.
    unsafe extern "system" fn notified(
        context: *const c_void,
        event: u32,
        _setting: *const c_void,
    ) -> u32 {
        if let Some(command) = pbt_command(event) {
            // SAFETY: the context is the handler leaked in observe.
            let handler = unsafe { &*context.cast::<Handler>() };
            handler(command);
        }
        0 // ERROR_SUCCESS
    }

    pub fn observe(handler: impl Fn(OwnerCommand) + Send + Sync + 'static) -> bool {
        // The registration lasts for the life of the app, so its handler and
        // parameters are never freed.
        let handler: Handler = Box::new(handler);
        let handler: &'static Handler = Box::leak(Box::new(handler));
        let recipient = Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(notified),
            Context: std::ptr::from_ref(handler).cast_mut().cast(),
        }));
        let mut registration = std::ptr::null_mut();
        // SAFETY: both pointers stay valid for the life of the process.
        unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                std::ptr::from_mut(recipient).cast(),
                &mut registration,
            ) == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_power_events_map_to_sleep_and_wake() {
        assert_eq!(pbt_command(PBT_APMSUSPEND), Some(OwnerCommand::Sleep));
        assert_eq!(
            pbt_command(PBT_APMRESUMEAUTOMATIC),
            Some(OwnerCommand::Wake)
        );
        // PBT_APMRESUMESUSPEND, PBT_APMPOWERSTATUSCHANGE and
        // PBT_POWERSETTINGCHANGE change nothing for the node.
        for other in [0x7, 0xA, 0x8013, 0] {
            assert_eq!(pbt_command(other), None, "{other:#x}");
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging as user;
            assert_eq!(PBT_APMSUSPEND, user::PBT_APMSUSPEND);
            assert_eq!(PBT_APMRESUMEAUTOMATIC, user::PBT_APMRESUMEAUTOMATIC);
        }
    }

    /// The real AppKit registration, driven by posting AppKit's own names on
    /// the workspace notification center, where the system posts them.
    #[cfg(target_os = "macos")]
    #[test]
    fn workspace_sleep_and_wake_notifications_reach_the_handler() {
        use objc2_app_kit::{
            NSWorkspace, NSWorkspaceDidWakeNotification, NSWorkspaceWillSleepNotification,
        };
        use objc2_foundation::{NSNotificationCenter, NSString};
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        assert!(macos::observe(move |command| record
            .lock()
            .unwrap()
            .push(command)));
        let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
        // SAFETY: notification names posted with no object.
        unsafe {
            // Neither another center nor another name is a sleep.
            NSNotificationCenter::defaultCenter()
                .postNotificationName_object(NSWorkspaceWillSleepNotification, None);
            workspace.postNotificationName_object(&NSString::from_str("ScarlettTestOther"), None);
            workspace.postNotificationName_object(NSWorkspaceWillSleepNotification, None);
            workspace.postNotificationName_object(NSWorkspaceDidWakeNotification, None);
        }
        assert_eq!(
            *seen.lock().unwrap(),
            [OwnerCommand::Sleep, OwnerCommand::Wake]
        );
    }

    /// A node started and stopped on the app's async runtime, as its commands
    /// are, with events from a plain thread, as the OS sends them. It records
    /// each owner line and then the pipe's EOF.
    #[cfg(unix)]
    #[test]
    fn sleep_is_held_for_the_goodbye_and_the_pipe_stays_open() {
        use std::{os::unix::fs::PermissionsExt, time::Instant};
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("node");
        let helper = temp.path().join("helper");
        std::fs::write(&binary, "#!/bin/sh\ncase \"$1 $2\" in\n'accounts list') printf '[]';;\n'desktop run') while IFS= read -r line; do printf '%s\\n' \"$line\" >> \"$SCARLETT_STATE_DIR/owner\"; done; printf 'EOF\\n' >> \"$SCARLETT_STATE_DIR/owner\";;\n'drain ') ;;\n*) exit 1;;\nesac\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&helper, "synthetic helper fixture").unwrap();
        let state = temp.path().join("state");
        crate::node::private_dir_with_helper(&state, &binary).unwrap();
        std::fs::write(state.join("identity.json"), "{}").unwrap();
        let node = Arc::new(Node::new(state.clone(), binary, helper));
        let lines = || std::fs::read_to_string(state.join("owner")).unwrap_or_default();
        let hold = Duration::from_millis(300);
        // Nothing runs: there is no line to write, so the sleep is not held.
        let began = Instant::now();
        forward(&node, OwnerCommand::Sleep, Duration::from_secs(10));
        assert!(began.elapsed() < Duration::from_secs(2));
        let wait_for = |want: &str| {
            let began = Instant::now();
            while lines() != want {
                assert!(began.elapsed() < Duration::from_secs(5), "{:?}", lines());
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        tauri::async_runtime::block_on(node.start()).unwrap();
        let began = Instant::now();
        forward(&node, OwnerCommand::Sleep, hold);
        assert!(began.elapsed() >= hold);
        wait_for("sleep\n");
        let began = Instant::now();
        forward(&node, OwnerCommand::Wake, Duration::from_secs(10));
        assert!(began.elapsed() < Duration::from_secs(2));
        wait_for("sleep\nwake\n");
        // Neither line closed the pipe: the node still runs until Stop
        // closes it, and only then sees EOF.
        assert!(tauri::async_runtime::block_on(node.snapshot()).supervised);
        tauri::async_runtime::block_on(node.stop()).unwrap();
        assert_eq!(lines(), "sleep\nwake\nEOF\n");
        assert!(!tauri::async_runtime::block_on(
            node.owner_command(OwnerCommand::Wake)
        ));
    }
}
