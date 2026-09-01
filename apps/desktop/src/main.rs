slint::include_modules!();

use incomudon_core::TransceiverProfile;
use slint::{ComponentHandle, SharedString};

fn main() -> Result<(), slint::PlatformError> {
    let profile = TransceiverProfile::default();
    let window = AppWindow::new()?;

    window.set_profile_name(SharedString::from(profile.name));
    window.set_channel_id(SharedString::from(profile.channel_id.to_string()));
    window.set_sender_id(SharedString::from(profile.sender_id.to_string()));
    window.set_connection_status(SharedString::from("Disconnected"));
    window.set_active_talker(SharedString::from("No active speaker"));
    window.set_receive_only(profile.receive_only);
    window.set_mute_self_id(profile.mute_self_id);
    window.set_bitrate_bps(profile.bitrate_bps.unwrap_or_default() as i32);

    let pressed_window = window.as_weak();
    window.on_ptt_pressed(move || {
        if let Some(window) = pressed_window.upgrade() {
            window.set_connection_status(SharedString::from("Transmitting"));
        }
    });

    let released_window = window.as_weak();
    window.on_ptt_released(move || {
        if let Some(window) = released_window.upgrade() {
            window.set_connection_status(SharedString::from("Connected"));
        }
    });

    window.on_profile_value_changed(|| {
        // Persistence is intentionally deferred until the secure profile store exists.
    });

    window.run()
}
