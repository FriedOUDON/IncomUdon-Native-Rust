slint::include_modules!();

mod profile_storage;

use std::sync::{Arc, Mutex};

use incomudon_core::{validate_profile, Codec, ProfileStore, TransceiverProfile};
use slint::{ComponentHandle, SharedString};

fn main() -> Result<(), slint::PlatformError> {
    let (store, load_status) = load_profile_store();
    let store = Arc::new(Mutex::new(store));
    let window = AppWindow::new()?;

    apply_profile_to_window(
        &window,
        store.lock().expect("profile store lock poisoned").active(),
    );
    window.set_connection_status(SharedString::from("Disconnected"));
    window.set_active_talker(SharedString::from("No active speaker"));
    window.set_profile_save_status(SharedString::from(load_status));

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

    let save_window = window.as_weak();
    let save_store = Arc::clone(&store);
    window.on_save_profile(move || {
        let Some(window) = save_window.upgrade() else {
            return;
        };
        let profile = match profile_from_window(&window) {
            Ok(profile) => profile,
            Err(error) => {
                window.set_profile_save_status(SharedString::from(format!("Not saved: {error}")));
                return;
            }
        };

        let mut store = save_store.lock().expect("profile store lock poisoned");
        if let Err(error) = store.replace_active(profile) {
            window.set_profile_save_status(SharedString::from(format!("Not saved: {error}")));
            return;
        }
        match profile_storage::default_profile_path()
            .and_then(|path| profile_storage::save_to_path(&path, &store))
        {
            Ok(()) => window.set_profile_save_status(SharedString::from("Profile saved")),
            Err(error) => {
                window.set_profile_save_status(SharedString::from(format!("Not saved: {error}")))
            }
        }
    });

    window.on_profile_value_changed(|| {
        // The save button persists a complete, validated profile in one operation.
    });

    window.run()
}

fn load_profile_store() -> (ProfileStore, String) {
    match profile_storage::default_profile_path() {
        Ok(path) if path.exists() => match profile_storage::load_from_path(&path) {
            Ok(store) => (store, "Profile restored".to_owned()),
            Err(error) => (ProfileStore::default(), format!("Using defaults: {error}")),
        },
        Ok(_) => (
            ProfileStore::default(),
            "Unsaved default profile".to_owned(),
        ),
        Err(error) => (ProfileStore::default(), format!("Using defaults: {error}")),
    }
}

fn apply_profile_to_window(window: &AppWindow, profile: &TransceiverProfile) {
    window.set_profile_name(SharedString::from(profile.name.as_str()));
    window.set_channel_id(SharedString::from(profile.channel_id.to_string()));
    window.set_sender_id(SharedString::from(profile.sender_id.to_string()));
    window.set_receive_only(profile.receive_only);
    window.set_mute_self_id(profile.mute_self_id);
    window.set_codec_index(codec_to_index(profile.codec));
    window.set_bitrate_bps(profile.bitrate_bps.unwrap_or_default() as i32);
}

fn profile_from_window(window: &AppWindow) -> Result<TransceiverProfile, String> {
    let channel_id = window
        .get_channel_id()
        .parse::<u32>()
        .map_err(|_| "channel ID must be an unsigned integer")?;
    let sender_id = window
        .get_sender_id()
        .parse::<u32>()
        .map_err(|_| "sender ID must be an unsigned integer")?;
    let codec = codec_from_index(window.get_codec_index())?;
    let bitrate_bps = if codec == Codec::Pcm {
        None
    } else {
        u32::try_from(window.get_bitrate_bps())
            .ok()
            .filter(|value| *value > 0)
    };
    let profile = TransceiverProfile {
        name: window.get_profile_name().trim().to_owned(),
        channel_id,
        sender_id,
        codec,
        bitrate_bps,
        encryption: incomudon_core::EncryptionMode::AesGcmV2,
        receive_only: window.get_receive_only(),
        mute_self_id: window.get_mute_self_id(),
    };
    validate_profile(&profile).map_err(|error| error.to_string())?;
    Ok(profile)
}

fn codec_to_index(codec: Codec) -> i32 {
    match codec {
        Codec::Opus => 0,
        Codec::Codec2 => 1,
        Codec::Pcm => 2,
    }
}

fn codec_from_index(index: i32) -> Result<Codec, String> {
    match index {
        0 => Ok(Codec::Opus),
        1 => Ok(Codec::Codec2),
        2 => Ok(Codec::Pcm),
        _ => Err("unknown codec selection".to_owned()),
    }
}
