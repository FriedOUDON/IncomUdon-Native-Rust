//! Abstractions implemented by desktop and Android adapters.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub biometric_unlock: bool,
    pub bluetooth_audio: bool,
    pub background_ptt: bool,
}

pub trait PlatformServices {
    fn capabilities(&self) -> PlatformCapabilities;
    fn request_microphone_permission(&self) -> Result<(), String>;
    fn notify_user(&self, message: &str);
}
