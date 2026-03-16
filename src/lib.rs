//! Cross-platform system proxy configuration library.
//!
//! Supports Windows, macOS and Linux (GNOME/KDE).
//! On Windows, uses WinINet API with RAS connection enumeration for maximum compatibility.
//! On macOS, uses `networksetup` command.
//! On Linux, uses `gsettings` (GNOME) or `kreadconfig`/`kwriteconfig` (KDE).

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub mod utils;

/// Represents a system HTTP/SOCKS proxy configuration.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sysproxy {
    pub enable: bool,
    pub host: String,
    pub port: u16,
    pub bypass: String,
}

/// Represents a system auto-proxy (PAC) configuration.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Autoproxy {
    pub enable: bool,
    pub url: String,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to parse string `{0}`")]
    ParseStr(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("failed to get default network interface")]
    NetworkInterface,

    #[error("failed to set proxy for this environment")]
    NotSupport,

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Xdg(#[from] xdg::BaseDirectoriesError),

    #[cfg(target_os = "windows")]
    #[error("system call failed: {0}")]
    SystemCall(#[from] ::windows::core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Sysproxy {
    /// Returns `true` if the current platform is supported.
    pub fn is_support() -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
        ))
    }
}

impl Autoproxy {
    /// Returns `true` if the current platform is supported.
    pub fn is_support() -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
        ))
    }
}
