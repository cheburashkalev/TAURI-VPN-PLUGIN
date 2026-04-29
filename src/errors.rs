use serde::Serialize;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, VpnError>;

#[derive(Debug, Error, Serialize)]
#[serde(tag = "code", content = "message")]
pub enum VpnError {
    #[error("unsupported protocol or feature: {0}")]
    Unsupported(String),
    #[error("invalid VPN profile: {0}")]
    InvalidProfile(String),
    #[error("import failed: {0}")]
    Import(String),
    #[error("engine is already running")]
    AlreadyRunning,
    #[error("engine is not running")]
    NotRunning,
    #[error("engine failed: {0}")]
    Engine(String),
    #[error("{0}")]
    Platform(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for VpnError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<url::ParseError> for VpnError {
    fn from(value: url::ParseError) -> Self {
        Self::Import(value.to_string())
    }
}
