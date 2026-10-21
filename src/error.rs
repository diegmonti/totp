use thiserror::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    General(String),
    #[error("{0}")]
    InvalidArguments(String),
    #[error("credential '{0}' not found")]
    NotFound(String),
    #[error("secure storage backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("credential store locked or interaction required: {0}")]
    InteractionRequired(String),
    #[error("invalid secret or TOTP configuration: {0}")]
    InvalidConfiguration(String),
    #[error("credential '{0}' already exists; use --replace")]
    AlreadyExists(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("native credential enumeration unavailable: {0}")]
    EnumerationUnavailable(String),
    #[error("unsupported credential schema")]
    UnsupportedSchema,
}
impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::General(_) => 1,
            Self::InvalidArguments(_) => 2,
            Self::NotFound(_) => 3,
            Self::BackendUnavailable(_) => 4,
            Self::InteractionRequired(_) => 5,
            Self::InvalidConfiguration(_) => 6,
            Self::AlreadyExists(_) => 7,
            Self::PermissionDenied(_) => 8,
            Self::EnumerationUnavailable(_) => 9,
            Self::UnsupportedSchema => 10,
        }
    }
}
