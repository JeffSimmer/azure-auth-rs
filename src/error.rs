use std::borrow::Cow;
use std::error::Error as StdError;
use thiserror::Error;

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

#[derive(Error, Debug)]
#[error("Custom error message: {}", .msg)]
pub struct Error {
    kind: ErrorKind,
    msg: Cow<'static, str>,
    inner: Option<BoxError>,
}

impl Error {
    pub fn new<M: Into<Cow<'static, str>>>(kind: ErrorKind, msg: M) -> Error {
        Error {
            kind,
            msg: msg.into(),
            inner: None,
        }
    }
    pub fn new_with_inner<M: Into<Cow<'static, str>>>(
        kind: ErrorKind,
        msg: M,
        inner: BoxError,
    ) -> Error {
        Error {
            kind,
            msg: msg.into(),
            inner: inner.into(),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        let kind = if err.is_timeout() {
            ErrorKind::Timeout
        } else {
            ErrorKind::Unknown
        };

        Error::new_with_inner(kind, err.to_string(), err.into())
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    Unknown,
    Timeout,
    Unauthorized,
}
