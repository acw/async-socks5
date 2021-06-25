use std::io;
use std::string::FromUtf8Error;
use thiserror::Error;

/// All the errors that can pop up when trying to turn raw bytes into SOCKSv5
/// messages.
#[derive(Error, Debug)]
pub enum DeserializationError {
    #[error("Invalid protocol version for packet ({1} is not {0}!)")]
    InvalidVersion(u8, u8),
    #[error("Not enough data found")]
    NotEnoughData,
    #[error("Ooops! Found an empty string where I shouldn't")]
    InvalidEmptyString,
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),
    #[error("SOCKS authentication format parse error: {0}")]
    AuthenticationMethodError(#[from] AuthenticationDeserializationError),
    #[error("Error converting from UTF-8: {0}")]
    UTF8Error(#[from] FromUtf8Error),
    #[error("Invalid address type; wanted 1, 3, or 4, got {0}")]
    InvalidAddressType(u8),
    #[error("Invalid client command {0}; expected 1, 2, or 3")]
    InvalidClientCommand(u8),
    #[error("Invalid server status {0}; expected 0-8")]
    InvalidServerResponse(u8),
}

/// All the errors that can occur trying to turn SOCKSv5 message structures
/// into raw bytes. There's a few places that the message structures allow
/// for information that can't be serialized; often, you have to be careful
/// about how long your strings are ...
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("Too many authentication methods for serialization ({0} > 255)")]
    TooManyAuthMethods(usize),
    #[error("Invalid length for string: {0}")]
    InvalidStringLength(String),
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum AuthenticationDeserializationError {
    #[error("No data found deserializing SOCKS authentication type")]
    NoDataFound,
    #[error("Invalid authentication type value: {0}")]
    InvalidAuthenticationByte(u8),
    #[error("IO error reading SOCKS authentication type: {0}")]
    IOError(#[from] io::Error),
}
