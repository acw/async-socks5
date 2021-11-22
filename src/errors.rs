use std::io;
use std::string::FromUtf8Error;
use thiserror::Error;

use crate::network::SOCKSv5Address;

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
    #[error("Invalid byte in reserved byte ({0})")]
    InvalidReservedByte(u8),
}

#[test]
fn des_error_reasonable_equals() {
    let invalid_version = DeserializationError::InvalidVersion(1, 2);
    assert_eq!(invalid_version, invalid_version);
    let not_enough = DeserializationError::NotEnoughData;
    assert_eq!(not_enough, not_enough);
    let invalid_empty = DeserializationError::InvalidEmptyString;
    assert_eq!(invalid_empty, invalid_empty);
    let auth_method = DeserializationError::AuthenticationMethodError(
        AuthenticationDeserializationError::NoDataFound,
    );
    assert_eq!(auth_method, auth_method);
    let utf8 = DeserializationError::UTF8Error(String::from_utf8(vec![0, 159]).unwrap_err());
    assert_eq!(utf8, utf8);
    let invalid_address = DeserializationError::InvalidAddressType(3);
    assert_eq!(invalid_address, invalid_address);
    let invalid_client_cmd = DeserializationError::InvalidClientCommand(32);
    assert_eq!(invalid_client_cmd, invalid_client_cmd);
    let invalid_server_resp = DeserializationError::InvalidServerResponse(42);
    assert_eq!(invalid_server_resp, invalid_server_resp);

    assert_ne!(invalid_version, invalid_address);
    assert_ne!(not_enough, invalid_empty);
    assert_ne!(auth_method, invalid_client_cmd);
    assert_ne!(utf8, invalid_server_resp);
}

impl PartialEq for DeserializationError {
    fn eq(&self, other: &DeserializationError) -> bool {
        match (self, other) {
            (
                &DeserializationError::InvalidVersion(a, b),
                &DeserializationError::InvalidVersion(x, y),
            ) => (a == x) && (b == y),
            (&DeserializationError::NotEnoughData, &DeserializationError::NotEnoughData) => true,
            (
                &DeserializationError::InvalidEmptyString,
                &DeserializationError::InvalidEmptyString,
            ) => true,
            (
                &DeserializationError::AuthenticationMethodError(ref a),
                &DeserializationError::AuthenticationMethodError(ref b),
            ) => a == b,
            (&DeserializationError::UTF8Error(ref a), &DeserializationError::UTF8Error(ref b)) => {
                a == b
            }
            (
                &DeserializationError::InvalidAddressType(a),
                &DeserializationError::InvalidAddressType(b),
            ) => a == b,
            (
                &DeserializationError::InvalidClientCommand(a),
                &DeserializationError::InvalidClientCommand(b),
            ) => a == b,
            (
                &DeserializationError::InvalidServerResponse(a),
                &DeserializationError::InvalidServerResponse(b),
            ) => a == b,
            (
                &DeserializationError::InvalidReservedByte(a),
                &DeserializationError::InvalidReservedByte(b),
            ) => a == b,
            (_, _) => false,
        }
    }
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

#[test]
fn ser_err_reasonable_equals() {
    let too_many = SerializationError::TooManyAuthMethods(512);
    assert_eq!(too_many, too_many);
    let invalid_str = SerializationError::InvalidStringLength("Whoopsy!".to_string());
    assert_eq!(invalid_str, invalid_str);

    assert_ne!(too_many, invalid_str);
}

impl PartialEq for SerializationError {
    fn eq(&self, other: &SerializationError) -> bool {
        match (self, other) {
            (
                &SerializationError::TooManyAuthMethods(a),
                &SerializationError::TooManyAuthMethods(b),
            ) => a == b,
            (
                &SerializationError::InvalidStringLength(ref a),
                &SerializationError::InvalidStringLength(ref b),
            ) => a == b,
            (_, _) => false,
        }
    }
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

#[test]
fn auth_des_err_reasonable_equals() {
    let no_data = AuthenticationDeserializationError::NoDataFound;
    assert_eq!(no_data, no_data);
    let invalid_auth = AuthenticationDeserializationError::InvalidAuthenticationByte(39);
    assert_eq!(invalid_auth, invalid_auth);

    assert_ne!(no_data, invalid_auth);
}

impl PartialEq for AuthenticationDeserializationError {
    fn eq(&self, other: &AuthenticationDeserializationError) -> bool {
        match (self, other) {
            (
                &AuthenticationDeserializationError::NoDataFound,
                &AuthenticationDeserializationError::NoDataFound,
            ) => true,
            (
                &AuthenticationDeserializationError::InvalidAuthenticationByte(x),
                &AuthenticationDeserializationError::InvalidAuthenticationByte(y),
            ) => x == y,
            (_, _) => false,
        }
    }
}

/// The errors that can happen, as a server, when we're negotiating the start
/// of a SOCKS session.
#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Firewall disallowed connection from {0}:{1}")]
    FirewallRejected(SOCKSv5Address, u16),
    #[error("Could not agree on an authentication method with the client")]
    ItsNotUsItsYou,
    #[error("Failure in serializing response message: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Failed TLS handshake")]
    FailedTLSHandshake,
    #[error("IO error writing response message: {0}")]
    IOError(#[from] io::Error),
    #[error("Failure in reading client message: {0}")]
    DeserializationError(#[from] DeserializationError),
    #[error("Username/password check failed (username was {0})")]
    FailedUsernamePassword(String),
}
