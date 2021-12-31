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
    let invalid_version1 = DeserializationError::InvalidVersion(1, 2);
    let invalid_version2 = DeserializationError::InvalidVersion(1, 2);
    assert_eq!(invalid_version1, invalid_version2);

    let not_enough1 = DeserializationError::NotEnoughData;
    let not_enough2 = DeserializationError::NotEnoughData;
    assert_eq!(not_enough1, not_enough2);

    let invalid_empty1 = DeserializationError::InvalidEmptyString;
    let invalid_empty2 = DeserializationError::InvalidEmptyString;
    assert_eq!(invalid_empty1, invalid_empty2);

    let auth_method1 = DeserializationError::AuthenticationMethodError(
        AuthenticationDeserializationError::NoDataFound,
    );
    let auth_method2 = DeserializationError::AuthenticationMethodError(
        AuthenticationDeserializationError::NoDataFound,
    );
    assert_eq!(auth_method1, auth_method2);

    let utf8a = DeserializationError::UTF8Error(String::from_utf8(vec![0, 159]).unwrap_err());
    let utf8b = DeserializationError::UTF8Error(String::from_utf8(vec![0, 159]).unwrap_err());
    assert_eq!(utf8a, utf8b);

    let invalid_address1 = DeserializationError::InvalidAddressType(3);
    let invalid_address2 = DeserializationError::InvalidAddressType(3);
    assert_eq!(invalid_address1, invalid_address2);

    let invalid_client_cmd1 = DeserializationError::InvalidClientCommand(32);
    let invalid_client_cmd2 = DeserializationError::InvalidClientCommand(32);
    assert_eq!(invalid_client_cmd1, invalid_client_cmd2);

    let invalid_server_resp1 = DeserializationError::InvalidServerResponse(42);
    let invalid_server_resp2 = DeserializationError::InvalidServerResponse(42);
    assert_eq!(invalid_server_resp1, invalid_server_resp2);

    assert_ne!(invalid_version1, invalid_address1);
    assert_ne!(not_enough1, invalid_empty1);
    assert_ne!(auth_method1, invalid_client_cmd1);
    assert_ne!(utf8a, invalid_server_resp1);
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
    let too_many1 = SerializationError::TooManyAuthMethods(512);
    let too_many2 = SerializationError::TooManyAuthMethods(512);
    assert_eq!(too_many1, too_many2);

    let invalid_str1 = SerializationError::InvalidStringLength("Whoopsy!".to_string());
    let invalid_str2 = SerializationError::InvalidStringLength("Whoopsy!".to_string());
    assert_eq!(invalid_str1, invalid_str2);

    assert_ne!(too_many1, invalid_str1);
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
    let no_data1 = AuthenticationDeserializationError::NoDataFound;
    let no_data2 = AuthenticationDeserializationError::NoDataFound;
    assert_eq!(no_data1, no_data2);

    let invalid_auth1 = AuthenticationDeserializationError::InvalidAuthenticationByte(39);
    let invalid_auth2 = AuthenticationDeserializationError::InvalidAuthenticationByte(39);
    assert_eq!(invalid_auth1, invalid_auth2);

    assert_ne!(no_data1, invalid_auth1);
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
