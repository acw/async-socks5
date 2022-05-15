mod authentication_method;
mod client_command;
mod client_greeting;
mod client_username_password;
mod server_auth_response;
mod server_choice;
mod server_response;

pub(crate) mod string;

pub use crate::messages::authentication_method::{
    AuthenticationMethod, AuthenticationMethodReadError, AuthenticationMethodWriteError,
};
pub use crate::messages::client_command::{
    ClientConnectionCommand, ClientConnectionCommandReadError, ClientConnectionCommandWriteError,
    ClientConnectionRequest, ClientConnectionRequestReadError,
};
pub use crate::messages::client_greeting::{
    ClientGreeting, ClientGreetingReadError, ClientGreetingWriteError,
};
pub use crate::messages::client_username_password::{
    ClientUsernamePassword, ClientUsernamePasswordReadError, ClientUsernamePasswordWriteError,
};
pub use crate::messages::server_auth_response::{
    ServerAuthResponse, ServerAuthResponseReadError, ServerAuthResponseWriteError,
};
pub use crate::messages::server_choice::{
    ServerChoice, ServerChoiceReadError, ServerChoiceWriteError,
};
pub use crate::messages::server_response::{
    ServerResponse, ServerResponseReadError, ServerResponseStatus, ServerResponseWriteError,
};

#[doc(hidden)]
#[macro_export]
macro_rules! standard_roundtrip {
    ($name: ident, $t: ty) => {
        proptest::proptest! {
            #[test]
            fn $name(xs: $t) {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    use std::io::Cursor;

                    let buffer = vec![];
                    let mut write_cursor = Cursor::new(buffer);
                    xs.write(&mut write_cursor).await.unwrap();
                    let serialized_form = write_cursor.into_inner();
                    let mut read_cursor = Cursor::new(serialized_form);
                    let ys = <$t>::read(&mut read_cursor);
                    assert_eq!(xs, ys.await.unwrap());
                })
            }
        }
    };
}
